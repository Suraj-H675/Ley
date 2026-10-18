use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use reqwest::blocking::{Client, Response};
use reqwest::header::{
    ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, LOCATION, USER_AGENT,
};
use reqwest::redirect::Policy;
use url::Url;

use crate::html::{MAX_COMPRESSED_RESPONSE_BYTES, extract_html};
use crate::index::{InMemoryIndex, QueryError};
use crate::safe_fetch::FixtureCapability;
use crate::url_key::{UrlKey, UrlKeyError};

const CRAWLER_AGENT: &str = "LeyBot";
const FIXTURE_HOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

type CapturedHeaders = Vec<Vec<(String, String)>>;

#[derive(Clone, Debug)]
pub(super) struct FixtureResponse {
    status: u16,
    content_type: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    delay: Duration,
}

impl FixtureResponse {
    pub(super) fn html(body: impl AsRef<[u8]>) -> Self {
        Self::new(200, "text/html; charset=utf-8", body)
    }

    pub(super) fn text(body: impl AsRef<[u8]>) -> Self {
        Self::new(200, "text/plain; charset=utf-8", body)
    }

    #[cfg(test)]
    pub(super) fn redirect(location: impl Into<String>) -> Self {
        let mut response = Self::new(302, "text/plain", Vec::new());
        response
            .headers
            .push(("Location".to_owned(), location.into()));
        response
    }

    pub(super) fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    #[cfg(test)]
    pub(super) fn delayed(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    pub(super) fn new(status: u16, content_type: &str, body: impl AsRef<[u8]>) -> Self {
        Self {
            status,
            content_type: content_type.to_owned(),
            headers: Vec::new(),
            body: body.as_ref().to_vec(),
            delay: Duration::ZERO,
        }
    }
}

pub(super) struct LocalFixture {
    origin: FixtureOrigin,
    capability: FixtureCapability,
    #[cfg(test)]
    routes: Arc<Mutex<BTreeMap<String, FixtureResponse>>>,
    requests: Arc<Mutex<Vec<String>>>,
    #[cfg(test)]
    request_header_log: Arc<Mutex<CapturedHeaders>>,
    accepted_connections: Arc<AtomicUsize>,
    #[cfg(test)]
    conditional_requests: Arc<AtomicUsize>,
    fixture_alive: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    server_thread: Option<JoinHandle<()>>,
}

impl LocalFixture {
    pub(super) fn start(
        routes: impl IntoIterator<Item = (String, FixtureResponse)>,
    ) -> Result<Self, CrawlError> {
        let routes = routes.into_iter().collect();
        Self::start_with_origin(|_| routes)
    }

    pub(super) fn start_with_origin(
        routes: impl FnOnce(FixtureOrigin) -> Vec<(String, FixtureResponse)>,
    ) -> Result<Self, CrawlError> {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(FIXTURE_HOST), 0))
            .map_err(|error| CrawlError::Fixture(error.to_string()))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| CrawlError::Fixture(error.to_string()))?;
        let address = listener
            .local_addr()
            .map_err(|error| CrawlError::Fixture(error.to_string()))?;
        let origin = FixtureOrigin::from_listener(address)?;
        let fixture_alive = Arc::new(AtomicBool::new(true));
        let capability =
            FixtureCapability::from_owned_listener("127.0.0.1", &listener, &fixture_alive)
                .ok_or_else(|| {
                    CrawlError::Fixture("could not bind listener capability".to_owned())
                })?;
        let routes = Arc::new(Mutex::new(routes(origin).into_iter().collect()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let request_header_log = Arc::new(Mutex::new(Vec::new()));
        let accepted_connections = Arc::new(AtomicUsize::new(0));
        let conditional_requests = Arc::new(AtomicUsize::new(0));
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_routes = Arc::clone(&routes);
        let thread_requests = Arc::clone(&requests);
        let thread_header_log = Arc::clone(&request_header_log);
        let thread_accepts = Arc::clone(&accepted_connections);
        let thread_conditionals = Arc::clone(&conditional_requests);
        let thread_stopping = Arc::clone(&stopping);
        let server_thread = thread::Builder::new()
            .name("ley-local-fixture".to_owned())
            .spawn(move || {
                while !thread_stopping.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            thread_accepts.fetch_add(1, Ordering::SeqCst);
                            serve_one(
                                stream,
                                &thread_routes,
                                &thread_requests,
                                &thread_header_log,
                                &thread_conditionals,
                            );
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
            })
            .map_err(|error| CrawlError::Fixture(error.to_string()))?;
        Ok(Self {
            origin,
            capability,
            #[cfg(test)]
            routes,
            requests,
            #[cfg(test)]
            request_header_log,
            accepted_connections,
            #[cfg(test)]
            conditional_requests,
            fixture_alive,
            stopping,
            server_thread: Some(server_thread),
        })
    }

    pub(super) fn origin(&self) -> FixtureOrigin {
        self.origin
    }

    pub(super) fn capability(&self) -> FixtureCapability {
        self.capability.clone()
    }

    pub(super) fn base_url(&self) -> Url {
        Url::parse(&format!("http://127.0.0.1:{}/", self.origin.port))
            .expect("fixture origin is a validated loopback URL")
    }

    pub(super) fn request_log(&self) -> Vec<String> {
        self.requests
            .lock()
            .expect("fixture request log poisoned")
            .clone()
    }

    #[cfg(test)]
    pub(super) fn request_header_log(&self) -> CapturedHeaders {
        self.request_header_log
            .lock()
            .expect("fixture request headers poisoned")
            .clone()
    }

    pub(super) fn accepted_connections(&self) -> usize {
        self.accepted_connections.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(super) fn conditional_requests(&self) -> usize {
        self.conditional_requests.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(super) fn replace_response(&self, path: &str, response: FixtureResponse) {
        self.routes
            .lock()
            .expect("fixture routes poisoned")
            .insert(path.to_owned(), response);
    }
}

impl Drop for LocalFixture {
    fn drop(&mut self) {
        self.fixture_alive.store(false, Ordering::SeqCst);
        self.stopping.store(true, Ordering::Relaxed);
        if let Some(server_thread) = self.server_thread.take() {
            let _ = server_thread.join();
        }
    }
}

fn serve_one(
    mut stream: TcpStream,
    routes: &Mutex<BTreeMap<String, FixtureResponse>>,
    requests: &Mutex<Vec<String>>,
    request_header_log: &Mutex<CapturedHeaders>,
    conditional_requests: &AtomicUsize,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    let Ok(reader_stream) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(reader_stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }
    let mut target = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_owned();
    let mut conditional = false;
    let mut observed_headers = Vec::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).is_err() || header == "\r\n" || header == "\n" {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_owned();
            if matches!(name.as_str(), "if-none-match" | "if-modified-since") {
                conditional = true;
            }
            observed_headers.push((name, value));
        }
    }
    request_header_log
        .lock()
        .expect("fixture request headers poisoned")
        .push(observed_headers);
    if conditional {
        conditional_requests.fetch_add(1, Ordering::SeqCst);
    }
    if !target.starts_with('/') {
        target = "/".to_owned();
    }
    let route = target.split(['?', '#']).next().unwrap_or("/").to_owned();
    requests
        .lock()
        .expect("fixture request log poisoned")
        .push(target);
    let fallback = FixtureResponse::new(404, "text/plain", b"not found");
    let response = routes
        .lock()
        .expect("fixture routes poisoned")
        .get(&route)
        .cloned()
        .unwrap_or(fallback);
    let (status, body) = if response.status == 304 && !conditional {
        (200, response.body.as_slice())
    } else if response.status == 304 {
        (304, &[][..])
    } else {
        (response.status, response.body.as_slice())
    };
    if !response.delay.is_zero() {
        thread::sleep(response.delay);
    }
    let reason = match status {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        404 => "Not Found",
        _ => "Fixture Response",
    };
    let mut headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        status,
        reason,
        response.content_type,
        body.len()
    );
    for (name, value) in &response.headers {
        headers.push_str(name);
        headers.push_str(": ");
        headers.push_str(value);
        headers.push_str("\r\n");
    }
    headers.push_str("\r\n");
    if stream.write_all(headers.as_bytes()).is_ok() {
        let _ = stream.write_all(body);
        let _ = stream.flush();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FixtureOrigin {
    port: u16,
}

impl FixtureOrigin {
    fn from_listener(address: SocketAddr) -> Result<Self, CrawlError> {
        if address.ip() != IpAddr::V4(FIXTURE_HOST) {
            return Err(CrawlError::InvalidFixtureOrigin);
        }
        Ok(Self {
            port: address.port(),
        })
    }

    fn contains(&self, url: &Url) -> bool {
        url.scheme() == "http"
            && url.host_str() == Some("127.0.0.1")
            && url.port_or_known_default() == Some(self.port)
            && url.username().is_empty()
            && url.password().is_none()
    }

    pub(super) fn url(&self, path: &str) -> Result<UrlKey, CrawlError> {
        let url = Url::parse(&format!("http://127.0.0.1:{}{path}", self.port))
            .map_err(|error| CrawlError::Url(error.to_string()))?;
        UrlKey::parse(url.as_str()).map_err(CrawlError::from)
    }
}

#[derive(Clone, Debug)]
pub(super) struct CrawlConfig {
    max_requests: usize,
    max_redirects: usize,
    max_pages: usize,
    overall_deadline: Duration,
    request_timeout: Duration,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            max_requests: 32,
            max_redirects: 10,
            max_pages: 16,
            overall_deadline: Duration::from_secs(10),
            request_timeout: Duration::from_secs(2),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct CrawlStats {
    pub requests: usize,
    pub pages_fetched: usize,
    pub redirects: usize,
    pub unique_links: usize,
    pub duplicate_links_dropped: usize,
    pub disallowed_links: usize,
    pub out_of_origin_links: usize,
}

#[derive(Debug)]
pub(super) struct CrawlResult {
    pub index: InMemoryIndex,
    pub stats: CrawlStats,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum CrawlError {
    Fixture(String),
    InvalidFixtureOrigin,
    OriginEscape(String),
    Url(String),
    InvalidResponse(String),
    RequestLimit,
    Deadline,
    RedirectLimit,
    RedirectLoop,
    RobotsUnavailable,
    RobotsDisallowed(String),
    HttpStatus(u16),
    BodyTooLarge,
    Html(String),
    Index(String),
}

impl fmt::Display for CrawlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fixture(message) => write!(f, "local fixture error: {message}"),
            Self::InvalidFixtureOrigin => f.write_str("fixture must bind exactly 127.0.0.1"),
            Self::OriginEscape(url) => {
                write!(f, "refused fetch outside exact fixture origin: {url}")
            }
            Self::Url(message) => write!(f, "invalid crawl URL: {message}"),
            Self::InvalidResponse(message) => write!(f, "invalid HTTP response: {message}"),
            Self::RequestLimit => f.write_str("fixture HTTP request limit exceeded"),
            Self::Deadline => f.write_str("fixture crawl deadline exceeded"),
            Self::RedirectLimit => f.write_str("fixture redirect limit exceeded"),
            Self::RedirectLoop => f.write_str("fixture redirect loop detected"),
            Self::RobotsUnavailable => {
                f.write_str("fixture robots policy unavailable; crawl denied")
            }
            Self::RobotsDisallowed(path) => write!(f, "fixture robots policy disallows {path}"),
            Self::HttpStatus(status) => write!(f, "fixture returned HTTP status {status}"),
            Self::BodyTooLarge => write!(
                f,
                "fixture response exceeds {MAX_COMPRESSED_RESPONSE_BYTES} bytes"
            ),
            Self::Html(message) => write!(f, "HTML extraction failed: {message}"),
            Self::Index(message) => write!(f, "index operation failed: {message}"),
        }
    }
}

impl std::error::Error for CrawlError {}

impl From<UrlKeyError> for CrawlError {
    fn from(error: UrlKeyError) -> Self {
        Self::Url(error.to_string())
    }
}

struct FetchResponse {
    bytes: Vec<u8>,
    content_type: String,
    content_encoding: Option<String>,
    effective_url: String,
}

struct CrawlState {
    client: Client,
    origin: FixtureOrigin,
    config: CrawlConfig,
    deadline: Instant,
    stats: CrawlStats,
}

pub(super) fn crawl_fixture(
    origin: FixtureOrigin,
    start: UrlKey,
    config: CrawlConfig,
) -> Result<CrawlResult, CrawlError> {
    let client = Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .http1_only()
        .connect_timeout(config.request_timeout.min(Duration::from_secs(1)))
        .build()
        .map_err(|error| CrawlError::Fixture(error.to_string()))?;
    let deadline = Instant::now()
        .checked_add(config.overall_deadline)
        .ok_or(CrawlError::Deadline)?;
    let mut state = CrawlState {
        client,
        origin,
        config,
        deadline,
        stats: CrawlStats::default(),
    };
    if !origin.contains(&start.to_url()?) {
        return Err(CrawlError::OriginEscape(start.to_string()));
    }
    let robots_url = origin.url("/robots.txt")?;
    let robots_response = state.fetch(&robots_url, None)?;
    let robots =
        RobotsPolicy::parse(&robots_response.bytes).ok_or(CrawlError::RobotsUnavailable)?;
    let mut queue = VecDeque::from([start.clone()]);
    let mut scheduled = BTreeSet::from([start]);
    let mut index = InMemoryIndex::new();
    while let Some(key) = queue.pop_front() {
        if index.len() >= state.config.max_pages {
            break;
        }
        let page_url = key.to_url()?;
        if !origin.contains(&page_url) {
            state.stats.out_of_origin_links += 1;
            continue;
        }
        if robots.disallows(page_url.path()) {
            state.stats.disallowed_links += 1;
            continue;
        }
        let fetched = match state.fetch(&key, Some(&robots)) {
            Ok(response) => response,
            Err(CrawlError::RobotsDisallowed(path)) => {
                state.stats.disallowed_links += 1;
                let _ = path;
                continue;
            }
            Err(error) => return Err(error),
        };
        let document = extract_html(
            &fetched.bytes,
            &fetched.content_type,
            fetched.content_encoding.as_deref(),
            key,
            &fetched.effective_url,
        )
        .map_err(|error| CrawlError::Html(error.to_string()))?;
        state.stats.pages_fetched += 1;
        let links = document.links.clone();
        state.stats.duplicate_links_dropped += document.duplicate_links;
        index
            .insert(document)
            .map_err(|error: QueryError| CrawlError::Index(error.to_string()))?;
        for link in links {
            state.stats.unique_links += 1;
            let link_url = link.to_url()?;
            if !origin.contains(&link_url) {
                state.stats.out_of_origin_links += 1;
                continue;
            }
            if !scheduled.insert(link.clone()) {
                state.stats.duplicate_links_dropped += 1;
            } else {
                queue.push_back(link);
            }
        }
    }
    Ok(CrawlResult {
        index,
        stats: state.stats,
    })
}

impl CrawlState {
    fn fetch(
        &mut self,
        requested: &UrlKey,
        robots: Option<&RobotsPolicy>,
    ) -> Result<FetchResponse, CrawlError> {
        let mut current_key = requested.clone();
        let mut chain = BTreeSet::from([current_key.clone()]);
        let mut redirects = 0usize;
        loop {
            let current = current_key.to_url()?;
            if !self.origin.contains(&current) {
                return Err(CrawlError::OriginEscape(current_key.to_string()));
            }
            if let Some(robots) = robots
                && robots.disallows(current.path())
            {
                return Err(CrawlError::RobotsDisallowed(current.path().to_owned()));
            }
            if Instant::now() >= self.deadline {
                return Err(CrawlError::Deadline);
            }
            if self.stats.requests >= self.config.max_requests {
                return Err(CrawlError::RequestLimit);
            }
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            let timeout = remaining.min(self.config.request_timeout);
            if timeout.is_zero() {
                return Err(CrawlError::Deadline);
            }
            self.stats.requests += 1;
            let response = self
                .client
                .get(current_key.as_str())
                .header(USER_AGENT, concat!("LeyBot/", env!("CARGO_PKG_VERSION")))
                .header(ACCEPT_ENCODING, "identity")
                .timeout(timeout)
                .send()
                .map_err(|error| {
                    if error.is_timeout() {
                        CrawlError::Deadline
                    } else {
                        CrawlError::Fixture(error.to_string())
                    }
                })?;
            let status = response.status();
            if matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308) {
                if redirects >= self.config.max_redirects {
                    return Err(CrawlError::RedirectLimit);
                }
                let location = response
                    .headers()
                    .get(LOCATION)
                    .ok_or_else(|| {
                        CrawlError::InvalidResponse("redirect has no Location".to_owned())
                    })?
                    .to_str()
                    .map_err(|error| CrawlError::InvalidResponse(error.to_string()))?;
                let target = UrlKey::resolve(&current, location)?;
                let target_url = target.to_url()?;
                if !self.origin.contains(&target_url) {
                    return Err(CrawlError::OriginEscape(target.to_string()));
                }
                if robots.is_some_and(|policy| policy.disallows(target_url.path())) {
                    return Err(CrawlError::RobotsDisallowed(target_url.path().to_owned()));
                }
                if !chain.insert(target.clone()) {
                    return Err(CrawlError::RedirectLoop);
                }
                redirects += 1;
                self.stats.redirects += 1;
                current_key = target;
                continue;
            }
            if !status.is_success() {
                return Err(CrawlError::HttpStatus(status.as_u16()));
            }
            if response
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<usize>().ok())
                .is_some_and(|length| length > MAX_COMPRESSED_RESPONSE_BYTES)
            {
                return Err(CrawlError::BodyTooLarge);
            }
            return read_response(response, current_key.as_str());
        }
    }
}

fn read_response(mut response: Response, effective_url: &str) -> Result<FetchResponse, CrawlError> {
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let content_encoding = response
        .headers()
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take((MAX_COMPRESSED_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| CrawlError::Fixture(error.to_string()))?;
    if bytes.len() > MAX_COMPRESSED_RESPONSE_BYTES {
        return Err(CrawlError::BodyTooLarge);
    }
    Ok(FetchResponse {
        bytes,
        content_type,
        content_encoding,
        effective_url: effective_url.to_owned(),
    })
}

struct RobotsPolicy {
    disallows: Vec<String>,
}

impl RobotsPolicy {
    fn parse(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let mut active = false;
        let mut recognized_agent = false;
        let mut disallows = Vec::new();
        for line in text.lines() {
            let directive = line.split('#').next().unwrap_or_default().trim();
            let Some((name, value)) = directive.split_once(':') else {
                continue;
            };
            if name.trim().eq_ignore_ascii_case("user-agent") {
                active = value.trim() == "*" || value.trim().eq_ignore_ascii_case(CRAWLER_AGENT);
                recognized_agent |= active;
            } else if name.trim().eq_ignore_ascii_case("disallow") && active {
                let path = value.trim();
                if !path.is_empty() {
                    disallows.push(path.to_owned());
                }
            }
        }
        recognized_agent.then_some(Self { disallows })
    }

    fn disallows(&self, path: &str) -> bool {
        self.disallows.iter().any(|prefix| path.starts_with(prefix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes(
        extra: impl IntoIterator<Item = (String, FixtureResponse)>,
    ) -> Vec<(String, FixtureResponse)> {
        let mut routes = vec![(
            "/robots.txt".to_owned(),
            FixtureResponse::text("User-agent: LeyBot\nDisallow: /private\n"),
        )];
        routes.extend(extra);
        routes
    }

    #[test]
    fn rejects_foreign_redirect_origin_before_requesting_it() {
        let destination = LocalFixture::start(routes([(
            "/never".to_owned(),
            FixtureResponse::html("<title>outside</title>"),
        )]))
        .unwrap();
        let target = format!("{}never", destination.base_url());
        let source = LocalFixture::start(routes([(
            "/escape".to_owned(),
            FixtureResponse::redirect(target),
        )]))
        .unwrap();
        let start = source.origin.url("/escape").unwrap();
        let error = crawl_fixture(source.origin(), start, CrawlConfig::default()).unwrap_err();
        assert!(matches!(error, CrawlError::OriginEscape(_)));
        assert!(destination.request_log().is_empty());
        assert_eq!(source.request_log(), ["/robots.txt", "/escape"]);
    }

    #[test]
    fn rejects_empty_userinfo_redirect_before_requesting_target() {
        let fixture = LocalFixture::start_with_origin(|origin| {
            routes([
                (
                    "/redirect".to_owned(),
                    FixtureResponse::redirect(format!("//@127.0.0.1:{}/secret", origin.port)),
                ),
                (
                    "/secret".to_owned(),
                    FixtureResponse::html("<title>must not be requested</title>"),
                ),
            ])
        })
        .unwrap();
        let start = fixture.origin.url("/redirect").unwrap();

        let result = crawl_fixture(fixture.origin(), start, CrawlConfig::default());
        assert!(matches!(
            result,
            Err(CrawlError::Url(message)) if message == "URL userinfo is not allowed"
        ));
        assert_eq!(fixture.request_log(), ["/robots.txt", "/redirect"]);
    }

    #[test]
    fn rejects_over_limit_bodies_and_request_timeouts() {
        let large = vec![b'x'; MAX_COMPRESSED_RESPONSE_BYTES + 1];
        let fixture = LocalFixture::start(routes([(
            "/large".to_owned(),
            FixtureResponse::html(large),
        )]))
        .unwrap();
        let error = crawl_fixture(
            fixture.origin(),
            fixture.origin.url("/large").unwrap(),
            CrawlConfig::default(),
        )
        .unwrap_err();
        assert_eq!(error, CrawlError::BodyTooLarge);

        let slow = LocalFixture::start(routes([(
            "/slow".to_owned(),
            FixtureResponse::html("<title>slow</title>").delayed(Duration::from_millis(150)),
        )]))
        .unwrap();
        let config = CrawlConfig {
            request_timeout: Duration::from_millis(40),
            overall_deadline: Duration::from_millis(500),
            ..CrawlConfig::default()
        };
        let error =
            crawl_fixture(slow.origin(), slow.origin.url("/slow").unwrap(), config).unwrap_err();
        assert_eq!(error, CrawlError::Deadline);
    }

    #[test]
    fn disallowed_redirect_target_is_not_requested() {
        let fixture = LocalFixture::start(routes([(
            "/jump".to_owned(),
            FixtureResponse::redirect("/private/secret"),
        )]))
        .unwrap();
        let result = crawl_fixture(
            fixture.origin(),
            fixture.origin.url("/jump").unwrap(),
            CrawlConfig::default(),
        )
        .unwrap();
        assert_eq!(result.index.len(), 0);
        assert_eq!(result.stats.disallowed_links, 1);
        assert_eq!(fixture.request_log(), ["/robots.txt", "/jump"]);
    }

    #[test]
    fn rejects_wrong_seed_port_before_any_request() {
        let fixture = LocalFixture::start(routes([])).unwrap();
        let outside = UrlKey::parse("http://127.0.0.1:1/").unwrap();
        let error = crawl_fixture(fixture.origin(), outside, CrawlConfig::default()).unwrap_err();
        assert!(matches!(error, CrawlError::OriginEscape(_)));
        assert!(fixture.request_log().is_empty());
    }

    #[test]
    fn rejects_wrong_host_and_redirect_budget_before_following() {
        let destination = LocalFixture::start(routes([(
            "/unused".to_owned(),
            FixtureResponse::html("<title>unused</title>"),
        )]))
        .unwrap();
        let source_routes = routes([(
            "/escape-host".to_owned(),
            FixtureResponse::redirect(format!(
                "http://localhost:{}/unused",
                destination.origin().port
            )),
        )]);
        let source = LocalFixture::start(source_routes).unwrap();
        let error = crawl_fixture(
            source.origin(),
            source.origin.url("/escape-host").unwrap(),
            CrawlConfig::default(),
        )
        .unwrap_err();
        assert!(matches!(error, CrawlError::OriginEscape(_)));
        assert_eq!(source.request_log(), ["/robots.txt", "/escape-host"]);
        assert!(destination.request_log().is_empty());

        let mut chain = Vec::new();
        for hop in 0..=11 {
            chain.push((
                format!("/r{hop}"),
                FixtureResponse::redirect(format!("/r{}", hop + 1)),
            ));
        }
        let redirects = LocalFixture::start(routes(chain)).unwrap();
        let error = crawl_fixture(
            redirects.origin(),
            redirects.origin.url("/r0").unwrap(),
            CrawlConfig::default(),
        )
        .unwrap_err();
        assert_eq!(error, CrawlError::RedirectLimit);
        assert!(!redirects.request_log().iter().any(|path| path == "/r11"));
    }

    #[test]
    fn enforces_total_request_budget_before_opening_another_connection() {
        let fixture = LocalFixture::start(routes([(
            "/page".to_owned(),
            FixtureResponse::html("<title>page</title>"),
        )]))
        .unwrap();
        let config = CrawlConfig {
            max_requests: 1,
            ..CrawlConfig::default()
        };
        let error = crawl_fixture(
            fixture.origin(),
            fixture.origin.url("/page").unwrap(),
            config,
        )
        .unwrap_err();
        assert_eq!(error, CrawlError::RequestLimit);
        assert_eq!(fixture.request_log(), ["/robots.txt"]);
    }
}

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr, TcpListener, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use flate2::read::GzDecoder;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT_ENCODING, CONTENT_ENCODING, HeaderMap, LOCATION, USER_AGENT};
use reqwest::redirect::Policy;
use url::Url;

use crate::html::{MAX_COMPRESSED_RESPONSE_BYTES, MAX_DECODED_RESPONSE_BYTES};

pub const MAX_DNS_ANSWERS: usize = 16;
pub const MAX_ROBOTS_REDIRECTS: usize = 5;
pub const MAX_RESPONSE_HEADER_BYTES: usize = 32 * 1024;
pub const MAX_RESPONSE_HEADER_VALUES: usize = 128;
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const CRAWL_USER_AGENT: &str = concat!("LeyBot/", env!("CARGO_PKG_VERSION"));
const RESOLVER_WORKERS: usize = 4;
const RESOLVER_QUEUE: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SafeFetchError {
    InvalidUrl,
    UnadmittedAuthority,
    Resolution(String),
    EmptyResolution,
    TooManyAddresses,
    UnsafeAddress(String),
    Request(String),
    ResponseBody(String),
    CompressedBodyTooLarge,
    DecompressedBodyTooLarge,
    UnsupportedContentEncoding(String),
    InvalidHeader(String),
    ResponseHeadersTooLarge,
    ResolverBusy,
    ResolverTimeout,
}

impl fmt::Display for SafeFetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl => f.write_str("only credential-free HTTP URLs are supported"),
            Self::UnadmittedAuthority => f.write_str("authority has no owned fixture capability"),
            Self::Resolution(message) => write!(f, "destination resolution failed: {message}"),
            Self::EmptyResolution => f.write_str("destination resolver returned no addresses"),
            Self::TooManyAddresses => {
                write!(f, "destination resolver exceeded {MAX_DNS_ANSWERS} answers")
            }
            Self::UnsafeAddress(address) => write!(
                f,
                "destination answer is outside the owned fixture: {address}"
            ),
            Self::Request(message) => write!(f, "HTTP request failed: {message}"),
            Self::ResponseBody(message) => write!(f, "HTTP response body failed: {message}"),
            Self::CompressedBodyTooLarge => write!(
                f,
                "compressed response exceeds {MAX_COMPRESSED_RESPONSE_BYTES} bytes"
            ),
            Self::DecompressedBodyTooLarge => write!(
                f,
                "decompressed response exceeds {MAX_DECODED_RESPONSE_BYTES} bytes"
            ),
            Self::UnsupportedContentEncoding(encoding) => {
                write!(f, "unsupported content encoding: {encoding}")
            }
            Self::InvalidHeader(name) => write!(f, "invalid or repeated {name} header"),
            Self::ResponseHeadersTooLarge => write!(
                f,
                "response headers exceed {MAX_RESPONSE_HEADER_BYTES} bytes or {MAX_RESPONSE_HEADER_VALUES} values"
            ),
            Self::ResolverBusy => f.write_str("bounded destination resolver queue is full"),
            Self::ResolverTimeout => f.write_str("destination resolution exceeded request timeout"),
        }
    }
}

impl std::error::Error for SafeFetchError {}

pub trait DestinationResolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

impl DestinationResolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        (host, port)
            .to_socket_addrs()
            .map(|addresses| addresses.take(MAX_DNS_ANSWERS + 1).collect())
    }
}

type ResolverJob = Box<dyn FnOnce() + Send + 'static>;

struct ResolverPool {
    sender: mpsc::SyncSender<ResolverJob>,
}

fn resolver_pool() -> Result<&'static ResolverPool, SafeFetchError> {
    static POOL: OnceLock<Result<ResolverPool, String>> = OnceLock::new();
    match POOL.get_or_init(|| {
        let (sender, receiver) = mpsc::sync_channel::<ResolverJob>(RESOLVER_QUEUE);
        let receiver = Arc::new(Mutex::new(receiver));
        for index in 0..RESOLVER_WORKERS {
            let receiver = Arc::clone(&receiver);
            thread::Builder::new()
                .name(format!("ley-dns-{index}"))
                .spawn(move || {
                    loop {
                        let job = match receiver.lock() {
                            Ok(receiver) => receiver.recv(),
                            Err(_) => return,
                        };
                        match job {
                            Ok(job) => job(),
                            Err(_) => return,
                        }
                    }
                })
                .map_err(|error| error.to_string())?;
        }
        Ok(ResolverPool { sender })
    }) {
        Ok(pool) => Ok(pool),
        Err(error) => Err(SafeFetchError::Resolution(error.clone())),
    }
}

fn resolve_bounded<R: DestinationResolver + 'static>(
    resolver: Arc<R>,
    host: String,
    port: u16,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, SafeFetchError> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let job = Box::new(move || {
        let result = resolver.resolve(&host, port);
        let _ = sender.send(result);
    });
    resolver_pool()?
        .sender
        .try_send(job)
        .map_err(|error| match error {
            mpsc::TrySendError::Full(_) => SafeFetchError::ResolverBusy,
            mpsc::TrySendError::Disconnected(_) => {
                SafeFetchError::Resolution("resolver pool has stopped".to_owned())
            }
        })?;
    match receiver.recv_timeout(timeout) {
        Ok(result) => result.map_err(|error| SafeFetchError::Resolution(error.to_string())),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(SafeFetchError::ResolverTimeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(SafeFetchError::Resolution(
            "resolver worker stopped before returning an answer".to_owned(),
        )),
    }
}

#[derive(Clone, Debug)]
pub(crate) struct FixtureCapability {
    host: String,
    port: u16,
    endpoint: SocketAddr,
    alive: Weak<AtomicBool>,
}

impl FixtureCapability {
    pub(crate) fn from_owned_listener(
        host: &str,
        listener: &TcpListener,
        alive: &Arc<AtomicBool>,
    ) -> Option<Self> {
        let endpoint = listener.local_addr().ok()?;
        if endpoint.port() == 0 || !endpoint.ip().is_loopback() || host.is_empty() {
            return None;
        }
        Some(Self {
            host: host.to_ascii_lowercase(),
            port: endpoint.port(),
            endpoint,
            alive: Arc::downgrade(alive),
        })
    }

    #[cfg(test)]
    pub(crate) fn named_for_host(&self, host: &str) -> Option<Self> {
        if host.is_empty() || !self.is_alive() {
            return None;
        }
        let mut capability = self.clone();
        capability.host = host.to_ascii_lowercase();
        Some(capability)
    }

    fn is_alive(&self) -> bool {
        self.alive
            .upgrade()
            .is_some_and(|alive| alive.load(Ordering::SeqCst))
    }
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HeaderMap,
    /// `Err` means a validated response head arrived but its body was rejected.
    pub body: Result<Vec<u8>, SafeFetchError>,
    pub requested_url: String,
    pub wire_bytes: usize,
    pub decoded_bytes: usize,
}

impl HttpResponse {
    pub fn location(&self) -> Result<Option<&str>, SafeFetchError> {
        let mut values = self.headers.get_all(LOCATION).iter();
        let Some(value) = values.next() else {
            return Ok(None);
        };
        if values.next().is_some() {
            return Err(SafeFetchError::InvalidHeader("Location".to_owned()));
        }
        value
            .to_str()
            .map(Some)
            .map_err(|_| SafeFetchError::InvalidHeader("Location".to_owned()))
    }

    pub fn header_values<'a>(&'a self, name: &'static str) -> impl Iterator<Item = &'a str> {
        let name = reqwest::header::HeaderName::from_static(name);
        self.headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
    }
}

pub struct SafeFetcher<R> {
    resolver: Arc<R>,
    capabilities: Vec<FixtureCapability>,
    request_timeout: Duration,
}

impl<R: DestinationResolver + 'static> SafeFetcher<R> {
    pub(crate) fn new(resolver: R, capabilities: Vec<FixtureCapability>) -> Self {
        Self {
            resolver: Arc::new(resolver),
            capabilities,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }

    pub(crate) fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout.min(Duration::from_secs(30));
        self
    }

    pub(crate) fn has_capability(&self, url: &Url) -> bool {
        let Some(host) = url.host_str() else {
            return false;
        };
        let Some(port) = url.port_or_known_default() else {
            return false;
        };
        self.capabilities.iter().any(|capability| {
            capability.is_alive()
                && capability.host.eq_ignore_ascii_case(host)
                && capability.port == port
        })
    }

    #[cfg(test)]
    pub fn fetch(&self, url: &Url) -> Result<HttpResponse, SafeFetchError> {
        self.fetch_with_headers(url, &HeaderMap::new())
    }

    pub fn fetch_with_headers(
        &self,
        url: &Url,
        request_headers: &HeaderMap,
    ) -> Result<HttpResponse, SafeFetchError> {
        let deadline = Instant::now() + self.request_timeout;
        if url.scheme() != "http"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.host_str().is_none()
        {
            return Err(SafeFetchError::InvalidUrl);
        }
        let host = url.host_str().ok_or(SafeFetchError::InvalidUrl)?;
        let port = url
            .port_or_known_default()
            .ok_or(SafeFetchError::InvalidUrl)?;
        let capability = self
            .capabilities
            .iter()
            .find(|capability| {
                capability.is_alive()
                    && capability.host.eq_ignore_ascii_case(host)
                    && capability.port == port
            })
            .ok_or(SafeFetchError::UnadmittedAuthority)?;

        let resolve_timeout = deadline.saturating_duration_since(Instant::now());
        if resolve_timeout.is_zero() {
            return Err(SafeFetchError::ResolverTimeout);
        }
        let answers = resolve_bounded(
            Arc::clone(&self.resolver),
            host.to_owned(),
            port,
            resolve_timeout,
        )?;
        if answers.is_empty() {
            return Err(SafeFetchError::EmptyResolution);
        }
        if answers.len() > MAX_DNS_ANSWERS {
            return Err(SafeFetchError::TooManyAddresses);
        }
        let mut pinned_ips = BTreeSet::new();
        for answer in answers {
            let ip = answer.ip();
            if ip != capability.endpoint.ip() || !is_loopback(ip) {
                return Err(SafeFetchError::UnsafeAddress(answer.to_string()));
            }
            pinned_ips.insert(ip);
        }
        if pinned_ips.len() != 1 {
            return Err(SafeFetchError::UnsafeAddress(
                "fixture answer set is not a single owned endpoint".to_owned(),
            ));
        }
        let pinned: Vec<SocketAddr> = pinned_ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, 0))
            .collect();

        // A new client per request prevents pooled connections from bypassing
        // the just-validated DNS answer set. Automatic redirects and proxies
        // are disabled, and reqwest's resolver override pins the connection.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(SafeFetchError::ResolverTimeout);
        }
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(remaining.min(Duration::from_secs(5)))
            .timeout(remaining)
            .pool_max_idle_per_host(0)
            .resolve_to_addrs(host, &pinned)
            .build()
            .map_err(|error| SafeFetchError::Request(error.to_string()))?;
        let mut request = client.get(url.clone()).header(ACCEPT_ENCODING, "gzip");
        for (name, value) in request_headers {
            request = request.header(name, value);
        }
        request = request.header(USER_AGENT, CRAWL_USER_AGENT);
        let mut response = request
            .send()
            .map_err(|error| SafeFetchError::Request(error.to_string()))?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        check_response_header_bounds(&headers)?;
        let mut wire = Vec::with_capacity(4096);
        let wire_result = response
            .by_ref()
            .take((MAX_COMPRESSED_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut wire);
        let observed_wire_bytes = wire.len();
        let wire_bytes = observed_wire_bytes.min(MAX_COMPRESSED_RESPONSE_BYTES);
        let mut decoded_bytes = 0;
        let body = match wire_result {
            Err(error) => {
                decoded_bytes = wire_bytes;
                Err(SafeFetchError::ResponseBody(error.to_string()))
            }
            Ok(_) if observed_wire_bytes > MAX_COMPRESSED_RESPONSE_BYTES => {
                Err(SafeFetchError::CompressedBodyTooLarge)
            }
            Ok(_) => match single_header(&headers, CONTENT_ENCODING, "Content-Encoding") {
                Err(error) => Err(error),
                Ok(content_encoding) => match content_encoding.as_deref().map(str::trim) {
                    None | Some("") | Some("identity") => {
                        decoded_bytes = wire_bytes;
                        Ok(wire)
                    }
                    Some(encoding) if encoding.eq_ignore_ascii_case("gzip") => {
                        let mut decoded = Vec::with_capacity(wire.len().min(64 * 1024));
                        let decoded_result = GzDecoder::new(wire.as_slice())
                            .take((MAX_DECODED_RESPONSE_BYTES + 1) as u64)
                            .read_to_end(&mut decoded);
                        let observed_decoded_bytes = decoded.len();
                        decoded_bytes = observed_decoded_bytes.min(MAX_DECODED_RESPONSE_BYTES);
                        match decoded_result {
                            Err(error) => Err(SafeFetchError::ResponseBody(error.to_string())),
                            Ok(_) if observed_decoded_bytes > MAX_DECODED_RESPONSE_BYTES => {
                                Err(SafeFetchError::DecompressedBodyTooLarge)
                            }
                            Ok(_) => Ok(decoded),
                        }
                    }
                    Some(encoding) => Err(SafeFetchError::UnsupportedContentEncoding(
                        encoding.to_owned(),
                    )),
                },
            },
        };
        Ok(HttpResponse {
            status,
            headers,
            decoded_bytes,
            body,
            requested_url: url.to_string(),
            wire_bytes,
        })
    }
}

fn single_header(
    headers: &HeaderMap,
    name: reqwest::header::HeaderName,
    display_name: &str,
) -> Result<Option<String>, SafeFetchError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(SafeFetchError::InvalidHeader(display_name.to_owned()));
    }
    value
        .to_str()
        .map(|value| Some(value.to_owned()))
        .map_err(|_| SafeFetchError::InvalidHeader(display_name.to_owned()))
}

fn check_response_header_bounds(headers: &HeaderMap) -> Result<(), SafeFetchError> {
    let mut bytes = 0usize;
    let mut values = 0usize;
    for name in headers.keys() {
        for value in headers.get_all(name) {
            values = values.saturating_add(1);
            bytes = bytes
                .saturating_add(name.as_str().len())
                .saturating_add(value.as_bytes().len());
            if values > MAX_RESPONSE_HEADER_VALUES || bytes > MAX_RESPONSE_HEADER_BYTES {
                return Err(SafeFetchError::ResponseHeadersTooLarge);
            }
        }
    }
    Ok(())
}

fn is_loopback(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_loopback(),
        IpAddr::V6(address) => address.is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};

    use super::*;

    type TestRoute = (u16, Vec<(String, String)>, Vec<u8>);
    type TestRoutes = BTreeMap<String, TestRoute>;
    type CapturedHeaders = Vec<Vec<(String, String)>>;

    struct MutableResolver {
        answers: Mutex<BTreeMap<String, Vec<SocketAddr>>>,
        calls: AtomicUsize,
    }

    impl DestinationResolver for Arc<MutableResolver> {
        fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.answers
                .lock()
                .unwrap()
                .get(&host.to_ascii_lowercase())
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unmapped fixture host"))
        }
    }

    struct BlockingResolver {
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
        finished: mpsc::Sender<()>,
        answer: SocketAddr,
    }

    impl DestinationResolver for BlockingResolver {
        fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            let _ = self.entered.send(());
            let _ = self.release.lock().unwrap().recv();
            let _ = self.finished.send(());
            Ok(vec![self.answer])
        }
    }

    struct SocketFixture {
        address: SocketAddr,
        alive: Arc<AtomicBool>,
        capability: FixtureCapability,
        accepts: Arc<AtomicUsize>,
        headers: Arc<Mutex<CapturedHeaders>>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl SocketFixture {
        fn start(routes: TestRoutes) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let alive = Arc::new(AtomicBool::new(true));
            let capability =
                FixtureCapability::from_owned_listener("fixture.invalid", &listener, &alive)
                    .expect("bound loopback fixture listener");
            let accepts = Arc::new(AtomicUsize::new(0));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let headers = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let thread_accepts = Arc::clone(&accepts);
            let thread_requests = Arc::clone(&requests);
            let thread_headers = Arc::clone(&headers);
            let thread_stop = Arc::clone(&stop);
            let thread = thread::spawn(move || {
                while !thread_stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            thread_accepts.fetch_add(1, Ordering::SeqCst);
                            serve(stream, &routes, &thread_requests, &thread_headers);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                address,
                alive,
                capability,
                accepts,
                headers,
                stop,
                thread: Some(thread),
            }
        }

        fn capability(&self, host: &str) -> FixtureCapability {
            self.capability.named_for_host(host).unwrap()
        }

        fn accepts(&self) -> usize {
            self.accepts.load(Ordering::SeqCst)
        }

        fn request_headers(&self) -> CapturedHeaders {
            self.headers.lock().unwrap().clone()
        }
    }

    impl Drop for SocketFixture {
        fn drop(&mut self) {
            self.alive.store(false, Ordering::SeqCst);
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn serve(
        mut stream: TcpStream,
        routes: &TestRoutes,
        requests: &Mutex<Vec<String>>,
        observed_headers: &Mutex<CapturedHeaders>,
    ) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request = String::new();
        if reader.read_line(&mut request).is_err() || request.is_empty() {
            return;
        }
        let target = request.split_whitespace().nth(1).unwrap_or("/").to_owned();
        requests.lock().unwrap().push(target.clone());
        let mut headers = Vec::new();
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).is_err() || header == "\r\n" || header == "\n" {
                break;
            }
            if let Some((name, value)) = header.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
            }
        }
        observed_headers.lock().unwrap().push(headers);
        let (status, headers, body) = routes
            .get(target.split('?').next().unwrap_or("/"))
            .cloned()
            .unwrap_or((404, Vec::new(), b"missing".to_vec()));
        let mut head = format!(
            "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        if stream.write_all(head.as_bytes()).is_ok() {
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
    }

    #[test]
    fn pins_owned_fixture_answers_and_rejects_changed_or_mixed_dns_before_connect() {
        let fixture = SocketFixture::start(BTreeMap::new());
        let resolver = Arc::new(MutableResolver {
            answers: Mutex::new(BTreeMap::from([(
                "owned.fixture.test".to_owned(),
                vec![fixture.address],
            )])),
            calls: AtomicUsize::new(0),
        });
        let fetcher = SafeFetcher::new(
            Arc::clone(&resolver),
            vec![fixture.capability("owned.fixture.test")],
        );
        let url = Url::parse(&format!(
            "http://owned.fixture.test:{}/",
            fixture.address.port()
        ))
        .unwrap();
        let response = fetcher.fetch(&url).unwrap();
        assert_eq!(response.status, 404);
        assert_eq!(fixture.accepts(), 1);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture.request_headers()[0]
                .iter()
                .find(|(name, _)| name == "user-agent")
                .map(|(_, value)| value.as_str()),
            Some(CRAWL_USER_AGENT)
        );

        resolver.answers.lock().unwrap().insert(
            "owned.fixture.test".to_owned(),
            vec![fixture.address, "192.0.2.10:0".parse().unwrap()],
        );
        assert!(matches!(
            fetcher.fetch(&url),
            Err(SafeFetchError::UnsafeAddress(_))
        ));
        assert_eq!(
            fixture.accepts(),
            1,
            "mixed DNS answers must fail before connecting"
        );

        resolver.answers.lock().unwrap().insert(
            "owned.fixture.test".to_owned(),
            vec!["127.0.0.2:0".parse().unwrap()],
        );
        assert!(matches!(
            fetcher.fetch(&url),
            Err(SafeFetchError::UnsafeAddress(_))
        ));
        assert_eq!(
            fixture.accepts(),
            1,
            "a changed DNS answer must fail before connecting"
        );

        resolver.answers.lock().unwrap().insert(
            "owned.fixture.test".to_owned(),
            vec![fixture.address; MAX_DNS_ANSWERS + 1],
        );
        assert!(matches!(
            fetcher.fetch(&url),
            Err(SafeFetchError::TooManyAddresses)
        ));
        assert_eq!(
            fixture.accepts(),
            1,
            "the DNS answer count cap fails before another connection"
        );
    }

    #[test]
    fn blocking_resolver_obeys_whole_request_deadline_without_connecting_later() {
        let fixture = SocketFixture::start(BTreeMap::new());
        let warm = SafeFetcher::new(
            Arc::new(MutableResolver {
                answers: Mutex::new(BTreeMap::from([(
                    "warm.fixture.test".to_owned(),
                    vec![fixture.address],
                )])),
                calls: AtomicUsize::new(0),
            }),
            vec![fixture.capability("warm.fixture.test")],
        );
        let warm_url = Url::parse(&format!(
            "http://warm.fixture.test:{}/",
            fixture.address.port()
        ))
        .unwrap();
        warm.fetch(&warm_url).unwrap();

        let (entered_sender, entered_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        let (finished_sender, finished_receiver) = mpsc::channel();
        let fetcher = SafeFetcher::new(
            BlockingResolver {
                entered: entered_sender,
                release: Mutex::new(release_receiver),
                finished: finished_sender,
                answer: fixture.address,
            },
            vec![fixture.capability("blocked.fixture.test")],
        )
        .with_timeout(Duration::from_millis(100));
        let url = Url::parse(&format!(
            "http://blocked.fixture.test:{}/",
            fixture.address.port()
        ))
        .unwrap();
        let before = fixture.accepts();
        let started = Instant::now();

        let result = fetcher.fetch(&url);

        assert!(matches!(result, Err(SafeFetchError::ResolverTimeout)));
        assert!(started.elapsed() < Duration::from_secs(1));
        entered_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        release_sender.send(()).unwrap();
        finished_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            fixture.accepts(),
            before,
            "timed out DNS cannot connect later"
        );
    }

    #[test]
    fn unadmitted_redirect_host_gets_no_socket_connection() {
        let fixture = SocketFixture::start(BTreeMap::from([(
            "/start".to_owned(),
            (
                302,
                vec![(
                    "Location".to_owned(),
                    "http://denied.fixture.test:8123/".to_owned(),
                )],
                Vec::new(),
            ),
        )]));
        let resolver = Arc::new(MutableResolver {
            answers: Mutex::new(BTreeMap::from([(
                "owned.fixture.test".to_owned(),
                vec![fixture.address],
            )])),
            calls: AtomicUsize::new(0),
        });
        let fetcher = SafeFetcher::new(
            Arc::clone(&resolver),
            vec![fixture.capability("owned.fixture.test")],
        );
        let start = Url::parse(&format!(
            "http://owned.fixture.test:{}/start",
            fixture.address.port()
        ))
        .unwrap();
        let response = fetcher.fetch(&start).unwrap();
        let target = start.join(response.location().unwrap().unwrap()).unwrap();
        assert!(matches!(
            fetcher.fetch(&target),
            Err(SafeFetchError::UnadmittedAuthority)
        ));
        assert_eq!(
            fixture.accepts(),
            1,
            "redirect target was denied before its socket boundary"
        );
        assert_eq!(
            resolver.calls.load(Ordering::SeqCst),
            1,
            "denied authority was not resolved or connected"
        );
    }

    #[test]
    fn fixture_capability_expires_with_its_owned_listener() {
        let fixture = SocketFixture::start(BTreeMap::new());
        let accepts = Arc::clone(&fixture.accepts);
        let endpoint = fixture.address;
        let capability = fixture.capability("owned.fixture.test");
        drop(fixture);
        let resolver = Arc::new(MutableResolver {
            answers: Mutex::new(BTreeMap::from([(
                "owned.fixture.test".to_owned(),
                vec![endpoint],
            )])),
            calls: AtomicUsize::new(0),
        });
        let fetcher = SafeFetcher::new(Arc::clone(&resolver), vec![capability]);
        let url = Url::parse(&format!("http://owned.fixture.test:{}/", endpoint.port())).unwrap();
        assert!(matches!(
            fetcher.fetch(&url),
            Err(SafeFetchError::UnadmittedAuthority)
        ));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
        assert_eq!(accepts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn response_header_bytes_are_bounded_at_the_socket_boundary() {
        let headers = (0..20)
            .map(|index| (format!("X-Fixture-{index}"), "x".repeat(2048)))
            .collect();
        let fixture = SocketFixture::start(BTreeMap::from([(
            "/".to_owned(),
            (200, headers, b"ok".to_vec()),
        )]));
        let resolver = Arc::new(MutableResolver {
            answers: Mutex::new(BTreeMap::from([(
                "owned.fixture.test".to_owned(),
                vec![fixture.address],
            )])),
            calls: AtomicUsize::new(0),
        });
        let fetcher = SafeFetcher::new(
            Arc::clone(&resolver),
            vec![fixture.capability("owned.fixture.test")],
        );
        let url = Url::parse(&format!(
            "http://owned.fixture.test:{}/",
            fixture.address.port()
        ))
        .unwrap();
        assert!(matches!(
            fetcher.fetch(&url),
            Err(SafeFetchError::ResponseHeadersTooLarge)
        ));
        assert_eq!(fixture.accepts(), 1);
    }

    #[test]
    fn compressed_and_decompressed_body_limits_stop_at_the_transport_boundary() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&vec![b'x'; MAX_DECODED_RESPONSE_BYTES + 1])
            .unwrap();
        let gzip_body = encoder.finish().unwrap();
        let gzip_fixture = SocketFixture::start(BTreeMap::from([(
            "/".to_owned(),
            (
                200,
                vec![
                    ("Content-Encoding".to_owned(), "gzip".to_owned()),
                    ("X-Robots-Tag".to_owned(), "noindex".to_owned()),
                ],
                gzip_body,
            ),
        )]));
        let resolver = Arc::new(MutableResolver {
            answers: Mutex::new(BTreeMap::from([(
                "owned.fixture.test".to_owned(),
                vec![gzip_fixture.address],
            )])),
            calls: AtomicUsize::new(0),
        });
        let fetcher = SafeFetcher::new(
            Arc::clone(&resolver),
            vec![gzip_fixture.capability("owned.fixture.test")],
        );
        let gzip_url = Url::parse(&format!(
            "http://owned.fixture.test:{}/",
            gzip_fixture.address.port()
        ))
        .unwrap();
        let response = fetcher.fetch(&gzip_url).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, Err(SafeFetchError::DecompressedBodyTooLarge));
        assert_eq!(response.decoded_bytes, MAX_DECODED_RESPONSE_BYTES);
        assert_eq!(
            response.header_values("x-robots-tag").collect::<Vec<_>>(),
            ["noindex"]
        );
        assert_eq!(gzip_fixture.accepts(), 1);

        let compressed_fixture = SocketFixture::start(BTreeMap::from([(
            "/".to_owned(),
            (
                200,
                vec![("X-Robots-Tag".to_owned(), "LeyBot: noindex".to_owned())],
                vec![b'x'; MAX_COMPRESSED_RESPONSE_BYTES + 1],
            ),
        )]));
        let compressed_resolver = Arc::new(MutableResolver {
            answers: Mutex::new(BTreeMap::from([(
                "owned.fixture.test".to_owned(),
                vec![compressed_fixture.address],
            )])),
            calls: AtomicUsize::new(0),
        });
        let compressed_fetcher = SafeFetcher::new(
            Arc::clone(&compressed_resolver),
            vec![compressed_fixture.capability("owned.fixture.test")],
        );
        let compressed_url = Url::parse(&format!(
            "http://owned.fixture.test:{}/",
            compressed_fixture.address.port()
        ))
        .unwrap();
        let response = compressed_fetcher.fetch(&compressed_url).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, Err(SafeFetchError::CompressedBodyTooLarge));
        assert_eq!(response.wire_bytes, MAX_COMPRESSED_RESPONSE_BYTES);
        assert_eq!(
            response.header_values("x-robots-tag").collect::<Vec<_>>(),
            ["LeyBot: noindex"]
        );
        assert_eq!(compressed_fixture.accepts(), 1);
    }
}

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, ToSocketAddrs};
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
const CRAWL_USER_AGENT: &str = concat!(
    "LeyBot/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/Suraj-H675/Ley/issues)"
);
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
    ConnectedAddressUnavailable,
    ConnectedAddressMismatch(String),
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
            Self::InvalidUrl => {
                f.write_str("only credential-free HTTP or admitted HTTPS URLs are supported")
            }
            Self::UnadmittedAuthority => f.write_str("authority has no active source grant"),
            Self::Resolution(message) => write!(f, "destination resolution failed: {message}"),
            Self::EmptyResolution => f.write_str("destination resolver returned no addresses"),
            Self::TooManyAddresses => {
                write!(f, "destination resolver exceeded {MAX_DNS_ANSWERS} answers")
            }
            Self::UnsafeAddress(address) => write!(
                f,
                "destination answer is not permitted by the active address policy: {address}"
            ),
            Self::ConnectedAddressUnavailable => {
                f.write_str("HTTP transport did not expose its connected destination")
            }
            Self::ConnectedAddressMismatch(address) => {
                write!(
                    f,
                    "connected destination was not in the validated DNS set: {address}"
                )
            }
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

    #[cfg(test)]
    fn matches(&self, other: &Self) -> bool {
        self.is_alive()
            && other.is_alive()
            && self.host == other.host
            && self.port == other.port
            && self.endpoint == other.endpoint
    }
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct OwnedFixtureTls {
    capability: FixtureCapability,
    root_certificate_pem: Vec<u8>,
}

#[cfg(test)]
impl OwnedFixtureTls {
    fn from_owned_listener(
        host: &str,
        listener: &TcpListener,
        alive: &Arc<AtomicBool>,
        root_certificate_pem: Vec<u8>,
    ) -> Option<Self> {
        Some(Self {
            capability: FixtureCapability::from_owned_listener(host, listener, alive)?,
            root_certificate_pem,
        })
    }
}

#[cfg(test)]
impl DestinationResolver for OwnedFixtureTls {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if self.capability.is_alive()
            && self.capability.host.eq_ignore_ascii_case(host)
            && self.capability.port == port
        {
            Ok(vec![self.capability.endpoint])
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "owned fixture resolver only serves its pinned listener",
            ))
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PublicAuthority {
    host: String,
    port: u16,
    origin: String,
    user_agent: String,
}

impl PublicAuthority {
    pub(crate) fn from_origin(origin: &Url) -> Option<Self> {
        let host = origin.host_str()?;
        let port = origin.port_or_known_default()?;
        if origin.scheme() != "https"
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || host.parse::<IpAddr>().is_ok()
            || !host.contains('.')
        {
            return None;
        }
        Some(Self {
            host: host.to_ascii_lowercase(),
            port,
            origin: origin_of_url(origin),
            user_agent: CRAWL_USER_AGENT.to_owned(),
        })
    }

    pub(crate) fn with_crawler_identity(mut self, identity: &str, contact: &str) -> Self {
        self.user_agent = format!("{identity} (+{contact})");
        self
    }

    fn allows(&self, url: &Url) -> bool {
        url.scheme() == "https"
            && url
                .host_str()
                .is_some_and(|host| self.host.eq_ignore_ascii_case(host))
            && url.port_or_known_default() == Some(self.port)
            && origin_of_url(url) == self.origin
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DestinationEvidence {
    pub requested_url: String,
    pub resolved_addresses: Vec<SocketAddr>,
    pub connected_peer: SocketAddr,
    pub response_status: u16,
    pub proxy_used: bool,
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
    public_authorities: Vec<PublicAuthority>,
    network_evidence: Mutex<Vec<DestinationEvidence>>,
    request_timeout: Duration,
    #[cfg(test)]
    test_public_transport: Option<TestPublicTransport>,
    #[cfg(test)]
    test_owned_fixture_tls: Option<OwnedFixtureTls>,
}

#[cfg(test)]
struct TestPublicTransport {
    host: String,
    endpoint: SocketAddr,
    root_certificate_pem: Vec<u8>,
}

impl<R: DestinationResolver + 'static> SafeFetcher<R> {
    #[cfg(test)]
    pub(crate) fn new(resolver: R, capabilities: Vec<FixtureCapability>) -> Self {
        Self {
            resolver: Arc::new(resolver),
            capabilities,
            public_authorities: Vec::new(),
            network_evidence: Mutex::new(Vec::new()),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            test_public_transport: None,
            test_owned_fixture_tls: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_owned_fixture_tls(resolver: R, fixture: OwnedFixtureTls) -> Self {
        Self {
            resolver: Arc::new(resolver),
            capabilities: vec![fixture.capability.clone()],
            public_authorities: Vec::new(),
            network_evidence: Mutex::new(Vec::new()),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            test_public_transport: None,
            test_owned_fixture_tls: Some(fixture),
        }
    }

    pub(crate) fn new_with_public(
        resolver: R,
        capabilities: Vec<FixtureCapability>,
        public_authorities: Vec<PublicAuthority>,
    ) -> Self {
        Self {
            resolver: Arc::new(resolver),
            capabilities,
            public_authorities,
            network_evidence: Mutex::new(Vec::new()),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            #[cfg(test)]
            test_public_transport: None,
            #[cfg(test)]
            test_owned_fixture_tls: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn set_test_public_tls(
        &mut self,
        host: &str,
        endpoint: SocketAddr,
        root_certificate_pem: Vec<u8>,
    ) {
        self.test_public_transport = Some(TestPublicTransport {
            host: host.to_ascii_lowercase(),
            endpoint,
            root_certificate_pem,
        });
    }

    pub(crate) fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout.min(Duration::from_secs(30));
        self
    }

    pub(crate) fn has_capability(&self, url: &Url) -> bool {
        self.has_fixture_capability(url) || self.has_public_authority(url)
    }

    pub(crate) fn has_fixture_capability(&self, url: &Url) -> bool {
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

    pub(crate) fn has_public_authority(&self, url: &Url) -> bool {
        self.public_authorities
            .iter()
            .any(|authority| authority.allows(url))
    }

    pub(crate) fn clear_network_evidence(&self) {
        if let Ok(mut evidence) = self.network_evidence.lock() {
            evidence.clear();
        }
    }

    pub(crate) fn take_network_evidence(&self) -> Vec<DestinationEvidence> {
        self.network_evidence
            .lock()
            .map(|mut evidence| std::mem::take(&mut *evidence))
            .unwrap_or_default()
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
        if !matches!(url.scheme(), "http" | "https")
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
        let fixture = self.capabilities.iter().find(|capability| {
            capability.is_alive()
                && capability.host.eq_ignore_ascii_case(host)
                && capability.port == port
        });
        let public = self
            .public_authorities
            .iter()
            .find(|authority| authority.allows(url));
        #[cfg(test)]
        let test_owned_fixture_tls = self.test_owned_fixture_tls.as_ref().filter(|transport| {
            fixture.is_some_and(|capability| transport.capability.matches(capability))
                && transport.capability.host.eq_ignore_ascii_case(host)
                && transport.capability.port == port
        });
        #[cfg(test)]
        let fixture_scheme_is_allowed = fixture.is_none()
            || url.scheme() == "http"
            || (url.scheme() == "https" && test_owned_fixture_tls.is_some());
        #[cfg(not(test))]
        let fixture_scheme_is_allowed = fixture.is_none() || url.scheme() == "http";
        if (fixture.is_none() && public.is_none())
            || !fixture_scheme_is_allowed
            || (public.is_some() && url.scheme() != "https")
        {
            return Err(SafeFetchError::UnadmittedAuthority);
        }
        #[cfg(test)]
        let test_public_transport = self
            .test_public_transport
            .as_ref()
            .filter(|transport| public.is_some() && transport.host == host.to_ascii_lowercase());

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
            let permitted = if let Some(capability) = fixture {
                ip == capability.endpoint.ip()
                    && answer.port() == capability.endpoint.port()
                    && is_loopback(ip)
            } else {
                #[cfg(test)]
                if let Some(transport) = test_public_transport {
                    answer == transport.endpoint
                } else {
                    answer.port() == port && is_public_unicast(ip)
                }
                #[cfg(not(test))]
                {
                    answer.port() == port && is_public_unicast(ip)
                }
            };
            if !permitted {
                return Err(SafeFetchError::UnsafeAddress(answer.to_string()));
            }
            pinned_ips.insert(ip);
        }
        if pinned_ips.is_empty() || (fixture.is_some() && pinned_ips.len() != 1) {
            return Err(SafeFetchError::UnsafeAddress(
                "validated destination set is empty or violates fixture isolation".to_owned(),
            ));
        }
        #[cfg(test)]
        let test_endpoint = test_owned_fixture_tls
            .map(|transport| transport.capability.endpoint)
            .or_else(|| test_public_transport.map(|transport| transport.endpoint));
        #[cfg(not(test))]
        let test_endpoint = None::<SocketAddr>;
        let resolved_addresses = test_endpoint.map_or_else(
            || {
                pinned_ips
                    .iter()
                    .copied()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect::<Vec<_>>()
            },
            |endpoint| vec![endpoint],
        );
        let pinned: Vec<SocketAddr> = test_endpoint.map_or_else(
            || {
                pinned_ips
                    .iter()
                    .copied()
                    .map(|ip| SocketAddr::new(ip, 0))
                    .collect()
            },
            |endpoint| vec![endpoint],
        );

        // A new client per request prevents pooled connections from bypassing
        // the just-validated DNS answer set. Automatic redirects and proxies
        // are disabled, and reqwest's resolver override pins the connection.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(SafeFetchError::ResolverTimeout);
        }
        let client_builder = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(remaining.min(Duration::from_secs(5)))
            .timeout(remaining)
            .pool_max_idle_per_host(0);
        #[cfg(test)]
        let client_builder = if let Some(transport) = test_owned_fixture_tls {
            let certificate = reqwest::Certificate::from_pem(&transport.root_certificate_pem)
                .map_err(|error| SafeFetchError::Request(error.to_string()))?;
            client_builder.add_root_certificate(certificate)
        } else if let Some(transport) = test_public_transport {
            let certificate = reqwest::Certificate::from_pem(&transport.root_certificate_pem)
                .map_err(|error| SafeFetchError::Request(error.to_string()))?;
            client_builder.add_root_certificate(certificate)
        } else {
            client_builder
        };
        let client = client_builder
            .resolve_to_addrs(host, &pinned)
            .build()
            .map_err(|error| SafeFetchError::Request(error.to_string()))?;
        let mut request = client.get(url.clone()).header(ACCEPT_ENCODING, "gzip");
        for (name, value) in request_headers {
            request = request.header(name, value);
        }
        let user_agent = public.map_or(CRAWL_USER_AGENT, |authority| authority.user_agent.as_str());
        request = request.header(USER_AGENT, user_agent);
        let mut response = request
            .send()
            .map_err(|error| SafeFetchError::Request(error.to_string()))?;
        let connected_peer = response
            .remote_addr()
            .ok_or(SafeFetchError::ConnectedAddressUnavailable)?;
        #[cfg(test)]
        let connected_to_validated_destination = test_endpoint
            .map(|endpoint| connected_peer == endpoint)
            .unwrap_or_else(|| {
                connected_peer.port() == port && pinned_ips.contains(&connected_peer.ip())
            });
        #[cfg(not(test))]
        let connected_to_validated_destination =
            connected_peer.port() == port && pinned_ips.contains(&connected_peer.ip());
        if !connected_to_validated_destination {
            return Err(SafeFetchError::ConnectedAddressMismatch(
                connected_peer.to_string(),
            ));
        }
        let status = response.status().as_u16();
        let destination = DestinationEvidence {
            requested_url: url.to_string(),
            resolved_addresses,
            connected_peer,
            response_status: status,
            proxy_used: false,
        };
        if let Ok(mut evidence) = self.network_evidence.lock() {
            if evidence.len() >= 10_000 {
                return Err(SafeFetchError::Request(
                    "per-run destination evidence limit exhausted".to_owned(),
                ));
            }
            evidence.push(destination.clone());
        } else {
            return Err(SafeFetchError::Request(
                "destination evidence lock is unavailable".to_owned(),
            ));
        }
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

fn origin_of_url(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let port = url.port_or_known_default().unwrap_or(0);
    format!("{}://{}:{}", url.scheme().to_ascii_lowercase(), host, port)
}

fn is_public_unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let value = u32::from(ip);
    const DENIED: &[(u32, u8)] = &[
        (u32::from_be_bytes([0, 0, 0, 0]), 8),
        (u32::from_be_bytes([10, 0, 0, 0]), 8),
        (u32::from_be_bytes([100, 64, 0, 0]), 10),
        (u32::from_be_bytes([127, 0, 0, 0]), 8),
        (u32::from_be_bytes([169, 254, 0, 0]), 16),
        (u32::from_be_bytes([172, 16, 0, 0]), 12),
        (u32::from_be_bytes([192, 0, 0, 0]), 24),
        (u32::from_be_bytes([192, 0, 2, 0]), 24),
        (u32::from_be_bytes([192, 88, 99, 0]), 24),
        (u32::from_be_bytes([192, 168, 0, 0]), 16),
        (u32::from_be_bytes([198, 18, 0, 0]), 15),
        (u32::from_be_bytes([198, 51, 100, 0]), 24),
        (u32::from_be_bytes([203, 0, 113, 0]), 24),
        (u32::from_be_bytes([224, 0, 0, 0]), 4),
        (u32::from_be_bytes([240, 0, 0, 0]), 4),
    ];
    !DENIED.iter().any(|(network, prefix)| {
        let mask = u32::MAX << (32 - prefix);
        value & mask == *network & mask
    })
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let value = u128::from(ip);
    let prefix_matches = |network: u128, prefix: u32| {
        let mask = u128::MAX << (128 - prefix);
        value & mask == network & mask
    };
    prefix_matches(u128::from(Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0)), 3)
        && !prefix_matches(u128::from(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0)), 23)
        && !prefix_matches(
            u128::from(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0)),
            32,
        )
        && !prefix_matches(u128::from(Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0)), 16)
        && !prefix_matches(u128::from(Ipv6Addr::new(0x3ffe, 0, 0, 0, 0, 0, 0, 0)), 16)
        && !prefix_matches(u128::from(Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0)), 20)
}

#[cfg(test)]
pub(crate) mod tls_test_support {
    use super::OwnedFixtureTls;

    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    #[derive(Clone)]
    pub(crate) struct Response {
        pub(crate) status: u16,
        pub(crate) headers: Vec<(String, String)>,
        pub(crate) body: Vec<u8>,
        delay: Duration,
    }

    impl Response {
        pub(crate) fn text(body: &str) -> Self {
            Self::body(200, "text/plain", body.as_bytes().to_vec())
        }

        pub(crate) fn html(body: &str) -> Self {
            Self::body(200, "text/html; charset=utf-8", body.as_bytes().to_vec())
        }

        pub(crate) fn body(status: u16, content_type: &str, body: Vec<u8>) -> Self {
            Self {
                status,
                headers: vec![("content-type".to_owned(), content_type.to_owned())],
                body,
                delay: Duration::ZERO,
            }
        }

        pub(crate) fn redirect(location: &str) -> Self {
            Self {
                status: 302,
                headers: vec![("location".to_owned(), location.to_owned())],
                body: Vec::new(),
                delay: Duration::ZERO,
            }
        }

        pub(crate) fn delayed(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
        }
    }

    pub(crate) type Routes = BTreeMap<String, Response>;

    pub(crate) struct Fixture {
        pub(crate) address: SocketAddr,
        root_certificate_pem: Vec<u8>,
        owned_transport: OwnedFixtureTls,
        accepts: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<String>>>,
        accepted_peers: Arc<Mutex<Vec<SocketAddr>>>,
        response_bytes: Arc<AtomicUsize>,
        user_agents: Arc<Mutex<Vec<String>>>,
        request_starts: Arc<Mutex<Vec<std::time::Instant>>>,
        routes: Arc<Mutex<Routes>>,
        alive: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
        directory: TempDirectory,
    }

    impl Fixture {
        pub(crate) fn start(certificate_host: &str, routes: Routes) -> Self {
            let directory = TempDirectory::new();
            create_certificates(&directory.path, certificate_host);
            let root_certificate_pem = fs::read(directory.path.join("ca.pem")).unwrap();
            let certificate = rustls::pki_types::CertificateDer::from(
                fs::read(directory.path.join("server.der")).unwrap(),
            );
            let key = rustls::pki_types::PrivateKeyDer::try_from(
                fs::read(directory.path.join("server.pk8")).unwrap(),
            )
            .unwrap();
            let config = Arc::new(
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(vec![certificate], key)
                    .unwrap(),
            );
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let alive = Arc::new(AtomicBool::new(true));
            let owned_transport = OwnedFixtureTls::from_owned_listener(
                certificate_host,
                &listener,
                &alive,
                root_certificate_pem.clone(),
            )
            .expect("owned TLS fixture must bind a live loopback listener");
            let accepts = Arc::new(AtomicUsize::new(0));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let accepted_peers = Arc::new(Mutex::new(Vec::new()));
            let response_bytes = Arc::new(AtomicUsize::new(0));
            let user_agents = Arc::new(Mutex::new(Vec::new()));
            let request_starts = Arc::new(Mutex::new(Vec::new()));
            let routes = Arc::new(Mutex::new(routes));
            let stop = Arc::new(AtomicBool::new(false));
            let thread_accepts = Arc::clone(&accepts);
            let thread_requests = Arc::clone(&requests);
            let thread_peers = Arc::clone(&accepted_peers);
            let thread_response_bytes = Arc::clone(&response_bytes);
            let thread_user_agents = Arc::clone(&user_agents);
            let thread_request_starts = Arc::clone(&request_starts);
            let thread_routes = Arc::clone(&routes);
            let thread_stop = Arc::clone(&stop);
            let thread = thread::spawn(move || {
                while !thread_stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, peer)) => {
                            thread_accepts.fetch_add(1, Ordering::SeqCst);
                            thread_peers.lock().unwrap().push(peer);
                            serve(
                                stream,
                                &config,
                                &thread_routes,
                                &thread_requests,
                                &thread_user_agents,
                                &thread_request_starts,
                                &thread_response_bytes,
                            );
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                address,
                root_certificate_pem,
                owned_transport,
                accepts,
                requests,
                accepted_peers,
                response_bytes,
                user_agents,
                request_starts,
                routes,
                alive,
                stop,
                thread: Some(thread),
                directory,
            }
        }

        pub(crate) fn owned_transport(&self) -> OwnedFixtureTls {
            self.owned_transport.clone()
        }

        pub(crate) fn root_certificate_pem(&self) -> Vec<u8> {
            self.root_certificate_pem.clone()
        }

        pub(crate) fn accepts(&self) -> usize {
            self.accepts.load(Ordering::SeqCst)
        }

        pub(crate) fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }

        pub(crate) fn accepted_peers(&self) -> Vec<SocketAddr> {
            self.accepted_peers.lock().unwrap().clone()
        }

        pub(crate) fn response_bytes(&self) -> usize {
            self.response_bytes.load(Ordering::SeqCst)
        }

        pub(crate) fn replace_routes(&self, routes: Routes) {
            *self.routes.lock().unwrap() = routes;
        }

        pub(crate) fn user_agents(&self) -> Vec<String> {
            self.user_agents.lock().unwrap().clone()
        }

        pub(crate) fn request_starts(&self) -> Vec<std::time::Instant> {
            self.request_starts.lock().unwrap().clone()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.alive.store(false, Ordering::SeqCst);
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            let _ = &self.directory;
        }
    }

    struct TempDirectory {
        path: PathBuf,
    }

    impl TempDirectory {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(1);
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("ley-owned-tls-{}-{id}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn create_certificates(directory: &PathBuf, certificate_host: &str) {
        run_openssl(
            directory,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-days",
                "2",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
                "-subj",
                "/CN=Ley Owned Test Root",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        );
        run_openssl(
            directory,
            &[
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-keyout",
                "server.key",
                "-out",
                "server.csr",
                "-subj",
                &format!("/CN={certificate_host}"),
            ],
        );
        fs::write(
            directory.join("server.ext"),
            format!(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{certificate_host}\n"
            ),
        )
        .unwrap();
        run_openssl(
            directory,
            &[
                "x509",
                "-req",
                "-sha256",
                "-days",
                "2",
                "-in",
                "server.csr",
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                "server.pem",
                "-extfile",
                "server.ext",
            ],
        );
        run_openssl(
            directory,
            &[
                "x509",
                "-in",
                "server.pem",
                "-outform",
                "DER",
                "-out",
                "server.der",
            ],
        );
        run_openssl(
            directory,
            &[
                "pkcs8",
                "-topk8",
                "-nocrypt",
                "-in",
                "server.key",
                "-outform",
                "DER",
                "-out",
                "server.pk8",
            ],
        );
    }

    fn run_openssl(directory: &PathBuf, arguments: &[&str]) {
        let output = Command::new("openssl")
            .current_dir(directory)
            .args(arguments)
            .output()
            .expect("OpenSSL is required for owned TLS fixtures");
        assert!(
            output.status.success(),
            "OpenSSL fixture command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn serve(
        stream: TcpStream,
        config: &Arc<rustls::ServerConfig>,
        routes: &Mutex<Routes>,
        requests: &Mutex<Vec<String>>,
        user_agents: &Mutex<Vec<String>>,
        request_starts: &Mutex<Vec<std::time::Instant>>,
        response_bytes: &AtomicUsize,
    ) {
        let connection = match rustls::ServerConnection::new(Arc::clone(config)) {
            Ok(connection) => connection,
            Err(_) => return,
        };
        let mut stream = rustls::StreamOwned::new(connection, stream);
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        while request.len() < 32 * 1024 {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(count) => request.extend_from_slice(&chunk[..count]),
            }
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&request);
        let mut lines = text.lines();
        let target = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/")
            .to_owned();
        request_starts
            .lock()
            .unwrap()
            .push(std::time::Instant::now());
        for line in lines {
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("user-agent")
            {
                user_agents.lock().unwrap().push(value.trim().to_owned());
            }
        }
        requests.lock().unwrap().push(target.clone());
        let response = routes
            .lock()
            .unwrap()
            .get(target.split('?').next().unwrap_or("/"))
            .cloned()
            .unwrap_or_else(|| Response {
                status: 404,
                headers: Vec::new(),
                body: b"missing".to_vec(),
                delay: Duration::ZERO,
            });
        thread::sleep(response.delay);
        let mut headers = format!(
            "HTTP/1.1 {} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n",
            response.status,
            response.body.len()
        );
        for (name, value) in response.headers {
            headers.push_str(&format!("{name}: {value}\r\n"));
        }
        headers.push_str("\r\n");
        if stream.write_all(headers.as_bytes()).is_ok() {
            response_bytes.fetch_add(headers.len(), Ordering::SeqCst);
            if stream.write_all(&response.body).is_ok() {
                response_bytes.fetch_add(response.body.len(), Ordering::SeqCst);
                let _ = stream.flush();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::process::Command;
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
        let evidence = fetcher.take_network_evidence();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].connected_peer, fixture.address);
        assert_eq!(evidence[0].resolved_addresses, vec![fixture.address]);
        assert!(!evidence[0].proxy_used);
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

    #[test]
    fn public_address_filter_accepts_global_unicast_and_rejects_special_ranges() {
        for address in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"] {
            assert!(
                is_public_unicast(address.parse().unwrap()),
                "expected globally routable address {address}"
            );
        }
        for address in [
            "0.0.0.1",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.10.1",
            "172.20.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.2",
            "203.0.113.9",
            "224.0.0.1",
            "240.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(
                !is_public_unicast(address.parse().unwrap()),
                "expected non-public address {address} to be denied"
            );
        }
    }

    #[test]
    fn public_address_filter_checks_local_registry_boundary_vectors() {
        for (address, expected) in [
            ("0.255.255.255", false),
            ("1.0.0.0", true),
            ("100.63.255.255", true),
            ("100.64.0.0", false),
            ("100.127.255.255", false),
            ("100.128.0.0", true),
            ("192.0.0.8", false),
            ("192.0.0.9", false),
            ("192.0.0.10", false),
            ("192.0.0.255", false),
            ("192.0.1.0", true),
            ("192.88.98.255", true),
            ("192.88.99.0", false),
            ("192.88.99.255", false),
            ("192.88.100.0", true),
            ("198.17.255.255", true),
            ("198.18.0.0", false),
            ("198.19.255.255", false),
            ("198.20.0.0", true),
            ("223.255.255.255", true),
            ("224.0.0.0", false),
            ("239.255.255.255", false),
            ("240.0.0.0", false),
            ("255.255.255.255", false),
            ("1fff:ffff::", false),
            ("2000::", true),
            ("2001::", false),
            ("2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:200::", true),
            ("2001:db8::", false),
            ("2001:db9::", true),
            ("2002::", false),
            ("3ffe::", false),
            ("3fff::", false),
            ("3fff:fff:ffff::", false),
            ("3fff:1000::", true),
            ("4000::", false),
            ("::ffff:8.8.8.8", false),
            ("2001:4860:4860::8888", true),
        ] {
            assert_eq!(
                is_public_unicast(address.parse().unwrap()),
                expected,
                "unexpected public-address classification for {address}"
            );
        }
    }

    #[test]
    fn public_fetch_rejects_private_or_mixed_dns_answers_before_connecting() {
        let fixture = SocketFixture::start(BTreeMap::from([(
            "/".to_owned(),
            (200, Vec::new(), b"must not be reached".to_vec()),
        )]));
        let host = "public.example.org";
        let url = Url::parse(&format!("https://{host}:{}/", fixture.address.port())).unwrap();
        let origin = Url::parse(&format!("https://{host}:{}/", fixture.address.port())).unwrap();
        let authority = PublicAuthority::from_origin(&origin)
            .unwrap()
            .with_crawler_identity(
                concat!("LeyBot/", env!("CARGO_PKG_VERSION")),
                "https://github.com/Suraj-H675/Ley/issues",
            );
        let resolver = Arc::new(MutableResolver {
            answers: Mutex::new(BTreeMap::from([(host.to_owned(), vec![fixture.address])])),
            calls: AtomicUsize::new(0),
        });
        let fetcher =
            SafeFetcher::new_with_public(Arc::clone(&resolver), Vec::new(), vec![authority]);
        assert!(matches!(
            fetcher.fetch(&url),
            Err(SafeFetchError::UnsafeAddress(_))
        ));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.accepts(), 0);

        let default_port_url = Url::parse("https://public.example.org/").unwrap();
        let default_origin = Url::parse("https://public.example.org/").unwrap();
        let default_authority = PublicAuthority::from_origin(&default_origin)
            .unwrap()
            .with_crawler_identity(
                concat!("LeyBot/", env!("CARGO_PKG_VERSION")),
                "https://github.com/Suraj-H675/Ley/issues",
            );
        let resolver2 = Arc::new(MutableResolver {
            answers: Mutex::new(BTreeMap::from([(
                host.to_owned(),
                vec![
                    "8.8.8.8:443".parse().unwrap(),
                    "10.0.0.7:443".parse().unwrap(),
                ],
            )])),
            calls: AtomicUsize::new(0),
        });
        let mixed = SafeFetcher::new_with_public(
            Arc::clone(&resolver2),
            Vec::new(),
            vec![default_authority],
        );
        assert!(matches!(
            mixed.fetch(&default_port_url),
            Err(SafeFetchError::UnsafeAddress(_))
        ));
        assert_eq!(resolver2.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.accepts(), 0);

        let dual_stack_resolver = Arc::new(MutableResolver {
            answers: Mutex::new(BTreeMap::from([(
                "public.example.org".to_owned(),
                vec![
                    "8.8.8.8:443".parse().unwrap(),
                    "[fd00::9]:443".parse().unwrap(),
                ],
            )])),
            calls: AtomicUsize::new(0),
        });
        let dual_stack = SafeFetcher::new_with_public(
            Arc::clone(&dual_stack_resolver),
            Vec::new(),
            vec![PublicAuthority::from_origin(&default_origin).unwrap()],
        );
        assert!(matches!(
            dual_stack.fetch(&default_port_url),
            Err(SafeFetchError::UnsafeAddress(_))
        ));
        assert_eq!(dual_stack_resolver.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.accepts(), 0);
    }

    #[test]
    fn public_https_transport_validates_tls_pins_peer_and_bypasses_poisoned_proxies() {
        if std::env::var("LEY_PROXY_CHILD").as_deref() != Ok("1") {
            let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
            let proxy_port = reservation.local_addr().unwrap().port();
            drop(reservation);
            let proxy = format!("http://127.0.0.1:{proxy_port}");
            let output = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(
                    "safe_fetch::tests::public_https_transport_validates_tls_pins_peer_and_bypasses_poisoned_proxies",
                )
                .arg("--test-threads=1")
                .env("LEY_PROXY_CHILD", "1")
                .env("LEY_PROXY_SENTINEL_PORT", proxy_port.to_string())
                .env("HTTP_PROXY", &proxy)
                .env("HTTPS_PROXY", &proxy)
                .env("ALL_PROXY", &proxy)
                .env("http_proxy", &proxy)
                .env("https_proxy", &proxy)
                .env("all_proxy", &proxy)
                .env("NO_PROXY", "")
                .env("no_proxy", "")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated public TLS child failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let proxy_port = std::env::var("LEY_PROXY_SENTINEL_PORT")
            .unwrap()
            .parse::<u16>()
            .unwrap();
        let proxy_sentinel = TcpListener::bind(("127.0.0.1", proxy_port)).unwrap();
        proxy_sentinel.set_nonblocking(true).unwrap();
        let host = "public.example.org";
        let fixture = tls_test_support::Fixture::start(
            host,
            BTreeMap::from([(
                String::from("/"),
                tls_test_support::Response::text("pinned tls fixture"),
            )]),
        );
        let origin = Url::parse(&format!("https://{host}:{}/", fixture.address.port())).unwrap();
        let authority = PublicAuthority::from_origin(&origin)
            .unwrap()
            .with_crawler_identity(
                concat!("LeyBot/", env!("CARGO_PKG_VERSION")),
                "https://github.com/Suraj-H675/Ley/issues",
            );
        let resolver = Arc::new(MutableResolver {
            answers: Mutex::new(BTreeMap::from([(host.to_owned(), vec![fixture.address])])),
            calls: AtomicUsize::new(0),
        });
        let mut fetcher =
            SafeFetcher::new_with_public(Arc::clone(&resolver), Vec::new(), vec![authority]);
        fetcher.set_test_public_tls(host, fixture.address, fixture.root_certificate_pem());

        let response = fetcher.fetch(&origin).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body.unwrap(), b"pinned tls fixture");
        let evidence = fetcher.take_network_evidence();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].connected_peer, fixture.address);
        assert_eq!(evidence[0].resolved_addresses, [fixture.address]);
        assert!(!evidence[0].proxy_used);
        assert_eq!(fixture.requests(), ["/"]);
        assert_eq!(
            fixture.user_agents(),
            [concat!(
                "LeyBot/",
                env!("CARGO_PKG_VERSION"),
                " (+https://github.com/Suraj-H675/Ley/issues)"
            )]
        );

        let mut proxy_requests = Vec::new();
        loop {
            match proxy_sentinel.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_millis(100)))
                        .unwrap();
                    let mut first_line = String::new();
                    let _ = BufReader::new(stream).read_line(&mut first_line);
                    proxy_requests.push(first_line);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("proxy sentinel failed: {error}"),
            }
        }
        assert!(
            proxy_requests.is_empty(),
            "proxy received {proxy_requests:?}"
        );

        let calls = resolver.calls.load(Ordering::SeqCst);
        for unexpected in [
            Url::parse(&format!("http://{host}:{}/", fixture.address.port())).unwrap(),
            Url::parse(&format!(
                "https://other.example.org:{}/",
                fixture.address.port()
            ))
            .unwrap(),
            Url::parse(&format!("https://{host}:{}/", fixture.address.port() + 1)).unwrap(),
        ] {
            assert!(matches!(
                fetcher.fetch(&unexpected),
                Err(SafeFetchError::InvalidUrl | SafeFetchError::UnadmittedAuthority)
            ));
        }
        assert_eq!(resolver.calls.load(Ordering::SeqCst), calls);
        assert_eq!(fixture.accepts(), 1);

        resolver.answers.lock().unwrap().insert(
            host.to_owned(),
            vec![
                fixture.address,
                format!("10.0.0.9:{}", fixture.address.port())
                    .parse()
                    .unwrap(),
            ],
        );
        assert!(matches!(
            fetcher.fetch(&origin),
            Err(SafeFetchError::UnsafeAddress(_))
        ));
        resolver.answers.lock().unwrap().insert(
            host.to_owned(),
            vec![
                format!("127.0.0.2:{}", fixture.address.port())
                    .parse()
                    .unwrap(),
            ],
        );
        assert!(matches!(
            fetcher.fetch(&origin),
            Err(SafeFetchError::UnsafeAddress(_))
        ));
        assert_eq!(fixture.accepts(), 1);

        let wrong_host = "other.example.org";
        let wrong_fixture = tls_test_support::Fixture::start(
            wrong_host,
            BTreeMap::from([(
                String::from("/"),
                tls_test_support::Response::text("must not be read"),
            )]),
        );
        let wrong_origin =
            Url::parse(&format!("https://{host}:{}/", wrong_fixture.address.port())).unwrap();
        let wrong_authority = PublicAuthority::from_origin(&wrong_origin).unwrap();
        let wrong_resolver = Arc::new(MutableResolver {
            answers: Mutex::new(BTreeMap::from([(
                host.to_owned(),
                vec![wrong_fixture.address],
            )])),
            calls: AtomicUsize::new(0),
        });
        let mut wrong_fetcher = SafeFetcher::new_with_public(
            Arc::clone(&wrong_resolver),
            Vec::new(),
            vec![wrong_authority],
        );
        wrong_fetcher.set_test_public_tls(
            host,
            wrong_fixture.address,
            wrong_fixture.root_certificate_pem(),
        );
        assert!(matches!(
            wrong_fetcher.fetch(&wrong_origin),
            Err(SafeFetchError::Request(_))
        ));
        assert_eq!(wrong_fixture.accepts(), 1);
        assert!(wrong_fixture.requests().is_empty());
    }

    #[test]
    fn public_https_enforces_wire_byte_and_request_deadline_bounds() {
        let host = "public.example.org";
        let large_fixture = tls_test_support::Fixture::start(
            host,
            BTreeMap::from([(
                "/large".to_owned(),
                tls_test_support::Response::body(
                    200,
                    "text/plain",
                    vec![b'x'; MAX_COMPRESSED_RESPONSE_BYTES + 1],
                ),
            )]),
        );
        let large_url = Url::parse(&format!(
            "https://{host}:{}/large",
            large_fixture.address.port()
        ))
        .unwrap();
        let authority = PublicAuthority::from_origin(
            &Url::parse(&format!("https://{host}:{}/", large_fixture.address.port())).unwrap(),
        )
        .unwrap();
        let resolver = Arc::new(MutableResolver {
            answers: Mutex::new(BTreeMap::from([(
                host.to_owned(),
                vec![large_fixture.address],
            )])),
            calls: AtomicUsize::new(0),
        });
        let mut fetcher =
            SafeFetcher::new_with_public(Arc::clone(&resolver), Vec::new(), vec![authority]);
        fetcher.set_test_public_tls(
            host,
            large_fixture.address,
            large_fixture.root_certificate_pem(),
        );

        let response = fetcher.fetch(&large_url).unwrap();
        assert_eq!(response.body, Err(SafeFetchError::CompressedBodyTooLarge));
        assert_eq!(response.wire_bytes, MAX_COMPRESSED_RESPONSE_BYTES);
        assert_eq!(large_fixture.requests(), ["/large"]);
        assert_eq!(fetcher.take_network_evidence().len(), 1);

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&vec![b'x'; MAX_DECODED_RESPONSE_BYTES + 1])
            .unwrap();
        let mut gzip_response =
            tls_test_support::Response::body(200, "text/plain", encoder.finish().unwrap());
        gzip_response
            .headers
            .push(("content-encoding".to_owned(), "gzip".to_owned()));
        let gzip_fixture = tls_test_support::Fixture::start(
            host,
            BTreeMap::from([(String::from("/gzip"), gzip_response)]),
        );
        let gzip_url = Url::parse(&format!(
            "https://{host}:{}/gzip",
            gzip_fixture.address.port()
        ))
        .unwrap();
        let gzip_authority = PublicAuthority::from_origin(
            &Url::parse(&format!("https://{host}:{}/", gzip_fixture.address.port())).unwrap(),
        )
        .unwrap();
        let gzip_resolver = Arc::new(MutableResolver {
            answers: Mutex::new(BTreeMap::from([(
                host.to_owned(),
                vec![gzip_fixture.address],
            )])),
            calls: AtomicUsize::new(0),
        });
        let mut gzip_fetcher = SafeFetcher::new_with_public(
            Arc::clone(&gzip_resolver),
            Vec::new(),
            vec![gzip_authority],
        );
        gzip_fetcher.set_test_public_tls(
            host,
            gzip_fixture.address,
            gzip_fixture.root_certificate_pem(),
        );
        let gzip_response = gzip_fetcher.fetch(&gzip_url).unwrap();
        assert_eq!(
            gzip_response.body,
            Err(SafeFetchError::DecompressedBodyTooLarge)
        );
        assert!(gzip_response.wire_bytes < MAX_COMPRESSED_RESPONSE_BYTES);
        assert_eq!(gzip_response.decoded_bytes, MAX_DECODED_RESPONSE_BYTES);
        assert_eq!(gzip_fixture.requests(), ["/gzip"]);

        let slow_fixture = tls_test_support::Fixture::start(
            host,
            BTreeMap::from([(
                "/slow".to_owned(),
                tls_test_support::Response::text("too late").delayed(Duration::from_millis(300)),
            )]),
        );
        let slow_url = Url::parse(&format!(
            "https://{host}:{}/slow",
            slow_fixture.address.port()
        ))
        .unwrap();
        let slow_authority = PublicAuthority::from_origin(
            &Url::parse(&format!("https://{host}:{}/", slow_fixture.address.port())).unwrap(),
        )
        .unwrap();
        let slow_resolver = Arc::new(MutableResolver {
            answers: Mutex::new(BTreeMap::from([(
                host.to_owned(),
                vec![slow_fixture.address],
            )])),
            calls: AtomicUsize::new(0),
        });
        let mut slow_fetcher = SafeFetcher::new_with_public(
            Arc::clone(&slow_resolver),
            Vec::new(),
            vec![slow_authority],
        )
        .with_timeout(Duration::from_millis(100));
        slow_fetcher.set_test_public_tls(
            host,
            slow_fixture.address,
            slow_fixture.root_certificate_pem(),
        );
        let started = Instant::now();
        assert!(matches!(
            slow_fetcher.fetch(&slow_url),
            Err(SafeFetchError::Request(_))
        ));
        assert!(started.elapsed() < Duration::from_millis(250));
        assert_eq!(slow_fixture.accepts(), 1);
        assert_eq!(slow_fixture.requests(), ["/slow"]);
    }
}

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, StatusCode};
use tokio::net::TcpStream;
use url::Url;

use rustls_platform_verifier::BuilderVerifierExt;

use crate::policy::Sources;
use crate::{Error, Policy};

/// Turns a host name into addresses. [`Fetcher`] uses the system resolver
/// unless you give it another one with [`Fetcher::with_resolver`].
///
/// Whatever it returns is checked against the policy before anything
/// connects, so a resolver doesn't need to filter.
pub trait Resolve: Send + Sync + 'static {
    /// The addresses of `host`, each with `port` set.
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>>;
}

struct System;

impl Resolve for System {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        Box::pin(async move { Ok(tokio::net::lookup_host((host, port)).await?.collect()) })
    }
}

/// The resolver every per-hop client is built with. Each client is pinned
/// to checked addresses with `resolve_to_addrs`, and reqwest asks this one
/// only for a name that wasn't pinned, which would be a bug here. Failing
/// is better than reqwest quietly using the system resolver.
struct Unpinned;

impl reqwest::dns::Resolve for Unpinned {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let name = name.as_str().to_string();
        Box::pin(async move { Err(format!("{name} was not checked against the policy").into()) })
    }
}

/// Headers that describe the connection or the message framing rather than
/// the request. The client sets them itself. A caller-supplied `Host` picks
/// the virtual host on a shared server, and a stale `Content-Length` hangs
/// the request, so none of them can be set from outside.
const REFUSED_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "expect",
    "host",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// An HTTP request for [`Fetcher::send`].
#[derive(Clone)]
#[must_use]
pub struct Request {
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
    refused: Option<HeaderName>,
}

// By hand, so header values, the body and everything in the URL after the
// host stay out of logs. Webhook URLs carry tokens in the path and the query.
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("origin", &self.url.origin().ascii_serialization())
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("body_len", &self.body.as_ref().map(Vec::len))
            .finish()
    }
}

impl Request {
    /// A request with no headers and no body.
    pub fn new(method: Method, url: Url) -> Request {
        Request {
            method,
            url,
            headers: HeaderMap::new(),
            body: None,
            refused: None,
        }
    }

    /// Add a header. Headers go to the request's own origin only: a
    /// redirect to another scheme, host or port is followed without them.
    ///
    /// `Host`, `Content-Length`, `Transfer-Encoding` and the other headers
    /// that belong to the connection rather than the request can't be set.
    /// [`Fetcher::send`] fails with [`Error::RefusedHeader`] if you try.
    /// `Authorization` and `Cookie` values are marked sensitive.
    pub fn header(mut self, name: HeaderName, mut value: HeaderValue) -> Request {
        if REFUSED_HEADERS.contains(&name.as_str()) {
            self.refused.get_or_insert(name);
            return self;
        }
        if name == header::AUTHORIZATION || name == header::COOKIE {
            value.set_sensitive(true);
        }
        self.headers.append(name, value);
        self
    }

    /// Set the body. Like headers, it doesn't follow a redirect to another
    /// origin, and it's dropped where the redirect turns the request into a
    /// GET.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Request {
        self.body = Some(body.into());
        self
    }
}

/// The response at the end of a redirect chain.
pub struct Response {
    inner: reqwest::Response,
    url: Url,
    timeout: Duration,
    max_body: usize,
    read: usize,
}

// By hand for the same reason as Request's. Set-Cookie is a header value.
impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status())
            .field("origin", &self.url.origin().ascii_serialization())
            .field("headers", &self.headers().keys().collect::<Vec<_>>())
            .field("remote_addr", &self.remote_addr())
            .field("read", &self.read)
            .finish()
    }
}

impl Response {
    /// The status code.
    pub fn status(&self) -> StatusCode {
        self.inner.status()
    }

    /// The response headers.
    pub fn headers(&self) -> &HeaderMap {
        self.inner.headers()
    }

    /// The URL that answered, after redirects.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The address that answered.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.inner.remote_addr()
    }

    /// The next piece of the body, or `None` at the end. Once the pieces add
    /// up to more than the policy's [`max_body`](Policy::max_body), it fails
    /// with [`Error::BodyTooLarge`].
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, Error> {
        let Some(chunk) = self.next_chunk().await? else {
            return Ok(None);
        };
        if self.read + chunk.len() > self.max_body {
            return Err(Error::BodyTooLarge(self.max_body));
        }
        self.read += chunk.len();
        Ok(Some(chunk))
    }

    /// The body, up to the policy's [`max_body`](Policy::max_body). A longer
    /// one is [`Error::BodyTooLarge`].
    pub async fn bytes(mut self) -> Result<Vec<u8>, Error> {
        let mut body = Vec::new();
        while let Some(chunk) = self.chunk().await? {
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// The first [`max_body`](Policy::max_body) bytes of the body, and
    /// whether there was more. Stops reading at the limit.
    pub async fn bytes_truncated(mut self) -> Result<(Vec<u8>, bool), Error> {
        let mut body = Vec::new();
        while let Some(chunk) = self.next_chunk().await? {
            let room = self.max_body - body.len();
            if chunk.len() > room {
                body.extend_from_slice(&chunk[..room]);
                return Ok((body, true));
            }
            body.extend_from_slice(&chunk);
        }
        Ok((body, false))
    }

    /// The body as text, with invalid UTF-8 replaced. No charset decoding.
    pub async fn text(self) -> Result<String, Error> {
        let body = self.bytes().await?;
        Ok(String::from_utf8(body)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
    }

    async fn next_chunk(&mut self) -> Result<Option<Bytes>, Error> {
        self.inner
            .chunk()
            .await
            .map_err(|e| http_error(e, self.timeout))
    }
}

/// Fetches URLs, and opens TCP connections, under a [`Policy`].
///
/// Cheap to clone. Each hop of a fetch builds its own HTTP client, pinned to
/// the addresses that hop was checked against, so connections aren't pooled
/// between fetches or hops.
#[derive(Clone)]
#[must_use]
pub struct Fetcher {
    policy: Arc<Policy>,
    resolver: Arc<dyn Resolve>,
    user_agent: Option<HeaderValue>,
}

impl std::fmt::Debug for Fetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fetcher")
            .field("policy", &self.policy)
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

impl Default for Fetcher {
    fn default() -> Fetcher {
        Fetcher::new(Policy::default())
    }
}

/// The smallest share of the timeout one address gets in
/// [`Fetcher::connect`], so a long list doesn't cut every attempt short.
const MIN_ATTEMPT: Duration = Duration::from_secs(1);

impl Fetcher {
    /// A fetcher that uses the system resolver.
    pub fn new(policy: Policy) -> Fetcher {
        Fetcher {
            policy: Arc::new(policy),
            resolver: Arc::new(System),
            user_agent: None,
        }
    }

    /// Resolve names with `resolver` instead of the system's.
    pub fn with_resolver(mut self, resolver: impl Resolve) -> Fetcher {
        self.resolver = Arc::new(resolver);
        self
    }

    /// The `User-Agent` sent on every hop, including cross-origin ones.
    pub fn user_agent(mut self, value: HeaderValue) -> Fetcher {
        self.user_agent = Some(value);
        self
    }

    /// The policy this fetcher checks against.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// GET `url`, following redirects.
    pub async fn get(&self, url: &str) -> Result<Response, Error> {
        // The text stays out of the error. It may carry a password or a token.
        let url = Url::parse(url).map_err(|e| Error::InvalidUrl(format!("not a URL: {e}")))?;
        self.send(Request::new(Method::GET, url)).await
    }

    /// Send `request`, following redirects by hand. Each hop is resolved and
    /// checked again, and the policy's timeout covers the whole chain.
    ///
    /// Only 301, 302, 303, 307 and 308 are followed. Any other status,
    /// another 3xx included, is the response.
    pub async fn send(&self, request: Request) -> Result<Response, Error> {
        if let Some(name) = &request.refused {
            return Err(Error::RefusedHeader(name.to_string()));
        }
        let started = Instant::now();
        let budget = self.policy.timeout;
        match tokio::time::timeout(budget, self.follow(request, started)).await {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout(budget)),
        }
    }

    async fn follow(&self, request: Request, started: Instant) -> Result<Response, Error> {
        let Request {
            mut method,
            mut url,
            mut headers,
            body,
            refused: _,
        } = request;
        let budget = self.policy.timeout;
        let max = self.policy.max_redirects;
        let (mut host, mut port) = target(&url)?;
        let mut send_body = body.is_some();
        // Cleared for good once a redirect leaves the first URL's origin.
        let mut trusted = true;
        for hop in 0..=max {
            let addrs = self.resolve(&host, port).await?;
            let remaining = budget.saturating_sub(started.elapsed());
            let client = self.client(&host, addrs, remaining)?;

            let mut req = client.request(method.clone(), url.clone());
            if trusted {
                req = req.headers(headers.clone());
            }
            if send_body {
                req = req.body(body.clone().unwrap_or_default());
            }
            let resp = req.send().await.map_err(|e| http_error(e, budget))?;

            let status = resp.status().as_u16();
            let follow = matches!(status, 301 | 302 | 303 | 307 | 308) && max > 0;
            let location = resp.headers().get(header::LOCATION).filter(|_| follow);
            let Some(location) = location else {
                return Ok(Response {
                    inner: resp,
                    url,
                    timeout: budget,
                    max_body: self.policy.max_body,
                    read: 0,
                });
            };
            if hop == max {
                return Err(Error::TooManyRedirects(max));
            }
            // Browsers read a Location with raw UTF-8 in it, and Url::join
            // percent-encodes it. Anything else isn't a URL.
            let location = std::str::from_utf8(location.as_bytes()).map_err(|_| {
                Error::BadRedirect(format!("HTTP {status} with a Location that isn't UTF-8"))
            })?;
            let next = url.join(location).map_err(|_| {
                Error::BadRedirect(format!("HTTP {status} to an unreadable Location"))
            })?;
            (host, port) = target(&next).map_err(|e| Error::BadRedirect(e.to_string()))?;
            trusted = trusted && same_origin(&url, &next);
            let (next_method, keep_body) = redirect_method(&method, status);
            // A body can hold credentials as well as a header can (a login
            // form, a JSON key), so it stays on the first origin too.
            let keep_body = send_body && keep_body && trusted;
            if send_body && !keep_body {
                for name in [
                    header::CONTENT_TYPE,
                    header::CONTENT_ENCODING,
                    header::CONTENT_LANGUAGE,
                    header::CONTENT_LOCATION,
                ] {
                    headers.remove(name);
                }
            }
            send_body = keep_body;
            method = next_method;
            url = next;
        }
        Err(Error::TooManyRedirects(max))
    }

    /// A client for one hop, pinned to `addrs`.
    fn client(
        &self,
        host: &str,
        addrs: Vec<SocketAddr>,
        remaining: Duration,
    ) -> Result<reqwest::Client, Error> {
        let from = self.policy.sources.for_peer(addrs[0].ip()).ok().flatten();
        let pinned: Vec<SocketAddr> = match from {
            // reqwest binds one local address for every connection, so with
            // sources set only the first address's family is tried.
            Some(from) => addrs
                .into_iter()
                .filter(|a| a.is_ipv4() == from.is_ipv4())
                .collect(),
            None => addrs,
        };
        let builder = || {
            let mut b = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                // A proxy from HTTP_PROXY or ALL_PROXY would resolve the
                // host itself and connect wherever that says.
                .no_proxy()
                .dns_resolver(Unpinned)
                .connect_timeout(remaining)
                .timeout(remaining)
                .local_address(from);
            if let Some(ua) = &self.user_agent {
                b = b.user_agent(ua.clone());
            }
            if host.parse::<IpAddr>().is_err() {
                b = b.resolve_to_addrs(host, &pinned);
            }
            b
        };
        // reqwest refuses a config built with a rustls other than its own.
        // Falling back to reqwest's own TLS setup would turn session
        // resumption back on, so that's an error, and the
        // reqwest_takes_the_shared_tls_config test catches it first.
        builder()
            .tls_backend_preconfigured(tls_config()?)
            .build()
            .map_err(|e| Error::Tls(e.without_url().to_string()))
    }

    /// The addresses of `host` this fetcher would connect to, each with
    /// `port` set. A host given as an IP address isn't looked up. If any
    /// address of a name is refused, the whole name is. A name that answers
    /// with a private address is misconfigured or pointed at you on purpose.
    ///
    /// Not covered by the policy's timeout. [`connect`](Fetcher::connect)
    /// and [`send`](Fetcher::send) are.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, Error> {
        let bare = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        let mut addrs = match bare.parse::<IpAddr>() {
            Ok(ip) => vec![SocketAddr::new(ip, port)],
            Err(_) => self
                .resolver
                .resolve(bare, port)
                .await
                .map_err(|source| Error::Resolve {
                    host: host.to_string(),
                    source,
                })?,
        };
        if addrs.is_empty() {
            let source = io::Error::new(io::ErrorKind::NotFound, "no addresses");
            return Err(Error::Resolve {
                host: host.to_string(),
                source,
            });
        }
        // A resolver hands back socket addresses, but the port is the
        // caller's to choose.
        for a in &mut addrs {
            a.set_port(port);
        }
        if let Some(bad) = addrs.iter().find(|a| !self.policy.allows(a.ip())) {
            return Err(Error::Denied {
                host: host.to_string(),
                addr: bad.ip(),
            });
        }
        let reachable = self.policy.sources.reachable(addrs);
        if reachable.is_empty() {
            return Err(Error::NoSource {
                host: host.to_string(),
            });
        }
        Ok(reachable)
    }

    /// A TCP connection to `host:port`, if the policy allows the host's
    /// addresses. Tries each address in turn. Each one gets an equal share
    /// of what's left of the policy's timeout, at least a second, so an
    /// address that never answers doesn't use up the time for the rest.
    pub async fn connect(&self, host: &str, port: u16) -> Result<TcpStream, Error> {
        let budget = self.policy.timeout;
        let started = Instant::now();
        let work = async {
            let addrs = self.resolve(host, port).await?;
            let count = addrs.len();
            let mut last = None;
            for (i, addr) in addrs.into_iter().enumerate() {
                let left = budget.saturating_sub(started.elapsed());
                let share = (left / (count - i) as u32).max(MIN_ATTEMPT.min(left));
                match tokio::time::timeout(share, connect_with(self.policy.sources, addr)).await {
                    Ok(Ok(stream)) => return Ok(stream),
                    Ok(Err(e)) => last = Some(e),
                    Err(_) => {
                        let msg = format!("{addr} didn't answer within {share:?}");
                        last = Some(io::Error::new(io::ErrorKind::TimedOut, msg));
                    }
                }
            }
            let source = last.unwrap_or_else(|| io::Error::other("no address to try"));
            Err(Error::Connect {
                host: host.to_string(),
                source,
            })
        };
        tokio::time::timeout(budget, work)
            .await
            .unwrap_or(Err(Error::Timeout(budget)))
    }
}

async fn connect_with(sources: Sources, to: SocketAddr) -> io::Result<TcpStream> {
    let from = sources
        .for_peer(to.ip())
        .map_err(|_| io::Error::other(format!("no source address in the family of {}", to.ip())))?;
    let Some(from) = from else {
        return TcpStream::connect(to).await;
    };
    let socket = match to {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };
    socket.bind(SocketAddr::new(from, 0))?;
    socket.connect(to).await
}

/// The host and port a URL connects to, or why it can't be fetched.
///
/// The messages never quote the URL, since it may carry a password or a
/// token in its query.
fn target(url: &Url) -> Result<(String, u16), Error> {
    // reqwest would send these as basic auth, to whichever host the URL
    // names. Credentials belong in a header, where redirects can't move them.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::InvalidUrl(
            "the URL has a user name or password in it".to_string(),
        ));
    }
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::InvalidUrl(format!(
            "{}: URLs can't be fetched, only http and https",
            url.scheme()
        )));
    }
    let host = match url.host_str() {
        Some(h) if !h.is_empty() => h.trim_start_matches('[').trim_end_matches(']').to_string(),
        _ => return Err(Error::InvalidUrl("the URL has no host".to_string())),
    };
    let port = url.port_or_known_default().unwrap_or(80);
    Ok((host, port))
}

fn http_error(e: reqwest::Error, budget: Duration) -> Error {
    if e.is_timeout() {
        Error::Timeout(budget)
    } else {
        // reqwest's message ends with the URL, query and all.
        Error::Http(Box::new(e.without_url()))
    }
}

/// The method a redirect is followed with, and whether the body goes along,
/// as browsers do it: 303 turns anything but HEAD into a GET, 301 and 302
/// turn a POST into a GET, and 307 and 308 repeat the request as it was.
fn redirect_method(method: &Method, status: u16) -> (Method, bool) {
    let get = (Method::GET, false);
    match status {
        303 if *method != Method::HEAD => get,
        301 | 302 if *method == Method::POST => get,
        _ => (method.clone(), true),
    }
}

/// Whether two URLs share scheme, host and port. A redirect that changes
/// any of them is followed without the request's headers and body, the way
/// curl treats `Authorization` without `--location-trusted`.
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    match rustls::crypto::CryptoProvider::get_default() {
        Some(p) => p.clone(),
        None => Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    }
}

/// The TLS config every client is built with, made once per process.
///
/// A platform verifier parses every root in the system store the first time
/// it's used. On a small 2-vCPU Linux machine that measured over 100 ms, and
/// reqwest would make a new one for every client, which here is every hop.
/// A root added to the system store is picked up after a restart. A failure
/// isn't kept, so the next fetch tries again.
///
/// Session resumption is off. One shared session store would let a server
/// tie together fetches made for different callers.
fn tls_config() -> Result<rustls::ClientConfig, Error> {
    static TLS: OnceLock<rustls::ClientConfig> = OnceLock::new();
    if let Some(tls) = TLS.get() {
        return Ok(tls.clone());
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tls(e.to_string()))?
        .with_platform_verifier()
        .map_err(|e| Error::Tls(format!("no trust store to verify against: {e}")))?
        .with_no_client_auth();
    // What reqwest sets for itself without its http2 feature.
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    tls.resumption = rustls::client::Resumption::disabled();
    Ok(TLS.get_or_init(|| tls).clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reqwest_takes_the_shared_tls_config() {
        // If this fails, every fetch fails with Error::Tls. It means reqwest
        // and this crate ended up on different rustls versions.
        reqwest::Client::builder()
            .tls_backend_preconfigured(tls_config().unwrap())
            .build()
            .unwrap();
    }

    #[test]
    fn request_debug_hides_secrets() {
        let url = Url::parse("https://example.com/hooks/s-789?token=q-012").unwrap();
        let req = Request::new(Method::POST, url)
            .header(
                header::AUTHORIZATION,
                HeaderValue::from_static("Bearer t-456"),
            )
            .header(
                HeaderName::from_static("x-api-key"),
                HeaderValue::from_static("k-123"),
            )
            .body("hunter2");
        let shown = format!("{req:?}");
        assert!(shown.contains("x-api-key"), "{shown}");
        assert!(shown.contains("https://example.com"), "{shown}");
        for secret in ["t-456", "k-123", "hunter2", "s-789", "q-012"] {
            assert!(!shown.contains(secret), "{shown}");
        }
        assert!(req.headers[header::AUTHORIZATION].is_sensitive());
    }

    #[test]
    fn redirect_methods() {
        assert_eq!(redirect_method(&Method::POST, 303), (Method::GET, false));
        assert_eq!(redirect_method(&Method::PUT, 303), (Method::GET, false));
        assert_eq!(redirect_method(&Method::HEAD, 303), (Method::HEAD, true));
        assert_eq!(redirect_method(&Method::POST, 301), (Method::GET, false));
        assert_eq!(redirect_method(&Method::POST, 302), (Method::GET, false));
        assert_eq!(redirect_method(&Method::PUT, 302), (Method::PUT, true));
        assert_eq!(redirect_method(&Method::POST, 307), (Method::POST, true));
        assert_eq!(redirect_method(&Method::PATCH, 308), (Method::PATCH, true));
        assert_eq!(redirect_method(&Method::GET, 301), (Method::GET, true));
    }

    #[test]
    fn origins() {
        let u = |s: &str| Url::parse(s).unwrap();
        assert!(same_origin(
            &u("https://example.com/a"),
            &u("https://example.com:443/b?c")
        ));
        assert!(!same_origin(
            &u("https://example.com/a"),
            &u("https://evil.example/a")
        ));
        assert!(
            !same_origin(&u("https://example.com/a"), &u("http://example.com/a")),
            "a downgrade is another origin"
        );
        assert!(!same_origin(
            &u("https://example.com/a"),
            &u("https://example.com:8443/a")
        ));
        assert!(!same_origin(
            &u("https://example.com/a"),
            &u("https://www.example.com/a")
        ));
        assert!(
            same_origin(&u("https://example.com/a"), &u("https://EXAMPLE.com/b")),
            "host case is not an origin"
        );
    }

    #[test]
    fn targets() {
        let t = |s: &str| target(&Url::parse(s).unwrap());
        assert_eq!(
            t("https://example.com/x").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(
            t("http://[2001:db8::1]:8080/").unwrap(),
            ("2001:db8::1".into(), 8080)
        );
        assert!(t("ftp://example.com/").is_err());
        assert!(t("https://user:pw@example.com/").is_err());
        assert!(t("https://user@example.com/").is_err());
        assert!(t("file:///etc/passwd").is_err());
    }

    #[test]
    fn url_errors_dont_repeat_the_url() {
        let t = |s: &str| target(&Url::parse(s).unwrap()).unwrap_err().to_string();
        for (url, secret) in [
            ("https://user:pw-345@example.com/", "pw-345"),
            ("ftp://user:pw-345@example.com/", "pw-345"),
            ("ftp://example.com/?token=q-012", "q-012"),
        ] {
            let shown = t(url);
            assert!(!shown.contains(secret), "{shown}");
        }
    }
}

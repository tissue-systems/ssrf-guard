use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::addr::{Cidr, denied};

/// What a [`Fetcher`](crate::Fetcher) may connect to, and how long it may
/// take. Build one with [`Policy::builder`].
///
/// The default refuses everything [`is_public`](crate::is_public) refuses,
/// follows at most 3 redirects, gives a whole fetch 10 seconds and reads at
/// most 10 MiB of body.
///
/// ```
/// use std::time::Duration;
/// use ssrf_guard::Policy;
///
/// # fn main() -> Result<(), ssrf_guard::Error> {
/// let ip = "8.8.8.8".parse().unwrap();
/// assert!(Policy::default().allows(ip));
///
/// let policy = Policy::builder()
///     // Public addresses of your own that a fetch shouldn't reach.
///     .deny("8.8.8.0/24".parse()?)
///     .timeout(Duration::from_secs(5))
///     .build();
/// assert!(!policy.allows(ip));
/// assert_eq!(policy.timeout(), Duration::from_secs(5));
/// assert_eq!(policy.max_redirects(), 3);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Policy {
    pub(crate) deny: Vec<Cidr>,
    pub(crate) allow: Vec<Cidr>,
    pub(crate) sources: Sources,
    pub(crate) max_redirects: usize,
    pub(crate) timeout: Duration,
    pub(crate) max_body: usize,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy {
            deny: Vec::new(),
            allow: Vec::new(),
            sources: Sources::default(),
            max_redirects: 3,
            timeout: Duration::from_secs(10),
            max_body: 10 * 1024 * 1024,
        }
    }
}

impl Policy {
    /// A builder that starts from the default policy.
    pub fn builder() -> PolicyBuilder {
        PolicyBuilder::default()
    }

    /// Whether this policy lets a connection go to `ip`.
    pub fn allows(&self, ip: IpAddr) -> bool {
        if self.deny.iter().any(|net| net.contains(ip)) {
            return false;
        }
        !denied(ip) || self.allow.iter().any(|net| net.contains(ip))
    }

    /// The blocks refused on top of the built-in list, in the order they
    /// were added.
    pub fn deny(&self) -> &[Cidr] {
        &self.deny
    }

    /// The blocks let through that the built-in list refuses, in the order
    /// they were added. [`allows`](Policy::allows) is what decides a
    /// single address.
    pub fn allow(&self) -> &[Cidr] {
        &self.allow
    }

    /// The source address for IPv4 connections, if one is set.
    pub fn source_v4(&self) -> Option<Ipv4Addr> {
        match self.sources.v4 {
            Some(IpAddr::V4(ip)) => Some(ip),
            _ => None,
        }
    }

    /// The source address for IPv6 connections, if one is set.
    pub fn source_v6(&self) -> Option<Ipv6Addr> {
        match self.sources.v6 {
            Some(IpAddr::V6(ip)) => Some(ip),
            _ => None,
        }
    }

    /// How many redirects a fetch follows.
    pub fn max_redirects(&self) -> usize {
        self.max_redirects
    }

    /// The budget for a whole fetch.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The most body a [`Response`](crate::Response) will read, in bytes.
    pub fn max_body(&self) -> usize {
        self.max_body
    }
}

/// Builds a [`Policy`]. Start with [`Policy::builder`], which starts from
/// the defaults, and finish with [`build`](PolicyBuilder::build).
#[derive(Clone, Debug, Default)]
#[must_use]
pub struct PolicyBuilder {
    policy: Policy,
}

impl PolicyBuilder {
    /// Refuse a block on top of the built-in list. A denied block wins over
    /// an allowed one. It covers every port.
    pub fn deny(mut self, net: Cidr) -> PolicyBuilder {
        self.policy.deny.push(net);
        self
    }

    /// Let a block through that the built-in list refuses, such as
    /// `127.0.0.0/8` in tests or a private network you mean to reach. An
    /// IPv6 block lets through the IPv4 addresses written inside it too, so
    /// allowing `::/0` allows `::ffff:127.0.0.1`.
    pub fn allow(mut self, net: Cidr) -> PolicyBuilder {
        self.policy.allow.push(net);
        self
    }

    /// Bind outgoing connections to `ip`, once for each address family you
    /// want to use. Once any source is set, a host with no address in a
    /// family that has one fails to connect rather than leaving from
    /// whatever address the kernel would pick.
    pub fn source(mut self, ip: IpAddr) -> PolicyBuilder {
        match ip {
            IpAddr::V4(_) => self.policy.sources.v4 = Some(ip),
            IpAddr::V6(_) => self.policy.sources.v6 = Some(ip),
        }
        self
    }

    /// How many redirects a fetch follows before it fails with
    /// [`Error::TooManyRedirects`](crate::Error::TooManyRedirects). With 0
    /// none are followed, and a redirect comes back as the response.
    pub fn max_redirects(mut self, n: usize) -> PolicyBuilder {
        self.policy.max_redirects = n;
        self
    }

    /// The budget for a whole fetch: every lookup, connection and redirect,
    /// and reading the body. For [`Fetcher::connect`](crate::Fetcher::connect)
    /// it covers the lookup and the connection.
    ///
    /// The system resolver runs `getaddrinfo` on tokio's blocking pool, and
    /// a timeout can't stop that thread. The caller gets
    /// [`Error::Timeout`](crate::Error::Timeout) on time, but a name that
    /// takes long to resolve keeps a thread busy until the OS resolver gives
    /// up. A server that fetches many untrusted URLs should give
    /// [`Fetcher::with_resolver`](crate::Fetcher::with_resolver) an async
    /// resolver, or limit how many fetches run at once.
    pub fn timeout(mut self, timeout: Duration) -> PolicyBuilder {
        self.policy.timeout = timeout;
        self
    }

    /// The most body a [`Response`](crate::Response) will read, in bytes.
    pub fn max_body(mut self, bytes: usize) -> PolicyBuilder {
        self.policy.max_body = bytes;
        self
    }

    /// The finished policy.
    pub fn build(self) -> Policy {
        self.policy
    }
}

/// Source addresses, at most one per family.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Sources {
    pub(crate) v4: Option<IpAddr>,
    pub(crate) v6: Option<IpAddr>,
}

impl Sources {
    /// The source for a connection to `to`. `Ok(None)` when no sources are
    /// set; `Err` when some are but none is in `to`'s family.
    pub(crate) fn for_peer(&self, to: IpAddr) -> Result<Option<IpAddr>, ()> {
        if self.v4.is_none() && self.v6.is_none() {
            return Ok(None);
        }
        match to {
            IpAddr::V4(_) => self.v4.map(Some).ok_or(()),
            IpAddr::V6(_) => self.v6.map(Some).ok_or(()),
        }
    }

    /// `addrs` without the ones no source can reach.
    pub(crate) fn reachable(&self, addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        addrs
            .into_iter()
            .filter(|a| self.for_peer(a.ip()).is_ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn deny_beats_allow_beats_builtin() {
        let p = Policy::default();
        assert!(!p.allows(ip("127.0.0.1")));
        assert!(p.allows(ip("8.8.8.8")));

        let p = Policy::builder()
            .allow("127.0.0.0/8".parse().unwrap())
            .build();
        assert!(p.allows(ip("127.0.0.1")));
        assert!(p.allows(ip("::ffff:127.0.0.1")));
        assert!(
            !p.allows(ip("::1")),
            "allowing 127/8 says nothing about ::1"
        );
        assert!(!p.allows(ip("10.1.2.3")));

        let p = Policy::builder()
            .allow("127.0.0.0/8".parse().unwrap())
            .deny("127.0.0.2".parse().unwrap())
            .deny("8.8.8.0/24".parse().unwrap())
            .build();
        assert!(p.allows(ip("127.0.0.1")));
        assert!(!p.allows(ip("127.0.0.2")));
        assert!(!p.allows(ip("8.8.8.8")));
        assert!(
            !p.allows(ip("64:ff9b::808:808")),
            "NAT64 spelling of a denied address"
        );
        assert!(p.allows(ip("8.8.4.4")));

        // An IPv6 deny holds the IPv6 spellings of IPv4 addresses as well.
        let p = Policy::builder().deny("::/0".parse().unwrap()).build();
        assert!(!p.allows(ip("::ffff:8.8.8.8")));
        assert!(!p.allows(ip("::8.8.8.8")));
        assert!(!p.allows(ip("2606:4700::1111")));
        assert!(p.allows(ip("8.8.8.8")));
        let p = Policy::builder()
            .deny("64:ff9b::/96".parse().unwrap())
            .build();
        assert!(!p.allows(ip("64:ff9b::808:808")));
    }

    #[test]
    fn no_sources_means_the_kernel_picks() {
        let none = Sources::default();
        assert_eq!(none.for_peer(ip("192.0.2.1")), Ok(None));
        let addrs = vec!["[2001:db8::1]:443".parse().unwrap()];
        assert_eq!(none.reachable(addrs.clone()), addrs);
    }

    #[test]
    fn a_family_without_a_source_is_unreachable() {
        let v4_only = Policy::builder().source(ip("198.51.100.7")).build().sources;
        assert_eq!(
            v4_only.for_peer(ip("192.0.2.1")),
            Ok(Some(ip("198.51.100.7")))
        );
        assert!(v4_only.for_peer(ip("2001:db8::1")).is_err());

        let both: Vec<SocketAddr> = vec![
            "[2001:db8::1]:443".parse().unwrap(),
            "192.0.2.1:443".parse().unwrap(),
        ];
        assert_eq!(
            v4_only.reachable(both),
            vec!["192.0.2.1:443".parse().unwrap()]
        );
        assert!(
            v4_only
                .reachable(vec!["[2001:db8::1]:443".parse().unwrap()])
                .is_empty()
        );
    }

    #[test]
    fn getters_read_back_what_the_builder_set() {
        let d = Policy::default();
        assert_eq!(
            (d.max_redirects(), d.timeout(), d.max_body()),
            (3, Duration::from_secs(10), 10 * 1024 * 1024)
        );
        assert!(d.deny().is_empty() && d.allow().is_empty());
        assert_eq!((d.source_v4(), d.source_v6()), (None, None));

        let p = Policy::builder()
            .deny("8.8.8.0/24".parse().unwrap())
            .deny("1.1.1.1".parse().unwrap())
            .allow("127.0.0.0/8".parse().unwrap())
            .source(ip("198.51.100.7"))
            .source(ip("2001:db8::7"))
            .max_redirects(0)
            .timeout(Duration::from_millis(1500))
            .max_body(99)
            .build();
        let shown: Vec<String> = p.deny().iter().map(ToString::to_string).collect();
        assert_eq!(shown, ["8.8.8.0/24", "1.1.1.1/32"]);
        assert_eq!(p.allow()[0].to_string(), "127.0.0.0/8");
        assert_eq!(p.source_v4(), Some("198.51.100.7".parse().unwrap()));
        assert_eq!(p.source_v6(), Some("2001:db8::7".parse().unwrap()));
        assert_eq!(
            (p.max_redirects(), p.timeout(), p.max_body()),
            (0, Duration::from_millis(1500), 99)
        );
    }
}

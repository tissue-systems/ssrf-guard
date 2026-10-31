use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::addr::{Cidr, denied};

/// What a [`Fetcher`](crate::Fetcher) may connect to, and how long it may
/// take.
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
/// let policy = Policy::default()
///     // Public addresses of your own that a fetch shouldn't reach.
///     .deny("8.8.8.0/24".parse()?)
///     .timeout(Duration::from_secs(5));
/// assert!(!policy.allows(ip));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
#[must_use]
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
    /// Refuse a block on top of the built-in list. A denied block wins over
    /// an allowed one. It covers every port.
    pub fn deny(mut self, net: Cidr) -> Policy {
        self.deny.push(net);
        self
    }

    /// Let a block through that the built-in list refuses, such as
    /// `127.0.0.0/8` in tests or a private network you mean to reach. An
    /// IPv6 block lets through the IPv4 addresses written inside it too, so
    /// allowing `::/0` allows `::ffff:127.0.0.1`.
    pub fn allow(mut self, net: Cidr) -> Policy {
        self.allow.push(net);
        self
    }

    /// Bind outgoing connections to `ip`, once for each address family you
    /// want to use. Once any source is set, a host with no address in a
    /// family that has one fails to connect rather than leaving from
    /// whatever address the kernel would pick.
    pub fn source(mut self, ip: IpAddr) -> Policy {
        match ip {
            IpAddr::V4(_) => self.sources.v4 = Some(ip),
            IpAddr::V6(_) => self.sources.v6 = Some(ip),
        }
        self
    }

    /// How many redirects a fetch follows before it fails with
    /// [`Error::TooManyRedirects`](crate::Error::TooManyRedirects). With 0
    /// none are followed, and a redirect comes back as the response.
    pub fn max_redirects(mut self, n: usize) -> Policy {
        self.max_redirects = n;
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
    pub fn timeout(mut self, timeout: Duration) -> Policy {
        self.timeout = timeout;
        self
    }

    /// The most body a [`Response`](crate::Response) will read.
    pub fn max_body(mut self, bytes: usize) -> Policy {
        self.max_body = bytes;
        self
    }

    /// Whether this policy lets a connection go to `ip`.
    pub fn allows(&self, ip: IpAddr) -> bool {
        if self.deny.iter().any(|net| net.contains(ip)) {
            return false;
        }
        !denied(ip) || self.allow.iter().any(|net| net.contains(ip))
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

        let p = Policy::default().allow("127.0.0.0/8".parse().unwrap());
        assert!(p.allows(ip("127.0.0.1")));
        assert!(p.allows(ip("::ffff:127.0.0.1")));
        assert!(
            !p.allows(ip("::1")),
            "allowing 127/8 says nothing about ::1"
        );
        assert!(!p.allows(ip("10.1.2.3")));

        let p = p
            .deny("127.0.0.2".parse().unwrap())
            .deny("8.8.8.0/24".parse().unwrap());
        assert!(p.allows(ip("127.0.0.1")));
        assert!(!p.allows(ip("127.0.0.2")));
        assert!(!p.allows(ip("8.8.8.8")));
        assert!(
            !p.allows(ip("64:ff9b::808:808")),
            "NAT64 spelling of a denied address"
        );
        assert!(p.allows(ip("8.8.4.4")));

        // An IPv6 deny holds the IPv6 spellings of IPv4 addresses as well.
        let p = Policy::default().deny("::/0".parse().unwrap());
        assert!(!p.allows(ip("::ffff:8.8.8.8")));
        assert!(!p.allows(ip("::8.8.8.8")));
        assert!(!p.allows(ip("2606:4700::1111")));
        assert!(p.allows(ip("8.8.8.8")));
        let p = Policy::default().deny("64:ff9b::/96".parse().unwrap());
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
        let v4_only = Policy::default().source(ip("198.51.100.7")).sources;
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
}

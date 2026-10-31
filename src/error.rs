use std::net::IpAddr;
use std::time::Duration;

/// Why a fetch or connect didn't happen, or didn't finish.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The URL isn't an absolute `http://` or `https://` URL with a host, or
    /// it carries a user name or password.
    #[error("{0}")]
    InvalidUrl(String),

    /// A string passed as an address block didn't parse.
    #[error("{0:?} is not an address or address block")]
    InvalidCidr(String),

    /// The request sets a header this crate won't send for you, such as
    /// `Host` or `Content-Length`. See [`Request::header`](crate::Request::header).
    #[error("the {0} header can't be set on a request")]
    RefusedHeader(String),

    /// The host is, or resolves to, an address the policy refuses. One such
    /// address refuses the whole name.
    ///
    /// The message leaves the address out when the host is a name, so it's
    /// safe to show to whoever typed the URL. `addr` is for your logs. Shown
    /// to the user, it tells them what your internal names resolve to.
    #[error("{}", denied(host, addr))]
    #[non_exhaustive]
    Denied {
        /// The host as the URL or the caller gave it.
        host: String,
        /// The first refused address it resolved to.
        addr: IpAddr,
    },

    /// The policy has a source address, but none in any family the host
    /// resolved to.
    #[error("no source address to reach {host} from")]
    #[non_exhaustive]
    NoSource {
        /// The host that had no reachable address.
        host: String,
    },

    /// The name didn't resolve, or resolved to nothing.
    #[error("{host} does not resolve")]
    #[non_exhaustive]
    Resolve {
        /// The name that was looked up.
        host: String,
        /// What the resolver said.
        source: std::io::Error,
    },

    /// A redirect had a `Location` that can't be followed: unparseable, to a
    /// scheme other than http and https, or with a user name or password.
    #[error("redirect refused: {0}")]
    BadRedirect(String),

    /// The chain was longer than the policy's redirect limit.
    #[error("more than {0} redirects")]
    TooManyRedirects(usize),

    /// The body was larger than the policy's limit.
    #[error("response body is over {0} bytes")]
    BodyTooLarge(usize),

    /// The policy's timeout ran out. It covers every hop of a fetch.
    #[error("no answer within {0:?}")]
    Timeout(Duration),

    /// No TCP connection could be made to any of the host's addresses.
    #[error("can't connect to {host}")]
    #[non_exhaustive]
    Connect {
        /// The host being connected to.
        host: String,
        /// The error from the last address tried.
        source: std::io::Error,
    },

    /// The TLS client couldn't be set up, usually because the system has
    /// no trust store to verify certificates against.
    #[error("TLS setup failed: {0}")]
    Tls(String),

    /// The request failed after it was allowed: refused, reset, a bad
    /// certificate. This is the HTTP client's own error, with the URL taken
    /// out of it.
    #[error(transparent)]
    Http(Box<dyn std::error::Error + Send + Sync>),
}

fn denied(host: &str, addr: &IpAddr) -> String {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<IpAddr>().is_ok() {
        format!("{addr} is an address this policy refuses")
    } else {
        format!("{host} resolves to an address this policy refuses")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown(host: &str) -> String {
        Error::Denied {
            host: host.to_string(),
            addr: "10.1.2.3".parse().unwrap(),
        }
        .to_string()
    }

    #[test]
    fn a_denied_name_keeps_its_address_quiet() {
        assert_eq!(
            shown("intranet.example"),
            "intranet.example resolves to an address this policy refuses"
        );
        assert_eq!(
            shown("10.1.2.3"),
            "10.1.2.3 is an address this policy refuses"
        );
        assert_eq!(
            shown("[::ffff:10.1.2.3]"),
            "10.1.2.3 is an address this policy refuses"
        );
    }

    #[test]
    fn the_cause_is_in_the_source_not_the_message() {
        let e = Error::Resolve {
            host: "nope.test".to_string(),
            source: std::io::Error::other("not in the table"),
        };
        assert_eq!(e.to_string(), "nope.test does not resolve");
        let source = std::error::Error::source(&e).unwrap();
        assert_eq!(source.to_string(), "not in the table");
    }
}

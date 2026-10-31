//! Fetch user-supplied URLs from a server without letting them reach your
//! private network.
//!
//! When a server fetches a URL someone else gave it (a webhook, a link
//! preview, an uptime check), the URL can point at `127.0.0.1`, at the cloud
//! metadata service on `169.254.169.254`, or at a name that resolves to one
//! of them.
//!
//! A [`Fetcher`] resolves every hop itself and refuses the whole name if any
//! address is loopback, private, link-local or otherwise not public
//! ([`is_public`] has the list, IPv6 spellings included). It then connects
//! only to the addresses it checked. A DNS answer that changes afterwards
//! changes nothing. Redirects are followed by hand and checked again, a
//! redirect to another origin goes without the headers and body you set,
//! proxies from the environment are ignored, and one timeout covers the
//! whole chain.
//!
//! ```no_run
//! use ssrf_guard::{Fetcher, Policy};
//!
//! # async fn run() -> Result<(), ssrf_guard::Error> {
//! let fetcher = Fetcher::new(Policy::default());
//! let resp = fetcher.get("https://example.com/").await?;
//! println!("{} from {:?}", resp.status(), resp.remote_addr());
//! let body = resp.text().await?;
//! # Ok(())
//! # }
//! ```
//!
//! A redirect to `http://localhost/` or to a name that resolves to `10.1.2.3`
//! fails with [`Error::Denied`]. [`Fetcher::connect`] does the same checks
//! for a plain TCP connection, and [`Fetcher::resolve`] for anything else
//! you connect yourself.
//!
//! To refuse more, such as your own servers' public addresses, add blocks
//! with [`Policy::deny`]. To let something through that the list refuses,
//! such as loopback in tests, use [`Policy::allow`].
//!
//! # Platform notes
//!
//! Needs a tokio runtime. TLS is rustls with the platform verifier, which
//! checks certificates against the operating system's trust store. On
//! Linux that needs a CA bundle installed (`ca-certificates` on Debian and
//! Alpine), which slim container images often leave out. TLS session
//! resumption is off. A server can't use session tickets to tie one
//! caller's fetches to another's. HTTP/1.1 only.
//!
//! The system resolver blocks a thread per lookup, and the policy's timeout
//! can't stop it. See [`Policy::timeout`].
//!
//! The checks run on the addresses this process connects to. They can't see
//! past a NAT64 gateway or a VPN that routes public addresses somewhere
//! private, and they don't stop a public server you fetch from doing
//! whatever it likes with the request.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod addr;
mod error;
mod fetch;
mod policy;

pub use addr::{Cidr, is_public};
pub use error::Error;
pub use fetch::{Fetcher, Request, Resolve, Response};
pub use policy::Policy;

pub use bytes::Bytes;
pub use http::header;
pub use http::{Method, StatusCode};
pub use url::Url;

// Compiles the README's example with the doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct Readme;

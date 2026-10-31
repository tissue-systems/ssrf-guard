# ssrf-guard

[![crates.io](https://img.shields.io/crates/v/ssrf-guard.svg)](https://crates.io/crates/ssrf-guard)
[![docs.rs](https://img.shields.io/docsrs/ssrf-guard)](https://docs.rs/ssrf-guard)
[![CI](https://github.com/tissue-systems/ssrf-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/tissue-systems/ssrf-guard/actions/workflows/ci.yml)

An HTTP client for fetching URLs that somebody else typed in. It resolves each
host itself, refuses loopback, private, link-local and metadata addresses
before connecting, and pins the connection to the addresses it checked. A
webhook or a link preview can't be pointed back into your own network.

```rust,no_run
use ssrf_guard::{Fetcher, Policy};

#[tokio::main]
async fn main() -> Result<(), ssrf_guard::Error> {
    let fetcher = Fetcher::new(Policy::default());
    let resp = fetcher.get("https://example.com/").await?;
    println!("{} from {:?}", resp.status(), resp.remote_addr());

    // Refused before any connection is made.
    let err = fetcher.get("http://169.254.169.254/latest/meta-data/").await;
    assert!(matches!(err, Err(ssrf_guard::Error::Denied { .. })));
    Ok(())
}
```

`cargo run --example fetch -- <url>` runs the same thing from the command line.

## What it does

Every hop of a fetch goes through the same steps. The host is resolved, and if
any of its addresses is refused the whole name is. The HTTP client is then
told to connect to exactly those addresses and has no resolver of its own, so
a DNS answer that changes between the check and the connect changes nothing.
Redirects (301, 302, 303, 307 and 308) are followed by hand, up to
`Policy::max_redirects` (3 by default), and each one goes through the same
steps from the start. A redirect to another scheme, host or port drops the
headers and body you set, and once a chain has left the first origin it
doesn't get them back. A 303, or a 301 or 302 after a POST, turns into a GET
without a body. A URL with a user name or password in it is refused, since
the client would turn those into an `Authorization` header for whatever host
it names.

The built-in list refuses loopback, RFC 1918, link-local (where cloud metadata
services answer), carrier-grade NAT, `0.0.0.0/8`, multicast, broadcast,
documentation, benchmarking and reserved space. In IPv6 it refuses loopback,
unique local, link-local, the deprecated site-local block, multicast,
documentation, benchmarking, the discard prefix and SRv6 segment IDs. An IPv6
address that carries an IPv4 one (`::ffff:10.1.2.3`, `::10.1.2.3`,
`64:ff9b::a01:203`) is judged by the IPv4 address inside it. 6to4 and Teredo are refused outright, since where those
packets come out is up to a relay. The list is `ssrf_guard::is_public` if you
want it on its own.

`Policy::deny` adds blocks of your own, such as the public addresses of your
own servers, and wins over everything. `Policy::allow` lets through a block
the built-in list refuses, which is how the tests reach a server on
`127.0.0.1`.

`HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` are ignored, because a proxy
resolves the host itself, after the check. `Host`, `Content-Length` and the
other headers that belong to the connection can't be set on a request.
`Policy::timeout` (10 seconds by default) covers every lookup, connection and
redirect, and reading the body. `Policy::max_body` (10 MiB by default) limits
what `bytes()`, `text()` and `chunk()` will read, and `bytes_truncated()`
gives you the first `max_body` bytes of a longer body instead of an error.
`Policy::source` binds outgoing connections to one address per family.

For protocols that aren't HTTP, `Fetcher::connect` makes a checked TCP
connection and `Fetcher::resolve` hands you the checked addresses.
`Fetcher::with_resolver` swaps out the system resolver.

A refused name's error message leaves out the address it resolved to, and no
error repeats the URL, which may carry a password or a token. You can show
the message to whoever typed the URL. The address is in `Error::Denied` for
your logs.

## What it doesn't do

It only checks the addresses this process connects to. A NAT64 gateway, a VPN
or a corporate proxy that routes public addresses somewhere private is
invisible to it, and so is anything a public server does with the request
after it arrives. It doesn't restrict ports or match host names, it doesn't
rate-limit, and it doesn't look at what comes back. HTTP/1.1 only.

The system resolver blocks a thread for each lookup, and the timeout can't
stop that thread. A server that fetches many untrusted URLs should pass an
async resolver to `Fetcher::with_resolver`, or limit how many fetches run at
once.

## Requirements

Rust 1.88 or later and a tokio runtime. TLS is rustls with the platform
verifier, which checks certificates against the operating system's trust
store. On Linux that needs a CA bundle, which slim container images often
leave out (`ca-certificates` on Debian and Alpine). Tested on Linux and macOS.

## Other crates

[reqwest-ssrf-guard](https://crates.io/crates/reqwest-ssrf-guard) plugs into a
`reqwest::ClientBuilder` you build yourself, through a DNS resolver and a
redirect policy. That fits better if you want to keep your own client and its
connection pool. It can also refuse ports and match host names, which
ssrf-guard doesn't do. The trade is that you wire up part of it yourself: a
URL with a literal IP never reaches the resolver, so it needs that crate's
`validate_url` or its middleware, and turning off `HTTP_PROXY` is up to you.
A name with one private address among public ones has the private one
dropped, where this crate refuses the name. ssrf-guard owns the client, which
is less flexible, but there's one call and nothing to forget.

[http-acl-reqwest](https://crates.io/crates/http-acl-reqwest) is the same idea
with a fuller access list (host wildcards, port ranges, header and path
rules) and the same trade.

If you want the check without this crate's client,
[url_jail](https://crates.io/crates/url_jail) resolves a URL and hands back an
address to connect to, and has Python bindings.

## About

ssrf-guard is written and maintained by
[Tissue Systems](https://tissue.systems/?ref=ssrf-guard). We built it for
[Tissue Mast](https://tissue.systems/mast?ref=ssrf-guard), an on-call paging
and monitoring service, whose uptime checks fetch URLs our customers type in.
Bug reports and pull requests are welcome whether or not you use it.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in ssrf-guard by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

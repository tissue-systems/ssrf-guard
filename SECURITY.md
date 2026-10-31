# Security policy

## Reporting a vulnerability

Please don't open a public issue for a security problem. Report it privately
through [GitHub's security advisory form](https://github.com/tissue-systems/ssrf-guard/security/advisories/new)
or by email to [security@tissue.systems](mailto:security@tissue.systems),
with what you found and the steps to reproduce it. A small program or a test
case that shows the problem is the most useful thing you can send.

We'll write back within three working days and credit you in the release
notes unless you'd rather we didn't. Please give us 90 days, or until a fix
ships if that's sooner, before you publish.

## Supported versions

ssrf-guard is pre-1.0. Fixes go into the latest 0.x release only.

## What's in scope

Anything that lets a URL reach an address the policy refuses:

- an address or IPv6 spelling the built-in list should refuse and doesn't
- a connection that lands on an address other than the one that was checked
- a redirect that isn't checked, or that carries the caller's headers or body
  to another origin
- a fetch that runs past the policy's timeout or body limit

Things the README lists under "What it doesn't do", such as a NAT64 gateway or
a VPN routing public addresses somewhere private, aren't vulnerabilities in
ssrf-guard. Neither is a policy that allows a block and then reaches it. Bugs
in reqwest, hyper or rustls themselves go upstream. If you're not sure, send
it anyway.

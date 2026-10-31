# Contributing

Bug reports and pull requests are welcome. For anything bigger than a small
fix, open an issue first so we can agree on the approach before you spend
time on it. A way to reach an address the policy should have refused is a
security problem, and goes where [SECURITY.md](SECURITY.md) says, not to the
issue tracker.

## Reporting a bug

Say which ssrf-guard and Rust versions you're on, the operating system, the
URL or a stand-in for it, and the error you got. If DNS is involved, the
addresses the name resolved to at the time help a lot.

## Building and testing

You need Rust 1.88 or later. CI runs these, so run them before you push:

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --locked
cargo package --locked
```

The tests run against servers on `127.0.0.1` and a resolver that answers from
a table, so they need no network. A few that do are marked `#[ignore]`:

```sh
cargo test -- --ignored
```

## Changes to the code

- Keep the minimum Rust version at 1.88. Raising it gets its own pull
  request.
- New behavior comes with a test. A fix comes with a test that fails without
  it.
- A change to the built-in address list needs the RFC or IANA registry entry
  that justifies it, in a comment next to the check in `src/addr.rs`, and an
  address on each side of the boundary in the `deny_table` test.
- Add a line to `CHANGELOG.md` for anything a user would notice.

## License

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in ssrf-guard by you, as defined in the Apache-2.0
license, shall be dual licensed as in the README, without any additional
terms or conditions.

// Its own test binary, because it sets environment variables for the whole
// process.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{Reply, serve};
use ssrf_guard::{Fetcher, Policy};

#[tokio::test]
async fn proxies_from_the_environment_are_ignored() {
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
    let used = Arc::new(AtomicUsize::new(0));
    let count = used.clone();
    tokio::spawn(async move {
        while proxy.accept().await.is_ok() {
            count.fetch_add(1, Ordering::SeqCst);
        }
    });
    for name in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        // SAFETY: the only test in this binary, and no other thread has
        // started reading the environment yet.
        unsafe { std::env::set_var(name, &proxy_url) };
    }
    unsafe {
        std::env::remove_var("NO_PROXY");
        std::env::remove_var("no_proxy");
    }

    let server = serve(|_| Reply::ok("direct")).await;
    let fetcher = Fetcher::new(
        Policy::builder()
            .allow("127.0.0.1".parse().unwrap())
            .build(),
    );
    let resp = fetcher.get(&server.url("/")).await.unwrap();
    assert_eq!(resp.text().await.unwrap(), "direct");
    assert_eq!(used.load(Ordering::SeqCst), 0, "the proxy was used");
}

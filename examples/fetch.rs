//! Fetch a URL the way a server would fetch one it was handed:
//!
//! ```sh
//! cargo run --example fetch -- https://example.com/
//! cargo run --example fetch -- http://169.254.169.254/latest/meta-data/
//! ```

use ssrf_guard::{Fetcher, Policy};

#[tokio::main]
async fn main() {
    let Some(url) = std::env::args().nth(1) else {
        eprintln!("usage: fetch <url>");
        std::process::exit(2);
    };
    let fetcher = Fetcher::new(Policy::default());
    match fetcher.get(&url).await {
        Ok(resp) => {
            let status = resp.status();
            let from = resp
                .remote_addr()
                .map(|a| a.to_string())
                .unwrap_or_default();
            let at = resp.url().clone();
            match resp.bytes().await {
                Ok(body) => println!("{status} from {from} at {at}, {} bytes", body.len()),
                Err(e) => println!("{status} from {from} at {at}, body failed: {e}"),
            }
        }
        Err(e) => {
            eprint!("refused or failed: {e}");
            let mut source = std::error::Error::source(&e);
            while let Some(cause) = source {
                eprint!(": {cause}");
                source = cause.source();
            }
            eprintln!();
            std::process::exit(1);
        }
    }
}

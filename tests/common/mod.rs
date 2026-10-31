// A small HTTP/1.1 server on loopback that records what it was sent, and a
// resolver that answers from a table.
#![allow(dead_code)]

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub delay: Duration,
}

impl Reply {
    pub fn ok(body: &str) -> Reply {
        Reply {
            status: 200,
            headers: vec![],
            body: body.as_bytes().to_vec(),
            delay: Duration::ZERO,
        }
    }

    pub fn redirect(status: u16, location: &str) -> Reply {
        Reply {
            status,
            headers: vec![("Location".into(), location.into())],
            body: vec![],
            delay: Duration::ZERO,
        }
    }

    pub fn after(mut self, delay: Duration) -> Reply {
        self.delay = delay;
        self
    }
}

pub struct Server {
    pub addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

pub async fn serve<F>(handler: F) -> Server
where
    F: Fn(&Seen) -> Reply + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let handler = Arc::new(handler);
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let handler = handler.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let _ = answer(sock, &*handler, &log).await;
            });
        }
    });
    Server { addr, seen }
}

async fn answer<F>(mut sock: TcpStream, handler: &F, log: &Mutex<Vec<Seen>>) -> io::Result<()>
where
    F: Fn(&Seen) -> Reply,
{
    let mut buf = Vec::new();
    let head_end = loop {
        let mut chunk = [0u8; 1024];
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default().to_string();
    let path = first.next().unwrap_or_default().to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < length {
        let mut chunk = [0u8; 1024];
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    let seen = Seen {
        method,
        path,
        headers,
        body,
    };
    log.lock().unwrap().push(seen.clone());
    let reply = handler(&seen);
    tokio::time::sleep(reply.delay).await;
    let mut out = format!(
        "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
        reply.status,
        reply.body.len()
    );
    for (n, v) in &reply.headers {
        out.push_str(&format!("{n}: {v}\r\n"));
    }
    out.push_str("\r\n");
    sock.write_all(out.as_bytes()).await?;
    sock.write_all(&reply.body).await?;
    sock.shutdown().await
}

/// Answers each name from a list of answers, one per lookup; the last
/// answer repeats. Counts lookups.
#[derive(Clone, Default)]
pub struct Table {
    answers: Arc<Mutex<HashMap<String, Vec<Vec<IpAddr>>>>>,
    pub lookups: Arc<Mutex<Vec<String>>>,
}

impl Table {
    pub fn with(self, name: &str, answers: &[&[&str]]) -> Table {
        let answers = answers
            .iter()
            .map(|a| a.iter().map(|ip| ip.parse().unwrap()).collect())
            .collect();
        self.answers
            .lock()
            .unwrap()
            .insert(name.to_string(), answers);
        self
    }

    pub fn lookups(&self) -> Vec<String> {
        self.lookups.lock().unwrap().clone()
    }
}

impl ssrf_guard::Resolve for Table {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        self.lookups.lock().unwrap().push(host.to_string());
        let mut answers = self.answers.lock().unwrap();
        let found = match answers.get_mut(host) {
            Some(list) if list.len() > 1 => Ok(list.remove(0)),
            Some(list) => Ok(list[0].clone()),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{host} is not in the table"),
            )),
        };
        let found = found.map(|ips| {
            ips.into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect()
        });
        Box::pin(async move { found })
    }
}

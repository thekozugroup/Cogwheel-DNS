//! A scripted HTTP server on loopback, for the client and settings tests: it answers each
//! connection with the next canned reply and records what it was sent. Plain `std::net`, one
//! thread, `Connection: close` on every reply so reqwest never reuses a socket across replies.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

/// One canned answer.
#[derive(Debug, Clone)]
pub struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
    /// Accept the connection and say nothing for this long (a hung upstream).
    silent: Option<Duration>,
}

impl Reply {
    /// A JSON reply.
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: body.into(),
            silent: None,
        }
    }

    /// The same, with one more header.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// A connection that is accepted and never answered within `wait`.
    pub fn silent(wait: Duration) -> Self {
        Self {
            silent: Some(wait),
            ..Self::json(200, "")
        }
    }
}

/// What one request carried.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    /// Path and query.
    pub target: String,
    /// Header names lowercased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Recorded {
    /// The first header of this (lowercase) name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// A listener that serves `replies` in order, one per connection, then stops accepting.
pub struct Stub {
    pub base: Url,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

impl Stub {
    pub fn serve(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback stub");
        let port = listener.local_addr().expect("the stub's address").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        std::thread::spawn(move || {
            for reply in replies {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                answer(stream, &reply, &recorded);
            }
        });
        Self {
            base: format!("http://127.0.0.1:{port}")
                .parse()
                .expect("a loopback url"),
            requests,
        }
    }

    /// Everything received so far, in order.
    pub fn requests(&self) -> Vec<Recorded> {
        self.requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

fn answer(stream: TcpStream, reply: &Reply, recorded: &Mutex<Vec<Recorded>>) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    recorded
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(Recorded {
            method,
            target,
            headers,
            body,
        });

    let mut stream = reader.into_inner();
    if let Some(wait) = reply.silent {
        std::thread::sleep(wait);
        return;
    }
    let mut head = format!(
        "HTTP/1.1 {} Stub\r\nContent-Length: {}\r\nConnection: close\r\n",
        reply.status,
        reply.body.len()
    );
    for (name, value) in &reply.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(reply.body.as_bytes());
    let _ = stream.flush();
}

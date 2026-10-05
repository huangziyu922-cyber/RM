use reqwest::{Method, blocking::Client};
use rm_client_sync::exchange;
use serde_json::json;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::time::Duration;

#[test]
fn sends_http_authorization_and_preserves_error_status() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut headers = String::new();
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            if line == "\r\n" {
                break;
            }
            headers.push_str(&line);
        }
        assert!(headers.starts_with("GET /texts HTTP/1.1\r\n"));
        assert!(
            headers
                .to_lowercase()
                .contains("authorization: bearer sample\r\n")
        );
        stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 7\r\nConnection: close\r\n\r\nexpired").unwrap();
    });
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let result = exchange(&client, &url, Method::GET, "/texts", "sample", None).unwrap();
    assert_eq!(result, (401, json!({"message":"expired"})));
    peer.join().unwrap();
}

#[test]
fn echo_request_puts_the_text_in_a_json_body() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());

        // Request line and headers.
        let mut head = String::new();
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            if line == "\r\n" {
                break;
            }
            head.push_str(&line);
        }

        // Body: exactly Content-Length bytes after the blank line.
        let length: usize = head
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(|value| value.trim().parse().unwrap())
            })
            .expect("Content-Length header");
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).unwrap();

        let payload = r#"{"data":"hello\nworld"}"#;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                    payload.len()
                )
                .as_bytes(),
            )
            .unwrap();
        (head, String::from_utf8(body).unwrap())
    });

    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let body = json!({"text": "hello\nworld"});
    let result = exchange(&client, &url, Method::POST, "/echo", "", Some(&body)).unwrap();
    let (head, sent_body) = peer.join().unwrap();

    let head = head.to_lowercase();
    assert!(head.starts_with("post /echo http/1.1\r\n"), "{head}");
    assert!(head.contains("content-type: application/json"), "{head}");
    assert!(!head.contains("authorization:"), "{head}");
    assert_eq!(sent_body, r#"{"text":"hello\nworld"}"#);
    assert_eq!(result, (200, json!({"data": "hello\nworld"})));
}

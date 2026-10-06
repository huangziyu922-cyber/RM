use reqwest::{Method, blocking::Client};
use rm_client_sync::{NetworkError, exchange};
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

/// Accept one connection, read the request head and body, and answer with
/// `status`. Returns the head plus the raw body the client actually sent.
fn send(status: &str, payload: &str) -> (std::thread::JoinHandle<(String, String)>, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    let response = format!("{head}{payload}");
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut head = String::new();
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            if line == "\r\n" {
                break;
            }
            head.push_str(&line);
        }
        let length: usize = head
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(|value| value.trim().parse().unwrap())
            })
            .unwrap_or(0);
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).unwrap();
        stream.write_all(response.as_bytes()).unwrap();
        (head, String::from_utf8(body).unwrap())
    });
    (peer, url)
}

#[test]
fn delete_sends_the_token_and_no_body() {
    let (peer, url) = send("401 Unauthorized", "expired");
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let result = exchange(&client, &url, Method::DELETE, "/texts/note", "sample", None).unwrap();
    let (head, sent_body) = peer.join().unwrap();

    let head = head.to_lowercase();
    assert!(
        head.starts_with("delete /texts/note http/1.1\r\n"),
        "{head}"
    );
    assert!(head.contains("authorization: bearer sample\r\n"), "{head}");
    // DELETE must not carry a request body, so there is nothing to decode.
    assert_eq!(sent_body, "");
    assert_eq!(result, (401, json!({"message": "expired"})));
}

#[test]
fn a_refused_connection_is_reported_as_unreachable() {
    // A port that was just released is free, so nothing is listening there.
    let address = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap()
    };
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();

    let error = exchange(
        &client,
        &format!("http://{address}"),
        Method::GET,
        "/ping",
        "",
        None,
    )
    .expect_err("nothing is listening, so the request must fail");

    assert_eq!(
        NetworkError::of(&error),
        NetworkError::Unreachable,
        "a refused connection must be told apart from a timeout; raw error: {error}"
    );
}

#[test]
fn a_server_that_never_answers_times_out() {
    // Accept the connection and then stay silent, so the client can only give up
    // because of its own timeout.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let peer = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_secs(4));
        drop(stream);
    });

    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(400))
        .build()
        .unwrap();
    let error = exchange(&client, &url, Method::GET, "/ping", "", None)
        .expect_err("the server never answers, so the request must fail");

    assert_eq!(
        NetworkError::of(&error),
        NetworkError::Timeout,
        "a silent server must classify as a timeout; raw error: {error}"
    );
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

use reqwest::{Method, blocking::Client};
use serde_json::Value;

/// Preserve HTTP status even when the error body is not JSON.
pub fn exchange(
    client: &Client,
    url: &str,
    method: Method,
    path: &str,
    token: &str,
    body: Option<&Value>,
) -> Result<(u16, Value), reqwest::Error> {
    let mut request = client.request(method, format!("{}{path}", url.trim_end_matches('/')));
    if !token.is_empty() {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(body);
    }
    let response = request.send()?;
    let status = response.status().as_u16();
    let text = response.text()?;
    let value =
        serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({"message": text}));
    Ok((status, value))
}

/// Combine the lines typed by the user into one text block.
///
/// A line containing only `.` ends the input and is not part of the text.
/// A line containing only `..` is unescaped into a single `.` line, so that
/// empty text, a trailing newline and a body line equal to the end marker can
/// all be expressed.
pub fn join_text(lines: &[String]) -> String {
    let mut text: Vec<String> = Vec::new();
    for line in lines {
        if line == "." {
            break;
        }
        if line == ".." {
            text.push(".".to_string());
        } else {
            text.push(line.clone());
        }
    }
    text.join("\n")
}

/// Decide whether the locally stored token survives a response.
///
/// Sending the token is not the same as still holding it: when the server says the
/// identity is no longer valid (401), and when the identity has just been given up
/// on purpose (`logout` or `delete-user` returning 200), the client must forget it.
/// A `login` response is handled separately, because it *replaces* the token rather
/// than keeping or clearing it.
pub fn keep_token(command: &str, status: u16) -> bool {
    status != 401 && !matches!((command, status), ("logout" | "delete-user", 200))
}

#[cfg(test)]
mod tests {
    use super::{join_text, keep_token};

    fn lines(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn the_token_is_forgotten_when_identity_is_lost() {
        // 401 means the token the client holds is no longer good.
        for command in ["ping", "list", "put", "delete", "get", "logout"] {
            assert!(!keep_token(command, 401), "{command} 401 should clear");
        }
        // Giving the identity up on purpose clears it too...
        assert!(!keep_token("logout", 200));
        assert!(!keep_token("delete-user", 200));
        // ...but a failed logout or delete-user means the token is still in use.
        assert!(keep_token("logout", 500));
        assert!(keep_token("delete-user", 500));
    }

    #[test]
    fn successful_requests_keep_the_token() {
        assert!(keep_token("ping", 200));
        assert!(keep_token("put", 200));
        assert!(keep_token("delete", 200));
        assert!(keep_token("get", 404));
    }

    #[test]
    fn empty_text_is_expressible() {
        assert_eq!(join_text(&lines(&["."])), "");
    }

    #[test]
    fn lines_are_joined_with_a_newline() {
        assert_eq!(join_text(&lines(&["hello", "world", "."])), "hello\nworld");
    }

    #[test]
    fn a_trailing_newline_is_expressible() {
        assert_eq!(join_text(&lines(&["hello", "", "."])), "hello\n");
    }

    #[test]
    fn a_body_line_equal_to_the_marker_is_expressible() {
        assert_eq!(join_text(&lines(&["a", "..", "b", "."])), "a\n.\nb");
        assert_eq!(join_text(&lines(&["..", "."])), ".");
    }

    #[test]
    fn unicode_is_preserved() {
        assert_eq!(join_text(&lines(&["你好", "世界", "."])), "你好\n世界");
    }
}

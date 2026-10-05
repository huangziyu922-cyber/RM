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

#[cfg(test)]
mod tests {
    use super::join_text;

    fn lines(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
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

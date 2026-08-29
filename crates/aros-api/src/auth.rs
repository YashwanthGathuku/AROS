//! Small deterministic HTTP authentication helpers for the local daemon.

use axum::http::{header::AUTHORIZATION, HeaderMap};

pub fn bearer_authorized(headers: &HeaderMap, expected_token: &str) -> bool {
    if expected_token.is_empty() {
        return false;
    }
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|token| token == expected_token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn missing_header_is_denied() {
        assert!(!bearer_authorized(&HeaderMap::new(), "secret-token"));
    }

    #[test]
    fn wrong_token_is_denied() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer wrong"));
        assert!(!bearer_authorized(&headers, "secret-token"));
    }

    #[test]
    fn malformed_scheme_is_denied() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic secret-token"),
        );
        assert!(!bearer_authorized(&headers, "secret-token"));
    }

    #[test]
    fn exact_bearer_token_is_allowed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer secret-token"),
        );
        assert!(bearer_authorized(&headers, "secret-token"));
    }

    #[test]
    fn empty_expected_token_can_never_authorize() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer "));
        assert!(!bearer_authorized(&headers, ""));
    }
}

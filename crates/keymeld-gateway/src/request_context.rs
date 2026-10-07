use crate::admission::ClientAddress;
use axum::{
    extract::{MatchedPath, Request, State},
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use std::{fmt, sync::Arc, time::Instant};
use tracing::Instrument;

pub(crate) static REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
pub(crate) static PARENT_REQUEST_ID: HeaderName = HeaderName::from_static("x-parent-request-id");
pub(crate) static SESSION_ID: HeaderName = HeaderName::from_static("x-session-id");

/// Longest value written to a request line.
const MAX_VALUE_CHARS: usize = 200;

/// Gives each request an id and writes one `http` line once it is answered.
/// Every event logged while handling the request carries the id through the
/// request span.
pub(crate) async fn request_context(
    State(client_address): State<Arc<ClientAddress>>,
    request: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let peer = ClientAddress::peer(&request);
    // Only a trusted proxy may name the request; anyone else gets a fresh id.
    let rid = peer
        .filter(|peer| client_address.is_trusted_proxy(*peer))
        .and_then(|_| header(&request, &REQUEST_ID))
        .filter(|rid| valid_request_id(rid))
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
    let prid = header(&request, &PARENT_REQUEST_ID)
        .filter(|prid| valid_request_id(prid))
        .unwrap_or("-")
        .to_owned();
    let sid = header(&request, &SESSION_ID)
        .filter(|sid| valid_session_id(sid))
        .unwrap_or("-")
        .to_owned();
    // A trusted proxy that omits or garbles the client header is answered by
    // admission where it matters; the line then shows the proxy itself.
    let ip = client_address
        .client_ip(&request)
        .ok()
        .or(peer)
        .map_or_else(|| "-".to_owned(), |ip| ip.to_string());
    let method = request.method().clone();
    // The route template, or the bare path when nothing matched. Never the query.
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| request.uri().path(), MatchedPath::as_str)
        .to_owned();

    let span = tracing::info_span!("request", rid = %rid);
    let mut response = next.run(request).instrument(span).await;

    if let Ok(value) = HeaderValue::from_str(&rid) {
        response.headers_mut().insert(REQUEST_ID.clone(), value);
    }
    if logs_requests_to(&route) {
        let line = RequestLine {
            rid: &rid,
            prid: &prid,
            sid: &sid,
            ip: &ip,
            method: method.as_str(),
            route: &route,
            status: response.status().as_u16(),
            ms: start.elapsed().as_millis(),
        };
        tracing::info!(target: "http", "{line}");
    }
    response
}

/// The contract's request line, written once per answered request.
struct RequestLine<'a> {
    rid: &'a str,
    prid: &'a str,
    sid: &'a str,
    ip: &'a str,
    method: &'a str,
    route: &'a str,
    status: u16,
    ms: u128,
}

impl fmt::Display for RequestLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "http rid={} prid={} sid={} ip={} method={} route={} status={} ms={} user=-",
            self.rid,
            self.prid,
            self.sid,
            self.ip,
            log_value(self.method),
            log_value(self.route),
            self.status,
            self.ms,
        )
    }
}

fn header<'a>(request: &'a Request, name: &HeaderName) -> Option<&'a str> {
    request.headers().get(name)?.to_str().ok()
}

/// `^[0-9A-Za-z-]{8,64}$`, for request ids and parent request ids.
fn valid_request_id(value: &str) -> bool {
    (8..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// `^[A-Za-z0-9_-]{16,32}$`, the browser's per-tab session id.
fn valid_session_id(value: &str) -> bool {
    (16..=32).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Health checks, metrics scrapes, static assets and the operator dashboard's
/// once-a-second fragment polling would drown out visitor requests.
fn logs_requests_to(route: &str) -> bool {
    !(route.starts_with("/api/v1/health")
        || route == "/api/v1/metrics"
        || route.starts_with("/api/v1/metrics/")
        || route.starts_with("/static/")
        || route.starts_with("/fragments/"))
}

/// Strips control characters, keeps at most 200 characters, and quotes values
/// holding a space, `"` or `=`.
fn log_value(raw: &str) -> String {
    let value: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_VALUE_CHARS)
        .collect();
    if !value.contains([' ', '"', '=']) {
        return value;
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for c in value.chars() {
        if c == '"' || c == '\\' {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_and_session_ids_follow_the_contract() {
        assert!(valid_request_id("0192f0c4-7a3e-7c1d-9b5e-3f2a1c4d5e6f"));
        assert!(valid_request_id("abcd1234"));
        assert!(!valid_request_id("abc123"));
        assert!(!valid_request_id(&"a".repeat(65)));
        assert!(!valid_request_id("abcd 1234"));
        assert!(!valid_request_id("abcd_1234"));
        assert!(valid_session_id("Zx_9-abcdefghijkl"));
        assert!(!valid_session_id("short"));
        assert!(!valid_session_id(&"a".repeat(33)));
        assert!(!valid_session_id("abcdefghijklmnop=="));
    }

    #[test]
    fn request_line_matches_the_contract() {
        let line = RequestLine {
            rid: "0192f0c4-7a3e-7c1d-9b5e-3f2a1c4d5e6f",
            prid: "-",
            sid: "Zx_9-abcdefghijkl",
            ip: "192.0.2.7",
            method: "GET",
            route: "/api/v1/enclaves/{enclave_id}/public-key",
            status: 200,
            ms: 37,
        };
        assert_eq!(
            line.to_string(),
            "http rid=0192f0c4-7a3e-7c1d-9b5e-3f2a1c4d5e6f prid=- sid=Zx_9-abcdefghijkl ip=192.0.2.7 method=GET route=/api/v1/enclaves/{enclave_id}/public-key status=200 ms=37 user=-"
        );
    }

    #[test]
    fn noisy_routes_are_not_logged() {
        for route in [
            "/api/v1/health",
            "/api/v1/health/detail",
            "/api/v1/metrics",
            "/static/app.min.js",
            "/fragments/stats",
        ] {
            assert!(!logs_requests_to(route), "{route}");
        }
        for route in [
            "/api/v1/confidential",
            "/api/v1/enclaves/{enclave_id}/public-key",
            "/",
            "/sessions",
        ] {
            assert!(logs_requests_to(route), "{route}");
        }
    }

    #[test]
    fn log_values_are_quoted_stripped_and_truncated() {
        assert_eq!(log_value("/api/v1/version"), "/api/v1/version");
        assert_eq!(log_value("/a=b"), r#""/a=b""#);
        assert_eq!(log_value(r#"/a"b\c d"#), r#""/a\"b\\c d""#);
        assert_eq!(log_value("/a\u{7}\nb"), "/ab");
        assert_eq!(log_value(&"x".repeat(300)).len(), MAX_VALUE_CHARS);
    }
}

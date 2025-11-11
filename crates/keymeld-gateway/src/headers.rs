use axum_extra::headers::{Header, HeaderName, HeaderValue};
use std::fmt;

/// For session-based authentication using session secrets
/// Custom header for session HMAC authentication
/// Format: "nonce:hmac"
/// Where HMAC is computed using the session secret
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHmac(pub String);

impl SessionHmac {
    pub fn value(&self) -> &str {
        &self.0
    }
}

impl Header for SessionHmac {
    fn name() -> &'static HeaderName {
        &SESSION_HMAC_HEADER
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, axum_extra::headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = values
            .next()
            .ok_or_else(axum_extra::headers::Error::invalid)?;
        let s = value
            .to_str()
            .map_err(|_| axum_extra::headers::Error::invalid())?;
        Ok(SessionHmac(s.to_string()))
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        if let Ok(value) = HeaderValue::from_str(&self.0) {
            values.extend(std::iter::once(value));
        }
    }
}

impl fmt::Display for SessionHmac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// For user-based authentication using user private keys (signing operations)
/// Custom header for user HMAC authentication (signing operations)
/// Format: "user_id:nonce:signature"
/// Where signature is created with the user's private key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningHmac(pub String);

impl SigningHmac {
    pub fn value(&self) -> &str {
        &self.0
    }
}

impl Header for SigningHmac {
    fn name() -> &'static HeaderName {
        &SIGNING_HMAC_HEADER
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, axum_extra::headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = values
            .next()
            .ok_or_else(axum_extra::headers::Error::invalid)?;
        let s = value
            .to_str()
            .map_err(|_| axum_extra::headers::Error::invalid())?;
        Ok(SigningHmac(s.to_string()))
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        if let Ok(value) = HeaderValue::from_str(&self.0) {
            values.extend(std::iter::once(value));
        }
    }
}

impl fmt::Display for SigningHmac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

static SESSION_HMAC_HEADER: HeaderName = HeaderName::from_static("x-session-hmac");
static SIGNING_HMAC_HEADER: HeaderName = HeaderName::from_static("x-signing-hmac");

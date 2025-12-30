use axum_extra::headers::{Header, HeaderName, HeaderValue};
use std::fmt;

/// For session-based authentication using seed-derived key pairs
/// Custom header for session signature authentication
/// Format: "nonce:signature"
/// Where signature is ECDSA signature of "session_id:nonce" using seed-derived private key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSignature(pub String);

impl SessionSignature {
    pub fn value(&self) -> &str {
        &self.0
    }
}

impl Header for SessionSignature {
    fn name() -> &'static HeaderName {
        &SESSION_SIGNATURE_HEADER
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, axum_extra::headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = values
            .next()
            .ok_or_else(axum_extra::headers::Error::invalid)?;
        let signature_str = value
            .to_str()
            .map_err(|_| axum_extra::headers::Error::invalid())?;

        Ok(SessionSignature(signature_str.to_string()))
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        if let Ok(value) = HeaderValue::from_str(&self.0) {
            values.extend(std::iter::once(value));
        }
    }
}

impl fmt::Display for SessionSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// For user-based authentication using user private keys (signing operations)
/// Custom header for user signature authentication (signing operations)
/// Format: "nonce:signature"
/// Where signature is ECDSA signature over SHA256("signing_session_id:user_id:nonce") created with the user's private key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSignature(pub String);

impl UserSignature {
    pub fn value(&self) -> &str {
        &self.0
    }
}

impl Header for UserSignature {
    fn name() -> &'static HeaderName {
        &USER_SIGNATURE_HEADER
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
        Ok(UserSignature(s.to_string()))
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        if let Ok(value) = HeaderValue::from_str(&self.0) {
            values.extend(std::iter::once(value));
        }
    }
}

impl fmt::Display for UserSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

static SESSION_SIGNATURE_HEADER: HeaderName = HeaderName::from_static("x-session-signature");
static USER_SIGNATURE_HEADER: HeaderName = HeaderName::from_static("x-user-signature");

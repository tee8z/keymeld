use axum_extra::headers::{Header, HeaderName, HeaderValue};
use std::fmt;

/// For session-based authentication using session secrets
/// Custom header for session HMAC authentication
/// Format: "user_id:nonce:hmac"
/// Where HMAC is computed using the session secret
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHmac(pub String);

impl SessionHmac {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn value(&self) -> &str {
        &self.0
    }

    pub fn parse_parts(&self) -> Result<(String, String, String), SessionHmacError> {
        let parts: Vec<&str> = self.0.split(':').collect();
        if parts.len() != 3 {
            return Err(SessionHmacError::InvalidFormat);
        }
        Ok((
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].to_string(),
        ))
    }

    pub fn user_id(&self) -> Result<String, SessionHmacError> {
        let (user_id, _, _) = self.parse_parts()?;
        Ok(user_id)
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
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn value(&self) -> &str {
        &self.0
    }

    pub fn parse_parts(&self) -> Result<(String, String, String), SigningHmacError> {
        let parts: Vec<&str> = self.0.split(':').collect();
        if parts.len() != 3 {
            return Err(SigningHmacError::InvalidFormat);
        }
        Ok((
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].to_string(),
        ))
    }

    pub fn user_id(&self) -> Result<String, SigningHmacError> {
        let (user_id, _, _) = self.parse_parts()?;
        Ok(user_id)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionHmacError {
    InvalidFormat,
}

impl fmt::Display for SessionHmacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionHmacError::InvalidFormat => {
                write!(
                    f,
                    "Invalid session HMAC format, expected 'user_id:nonce:hmac'"
                )
            }
        }
    }
}

impl std::error::Error for SessionHmacError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningHmacError {
    InvalidFormat,
}

impl fmt::Display for SigningHmacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigningHmacError::InvalidFormat => {
                write!(
                    f,
                    "Invalid signing HMAC format, expected 'user_id:nonce:signature'"
                )
            }
        }
    }
}

impl std::error::Error for SigningHmacError {}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_extra::headers::Header;

    #[test]
    fn test_session_hmac_parsing() {
        let hmac = SessionHmac::new("user123:nonce456:hmac789");
        let (user_id, nonce, hmac_val) = hmac.parse_parts().unwrap();

        assert_eq!(user_id, "user123");
        assert_eq!(nonce, "nonce456");
        assert_eq!(hmac_val, "hmac789");
        assert_eq!(hmac.user_id().unwrap(), "user123");
    }

    #[test]
    fn test_session_hmac_invalid_format() {
        let hmac = SessionHmac::new("invalid:format");
        assert!(matches!(
            hmac.parse_parts(),
            Err(SessionHmacError::InvalidFormat)
        ));
    }

    #[test]
    fn test_signing_hmac_parsing() {
        let hmac = SigningHmac::new("user789:nonce111:signature222");
        let (user_id, nonce, signature_val) = hmac.parse_parts().unwrap();

        assert_eq!(user_id, "user789");
        assert_eq!(nonce, "nonce111");
        assert_eq!(signature_val, "signature222");
        assert_eq!(hmac.user_id().unwrap(), "user789");
    }

    #[test]
    fn test_header_names() {
        assert_eq!(SessionHmac::name().as_str(), "x-session-hmac");
        assert_eq!(SigningHmac::name().as_str(), "x-signing-hmac");
    }
}

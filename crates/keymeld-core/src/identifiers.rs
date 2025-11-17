#[cfg(feature = "enclave")]
extern crate alloc;

#[cfg(feature = "enclave")]
use alloc::string::ToString;

#[cfg(not(feature = "enclave"))]
use std::string::ToString;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use concurrent_map::Minimum;

#[cfg(feature = "enclave")]
use alloc::{fmt, string::String, vec::Vec};

#[cfg(not(feature = "enclave"))]
use std::{fmt, string::String, vec::Vec};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
    Default,
)]
pub struct EnclaveId(u32);

impl EnclaveId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl From<u32> for EnclaveId {
    fn from(id: u32) -> Self {
        Self(id)
    }
}

impl fmt::Display for EnclaveId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "enclave-{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct UserId(#[serde(with = "uuid_serde")] Uuid);

mod uuid_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use uuid::Uuid;

    pub fn serialize<S>(uuid: &Uuid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        uuid.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Uuid::parse_str(&s).map_err(serde::de::Error::custom)
    }
}

impl UserId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(Uuid::parse_str(&id.into()).unwrap_or_else(|_| Uuid::now_v7()))
    }

    pub fn parse(id: impl AsRef<str>) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(id.as_ref())?))
    }

    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn as_string(&self) -> String {
        self.0.to_string()
    }

    pub fn as_str(&self) -> String {
        self.0.to_string()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn uuid(&self) -> Uuid {
        self.0
    }
}

impl TryFrom<String> for UserId {
    type Error = uuid::Error;

    fn try_from(id: String) -> Result<Self, Self::Error> {
        Self::parse(id)
    }
}

impl TryFrom<&str> for UserId {
    type Error = uuid::Error;

    fn try_from(id: &str) -> Result<Self, Self::Error> {
        Self::parse(id)
    }
}

impl From<Uuid> for UserId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "sqlx")]
impl sqlx::Type<sqlx::Sqlite> for UserId {
    fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
        <Vec<u8> as sqlx::Type<sqlx::Sqlite>>::type_info()
    }
}

#[cfg(feature = "sqlx")]
impl sqlx::Encode<'_, sqlx::Sqlite> for UserId {
    fn encode_by_ref(
        &self,
        args: &mut Vec<sqlx::sqlite::SqliteArgumentValue<'_>>,
    ) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Send + Sync>> {
        let bytes = self.0.as_bytes().to_vec();
        <Vec<u8> as sqlx::Encode<sqlx::Sqlite>>::encode_by_ref(&bytes, args)
    }
}

#[cfg(feature = "sqlx")]
impl sqlx::Decode<'_, sqlx::Sqlite> for UserId {
    fn decode(value: sqlx::sqlite::SqliteValueRef<'_>) -> Result<Self, sqlx::error::BoxDynError> {
        let bytes = <Vec<u8> as sqlx::Decode<sqlx::Sqlite>>::decode(value)?;
        let uuid = Uuid::from_slice(&bytes)?;
        Ok(UserId(uuid))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct SessionId(#[serde(with = "uuid_serde")] Uuid);

impl SessionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(Uuid::parse_str(&id.into()).unwrap_or_else(|_| Uuid::now_v7()))
    }

    pub fn parse(id: impl AsRef<str>) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(id.as_ref())?))
    }

    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn as_string(&self) -> String {
        self.0.to_string()
    }

    pub fn uuid(&self) -> Uuid {
        self.0
    }
}

impl TryFrom<String> for SessionId {
    type Error = uuid::Error;

    fn try_from(id: String) -> Result<Self, Self::Error> {
        Self::parse(id)
    }
}

impl TryFrom<&str> for SessionId {
    type Error = uuid::Error;

    fn try_from(id: &str) -> Result<Self, Self::Error> {
        Self::parse(id)
    }
}

impl From<Uuid> for SessionId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "sqlx")]
impl sqlx::Type<sqlx::Sqlite> for SessionId {
    fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
        <Vec<u8> as sqlx::Type<sqlx::Sqlite>>::type_info()
    }
}

#[cfg(feature = "sqlx")]
impl sqlx::Encode<'_, sqlx::Sqlite> for SessionId {
    fn encode_by_ref(
        &self,
        args: &mut Vec<sqlx::sqlite::SqliteArgumentValue<'_>>,
    ) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Send + Sync>> {
        let bytes = self.0.as_bytes().to_vec();
        <Vec<u8> as sqlx::Encode<sqlx::Sqlite>>::encode_by_ref(&bytes, args)
    }
}

#[cfg(feature = "sqlx")]
impl sqlx::Decode<'_, sqlx::Sqlite> for SessionId {
    fn decode(value: sqlx::sqlite::SqliteValueRef<'_>) -> Result<Self, sqlx::error::BoxDynError> {
        let bytes = <Vec<u8> as sqlx::Decode<sqlx::Sqlite>>::decode(value)?;
        let uuid = Uuid::from_slice(&bytes)?;
        Ok(SessionId(uuid))
    }
}

impl Minimum for SessionId {
    const MIN: Self = SessionId(Uuid::nil());
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct CorrelationId(#[serde(with = "uuid_serde")] Uuid);

impl CorrelationId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn parse(id: impl AsRef<str>) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(id.as_ref())?))
    }

    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn as_string(&self) -> String {
        self.0.to_string()
    }

    pub fn inner(&self) -> &Uuid {
        &self.0
    }
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<String> for CorrelationId {
    type Error = uuid::Error;

    fn try_from(id: String) -> Result<Self, Self::Error> {
        Self::parse(id)
    }
}

impl TryFrom<&str> for CorrelationId {
    type Error = uuid::Error;

    fn try_from(id: &str) -> Result<Self, Self::Error> {
        Self::parse(id)
    }
}

impl From<Uuid> for CorrelationId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "sqlx")]
impl sqlx::Type<sqlx::Sqlite> for CorrelationId {
    fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
        <Vec<u8> as sqlx::Type<sqlx::Sqlite>>::type_info()
    }
}

#[cfg(feature = "sqlx")]
impl sqlx::Encode<'_, sqlx::Sqlite> for CorrelationId {
    fn encode_by_ref(
        &self,
        args: &mut Vec<sqlx::sqlite::SqliteArgumentValue<'_>>,
    ) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Send + Sync>> {
        let bytes = self.0.as_bytes().to_vec();
        <Vec<u8> as sqlx::Encode<sqlx::Sqlite>>::encode_by_ref(&bytes, args)
    }
}

#[cfg(feature = "sqlx")]
impl sqlx::Decode<'_, sqlx::Sqlite> for CorrelationId {
    fn decode(value: sqlx::sqlite::SqliteValueRef<'_>) -> Result<Self, sqlx::error::BoxDynError> {
        let bytes = <Vec<u8> as sqlx::Decode<sqlx::Sqlite>>::decode(value)?;
        let uuid = Uuid::from_slice(&bytes)?;
        Ok(CorrelationId(uuid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "enclave")]
    use alloc::format;
    #[cfg(not(feature = "enclave"))]
    use std::format;

    #[test]
    fn test_enclave_id() {
        let coordinator_enclave = EnclaveId::from(0);
        assert_eq!(format!("{coordinator_enclave}"), "enclave-0");

        let user_enclave = EnclaveId::from(1);
        assert_eq!(format!("{user_enclave}"), "enclave-1");
    }

    #[test]
    fn test_user_id() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let user_id = UserId::try_from(uuid_str).expect("Valid UUID");
        assert_eq!(user_id.as_str(), uuid_str);
        assert_eq!(format!("{user_id}"), uuid_str);

        let invalid_uuid = "not-a-valid-uuid";
        assert!(UserId::try_from(invalid_uuid).is_err());
        assert!(UserId::parse(invalid_uuid).is_err());
    }

    #[test]
    fn test_session_id() {
        let session_id = SessionId::new("cbfacaae-9bdf-48c8-801e-2c7bb5197b7e");
        assert_eq!(
            session_id.as_string(),
            "cbfacaae-9bdf-48c8-801e-2c7bb5197b7e"
        );
        assert_eq!(
            format!("{session_id}"),
            "cbfacaae-9bdf-48c8-801e-2c7bb5197b7e"
        );

        let valid_uuid = "cbfacaae-9bdf-48c8-801e-2c7bb5197b7e";
        let session_id_try = SessionId::try_from(valid_uuid).expect("Valid UUID");
        assert_eq!(session_id_try.as_string(), valid_uuid);

        let invalid_uuid = "not-a-valid-uuid";
        assert!(SessionId::try_from(invalid_uuid).is_err());
        assert!(SessionId::parse(invalid_uuid).is_err());
    }

    #[test]
    fn test_correlation_id() {
        let correlation_id = CorrelationId::new();
        assert!(!correlation_id.as_string().is_empty());

        let valid_uuid = "550e8400-e29b-41d4-a716-446655440000";
        let correlation_id_try = CorrelationId::try_from(valid_uuid).expect("Valid UUID");
        assert_eq!(correlation_id_try.as_string(), valid_uuid);

        let invalid_uuid = "not-a-valid-uuid";
        assert!(CorrelationId::try_from(invalid_uuid).is_err());
        assert!(CorrelationId::parse(invalid_uuid).is_err());
    }
}

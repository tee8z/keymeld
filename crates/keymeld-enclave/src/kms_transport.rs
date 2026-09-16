//! KMS endpoints and TLS roots are enclave policy, never gateway-selected trust.
use anyhow::{bail, ensure, Result};
use aws_sdk_kms::{config::Region, Client};
use aws_smithy_http_client::{
    tls::{rustls_provider::CryptoMode, Provider, TlsContext, TrustStore},
    Builder as HttpClientBuilder,
};

const AWS_ROOTS: [&[u8]; 4] = [
    include_bytes!("kms_roots/AmazonRootCA1.pem"),
    include_bytes!("kms_roots/AmazonRootCA2.pem"),
    include_bytes!("kms_roots/AmazonRootCA3.pem"),
    include_bytes!("kms_roots/AmazonRootCA4.pem"),
];

#[derive(Debug, Clone)]
pub struct KmsTarget {
    endpoint: String,
    key_id: String,
    region: Option<String>,
    development: bool,
}

impl KmsTarget {
    pub fn validate(
        endpoint: &str,
        key_id: &str,
        region: Option<&str>,
        development: bool,
    ) -> Result<Self> {
        ensure!(!key_id.is_empty(), "KMS key identifier must not be empty");
        if development {
            // This is selected by enclave-local configuration, never by a command.
            ensure!(
                endpoint.starts_with("http://")
                    || endpoint.starts_with("https://")
                    || endpoint == "aws-kms",
                "Invalid development KMS endpoint"
            );
            return Ok(Self {
                endpoint: endpoint.into(),
                key_id: key_id.into(),
                region: region.map(str::to_owned),
                development,
            });
        }

        // Aliases can be retargeted by the account operator. Pin the immutable key
        // ARN before building the EIF so a different key policy cannot be selected.
        let parts: Vec<_> = key_id.split(':').collect();
        ensure!(
            parts.len() == 6 && parts[0] == "arn" && parts[2] == "kms",
            "Attested KMS requires a full key ARN"
        );
        let suffix = match parts[1] {
            "aws" | "aws-us-gov" => "amazonaws.com",
            "aws-cn" => "amazonaws.com.cn",
            _ => bail!("Unsupported AWS KMS partition"),
        };
        let arn_region = parts[3];
        ensure!(
            !arn_region.is_empty()
                && arn_region
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "Invalid KMS ARN region"
        );
        ensure!(
            parts[4].len() == 12 && parts[4].bytes().all(|b| b.is_ascii_digit()),
            "Invalid KMS ARN account"
        );
        let id = parts[5]
            .strip_prefix("key/")
            .ok_or_else(|| anyhow::anyhow!("KMS aliases are not accepted in attested mode"))?;
        let valid_id = uuid::Uuid::parse_str(id).is_ok()
            || id
                .strip_prefix("mrk-")
                .is_some_and(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit()));
        ensure!(valid_id, "Invalid KMS key identifier");
        if let Some(region) = region {
            ensure!(
                region == arn_region,
                "Enclave AWS region differs from the pinned KMS key"
            );
        }
        let expected = format!("https://kms.{arn_region}.{suffix}");
        ensure!(
            endpoint == "aws-kms" || endpoint == expected || endpoint == format!("{expected}/"),
            "Attested KMS requires the pinned regional AWS HTTPS endpoint"
        );
        Ok(Self {
            endpoint: expected,
            key_id: key_id.into(),
            region: Some(arn_region.into()),
            development: false,
        })
    }

    pub async fn client(&self) -> Result<Client> {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = &self.region {
            loader = loader.region(Region::new(region.clone()));
        }
        let shared = loader.load().await;
        let client = self.configure_client(aws_sdk_kms::config::Builder::from(&shared))?;
        if !self.development {
            let response = client.describe_key().key_id(&self.key_id).send().await?;
            let metadata = response
                .key_metadata()
                .ok_or_else(|| anyhow::anyhow!("KMS omitted key metadata"))?;
            self.validate_key_metadata(metadata)?;
        }
        Ok(client)
    }

    fn validate_key_metadata(&self, metadata: &aws_sdk_kms::types::KeyMetadata) -> Result<()> {
        use aws_sdk_kms::types::{KeySpec, KeyState, KeyUsageType, OriginType};
        ensure!(
            metadata.arn() == Some(self.key_id.as_str()),
            "KMS returned a different key ARN"
        );
        ensure!(
            metadata.enabled() && metadata.key_state() == Some(&KeyState::Enabled),
            "KMS key must be enabled"
        );
        ensure!(
            metadata.key_usage() == Some(&KeyUsageType::EncryptDecrypt)
                && metadata.key_spec() == Some(&KeySpec::SymmetricDefault),
            "KMS key must support symmetric encryption"
        );
        // An imported master key may already be known outside AWS. A multi-Region
        // replica can decrypt the same hierarchy under an independent key policy.
        ensure!(
            metadata.origin() == Some(&OriginType::AwsKms),
            "KMS key material must be generated by AWS KMS"
        );
        ensure!(
            metadata.multi_region() == Some(false),
            "Multi-Region KMS keys are not supported"
        );
        Ok(())
    }

    fn configure_client(&self, mut config: aws_sdk_kms::config::Builder) -> Result<Client> {
        if self.endpoint != "aws-kms" {
            // Set the service override explicitly, overriding ambient AWS endpoint
            // variables and profile configuration as well as the gateway request.
            config = config.endpoint_url(&self.endpoint);
        }
        if !self.development {
            let roots = AWS_ROOTS.iter().fold(TrustStore::empty(), |store, pem| {
                store.with_pem_certificate(pem.to_vec())
            });
            let tls = TlsContext::builder().with_trust_store(roots).build()?;
            let http = HttpClientBuilder::new()
                .tls_provider(Provider::Rustls(CryptoMode::AwsLc))
                .tls_context(tls)
                .build_https();
            config = config.http_client(http);
        }
        Ok(Client::from_conf(config.build()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &str = "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789abc";

    #[test]
    fn rejects_gateway_kms_redirection_and_mutable_keys() {
        for endpoint in [
            "http://kms.us-west-2.amazonaws.com",
            "https://kms.us-east-1.amazonaws.com",
            "https://attacker.test",
            "https://kms.us-west-2.amazonaws.com.attacker.test",
            "https://kms.us-west-2.amazonaws.com@attacker.test",
            "https://kms.us-west-2.amazonaws.com:444",
            "https://kms.us-west-2.amazonaws.com/?endpoint=attacker",
        ] {
            assert!(
                KmsTarget::validate(endpoint, KEY, Some("us-west-2"), false).is_err(),
                "accepted {endpoint}"
            );
        }
        for key in [
            "alias/keymeld",
            "12345678-1234-1234-1234-123456789abc",
            "arn:aws:kms:us-west-2:123456789012:alias/keymeld",
        ] {
            assert!(KmsTarget::validate("aws-kms", key, None, false).is_err());
        }
        assert!(KmsTarget::validate("aws-kms", KEY, Some("us-east-1"), false).is_err());
        let target = KmsTarget::validate("aws-kms", KEY, Some("us-west-2"), false).unwrap();
        assert_eq!(target.endpoint, "https://kms.us-west-2.amazonaws.com");
        assert!(!target.development);
        assert!(
            KmsTarget::validate("http://127.0.0.1:4566", "alias/test", None, true)
                .unwrap()
                .development
        );
    }

    #[test]
    fn bundled_aws_tls_roots_match_reviewed_certificates() {
        let expected = [
            "8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e",
            "1ba5b2aa8c65401a82960118f80bec4f62304d83cec4713a19c39c011ea46db4",
            "18ce6cfe7bf14e60b2e347b8dfe868cb31d02ebb3ada271569f50343b46db3a4",
            "e35d28419ed02025cfa69038cd623962458da5c695fbdea3c22b0bfb25897092",
        ];
        for (pem, fingerprint) in AWS_ROOTS.iter().zip(expected) {
            let cert = openssl::x509::X509::from_pem(pem).unwrap();
            assert_eq!(
                hex::encode(cert.digest(openssl::hash::MessageDigest::sha256()).unwrap()),
                fingerprint
            );
        }
    }

    #[test]
    fn rejects_imported_replicated_or_incomplete_kms_key_metadata() {
        use aws_sdk_kms::types::{KeyMetadata, KeySpec, KeyState, KeyUsageType, OriginType};
        let target = KmsTarget::validate("aws-kms", KEY, None, false).unwrap();
        let valid = KeyMetadata::builder()
            .key_id("12345678-1234-1234-1234-123456789abc")
            .arn(KEY)
            .enabled(true)
            .key_state(KeyState::Enabled)
            .key_usage(KeyUsageType::EncryptDecrypt)
            .key_spec(KeySpec::SymmetricDefault)
            .origin(OriginType::AwsKms)
            .multi_region(false);
        assert!(target
            .validate_key_metadata(&valid.clone().build().unwrap())
            .is_ok());
        for invalid in [
            valid.clone().origin(OriginType::External),
            valid.clone().origin(OriginType::ExternalKeyStore),
            valid.clone().origin(OriginType::AwsCloudhsm),
            valid.clone().multi_region(true),
            valid.clone().set_multi_region(None),
            valid.clone().set_origin(None),
            valid.clone().key_state(KeyState::Disabled),
            valid.clone().enabled(false),
            valid.clone().key_usage(KeyUsageType::SignVerify),
            valid.clone().key_spec(KeySpec::Rsa2048),
            valid
                .arn("arn:aws:kms:us-west-2:123456789012:key/aaaaaaaa-1234-1234-1234-123456789abc"),
        ] {
            assert!(target
                .validate_key_metadata(&invalid.build().unwrap())
                .is_err());
        }
    }

    #[tokio::test]
    async fn foreign_kms_tls_certificate_is_rejected_before_http() {
        use openssl::{
            asn1::Asn1Time,
            hash::MessageDigest,
            pkey::PKey,
            rsa::Rsa,
            ssl::{SslAcceptor, SslMethod},
            x509::{extension::SubjectAlternativeName, X509NameBuilder, X509},
        };
        use std::{net::TcpListener, time::Duration};

        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "foreign KMS fixture")
            .unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        let san = SubjectAlternativeName::new()
            .ip("127.0.0.1")
            .build(&cert.x509v3_context(None, None))
            .unwrap();
        cert.append_extension(san).unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.set_certificate(&cert.build()).unwrap();
        let acceptor = acceptor.build();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::task::spawn_blocking(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "No TLS connection attempted"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("TLS fixture accept failed: {e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            // The client must reject the foreign issuer during TLS, before any
            // signed KMS request or attacker-selected DEK can cross this boundary.
            assert!(
                acceptor.accept(stream).is_err(),
                "Foreign TLS certificate accepted"
            );
        });
        // Endpoint validation is tested separately. Bypass it only in this fixture
        // to exercise the actual production TLS client against a local server.
        let target = KmsTarget {
            endpoint: format!("https://{address}"),
            key_id: KEY.into(),
            region: Some("us-west-2".into()),
            development: false,
        };
        let config = aws_sdk_kms::config::Builder::new()
            .behavior_version_latest()
            .region(Region::new("us-west-2"))
            .credentials_provider(aws_sdk_kms::config::Credentials::new(
                "test",
                "test",
                None,
                None,
                "tls-fixture",
            ))
            .retry_config(aws_sdk_kms::config::retry::RetryConfig::disabled());
        let client = target.configure_client(config).unwrap();
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            client
                .generate_data_key()
                .key_id(KEY)
                .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
                .send(),
        )
        .await
        .expect("KMS TLS rejection timed out");
        assert!(response.is_err(), "Foreign KMS response accepted");
        server.await.unwrap();
    }
}

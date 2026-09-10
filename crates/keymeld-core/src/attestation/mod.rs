//! Verify the original Nitro COSE document before trusting any enclave key.
//!
//! Trust anchor: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
//! AWS Nitro Root G1 SHA-256: 641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b.
//! The root is bundled, never selected by a gateway or by the presented document.

use std::{collections::BTreeMap, time::Duration};

use coset::{iana, CborSerializable, CoseSign1, TaggedCborSerializable};
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use rustls_pki_types::{
    alg_id, AlgorithmIdentifier, CertificateDer, InvalidSignature, SignatureVerificationAlgorithm,
    UnixTime,
};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use x509_cert::der::Decode;

use crate::KeyMeldError;

const AWS_ROOT: &[u8] = include_bytes!("aws-nitro-root-g1.der");
const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// Measurements obtained from a trusted EIF build or signing certificate.
/// PCR0 pins the image; PCR8 pins its signer. At least one must be pinned.
#[derive(Debug, Clone)]
pub struct AttestationPolicy {
    required_pcrs: BTreeMap<u16, Vec<u8>>,
    max_age_seconds: u64,
}

impl AttestationPolicy {
    pub fn from_hex_measurements(
        measurements: &BTreeMap<String, String>,
    ) -> Result<Self, KeyMeldError> {
        let mut pcrs = BTreeMap::new();
        for (name, value) in measurements {
            let index = name
                .strip_prefix("PCR")
                .unwrap_or(name)
                .parse::<u16>()
                .map_err(|_| invalid("Invalid PCR index"))?;
            let value = hex::decode(value).map_err(|_| invalid("Invalid PCR hex measurement"))?;
            if pcrs.insert(index, value).is_some() {
                return Err(invalid("Duplicate PCR measurement"));
            }
        }
        Self::new(pcrs)
    }

    pub fn new(required_pcrs: BTreeMap<u16, Vec<u8>>) -> Result<Self, KeyMeldError> {
        if !required_pcrs.contains_key(&0) && !required_pcrs.contains_key(&8) {
            return Err(invalid("Pin PCR0 (image) or PCR8 (image signer)"));
        }
        if required_pcrs.iter().any(|(index, value)| {
            *index > 31 || value.len() != 48 || value.iter().all(|byte| *byte == 0)
        }) {
            return Err(invalid("PCR pins must be nonzero SHA-384 measurements"));
        }
        Ok(Self {
            required_pcrs,
            max_age_seconds: 300,
        })
    }

    /// Verify AWS signatures, chain validity, measurements, key and fresh challenge.
    pub fn verify(
        &self,
        document: &[u8],
        expected_public_key: &[u8],
        expected_nonce: &[u8],
        now_seconds: u64,
    ) -> Result<(), KeyMeldError> {
        self.verify_with_root(
            document,
            expected_public_key,
            expected_nonce,
            now_seconds,
            AWS_ROOT,
        )
    }

    fn verify_with_root(
        &self,
        document: &[u8],
        expected_public_key: &[u8],
        expected_nonce: &[u8],
        now_seconds: u64,
        root: &[u8],
    ) -> Result<(), KeyMeldError> {
        if document.is_empty() || document.len() > MAX_DOCUMENT_BYTES || expected_nonce.len() != 32
        {
            return Err(invalid("Missing or invalid attestation document/challenge"));
        }
        let cose = CoseSign1::from_slice(document)
            .or_else(|_| CoseSign1::from_tagged_slice(document))
            .map_err(|_| invalid("Invalid COSE_Sign1 document"))?;
        if cose.protected.header.alg != Some(coset::Algorithm::Assigned(iana::Algorithm::ES384))
            || !cose.protected.header.crit.is_empty()
            || cose.unprotected.alg.is_some()
            || !cose.unprotected.crit.is_empty()
        {
            return Err(invalid(
                "Attestation requires protected ES384 without unsupported critical headers",
            ));
        }
        let payload = cose
            .payload
            .as_ref()
            .ok_or_else(|| invalid("Missing COSE payload"))?;
        let doc: NitroDocument = serde_cbor::from_slice(payload)
            .map_err(|_| invalid("Invalid Nitro attestation payload"))?;
        if doc.module_id.is_empty()
            || doc.digest != "SHA384"
            || doc.certificate.is_empty()
            || doc.certificate.len() > 1024
            || doc.cabundle.is_empty()
            || doc.cabundle.len() > 10
            || doc
                .cabundle
                .iter()
                .any(|cert| cert.is_empty() || cert.len() > 1024)
            || doc.pcrs.is_empty()
            || doc
                .pcrs
                .iter()
                .any(|(index, value)| *index > 31 || value.len() != 48)
        {
            return Err(invalid("Invalid Nitro document fields"));
        }

        // webpki validates signatures, CA constraints, path length and leaf/intermediate dates.
        // Trust-anchor validity is deliberately not part of webpki, so enforce it here.
        let root_cert = x509_cert::Certificate::from_der(root)
            .map_err(|_| invalid("Invalid attestation trust anchor"))?;
        let validity = root_cert.tbs_certificate.validity;
        if now_seconds < validity.not_before.to_unix_duration().as_secs()
            || now_seconds > validity.not_after.to_unix_duration().as_secs()
        {
            return Err(invalid(
                "Attestation root certificate is outside its validity period",
            ));
        }
        let root_der = CertificateDer::from(root);
        let anchor = webpki::anchor_from_trusted_cert(&root_der)
            .map_err(|_| invalid("Invalid attestation trust anchor"))?;
        let leaf_der = CertificateDer::from(doc.certificate.as_ref());
        let leaf = webpki::EndEntityCert::try_from(&leaf_der)
            .map_err(|_| invalid("Invalid attestation signing certificate"))?;
        let intermediates = doc
            .cabundle
            .iter()
            .filter(|cert| cert.as_ref() != root)
            .map(|cert| CertificateDer::from(cert.as_ref()))
            .collect::<Vec<_>>();
        leaf.verify_for_usage(
            &[&P384_DER],
            &[anchor],
            &intermediates,
            UnixTime::since_unix_epoch(Duration::from_secs(now_seconds)),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|_| invalid("Nitro certificate chain verification failed"))?;
        cose.verify_signature(&[], |signature, message| {
            leaf.verify_signature(&P384_FIXED, message, signature)
        })
        .map_err(|_| invalid("Nitro COSE signature verification failed"))?;

        let now_ms = now_seconds
            .checked_mul(1000)
            .ok_or_else(|| invalid("Invalid clock"))?;
        if now_ms.saturating_sub(doc.timestamp) > self.max_age_seconds * 1000
            || doc.timestamp.saturating_sub(now_ms) > 30_000
        {
            return Err(invalid("Attestation is expired or dated in the future"));
        }
        if doc.nonce.as_ref().map(|value| value.as_ref()) != Some(expected_nonce) {
            return Err(invalid("Attestation challenge does not match"));
        }
        let actual_key = doc
            .public_key
            .as_deref()
            .ok_or_else(|| invalid("Attestation does not bind an enclave public key"))?;
        let actual_key = secp256k1::PublicKey::from_slice(actual_key)
            .map_err(|_| invalid("Attested enclave key is invalid"))?;
        let expected_key = secp256k1::PublicKey::from_slice(expected_public_key)
            .map_err(|_| invalid("Expected enclave key is invalid"))?;
        if actual_key != expected_key {
            return Err(invalid("Attested enclave key does not match the recipient"));
        }
        // Debug enclaves have zero PCR0, PCR1 and PCR2 regardless of configured pins.
        for index in [0, 1, 2] {
            if doc
                .pcrs
                .get(&index)
                .is_none_or(|pcr| pcr.iter().all(|byte| *byte == 0))
            {
                return Err(invalid("Debug-mode or incomplete enclave measurements"));
            }
        }
        for (index, expected) in &self.required_pcrs {
            if doc.pcrs.get(index).map(|value| value.as_ref()) != Some(expected.as_slice()) {
                return Err(invalid(
                    "Attestation PCR measurement does not match the trusted policy",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Deserialize, serde::Serialize, Clone)]
struct NitroDocument {
    module_id: String,
    timestamp: u64,
    digest: String,
    pcrs: BTreeMap<u16, ByteBuf>,
    certificate: ByteBuf,
    cabundle: Vec<ByteBuf>,
    public_key: Option<ByteBuf>,
    nonce: Option<ByteBuf>,
}

#[derive(Debug)]
struct P384Algorithm {
    fixed_signature: bool,
}
static P384_DER: P384Algorithm = P384Algorithm {
    fixed_signature: false,
};
static P384_FIXED: P384Algorithm = P384Algorithm {
    fixed_signature: true,
};

impl SignatureVerificationAlgorithm for P384Algorithm {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P384
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA384
    }
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
        let signature = if self.fixed_signature {
            Signature::from_slice(signature)
        } else {
            Signature::from_der(signature)
        }
        .map_err(|_| InvalidSignature)?;
        key.verify(message, &signature)
            .map_err(|_| InvalidSignature)
    }
}

fn invalid(message: &str) -> KeyMeldError {
    KeyMeldError::CryptoError(format!("Attestation verification failed: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::{CoseSign1Builder, HeaderBuilder};
    use p384::{
        ecdsa::{signature::Signer, SigningKey},
        pkcs8::DecodePrivateKey,
    };
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
        PKCS_ECDSA_P384_SHA384,
    };
    use sha2::{Digest, Sha256};

    const NOW: u64 = 1_800_000_000;

    struct Fixture {
        root: Vec<u8>,
        signer: SigningKey,
        document: NitroDocument,
        policy: AttestationPolicy,
        key: Vec<u8>,
    }

    fn certificate_params(name: &str, ca: bool) -> CertificateParams {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.not_before =
            time::OffsetDateTime::from_unix_timestamp((NOW - 86400) as i64).unwrap();
        params.not_after = time::OffsetDateTime::from_unix_timestamp((NOW + 86400) as i64).unwrap();
        params.is_ca = if ca {
            IsCa::Ca(BasicConstraints::Unconstrained)
        } else {
            IsCa::ExplicitNoCa
        };
        params.key_usages = if ca {
            vec![KeyUsagePurpose::KeyCertSign]
        } else {
            vec![KeyUsagePurpose::DigitalSignature]
        };
        params
    }

    fn make_fixture() -> Fixture {
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let root = certificate_params("test root", true)
            .self_signed(&root_key)
            .unwrap();
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let leaf = certificate_params("test NSM", false)
            .signed_by(&leaf_key, &root, &root_key)
            .unwrap();
        let signer = SigningKey::from_pkcs8_der(&leaf_key.serialize_der()).unwrap();
        let key = crate::crypto::SecureCrypto::generate_enclave_keypair()
            .unwrap()
            .1
            .serialize()
            .to_vec();
        let document = NitroDocument {
            module_id: "test-enclave".into(),
            timestamp: NOW * 1000,
            digest: "SHA384".into(),
            pcrs: BTreeMap::from([
                (0, ByteBuf::from(vec![1; 48])),
                (1, ByteBuf::from(vec![2; 48])),
                (2, ByteBuf::from(vec![3; 48])),
            ]),
            certificate: ByteBuf::from(leaf.der().to_vec()),
            cabundle: vec![ByteBuf::from(root.der().to_vec())],
            public_key: Some(ByteBuf::from(key.clone())),
            nonce: Some(ByteBuf::from(vec![42; 32])),
        };
        Fixture {
            root: root.der().to_vec(),
            signer,
            document,
            policy: AttestationPolicy::new(BTreeMap::from([(0, vec![1; 48])])).unwrap(),
            key,
        }
    }

    impl Fixture {
        fn signed(&self, document: &NitroDocument) -> Vec<u8> {
            CoseSign1Builder::new()
                .protected(
                    HeaderBuilder::new()
                        .algorithm(iana::Algorithm::ES384)
                        .build(),
                )
                .payload(serde_cbor::to_vec(document).unwrap())
                .create_signature(&[], |message| {
                    let signature: Signature = self.signer.sign(message);
                    signature.to_vec()
                })
                .build()
                .to_vec()
                .unwrap()
        }
        fn verify(&self, document: &[u8]) -> Result<(), KeyMeldError> {
            self.policy
                .verify_with_root(document, &self.key, &[42; 32], NOW, &self.root)
        }
    }

    #[test]
    fn valid_signed_document_and_tagged_form_verify() {
        let fixture = make_fixture();
        let document = fixture.signed(&fixture.document);
        fixture.verify(&document).unwrap();
        let tagged = CoseSign1::from_slice(&document)
            .unwrap()
            .to_tagged_vec()
            .unwrap();
        fixture.verify(&tagged).unwrap();
        // Test roots can never be selected through the production API.
        assert!(fixture
            .policy
            .verify(&document, &fixture.key, &[42; 32], NOW)
            .is_err());
    }

    #[test]
    fn rejects_modified_signatures_payloads_and_untrusted_certificates() {
        let fixture = make_fixture();
        let bytes = fixture.signed(&fixture.document);
        let mut cose = CoseSign1::from_slice(&bytes).unwrap();
        cose.signature[0] ^= 1;
        assert!(fixture.verify(&cose.to_vec().unwrap()).is_err());
        let mut cose = CoseSign1::from_slice(&bytes).unwrap();
        let mut doc = fixture.document.clone();
        doc.timestamp -= 1000;
        cose.payload = Some(serde_cbor::to_vec(&doc).unwrap());
        assert!(fixture.verify(&cose.to_vec().unwrap()).is_err());
        let stranger = make_fixture();
        assert!(fixture
            .policy
            .verify_with_root(&bytes, &fixture.key, &[42; 32], NOW, &stranger.root)
            .is_err());
        let mut doc = fixture.document.clone();
        doc.certificate[20] ^= 1;
        assert!(fixture.verify(&fixture.signed(&doc)).is_err());
    }

    #[test]
    fn rejects_signed_wrong_nonce_key_measurements_debug_and_timestamps() {
        let fixture = make_fixture();
        for mutation in 0..7 {
            let mut document = fixture.document.clone();
            match mutation {
                0 => document.nonce = Some(ByteBuf::from(vec![41; 32])),
                1 => {
                    document.public_key = Some(ByteBuf::from(
                        crate::crypto::SecureCrypto::generate_enclave_keypair()
                            .unwrap()
                            .1
                            .serialize()
                            .to_vec(),
                    ))
                }
                2 => {
                    document.pcrs.insert(0, ByteBuf::from(vec![2; 48]));
                }
                3 => {
                    document.pcrs.insert(1, ByteBuf::from(vec![0; 48]));
                }
                4 => document.timestamp -= 301_000,
                5 => document.timestamp += 31_000,
                _ => {
                    document.pcrs.remove(&2);
                }
            }
            assert!(
                fixture.verify(&fixture.signed(&document)).is_err(),
                "mutation {mutation}"
            );
        }
        assert!(fixture
            .policy
            .verify_with_root(
                &fixture.signed(&fixture.document),
                &fixture.key,
                &[42; 32],
                NOW + 86401,
                &fixture.root
            )
            .is_err());
    }

    #[test]
    fn rejects_missing_or_debug_only_policies() {
        assert!(AttestationPolicy::new(BTreeMap::new()).is_err());
        assert!(AttestationPolicy::new(BTreeMap::from([(1, vec![1; 48])])).is_err());
        assert!(AttestationPolicy::new(BTreeMap::from([(0, vec![0; 48])])).is_err());
        assert!(AttestationPolicy::new(BTreeMap::from([(0, vec![1; 32])])).is_err());
    }

    #[test]
    fn aws_root_fingerprint_and_real_nitro_signature_are_verified() {
        assert_eq!(
            hex::encode(Sha256::digest(AWS_ROOT)),
            "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
        );
        let bytes = include_bytes!("../../tests/fixtures/aws-nitro-attestation.cose");
        let fixture = make_fixture();
        // Historical AWS fixture has no challenge. Its chain/signature succeeds first,
        // then the mandatory fresh challenge rejects it; current time rejects its certs.
        let error = fixture
            .policy
            .verify(bytes, &fixture.key, &[42; 32], 1_736_179_625)
            .unwrap_err();
        assert!(
            error.to_string().contains("challenge does not match"),
            "{error}"
        );
        assert!(fixture
            .policy
            .verify(bytes, &fixture.key, &[42; 32], NOW)
            .unwrap_err()
            .to_string()
            .contains("certificate chain"));
    }
}

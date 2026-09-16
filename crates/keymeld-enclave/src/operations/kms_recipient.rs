//! AWS KMS recipient envelopes use CMS, not bare RSA ciphertext.
//!
//! Format: https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/main/source/cms.c
//! Public key: https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/main/docs/kms-apis/RecipientRequest.md
//! AWS's CBC envelope has no MAC. Authenticity comes from the enclave's pinned
//! TLS connection to KMS; padding validation alone cannot detect all tampering.
use crate::attestation::AttestationManager;
use aws_sdk_kms::{
    primitives::Blob,
    types::{KeyEncryptionMechanism, RecipientInfo},
};
use cms::{
    content_info::{CmsVersion, ContentInfo},
    enveloped_data::{EnvelopedData, RecipientIdentifier, RecipientInfo as CmsRecipientInfo},
};
use der::{asn1::ObjectIdentifier, Decode};
use keymeld_core::protocol::{CryptoError, EnclaveError};
use openssl::{
    cms::CmsContentInfo,
    pkey::{PKey, Private},
    rsa::Rsa,
};
use pkcs1::RsaOaepParams;
use zeroize::Zeroizing;

const ENVELOPED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");
const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const RSA_OAEP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.7");
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
const P_SPECIFIED: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.9");
const AES256_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");

type Result<T> = std::result::Result<T, EnclaveError>;

fn error(message: &str) -> EnclaveError {
    EnclaveError::Crypto(CryptoError::Other(message.into()))
}

fn invalid_envelope() -> EnclaveError {
    // Do not expose RSA or CBC padding errors through the command channel.
    error("Invalid KMS recipient ciphertext")
}

/// An ephemeral key for one KMS operation. Never persisted, exported, or cloned.
/// OpenSSL clears RSA private components when the final PKey is freed.
pub(super) struct KmsRecipient {
    private_key: PKey<Private>,
    info: RecipientInfo,
}

impl KmsRecipient {
    pub(super) fn new(manager: &AttestationManager) -> Result<Self> {
        Self::with_attestation(|spki| Ok(manager.get_kms_recipient_attestation(spki)?.raw_document))
    }

    fn with_attestation(attest: impl FnOnce(&[u8]) -> Result<Vec<u8>>) -> Result<Self> {
        let rsa =
            Rsa::generate(2048).map_err(|_| error("Failed to generate KMS recipient RSA key"))?;
        let private_key =
            PKey::from_rsa(rsa).map_err(|_| error("Failed to initialize KMS recipient RSA key"))?;
        let spki = private_key
            .public_key_to_der()
            .map_err(|_| error("Failed to encode KMS recipient public key"))?;
        let document = attest(&spki)?;
        if document.is_empty() {
            return Err(error("Missing KMS recipient attestation"));
        }
        let info = RecipientInfo::builder()
            .attestation_document(Blob::new(document))
            .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
            .build();
        Ok(Self { private_key, info })
    }

    fn decrypt_dek(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        // AWS allows up to 6144 bytes for CiphertextForRecipient on these APIs.
        if ciphertext.is_empty() || ciphertext.len() > 6144 {
            return Err(invalid_envelope());
        }
        // OpenSSL accepts AWS's BER encoding, including indefinite lengths and
        // fragmented OCTET STRINGs. Normalize it before typed DER validation.
        let envelope = CmsContentInfo::from_der(ciphertext).map_err(|_| invalid_envelope())?;
        let canonical = envelope.to_der().map_err(|_| invalid_envelope())?;
        validate_envelope(&canonical)?;
        // Nitro supplies a public key, not an X.509 recipient certificate. The
        // checks above enforce OAEP/SHA-256 and reject PKCS#1 v1.5 before this call.
        let plaintext = Zeroizing::new(
            envelope
                .decrypt_without_cert_check(&self.private_key)
                .map_err(|_| invalid_envelope())?,
        );
        if plaintext.len() != 32 {
            return Err(invalid_envelope());
        }
        let mut dek = Zeroizing::new([0; 32]);
        dek.copy_from_slice(&plaintext);
        Ok(dek)
    }
}

fn validate_envelope(canonical: &[u8]) -> Result<()> {
    let content = ContentInfo::from_der(canonical).map_err(|_| invalid_envelope())?;
    if content.content_type != ENVELOPED_DATA {
        return Err(invalid_envelope());
    }
    let envelope: EnvelopedData = content
        .content
        .decode_as()
        .map_err(|_| invalid_envelope())?;
    if envelope.version != CmsVersion::V2 || envelope.recip_infos.0.len() != 1 {
        return Err(invalid_envelope());
    }
    let Some(CmsRecipientInfo::Ktri(recipient)) = envelope.recip_infos.0.iter().next() else {
        return Err(invalid_envelope());
    };
    if recipient.version != CmsVersion::V2
        || !matches!(recipient.rid, RecipientIdentifier::SubjectKeyIdentifier(_))
        || recipient.enc_key.as_bytes().len() != 256
        || recipient.key_enc_alg.oid != RSA_OAEP
    {
        return Err(invalid_envelope());
    }
    let params = recipient
        .key_enc_alg
        .parameters
        .as_ref()
        .ok_or_else(invalid_envelope)?;
    let oaep: RsaOaepParams<'_> = params.decode_as().map_err(|_| invalid_envelope())?;
    if oaep.hash.oid != SHA256
        || oaep.hash.parameters.is_some_and(|p| !p.is_null())
        || oaep.mask_gen.oid != MGF1
        || !oaep
            .mask_gen
            .parameters
            .is_some_and(|p| p.oid == SHA256 && p.parameters.is_none_or(|p| p.is_null()))
        || oaep.p_source.oid != P_SPECIFIED
        || !oaep.p_source.parameters.is_some_and(|p| {
            p.decode_as::<der::asn1::OctetStringRef<'_>>()
                .is_ok_and(|label| label.as_bytes().is_empty())
        })
    {
        return Err(invalid_envelope());
    }
    let encrypted = &envelope.encrypted_content;
    if encrypted.content_type != DATA || encrypted.content_enc_alg.oid != AES256_CBC {
        return Err(invalid_envelope());
    }
    let iv = encrypted
        .content_enc_alg
        .parameters
        .as_ref()
        .ok_or_else(invalid_envelope)?
        .decode_as::<der::asn1::OctetStringRef<'_>>()
        .map_err(|_| invalid_envelope())?;
    // A 32-byte DEK plus PKCS#7 padding occupies exactly three AES blocks.
    if iv.as_bytes().len() != 16
        || encrypted
            .encrypted_content
            .as_ref()
            .is_none_or(|value| value.as_bytes().len() != 48)
    {
        return Err(invalid_envelope());
    }
    Ok(())
}

pub(super) enum KmsResponseProtection {
    Recipient(KmsRecipient),
    /// Selected explicitly by the local simulation entry point, never on error.
    DevelopmentPlaintext,
}

impl KmsResponseProtection {
    pub(super) fn recipient_info(&self) -> Option<RecipientInfo> {
        match self {
            Self::Recipient(recipient) => Some(recipient.info.clone()),
            Self::DevelopmentPlaintext => None,
        }
    }

    pub(super) fn decrypt_dek(
        &self,
        plaintext: Option<&Blob>,
        ciphertext_for_recipient: Option<&Blob>,
    ) -> Result<Zeroizing<[u8; 32]>> {
        match self {
            Self::Recipient(recipient) => {
                if plaintext.is_some_and(|value| !value.as_ref().is_empty()) {
                    return Err(error("KMS returned plaintext for an attested request"));
                }
                let ciphertext = ciphertext_for_recipient
                    .ok_or_else(|| error("KMS omitted CiphertextForRecipient"))?;
                recipient.decrypt_dek(ciphertext.as_ref())
            }
            Self::DevelopmentPlaintext => {
                if ciphertext_for_recipient.is_some() {
                    return Err(error(
                        "Unexpected recipient ciphertext in development KMS mode",
                    ));
                }
                let plaintext =
                    plaintext.ok_or_else(|| error("Development KMS omitted plaintext DEK"))?;
                if plaintext.as_ref().len() != 32 {
                    return Err(error("DEK must be exactly 32 bytes"));
                }
                let mut dek = Zeroizing::new([0; 32]);
                dek.copy_from_slice(plaintext.as_ref());
                Ok(dek)
            }
        }
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use super::*;
    use cms::enveloped_data::{EncryptedContentInfo, KeyTransRecipientInfo};
    use der::{
        asn1::{Any, AnyRef, OctetString, SetOfVec},
        Encode,
    };
    use openssl::{encrypt::Encrypter, hash::MessageDigest, rsa::Padding, symm};
    use spki::{AlgorithmIdentifier, AlgorithmIdentifierRef};

    /// Unsigned local evidence, used only to exercise request serialization.
    /// This is deliberately not an NSM document and AWS would reject it.
    pub(in crate::operations) fn recipient() -> KmsRecipient {
        KmsRecipient::with_attestation(|spki| {
            Ok(serde_cbor::to_vec(&std::collections::BTreeMap::from([(
                "public_key",
                serde_bytes::ByteBuf::from(spki.to_vec()),
            )]))
            .unwrap())
        })
        .unwrap()
    }

    /// Build the documented CMS envelope using typed ASN.1 and OpenSSL crypto.
    /// The fixture needs only the attested public key, as a KMS server would.
    pub(in crate::operations) fn envelope(spki: &[u8], dek: &[u8]) -> Vec<u8> {
        let public_key = PKey::public_key_from_der(spki).unwrap();
        let mut encrypter = Encrypter::new(&public_key).unwrap();
        encrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
        encrypter.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
        encrypter.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
        let content_key: [u8; 32] = rand::random();
        let iv: [u8; 16] = rand::random();
        let mut encrypted_key = vec![0; encrypter.encrypt_len(&content_key).unwrap()];
        let size = encrypter.encrypt(&content_key, &mut encrypted_key).unwrap();
        encrypted_key.truncate(size);
        let ciphertext =
            symm::encrypt(symm::Cipher::aes_256_cbc(), &content_key, Some(&iv), dek).unwrap();

        let sha256 = AlgorithmIdentifierRef {
            oid: SHA256,
            parameters: Some(AnyRef::NULL),
        };
        let oaep = RsaOaepParams {
            hash: sha256,
            mask_gen: AlgorithmIdentifier {
                oid: MGF1,
                parameters: Some(sha256),
            },
            p_source: RsaOaepParams::default().p_source,
        };
        let recipient = KeyTransRecipientInfo {
            version: CmsVersion::V2,
            rid: RecipientIdentifier::SubjectKeyIdentifier(
                OctetString::new(vec![1; 20]).unwrap().into(),
            ),
            key_enc_alg: AlgorithmIdentifier {
                oid: RSA_OAEP,
                parameters: Some(Any::encode_from(&oaep).unwrap()),
            },
            enc_key: OctetString::new(encrypted_key).unwrap(),
        };
        let enveloped_data = EnvelopedData {
            version: CmsVersion::V2,
            originator_info: None,
            recip_infos: SetOfVec::try_from(vec![CmsRecipientInfo::Ktri(recipient)])
                .unwrap()
                .into(),
            encrypted_content: EncryptedContentInfo {
                content_type: DATA,
                content_enc_alg: AlgorithmIdentifier {
                    oid: AES256_CBC,
                    parameters: Some(Any::encode_from(&OctetString::new(iv).unwrap()).unwrap()),
                },
                encrypted_content: Some(OctetString::new(ciphertext).unwrap()),
            },
            unprotected_attrs: None,
        };
        ContentInfo {
            content_type: ENVELOPED_DATA,
            content: Any::encode_from(&enveloped_data).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    pub(in crate::operations) fn public_key(recipient: &KmsRecipient) -> Vec<u8> {
        recipient.private_key.public_key_to_der().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{asn1::Any, Encode};

    #[test]
    fn recipient_uses_fresh_rsa2048_spki_in_attestation() {
        let first = test_support::recipient();
        let second = test_support::recipient();
        let info = &first.info;
        assert_eq!(
            info.key_encryption_algorithm(),
            Some(&KeyEncryptionMechanism::RsaesOaepSha256)
        );
        let document: std::collections::BTreeMap<String, serde_bytes::ByteBuf> =
            serde_cbor::from_slice(info.attestation_document().unwrap().as_ref()).unwrap();
        let public_key = PKey::public_key_from_der(&document["public_key"]).unwrap();
        assert_eq!(public_key.rsa().unwrap().size(), 256);
        assert_eq!(
            document["public_key"].as_ref(),
            test_support::public_key(&first)
        );
        assert_ne!(
            test_support::public_key(&first),
            test_support::public_key(&second)
        );
    }

    #[test]
    fn cms_roundtrip_and_wrong_recipient_rejection() {
        let recipient = test_support::recipient();
        let other_recipient = test_support::recipient();
        let ciphertext = test_support::envelope(&test_support::public_key(&recipient), &[0x51; 32]);
        assert_eq!(*recipient.decrypt_dek(&ciphertext).unwrap(), [0x51; 32]);
        assert!(other_recipient.decrypt_dek(&ciphertext).is_err());
    }

    #[test]
    fn cms_accepts_aws_ber_indefinite_lengths_and_fragmented_content() {
        let recipient = test_support::recipient();
        let ciphertext = test_support::envelope(&test_support::public_key(&recipient), &[0x51; 32]);
        let content = ContentInfo::from_der(&ciphertext).unwrap();
        let envelope: EnvelopedData = content.content.decode_as().unwrap();
        let encrypted = envelope.encrypted_content;
        let mut ber = vec![0x30, 0x80];
        ber.extend(ENVELOPED_DATA.to_der().unwrap());
        ber.extend([0xa0, 0x80, 0x30, 0x80]);
        ber.extend(CmsVersion::V2.to_der().unwrap());
        ber.extend(envelope.recip_infos.to_der().unwrap());
        ber.extend([0x30, 0x80]);
        ber.extend(DATA.to_der().unwrap());
        ber.extend(encrypted.content_enc_alg.to_der().unwrap());
        ber.extend([0xa0, 0x80]);
        for block in encrypted.encrypted_content.unwrap().as_bytes().chunks(16) {
            ber.extend([0x04, 16]);
            ber.extend(block);
        }
        ber.extend([0; 10]); // End encrypted octets, content info, envelope, explicit tag, outer sequence.
        assert_eq!(*recipient.decrypt_dek(&ber).unwrap(), [0x51; 32]);
    }

    #[test]
    fn cms_rejects_corrupt_padding_invalid_payload_and_wrong_dek_length() {
        let recipient = test_support::recipient();
        let mut ciphertext =
            test_support::envelope(&test_support::public_key(&recipient), &[0x51; 32]);
        // Change the last padding byte from 0x10 to 0x11 via CBC's preceding block.
        // This tests padding rejection, not authentication (CBC has no MAC).
        let previous_block_end = ciphertext.len() - 17;
        ciphertext[previous_block_end] ^= 1;
        assert!(recipient.decrypt_dek(&ciphertext).is_err());
        for invalid in [&[][..], &[0; 32], &[0; 256], &ciphertext[..20]] {
            assert!(recipient.decrypt_dek(invalid).is_err());
        }
        let short = test_support::envelope(&test_support::public_key(&recipient), &[0x51; 16]);
        assert!(recipient.decrypt_dek(&short).is_err());
    }

    #[test]
    fn cms_rejects_unrequested_key_encryption_algorithm() {
        let recipient = test_support::recipient();
        let ciphertext = test_support::envelope(&test_support::public_key(&recipient), &[0x51; 32]);
        let mut content = ContentInfo::from_der(&ciphertext).unwrap();
        let mut envelope: EnvelopedData = content.content.decode_as().unwrap();
        let CmsRecipientInfo::Ktri(mut info) =
            envelope.recip_infos.0.iter().next().unwrap().clone()
        else {
            panic!()
        };
        info.key_enc_alg.oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
        envelope.recip_infos = der::asn1::SetOfVec::try_from(vec![CmsRecipientInfo::Ktri(info)])
            .unwrap()
            .into();
        content.content = Any::encode_from(&envelope).unwrap();
        assert!(recipient.decrypt_dek(&content.to_der().unwrap()).is_err());
    }

    #[test]
    fn strict_response_rejects_plaintext_and_missing_recipient_ciphertext() {
        let recipient = test_support::recipient();
        let ciphertext = Blob::new(test_support::envelope(
            &test_support::public_key(&recipient),
            &[0x51; 32],
        ));
        let protection = KmsResponseProtection::Recipient(recipient);
        let plaintext = Blob::new([0x51; 32]);
        assert!(protection.decrypt_dek(Some(&plaintext), None).is_err());
        assert!(protection
            .decrypt_dek(Some(&plaintext), Some(&ciphertext))
            .is_err());
        assert!(protection.decrypt_dek(None, None).is_err());
        assert!(protection.decrypt_dek(None, Some(&Blob::new([]))).is_err());
        assert_eq!(
            *protection
                .decrypt_dek(Some(&Blob::new([])), Some(&ciphertext))
                .unwrap(),
            [0x51; 32]
        );
    }
}

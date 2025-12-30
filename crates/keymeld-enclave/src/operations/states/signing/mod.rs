pub mod collecting_nonces;
pub mod collecting_partial_signatures;
pub mod completed;
pub mod failed;
pub mod finalizing_signature;
pub mod generating_nonces;
pub mod generating_partial_signatures;
pub mod initialized;

pub use collecting_nonces::CollectingNonces;
pub use collecting_partial_signatures::CollectingPartialSignatures;
pub use completed::Completed;
pub use failed::Failed;
pub use finalizing_signature::FinalizingSignature;
pub use generating_nonces::GeneratingNonces;
pub use generating_partial_signatures::GeneratingPartialSignatures;
pub use initialized::Initialized;

use keymeld_core::enclave::{CryptoError, EnclaveError};
use keymeld_core::{
    encrypted_data::SigningSessionData, musig::AdaptorConfig, KeyMaterial, SessionSecret, UserId,
};

#[derive(Debug, Clone)]
pub struct CoordinatorData {
    pub user_id: UserId,
    pub private_key: KeyMaterial,
}

pub fn has_adaptor_configs(session_data: &SigningSessionData) -> bool {
    !session_data.adaptor_configs.is_empty()
}

pub fn decrypt_adaptor_configs(
    encrypted_adapator_configs: &str,
    session_secret: &SessionSecret,
) -> Result<Vec<AdaptorConfig>, EnclaveError> {
    let configs = keymeld_core::api::validation::decrypt_adaptor_configs(
        encrypted_adapator_configs,
        &hex::encode(session_secret.as_bytes()),
    )
    .map_err(|e| {
        EnclaveError::Crypto(CryptoError::DecryptionFailed {
            context: "data".to_string(),
            error: format!("Failed to decrypt adaptor configs: {e}"),
        })
    })?;

    Ok(configs)
}

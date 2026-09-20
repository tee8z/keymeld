//! Ciphertext-only relay. Do not persist, decode, normalize or log private payloads.
use crate::handlers::AppState;
use axum::{body::Bytes, extract::State, http::StatusCode, Json};
use keymeld_core::{
    confidential::{EnclaveEnvelope, RoutingHeader, MAX_WIRE_BYTES},
    protocol::{Command, EnclaveCommand, EnclaveOutcome},
};

pub async fn forward(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<EnclaveEnvelope>, StatusCode> {
    let envelope = decode_request(&body)?;
    let expected_header = envelope.header();
    let destination = envelope.destination_enclave;
    let outcome = state
        .enclave_manager
        .send_command_to_enclave(
            &destination,
            Command::new(EnclaveCommand::Confidential(Box::new(envelope))),
        )
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    accept_response(&expected_header, outcome.response).map(Json)
}

fn decode_request(body: &[u8]) -> Result<EnclaveEnvelope, StatusCode> {
    if body.len() > MAX_WIRE_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let envelope: EnclaveEnvelope =
        serde_json::from_slice(body).map_err(|_| StatusCode::BAD_REQUEST)?;
    envelope
        .validate_bounds()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(envelope)
}

fn accept_response(
    expected_header: &RoutingHeader,
    response: EnclaveOutcome,
) -> Result<EnclaveEnvelope, StatusCode> {
    match response {
        EnclaveOutcome::Confidential(response) => {
            response
                .validate_bounds()
                .map_err(|_| StatusCode::BAD_GATEWAY)?;
            if &response.header() != expected_header {
                return Err(StatusCode::BAD_GATEWAY);
            }
            Ok(*response)
        }
        // Never forward enclave diagnostic strings through this public boundary.
        _ => Err(StatusCode::BAD_GATEWAY),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keymeld_core::{
        confidential::TRANSPORT_VERSION,
        protocol::{EnclaveError, ErrorResponse, ValidationError},
        EnclaveId,
    };
    use uuid::Uuid;

    fn envelope() -> EnclaveEnvelope {
        EnclaveEnvelope {
            transport_version: TRANSPORT_VERSION,
            destination_enclave: EnclaveId::new(1),
            opaque_route_id: Uuid::now_v7(),
            correlation_id: "01".repeat(32),
            ciphertext: "001122".into(),
        }
    }

    #[test]
    fn relay_rejects_private_fields_and_bounds_before_deserialization() {
        let expected = envelope();
        let encoded = serde_json::to_vec(&expected).unwrap();
        assert_eq!(decode_request(&encoded).unwrap(), expected);
        let mut with_policy = serde_json::to_value(&expected).unwrap();
        with_policy["policy"] = serde_json::json!({"application": "private"});
        assert_eq!(
            decode_request(&serde_json::to_vec(&with_policy).unwrap()),
            Err(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            decode_request(&vec![b'['; MAX_WIRE_BYTES + 1]),
            Err(StatusCode::PAYLOAD_TOO_LARGE)
        );
        assert_eq!(
            decode_request(br#"{"private_invalid":"secret error"}"#),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn relay_never_returns_native_errors_or_mismatched_responses() {
        let expected = envelope();
        let header = expected.header();
        let error = EnclaveOutcome::Error(ErrorResponse {
            error: EnclaveError::Validation(ValidationError::Other(
                "private policy and signing details".into(),
            )),
        });
        assert_eq!(
            accept_response(&header, error),
            Err(StatusCode::BAD_GATEWAY)
        );
        let mut wrong = expected.clone();
        wrong.correlation_id = "02".repeat(32);
        assert_eq!(
            accept_response(&header, EnclaveOutcome::Confidential(Box::new(wrong))),
            Err(StatusCode::BAD_GATEWAY)
        );
        assert_eq!(
            accept_response(
                &header,
                EnclaveOutcome::Confidential(Box::new(expected.clone()))
            )
            .unwrap(),
            expected
        );
    }
}

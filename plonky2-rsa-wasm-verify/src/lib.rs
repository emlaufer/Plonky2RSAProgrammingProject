use base64::prelude::*;
use plonky2::field::types::Field;
use plonky2::plonk::circuit_data::{
    CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use wasm_bindgen::prelude::*;

use plonky2_rsa::gadgets::serialize::RSAGateSerializer;
use plonky2_rsa::utils::verify_ring_signature_proof_public_inputs;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

const MESSAGE_MAX_LENGTH: usize = 512;
const MAX_NUM_PUBLIC_KEYS: usize = 32;

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
    // Now println!s and panics will show in the browser/Node console.
}

/// Verify a Plonky2 proof has the correct public inputs in Wasm.
///
/// # Arguments
/// * `proof_base64` - Base64 encoded serialized proof (via `bincode`)
///
/// # Returns
/// * `true` if the proof is valid, else `false`
#[wasm_bindgen]
pub fn verify_plonky2_ring_rsa_proof_inputs(
    proof_base64: &str,
    expected_message: &str,
    expected_public_keys: Box<[JsValue]>,
) -> Result<bool, JsValue> {
    // Decode base64 data
    let proof_bytes = BASE64_STANDARD
        .decode(proof_base64)
        .map_err(|_| JsValue::from_str("Failed to decode proof from base64"))?;

    // Deserialize proof
    let proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(&proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize proof: {}", e)))?;

    let expected_public_keys = expected_public_keys
        .iter()
        .map(|js_value| {
            js_value
                .as_string()
                .ok_or_else(|| JsValue::from_str("Expected public key to be a string"))
        })
        .collect::<Result<Vec<String>, JsValue>>()?;

    // Verify public inputs
    if !verify_ring_signature_proof_public_inputs(
        &proof,
        MAX_NUM_PUBLIC_KEYS,
        expected_message,
        &expected_public_keys,
    ) {
        return Err(JsValue::from_str(
            "Public key or message verification failed: Inputs don't match the proof's public inputs",
        ));
    }

    Ok(true)
}

/// Verify a Plonky2 proof in WebAssembly.
///
/// # Arguments
/// * `proof_base64` - Base64 encoded serialized proof (via `bincode`)
/// * `verifier_only_base64` - Base64 encoded serialized verifier-only circuit data
/// * `common_data_base64` - Base64 encoded serialized common circuit data
///
/// # Returns
/// * `true` if the proof is valid, else `false`
#[wasm_bindgen]
pub fn verify_plonky2_ring_rsa_proof(
    proof_base64: &str,
    verifier_only_base64: &str,
    common_data_base64: &str,
    expected_message: &str,
    expected_public_keys: Box<[JsValue]>,
) -> Result<bool, JsValue> {
    // Decode base64 data
    let proof_bytes = BASE64_STANDARD
        .decode(proof_base64)
        .map_err(|_| JsValue::from_str("Failed to decode proof from base64"))?;

    let verifier_only_bytes = BASE64_STANDARD
        .decode(verifier_only_base64)
        .map_err(|_| JsValue::from_str("Failed to decode verifier-only data from base64"))?;

    let common_data_bytes = BASE64_STANDARD
        .decode(common_data_base64)
        .map_err(|_| JsValue::from_str("Failed to decode common circuit data from base64"))?;

    // Deserialize proof
    let proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(&proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize proof: {}", e)))?;

    // Use the default gate deserializer
    let gate_deserializer = RSAGateSerializer;

    // Deserialize verifier-only data
    let verifier_only: VerifierOnlyCircuitData<C, D> =
        VerifierOnlyCircuitData::from_bytes(verifier_only_bytes).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to deserialize verifier-only data: {:?}",
                e
            ))
        })?;

    // Deserialize common circuit data
    let common_data: CommonCircuitData<F, D> =
        CommonCircuitData::from_bytes(common_data_bytes, &gate_deserializer).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to deserialize common circuit data: {:?}",
                e
            ))
        })?;

    let verifier_data = VerifierCircuitData {
        verifier_only,
        common: common_data,
    };

    let expected_public_keys = expected_public_keys
        .iter()
        .map(|js_value| {
            js_value
                .as_string()
                .ok_or_else(|| JsValue::from_str("Expected public key to be a string"))
        })
        .collect::<Result<Vec<String>, JsValue>>()?;

    // Verify public inputs
    if !verify_ring_signature_proof_public_inputs(
        &proof,
        MAX_NUM_PUBLIC_KEYS,
        expected_message,
        &expected_public_keys,
    ) {
        return Err(JsValue::from_str(
            "Public key or message verification failed: Inputs don't match the proof's public inputs",
        ));
    }

    match verifier_data.verify(proof) {
        Ok(_) => Ok(true),
        Err(e) => Err(JsValue::from_str(&format!(
            "Proof verification failed: {:?}",
            e
        ))),
    }
}

import {
  init,
  verify_plonky2_ring_rsa_proof,
  verify_plonky2_ring_rsa_proof_inputs,
} from 'plonky2_rsa_wasm_verify';

async function verifyProof(
  proof: string,
  verifierData: string,
  common: string,
  message: string,
  public_keys: string[],
) {
  await init();

  const result: boolean = verify_plonky2_ring_rsa_proof(
    proof,
    verifierData,
    common,
    message,
    public_keys,
  );
  return result;
}

async function verifyProofInputs(proof: string, message: string, public_keys: string[]) {
  await init();

  const result: boolean = verify_plonky2_ring_rsa_proof_inputs(proof, message, public_keys);
  return result;
}

export { verifyProof, verifyProofInputs };

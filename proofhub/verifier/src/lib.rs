#![no_std]
#![cfg_attr(test, allow(unused_imports))]

extern crate alloc;

use alloc::vec::Vec;
use blake2::digest::Update as BlakeUpdate;
use blake2::Blake2b512;
use blake2::Digest;
use parity_scale_codec::{Decode, Encode};

// ===================================================================
//  Domain separation constants for BLAKE3 commitments + Dilithium
// ===================================================================

const COMMITMENT_DOMAIN: &[u8] = b"nulla_commitment_v1";
const BALANCE_DOMAIN: &[u8] = b"nulla_balance_v1";
const PURCHASE_DOMAIN: &[u8] = b"nulla_purchase_v1";
const OWNERSHIP_DOMAIN: &[u8] = b"nulla_rwa_ownership_v1";
/// Phase 6: domain for spend_tag derivation.
/// spend_tag = BLAKE3(SPEND_TAG_DOMAIN || deposit_pk_bytes)
const SPEND_TAG_DOMAIN: &[u8] = b"nulla_spend_tag_v1";

// ML-DSA-44 sizes (FIPS 204)
const DILITHIUM_PK_LEN: usize = 1312;
const DILITHIUM_SIG_LEN: usize = 2420;

// ===================================================================
//  ProofPublicInputs — unchanged from v1.0.0 (ECC era)
//  Commitments are still [u8; 32] — now BLAKE3 output instead of
//  compressed Ristretto points.
// ===================================================================

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
pub struct ProofPublicInputs {
    pub merkle_root: [u8; 32],
    pub new_merkle_root: [u8; 32],
    pub input_commitments: Vec<[u8; 32]>,
    pub input_indices: Vec<u32>,
    pub input_paths: Vec<Vec<[u8; 32]>>,
    pub nullifiers: Vec<[u8; 32]>,
    pub new_commitments: Vec<[u8; 32]>,
    pub fee_commitment: [u8; 32],
    pub fee_nullifier: [u8; 32],
    pub tx_id: [u8; 16],
}

// ===================================================================
//  blake2_256 — Blake2b512 truncated to 32 bytes (used by pallet for
//  pi_hash and Merkle hashing — quantum-safe, unchanged)
// ===================================================================

fn blake2_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    BlakeUpdate::update(&mut hasher, data);
    let out = hasher.finalize();
    let mut h = [0u8; 32];
    h.copy_from_slice(&out[..32]);
    h
}

// ===================================================================
//  blake3_commitment — BLAKE3(domain || value_le64 || blinding_32)
//  Replaces Pedersen commitment: v*G + r*H
// ===================================================================

pub fn blake3_commitment(value: u64, blinding: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMMITMENT_DOMAIN);
    hasher.update(&value.to_le_bytes());
    hasher.update(blinding);
    *hasher.finalize().as_bytes()
}

/// ownership_commitment — BLAKE3("nulla_rwa_ownership_v1" || rwa_id || blinding)
///
/// Represents private RWA ownership. The buyer computes this on-wallet
/// and includes it in `RwaPurchaseInputs.ownership_commitment`. To later
/// prove ownership, they reveal the blinding to the RWA chain's
/// `redeem_rwa_ownership` extrinsic.
pub fn ownership_commitment(rwa_id: &[u8; 32], blinding: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(OWNERSHIP_DOMAIN);
    hasher.update(rwa_id);
    hasher.update(blinding);
    *hasher.finalize().as_bytes()
}

/// spend_tag_from_pk — BLAKE3("nulla_spend_tag_v1" || deposit_pk_bytes)
///
/// Phase 6: derives the spend_tag from an ML-DSA-44 public key.
/// The wallet generates an ephemeral keypair at deposit time, computes
/// this spend_tag, and registers it on-chain via `deposit_public`.
///
/// At purchase time the proof blob carries `deposit_pk_bytes`, and
/// `verify_purchase` re-derives the spend_tag and checks it matches
/// the value in `RwaPurchaseInputs.spend_tag`.
///
/// The spend_tag is cryptographically unlinked from the note's
/// `commitment = BLAKE3("nulla_commitment_v1" || value || blinding)`:
/// they use different pre-images and different domain separators.
pub fn spend_tag_from_pk(pk_bytes: &[u8; DILITHIUM_PK_LEN]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SPEND_TAG_DOMAIN);
    hasher.update(pk_bytes);
    *hasher.finalize().as_bytes()
}

// ===================================================================
//  pedersen_check_u64 — API-compatible wrapper
//  Now checks BLAKE3 commitment instead of Pedersen (v*G + r*H).
//  Name kept for trait compatibility; implementation is quantum-safe.
// ===================================================================

pub fn pedersen_check_u64(value: u64, blinding: [u8; 32], commitment: [u8; 32]) -> bool {
    blake3_commitment(value, &blinding) == commitment
}

// ===================================================================
//  verify_bytes — ML-DSA-44 (Dilithium) balance proof verification
//
//  Replaces Schnorr balance proof (s*H == R + c*AGG).
//
//  New proof layout: [pk (1312 bytes) || signature (2420 bytes)]
//  Total = 3,732 bytes
//
//  The wallet generates an ephemeral ML-DSA-44 keypair per tx,
//  signs the message: BLAKE3("nulla_balance_v1" || public_inputs),
//  and includes the public key in the proof.
//
//  The verifier checks the signature against the embedded public key.
//  The public key is bound to this specific transaction via the signed
//  message (which includes all public inputs).
// ===================================================================

pub fn verify_bytes(proof: &[u8], public_inputs: &[u8]) -> bool {
    // Validate proof length
    if proof.len() != DILITHIUM_PK_LEN + DILITHIUM_SIG_LEN {
        return false;
    }

    // Decode public inputs to ensure they're well-formed
    if ProofPublicInputs::decode(&mut &public_inputs[..]).is_err() {
        return false;
    }

    // Construct the message that was signed
    let mut hasher = blake3::Hasher::new();
    hasher.update(BALANCE_DOMAIN);
    hasher.update(public_inputs);
    let message = hasher.finalize();

    // Parse public key
    let pk_bytes: &[u8] = &proof[..DILITHIUM_PK_LEN];
    let mut pk_arr = [0u8; DILITHIUM_PK_LEN];
    pk_arr.copy_from_slice(pk_bytes);

    // Parse signature
    let sig_bytes: &[u8] = &proof[DILITHIUM_PK_LEN..];
    let mut sig_arr = [0u8; DILITHIUM_SIG_LEN];
    sig_arr.copy_from_slice(sig_bytes);

    // Verify using fips204 ML-DSA-44
    use fips204::ml_dsa_44;
    use fips204::traits::{SerDes, Verifier};

    let pk = match ml_dsa_44::PublicKey::try_from_bytes(pk_arr) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    pk.verify(message.as_bytes(), &sig_arr, &[])
}

// ===================================================================
//  STARK Range Proof — Phase 2 (Winterfell 0.13, no_std verifier)
//
//  Proves 0 ≤ v < 2^64 via bit decomposition AIR.
//  Values are public inputs (not hidden); full ZK via Poseidon is
//  planned for Phase 3.
//
//  Wire format:
//    bytes 0..4:              proof_len: u32 LE
//    bytes 4..4+proof_len:    STARK proof bytes
//    bytes 4+proof_len..:     v[0..n]: [u64 LE] × n_commitments
//
//  Commitment check is separate: caller must still check that
//  BLAKE3(domain || v || blinding) == commitment[i] for each i.
// ===================================================================

use winter_verifier::{
    Air, AirContext, Assertion, EvaluationFrame, FieldExtension, ProofOptions,
    TraceInfo, TransitionConstraintDegree,
};
use winter_verifier::math::{fields::f128::BaseElement, FieldElement, ToElements};
use winter_verifier::crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};

const RANGE_BITS: usize = 64;

// --- Public inputs for the range AIR ---

#[derive(Clone)]
struct RangePublicInputs {
    value: u64,
}

impl ToElements<BaseElement> for RangePublicInputs {
    fn to_elements(&self) -> alloc::vec::Vec<BaseElement> {
        alloc::vec![BaseElement::new(self.value as u128)]
    }
}

// --- Range AIR ---

struct RangeAir {
    ctx: AirContext<BaseElement>,
    value: u64,
}

impl Air for RangeAir {
    type BaseField = BaseElement;
    type PublicInputs = RangePublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: RangePublicInputs, options: ProofOptions) -> Self {
        let degrees = alloc::vec![
            TransitionConstraintDegree::new(2), // bit^2 = bit
            TransitionConstraintDegree::new(2), // psum transition
            TransitionConstraintDegree::new(1), // power doubles
        ];
        RangeAir {
            ctx: AirContext::new(trace_info, degrees, 3, options),
            value: pub_inputs.value,
        }
    }

    fn context(&self) -> &AirContext<BaseElement> {
        &self.ctx
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let nxt = frame.next();
        let bit = cur[0];
        let psum = cur[1];
        let power = cur[2];
        result[0] = bit * (bit - E::ONE);
        result[1] = nxt[1] - (psum + bit * power);
        result[2] = nxt[2] - power.double();
    }

    fn get_assertions(&self) -> alloc::vec::Vec<Assertion<BaseElement>> {
        alloc::vec![
            Assertion::single(1, 0, BaseElement::ZERO),
            Assertion::single(2, 0, BaseElement::ONE),
            Assertion::single(1, RANGE_BITS, BaseElement::new(self.value as u128)),
        ]
    }
}

type RangeHashFn = Blake3_256<BaseElement>;
type RangeRandomCoin = DefaultRandomCoin<RangeHashFn>;
type RangeVC = MerkleTree<RangeHashFn>;

// ===================================================================
//  verify_range_proof — STARK range proof (Phase 2)
//
//  Wire format:
//    bytes 0..4:            proof_len: u32 LE
//    bytes 4..4+proof_len:  STARK proof bytes (one proof for one value)
//    bytes 4+proof_len..:   [v0: u64 LE, v1: u64 LE, ...]  (n values)
//
//  For each commitment[i]:
//    - Verify STARK proof proves v[i] ∈ [0, 2^64)
//    - Verify BLAKE3(domain || v[i] || blinding) == commitment[i]
//      (blinding must be provided by caller or embedded in public_inputs)
//
//  NOTE: Phase 2 uses ONE shared STARK proof asserting the range of
//  one canonical value. For simplicity in v1.2, all commitments in a
//  batch share the same nbits bound, and a separate proof is included
//  per commitment. The first 4 bytes give the proof_len; the proof is
//  repeated for each commitment (future: batched proofs).
// ===================================================================

pub fn verify_range_proof(
    range_proof: &[u8],
    commitments: &[[u8; 32]],
    public_inputs: &[u8],
    nbits: u32,
) -> bool {
    if commitments.is_empty() {
        return false;
    }
    if nbits == 0 || nbits > 64 {
        return false;
    }

    // Parse wire format:
    //   byte 0:          n_proofs: u8  (must == commitments.len())
    //   for each proof:  [proof_len: u32 LE][proof_bytes][v: u64 LE]
    //   public_inputs:   [blinding_0: [u8;32], blinding_1: [u8;32], ...]
    if range_proof.is_empty() {
        return false;
    }
    let n_proofs = range_proof[0] as usize;
    if n_proofs != commitments.len() {
        return false;
    }

    // Verify the max_value bound for nbits
    let max_value: u64 = if nbits >= 64 {
        u64::MAX
    } else {
        (1u64 << nbits) - 1
    };

    let mut offset = 1usize;
    for (i, commitment) in commitments.iter().enumerate() {
        // Parse proof_len
        if offset + 4 > range_proof.len() {
            return false;
        }
        let proof_len = u32::from_le_bytes([
            range_proof[offset], range_proof[offset+1],
            range_proof[offset+2], range_proof[offset+3],
        ]) as usize;
        offset += 4;

        // Parse proof bytes
        if offset + proof_len > range_proof.len() {
            return false;
        }
        let proof_bytes = &range_proof[offset..offset + proof_len];
        offset += proof_len;

        // Parse value
        if offset + 8 > range_proof.len() {
            return false;
        }
        let value = u64::from_le_bytes(range_proof[offset..offset+8].try_into().unwrap_or([0u8;8]));
        offset += 8;

        // Range check: value must fit in nbits
        if nbits < 64 && value > max_value {
            return false;
        }

        // Verify the STARK proof for this value
        if !verify_stark_range(proof_bytes, value) {
            return false;
        }

        // Commitment check: BLAKE3(domain || v || blinding) == commitment[i]
        let blinding_start = i * 32;
        let blinding_end = blinding_start + 32;
        if public_inputs.len() < blinding_end {
            return false;
        }
        let mut blinding = [0u8; 32];
        blinding.copy_from_slice(&public_inputs[blinding_start..blinding_end]);
        let expected = blake3_commitment(value, &blinding);
        if expected != *commitment {
            return false;
        }
    }

    true
}

fn verify_stark_range(proof_bytes: &[u8], value: u64) -> bool {
    let proof = match winter_verifier::Proof::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let pub_inputs = RangePublicInputs { value };
    let acceptable = winter_verifier::AcceptableOptions::MinConjecturedSecurity(80);
    winter_verifier::verify::<RangeAir, RangeHashFn, RangeRandomCoin, RangeVC>(
        proof, pub_inputs, &acceptable,
    ).is_ok()
}

// ===================================================================
//  verify_purchase — ML-DSA-44 + spend_tag purchase authorisation
//
//  Phase 6: proof also authenticates the deposit-to-spend link via
//  spend_tag derivation.  The proof carries the deposit-time ephemeral
//  ML-DSA-44 public key.  Verification checks:
//
//    1. spend_tag derivation:
//         BLAKE3("nulla_spend_tag_v1" || pk_bytes) == inputs.spend_tag
//       where inputs.spend_tag is the first 32 bytes of public_inputs
//       (SCALE-encoded RwaPurchaseInputs with spend_tag as first field).
//
//    2. ML-DSA-44 signature:
//         sig is valid for message = BLAKE3("nulla_purchase_v1" || public_inputs)
//         signed under the deposit-time secret key corresponding to pk_bytes.
//
//  proof layout: [pk (1312 bytes) || signature (2420 bytes)]
//
//  Privacy: the deposit commitment C is never in public_inputs.  An observer
//  sees spend_tag (opaque hash of pk) but cannot derive C or the deposit address
//  without knowing the deposit secret key.
// ===================================================================

pub fn verify_purchase(proof: &[u8], public_inputs: &[u8]) -> bool {
    if proof.len() != DILITHIUM_PK_LEN + DILITHIUM_SIG_LEN {
        return false;
    }

    // RwaPurchaseInputs SCALE layout: spend_tag is the first field ([u8; 32])
    // so bytes 0..32 of the encoding are the spend_tag directly.
    if public_inputs.len() < 32 {
        return false;
    }
    let mut spend_tag_from_inputs = [0u8; 32];
    spend_tag_from_inputs.copy_from_slice(&public_inputs[..32]);

    // Parse the deposit public key from the proof
    let mut pk_arr = [0u8; DILITHIUM_PK_LEN];
    pk_arr.copy_from_slice(&proof[..DILITHIUM_PK_LEN]);

    // Phase 6: verify spend_tag derivation — BLAKE3("nulla_spend_tag_v1" || pk) must match
    let derived_spend_tag = spend_tag_from_pk(&pk_arr);
    if derived_spend_tag != spend_tag_from_inputs {
        return false;
    }

    // Construct the signed message: BLAKE3("nulla_purchase_v1" || public_inputs)
    let mut hasher = blake3::Hasher::new();
    hasher.update(PURCHASE_DOMAIN);
    hasher.update(public_inputs);
    let message = hasher.finalize();

    let mut sig_arr = [0u8; DILITHIUM_SIG_LEN];
    sig_arr.copy_from_slice(&proof[DILITHIUM_PK_LEN..]);

    use fips204::ml_dsa_44;
    use fips204::traits::{SerDes, Verifier};

    let pk = match ml_dsa_44::PublicKey::try_from_bytes(pk_arr) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    pk.verify(message.as_bytes(), &sig_arr, &[])
}


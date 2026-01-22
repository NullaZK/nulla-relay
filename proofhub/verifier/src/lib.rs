#![no_std]
#![cfg_attr(test, allow(unused_imports))]

extern crate alloc;

use alloc::vec::Vec;
use blake2::digest::Update as BlakeUpdate;
use blake2::Blake2b512;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use parity_scale_codec::Decode;
use sha2::{Digest, Sha512};

#[derive(Decode, Clone, PartialEq, Eq, Debug)]
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

fn generator_h() -> RistrettoPoint {
    let mut hasher = Sha512::new();
    sha2::Digest::update(&mut hasher, b"VERIFIER_H_GENERATOR");
    let out = hasher.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&out);
    RistrettoPoint::from_uniform_bytes(&bytes)
}

fn decompress_point(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto(*bytes).decompress()
}

fn challenge(
    _transcript_label: &'static [u8],
    r: &RistrettoPoint,
    agg: &RistrettoPoint,
    pi_hash: &[u8; 32],
) -> Scalar {
    let mut t = Transcript::new(b"NULLA_SCHNORR_BALANCE");
    t.append_message(b"pi_hash", pi_hash);
    t.append_message(b"R", &r.compress().to_bytes());
    t.append_message(b"AGG", &agg.compress().to_bytes());
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"c", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

fn blake2_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    BlakeUpdate::update(&mut hasher, data);
    let out = hasher.finalize();
    let mut h = [0u8; 32];
    h.copy_from_slice(&out[..32]);
    h
}

use rand_core::{CryptoRng, Error as RandError, RngCore};
struct DeterministicRng {
    seed: [u8; 32],
    ctr: u64,
    buf: [u8; 64],
    idx: usize,
}
impl DeterministicRng { fn new(seed32: [u8; 32]) -> Self { Self { seed: seed32, ctr: 0, buf: [0u8; 64], idx: 64 } }
    fn refill(&mut self) {
        let mut data = [0u8; 40];
        data[..32].copy_from_slice(&self.seed);
        data[32..].copy_from_slice(&self.ctr.to_le_bytes());
        let mut h = Blake2b512::new();
        BlakeUpdate::update(&mut h, &data);
        let out = h.finalize();
        self.buf.copy_from_slice(&out[..64]);
        self.idx = 0;
        self.ctr = self.ctr.wrapping_add(1);
    }
}
impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 { let mut b = [0u8; 4]; self.fill_bytes(&mut b); u32::from_le_bytes(b) }
    fn next_u64(&mut self) -> u64 { let mut b = [0u8; 8]; self.fill_bytes(&mut b); u64::from_le_bytes(b) }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut written = 0;
        while written < dest.len() {
            if self.idx >= self.buf.len() { self.refill(); }
            let avail = self.buf.len() - self.idx;
            let need = core::cmp::min(avail, dest.len() - written);
            dest[written..written + need].copy_from_slice(&self.buf[self.idx..self.idx + need]);
            self.idx += need;
            written += need;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> { self.fill_bytes(dest); Ok(()) }
}
impl CryptoRng for DeterministicRng {}

pub fn verify_bytes(proof: &[u8], public_inputs: &[u8]) -> bool {
    let inputs = match ProofPublicInputs::decode(&mut &public_inputs[..]) { Ok(v) => v, Err(_) => return false };
    let pi_hash = blake2_256(public_inputs);
    if proof.len() != 64 { return false; }
    let mut r_bytes = [0u8; 32]; r_bytes.copy_from_slice(&proof[0..32]);
    let r_pt = match CompressedRistretto(r_bytes).decompress() { Some(p) => p, None => return false };
    let mut s_bytes = [0u8; 32]; s_bytes.copy_from_slice(&proof[32..64]);
    let s = Scalar::from_bytes_mod_order(s_bytes);
    let mut agg = RistrettoPoint::default();
    for c in inputs.input_commitments.iter() { let p = match decompress_point(c) { Some(p) => p, None => return false }; agg += p; }
    for c in inputs.new_commitments.iter() { let p = match decompress_point(c) { Some(p) => p, None => return false }; agg -= p; }
    let fee_p = match decompress_point(&inputs.fee_commitment) { Some(p) => p, None => return false };
    agg -= fee_p;
    let h = generator_h();
    let c = challenge(b"balance", &r_pt, &agg, &pi_hash);
    let lhs = s * h;
    let rhs = r_pt + c * agg;
    lhs == rhs
}

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT as G_NG;
use curve25519_dalek_ng::ristretto::{CompressedRistretto as CompressedRistrettoNG, RistrettoPoint as RistrettoPointNG};

pub fn verify_range_proof(
    range_proof: &[u8],
    commitments: &[[u8; 32]],
    public_inputs: &[u8],
    nbits: u32,
) -> bool {
    if commitments.is_empty() { return false; }
    if nbits == 0 || nbits > 64 { return false; }
    let mut cmts: alloc::vec::Vec<CompressedRistrettoNG> = alloc::vec::Vec::with_capacity(commitments.len());
    for c in commitments.iter() { cmts.push(CompressedRistrettoNG(*c)); }
    let rp = match RangeProof::from_bytes(range_proof) { Ok(p) => p, Err(_) => return false };
    let h = {
        let mut hasher = Sha512::new();
        sha2::Digest::update(&mut hasher, b"VERIFIER_H_GENERATOR");
        let out = hasher.finalize();
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&out);
        RistrettoPointNG::from_uniform_bytes(&bytes)
    };
    let pc_gens = PedersenGens { B: G_NG, B_blinding: h };
    let m = cmts.len();
    let party_capacity = m.next_power_of_two();
    let bp_gens = BulletproofGens::new(nbits as usize, party_capacity);
    let pi_hash = blake2_256(public_inputs);
    let mut t = Transcript::new(b"NULLA_BULLETPROOF_RANGE");
    t.append_message(b"pi_hash", &pi_hash);
    if party_capacity > m {
        let pad = party_capacity - m;
        for i in 0..pad {
            let mut hasher = Sha512::new();
            sha2::Digest::update(&mut hasher, b"PAD_R");
            sha2::Digest::update(&mut hasher, &pi_hash);
            sha2::Digest::update(&mut hasher, &(i as u32).to_le_bytes());
            let out = hasher.finalize();
            let mut w = [0u8; 64];
            w.copy_from_slice(&out);
            let r = curve25519_dalek_ng::scalar::Scalar::from_bytes_mod_order_wide(&w);
            let h = {
                let mut hasher = Sha512::new();
                sha2::Digest::update(&mut hasher, b"VERIFIER_H_GENERATOR");
                let out = hasher.finalize();
                let mut bytes = [0u8; 64];
                bytes.copy_from_slice(&out);
                RistrettoPointNG::from_uniform_bytes(&bytes)
            };
            let c = r * h;
            cmts.push(c.compress());
        }
    }
    let mut rng = DeterministicRng::new(pi_hash);
    rp.verify_multiple_with_rng(&bp_gens, &pc_gens, &mut t, &cmts, nbits as usize, &mut rng).is_ok()
}

pub fn pedersen_check_u64(value: u64, blinding: [u8; 32], commitment: [u8; 32]) -> bool {
    let c_pt = match CompressedRistretto(commitment).decompress() { Some(p) => p, None => return false };
    let r = Scalar::from_bytes_mod_order(blinding);
    let v = Scalar::from(value);
    let h = generator_h();
    let expected = v * G + r * h;
    expected == c_pt
}

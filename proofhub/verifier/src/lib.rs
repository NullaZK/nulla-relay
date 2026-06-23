#![no_std]
#![cfg_attr(test, allow(unused_imports))]

extern crate alloc;

use alloc::vec::Vec;
use blake2::digest::Update as BlakeUpdate;
use blake2::Blake2b512;
use blake2::Digest;
use parity_scale_codec::{Decode, Encode};

// ===================================================================
//  Domain separation constants
// ===================================================================
const COMMITMENT_DOMAIN: &[u8] = b"nulla_commitment_v1";
const BALANCE_DOMAIN:    &[u8] = b"nulla_balance_v1";
const PURCHASE_DOMAIN:   &[u8] = b"nulla_purchase_v1";
const WITHDRAWAL_DOMAIN: &[u8] = b"nulla_withdrawal_v1";
const OWNERSHIP_DOMAIN:  &[u8] = b"nulla_rwa_ownership_v1";
const SPEND_TAG_DOMAIN:  &[u8] = b"nulla_spend_tag_v1";

// ML-DSA-44 sizes (FIPS 204)
const DILITHIUM_PK_LEN:  usize = 1312;
const DILITHIUM_SIG_LEN: usize = 2420;

// ===================================================================
//  ProofPublicInputs
// ===================================================================
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
pub struct ProofPublicInputs {
    pub merkle_root:       [u8; 32],
    pub new_merkle_root:   [u8; 32],
    pub input_commitments: Vec<[u8; 32]>,
    pub input_indices:     Vec<u32>,
    pub input_paths:       Vec<Vec<[u8; 32]>>,
    pub nullifiers:        Vec<[u8; 32]>,
    pub new_commitments:   Vec<[u8; 32]>,
    pub fee_commitment:    [u8; 32],
    pub fee_nullifier:     [u8; 32],
    pub tx_id:             [u8; 16],
}

fn blake2_256(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2b512::new();
    BlakeUpdate::update(&mut h, data);
    let out = h.finalize();
    let mut res = [0u8; 32];
    res.copy_from_slice(&out[..32]);
    res
}

pub fn blake3_commitment(value: u64, blinding: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(COMMITMENT_DOMAIN);
    h.update(&value.to_le_bytes());
    h.update(blinding);
    *h.finalize().as_bytes()
}

pub fn ownership_commitment(rwa_id: &[u8; 32], blinding: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(OWNERSHIP_DOMAIN);
    h.update(rwa_id);
    h.update(blinding);
    *h.finalize().as_bytes()
}

pub fn verify_commitment(value: u64, blinding: [u8; 32], commitment: [u8; 32]) -> bool {
    blake3_commitment(value, &blinding) == commitment
}

pub fn verify_bytes(proof: &[u8], public_inputs: &[u8]) -> bool {
    if proof.len() != DILITHIUM_PK_LEN + DILITHIUM_SIG_LEN { return false; }
    if ProofPublicInputs::decode(&mut &public_inputs[..]).is_err() { return false; }
    let mut h = blake3::Hasher::new();
    h.update(BALANCE_DOMAIN);
    h.update(public_inputs);
    let message = h.finalize();
    let mut pk_arr = [0u8; DILITHIUM_PK_LEN];
    pk_arr.copy_from_slice(&proof[..DILITHIUM_PK_LEN]);
    let mut sig_arr = [0u8; DILITHIUM_SIG_LEN];
    sig_arr.copy_from_slice(&proof[DILITHIUM_PK_LEN..]);
    use fips204::ml_dsa_44;
    use fips204::traits::{SerDes, Verifier};
    match ml_dsa_44::PublicKey::try_from_bytes(pk_arr) {
        Ok(pk) => pk.verify(message.as_bytes(), &sig_arr, &[]),
        Err(_) => false,
    }
}

pub fn verify_purchase(proof: &[u8], public_inputs: &[u8]) -> bool {
    if proof.len() != DILITHIUM_PK_LEN + DILITHIUM_SIG_LEN { return false; }
    if public_inputs.len() < 32 { return false; }
    let mut th = blake3::Hasher::new();
    th.update(SPEND_TAG_DOMAIN);
    th.update(&proof[..DILITHIUM_PK_LEN]);
    let derived_tag = *th.finalize().as_bytes();
    if derived_tag != public_inputs[0..32] { return false; }
    let mut h = blake3::Hasher::new();
    h.update(PURCHASE_DOMAIN);
    h.update(public_inputs);
    let message = h.finalize();
    let mut pk_arr = [0u8; DILITHIUM_PK_LEN];
    pk_arr.copy_from_slice(&proof[..DILITHIUM_PK_LEN]);
    let mut sig_arr = [0u8; DILITHIUM_SIG_LEN];
    sig_arr.copy_from_slice(&proof[DILITHIUM_PK_LEN..]);
    use fips204::ml_dsa_44;
    use fips204::traits::{SerDes, Verifier};
    match ml_dsa_44::PublicKey::try_from_bytes(pk_arr) {
        Ok(pk) => pk.verify(message.as_bytes(), &sig_arr, &[]),
        Err(_) => false,
    }
}

pub fn verify_withdrawal(proof: &[u8], public_inputs: &[u8]) -> bool {
    if proof.len() != DILITHIUM_PK_LEN + DILITHIUM_SIG_LEN { return false; }
    if public_inputs.len() < 32 { return false; }
    let mut th = blake3::Hasher::new();
    th.update(SPEND_TAG_DOMAIN);
    th.update(&proof[..DILITHIUM_PK_LEN]);
    let derived_tag = *th.finalize().as_bytes();
    if derived_tag != public_inputs[0..32] { return false; }
    let mut h = blake3::Hasher::new();
    h.update(WITHDRAWAL_DOMAIN);
    h.update(public_inputs);
    let message = h.finalize();
    let mut pk_arr = [0u8; DILITHIUM_PK_LEN];
    pk_arr.copy_from_slice(&proof[..DILITHIUM_PK_LEN]);
    let mut sig_arr = [0u8; DILITHIUM_SIG_LEN];
    sig_arr.copy_from_slice(&proof[DILITHIUM_PK_LEN..]);
    use fips204::ml_dsa_44;
    use fips204::traits::{SerDes, Verifier};
    match ml_dsa_44::PublicKey::try_from_bytes(pk_arr) {
        Ok(pk) => pk.verify(message.as_bytes(), &sig_arr, &[]),
        Err(_) => false,
    }
}

// ===================================================================
//  STARK — winter_verifier types
// ===================================================================
use winter_verifier::{
    Air, AirContext, Assertion, EvaluationFrame, FieldExtension, ProofOptions,
    TraceInfo, TransitionConstraintDegree,
};
use winter_verifier::math::{fields::f128::BaseElement, FieldElement, StarkField, ToElements};
use winter_verifier::crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};

type StarkHash = Blake3_256<BaseElement>;
type StarkCoin = DefaultRandomCoin<StarkHash>;
type StarkVC   = MerkleTree<StarkHash>;

// ===================================================================
//  Poseidon parameters (spec 113 / Phase 8)
// ===================================================================
const POSEIDON_T:      usize = 4;
const POSEIDON_RF:     usize = 8;
const POSEIDON_RP:     usize = 56;
const POSEIDON_ROUNDS: usize = POSEIDON_RF + POSEIDON_RP; // 64

#[inline]
fn poseidon_rc(round: usize, col: usize) -> BaseElement {
    let mut buf = [0u8; 22];
    buf[..19].copy_from_slice(b"poseidon_f128_rc_v1");
    buf[19] = 0x01;
    buf[20] = round as u8;
    buf[21] = col as u8;
    let d = blake3::hash(&buf);
    BaseElement::new(u128::from_le_bytes(d.as_bytes()[..16].try_into().unwrap()))
}

#[inline]
fn poseidon_iv() -> BaseElement {
    let d = blake3::hash(b"poseidon_f128_iv_v1");
    BaseElement::new(u128::from_le_bytes(d.as_bytes()[..16].try_into().unwrap()))
}

#[inline]
fn is_full_round(round: usize) -> bool {
    round < POSEIDON_RF / 2 || round >= POSEIDON_RF / 2 + POSEIDON_RP
}

fn poseidon_periodic() -> Vec<Vec<BaseElement>> {
    let mut rc0 = Vec::with_capacity(POSEIDON_ROUNDS);
    let mut rc1 = Vec::with_capacity(POSEIDON_ROUNDS);
    let mut rc2 = Vec::with_capacity(POSEIDON_ROUNDS);
    let mut rc3 = Vec::with_capacity(POSEIDON_ROUNDS);
    let mut is_full = Vec::with_capacity(POSEIDON_ROUNDS);
    for r in 0..POSEIDON_ROUNDS {
        rc0.push(poseidon_rc(r, 0));
        rc1.push(poseidon_rc(r, 1));
        rc2.push(poseidon_rc(r, 2));
        rc3.push(poseidon_rc(r, 3));
        is_full.push(if is_full_round(r) { BaseElement::ONE } else { BaseElement::ZERO });
    }
    alloc::vec![rc0, rc1, rc2, rc3, is_full]
}

/// Evaluate one Poseidon round.
fn poseidon_eval_round_base(s: &[BaseElement; 4], round: usize, out: &mut [BaseElement; 4]) {
    let is_full = if is_full_round(round) { BaseElement::ONE } else { BaseElement::ZERO };
    let rc = [poseidon_rc(round, 0), poseidon_rc(round, 1), poseidon_rc(round, 2), poseidon_rc(round, 3)];
    let a = [s[0] + rc[0], s[1] + rc[1], s[2] + rc[2], s[3] + rc[3]];
    let ac = [a[0].square()*a[0], a[1].square()*a[1], a[2].square()*a[2], a[3].square()*a[3]];
    let b0 = ac[0];
    let b1 = is_full * ac[1] + (BaseElement::ONE - is_full) * a[1];
    let b2 = is_full * ac[2] + (BaseElement::ONE - is_full) * a[2];
    let b3 = is_full * ac[3] + (BaseElement::ONE - is_full) * a[3];
    let bsum = b0 + b1 + b2 + b3;
    out[0] = b0 + bsum; out[1] = b1 + bsum; out[2] = b2 + bsum; out[3] = b3 + bsum;
}

/// Poseidon permutation (t=4, α=3, 64 rounds).
fn poseidon_perm(state: &mut [BaseElement; 4]) {
    let mut tmp = *state;
    for r in 0..POSEIDON_ROUNDS {
        poseidon_eval_round_base(state, r, &mut tmp);
        *state = tmp;
    }
}

/// Compute commitment: Poseidon(iv, v, blo, bhi) → 32 bytes.
fn poseidon_hash(v: u64, blinding: &[u8; 32]) -> [u8; 32] {
    let blo = u128::from_le_bytes(blinding[..16].try_into().unwrap());
    let bhi = u128::from_le_bytes(blinding[16..].try_into().unwrap());
    let mut state = [poseidon_iv(), BaseElement::new(v as u128), BaseElement::new(blo), BaseElement::new(bhi)];
    poseidon_perm(&mut state);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&state[1].as_int().to_le_bytes());
    out[16..].copy_from_slice(&state[2].as_int().to_le_bytes());
    out
}

// ===================================================================
//  STARK 1 — Range AIR (unchanged from Phase 7)
// ===================================================================
const RANGE_BITS: usize = 64;

#[derive(Clone)]
struct RangePublicInputs { value: u64 }

impl ToElements<BaseElement> for RangePublicInputs {
    fn to_elements(&self) -> alloc::vec::Vec<BaseElement> {
        alloc::vec![BaseElement::new(self.value as u128)]
    }
}

struct RangeAir { ctx: AirContext<BaseElement>, value: u64 }

impl Air for RangeAir {
    type BaseField    = BaseElement;
    type PublicInputs = RangePublicInputs;

    fn new(ti: TraceInfo, pi: RangePublicInputs, opts: ProofOptions) -> Self {
        let d = alloc::vec![
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(1),
        ];
        RangeAir { ctx: AirContext::new(ti, d, 3, opts), value: pi.value }
    }

    fn context(&self) -> &AirContext<BaseElement> { &self.ctx }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self, f: &EvaluationFrame<E>, _p: &[E], r: &mut [E]) {
        let (c, n) = (f.current(), f.next());
        r[0] = c[0] * (c[0] - E::ONE);
        r[1] = n[1] - (c[1] + c[0] * c[2]);
        r[2] = n[2] - c[2].double();
    }

    fn get_assertions(&self) -> alloc::vec::Vec<Assertion<BaseElement>> {
        alloc::vec![
            Assertion::single(1, 0,          BaseElement::ZERO),
            Assertion::single(2, 0,          BaseElement::ONE),
            Assertion::single(1, RANGE_BITS, BaseElement::new(self.value as u128)),
        ]
    }
}

fn verify_stark_range(proof_bytes: &[u8], value: u64) -> bool {
    let proof = match winter_verifier::Proof::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let pub_inputs = RangePublicInputs { value };
    let acceptable = winter_verifier::AcceptableOptions::MinConjecturedSecurity(80);
    winter_verifier::verify::<RangeAir, StarkHash, StarkCoin, StarkVC>(
        proof, pub_inputs, &acceptable,
    ).is_ok()
}

// ===================================================================
//  STARK 2 — DepositCommitAir (Phase 8)
// ===================================================================
#[derive(Clone)]
struct DepositCommitPI { v: u64, rp_commitment: [u8; 32] }

impl ToElements<BaseElement> for DepositCommitPI {
    fn to_elements(&self) -> alloc::vec::Vec<BaseElement> {
        alloc::vec![
            BaseElement::new(self.v as u128),
            BaseElement::new(u128::from_le_bytes(self.rp_commitment[..16].try_into().unwrap())),
            BaseElement::new(u128::from_le_bytes(self.rp_commitment[16..].try_into().unwrap())),
        ]
    }
}

struct DepositCommitAir { ctx: AirContext<BaseElement>, v: u64, rp_commitment: [u8; 32] }

impl Air for DepositCommitAir {
    type BaseField    = BaseElement;
    type PublicInputs = DepositCommitPI;

    fn new(ti: TraceInfo, pi: DepositCommitPI, opts: ProofOptions) -> Self {
        let d = alloc::vec![
            TransitionConstraintDegree::with_cycles(3, alloc::vec![64]),
            TransitionConstraintDegree::with_cycles(3, alloc::vec![64]),
            TransitionConstraintDegree::with_cycles(3, alloc::vec![64]),
            TransitionConstraintDegree::with_cycles(3, alloc::vec![64]),
        ];
        DepositCommitAir { ctx: AirContext::new(ti, d, 3, opts), v: pi.v, rp_commitment: pi.rp_commitment }
    }

    fn context(&self) -> &AirContext<BaseElement> { &self.ctx }

    fn get_periodic_column_values(&self) -> Vec<Vec<BaseElement>> { poseidon_periodic() }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self, f: &EvaluationFrame<E>, p: &[E], r: &mut [E]) {
        let one = E::ONE;
        let s = [f.current()[0], f.current()[1], f.current()[2], f.current()[3]];
        let n = [f.next()[0],    f.next()[1],    f.next()[2],    f.next()[3]];
        // p: [rc0, rc1, rc2, rc3, is_full]
        let a = [s[0]+p[0], s[1]+p[1], s[2]+p[2], s[3]+p[3]];
        let ac = [a[0].square()*a[0], a[1].square()*a[1], a[2].square()*a[2], a[3].square()*a[3]];
        let b0 = ac[0];
        let b1 = p[4]*ac[1] + (one-p[4])*a[1];
        let b2 = p[4]*ac[2] + (one-p[4])*a[2];
        let b3 = p[4]*ac[3] + (one-p[4])*a[3];
        let bsum = b0+b1+b2+b3;
        r[0] = n[0] - (b0+bsum);
        r[1] = n[1] - (b1+bsum);
        r[2] = n[2] - (b2+bsum);
        r[3] = n[3] - (b3+bsum);
    }

    fn get_assertions(&self) -> alloc::vec::Vec<Assertion<BaseElement>> {
        let vf    = BaseElement::new(self.v as u128);
        let rp_lo = BaseElement::new(u128::from_le_bytes(self.rp_commitment[..16].try_into().unwrap()));
        let rp_hi = BaseElement::new(u128::from_le_bytes(self.rp_commitment[16..].try_into().unwrap()));
        alloc::vec![
            Assertion::single(1, 0,               vf),
            Assertion::single(1, POSEIDON_ROUNDS,  rp_lo),
            Assertion::single(2, POSEIDON_ROUNDS,  rp_hi),
        ]
    }
}

fn verify_stark_deposit_commit(proof_bytes: &[u8], v: u64, rp_commitment: &[u8; 32]) -> bool {
    let proof = match winter_verifier::Proof::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let pub_inputs = DepositCommitPI { v, rp_commitment: *rp_commitment };
    let acceptable = winter_verifier::AcceptableOptions::MinConjecturedSecurity(80);
    winter_verifier::verify::<DepositCommitAir, StarkHash, StarkCoin, StarkVC>(
        proof, pub_inputs, &acceptable,
    ).is_ok()
}

// ===================================================================
//  STARK 3 — PurchaseAir (Phase 8)
// ===================================================================
const PURCHASE_RANGE_ROWS:    usize = RANGE_BITS; // 64
const PURCHASE_POSEIDON_ROWS: usize = POSEIDON_ROUNDS; // 64
const PURCHASE_BRIDGE_STEP:   usize = PURCHASE_RANGE_ROWS + 2 * PURCHASE_POSEIDON_ROWS - 1; // 191

#[derive(Clone)]
struct PurchasePI { rp_commitment: [u8; 32], change_rp_commitment: [u8; 32], price: u64 }

impl ToElements<BaseElement> for PurchasePI {
    fn to_elements(&self) -> alloc::vec::Vec<BaseElement> {
        alloc::vec![
            BaseElement::new(u128::from_le_bytes(self.rp_commitment[..16].try_into().unwrap())),
            BaseElement::new(u128::from_le_bytes(self.rp_commitment[16..].try_into().unwrap())),
            BaseElement::new(u128::from_le_bytes(self.change_rp_commitment[..16].try_into().unwrap())),
            BaseElement::new(u128::from_le_bytes(self.change_rp_commitment[16..].try_into().unwrap())),
            BaseElement::new(self.price as u128),
        ]
    }
}

struct PurchaseAir { ctx: AirContext<BaseElement>, rp_commitment: [u8; 32], change_rp_commitment: [u8; 32], price: u64 }

impl Air for PurchaseAir {
    type BaseField    = BaseElement;
    type PublicInputs = PurchasePI;

    fn new(ti: TraceInfo, pi: PurchasePI, opts: ProofOptions) -> Self {
        let d = alloc::vec![
            // r[0..3]: Poseidon (base 3, period-64 is_full) + is_pos×is_bridge (period 512)
            TransitionConstraintDegree::with_cycles(3, alloc::vec![64, 512, 512]),
            TransitionConstraintDegree::with_cycles(3, alloc::vec![64, 512, 512]),
            TransitionConstraintDegree::with_cycles(3, alloc::vec![64, 512, 512]),
            TransitionConstraintDegree::with_cycles(3, alloc::vec![64, 512, 512]),
            // r[4,5]: range (base 2) + is_rng×is_bridge (period 512)
            TransitionConstraintDegree::with_cycles(2, alloc::vec![512, 512]),
            TransitionConstraintDegree::with_cycles(2, alloc::vec![512, 512]),
            // r[6]: doubling (base 1) + is_rng×is_bridge
            TransitionConstraintDegree::with_cycles(1, alloc::vec![512, 512]),
        ];
        // Always 8 assertions. When no change note (change_rp=[0;32]) the
        // expected change output is poseidon_hash(0,[0;32]) — enforces v==price.
        PurchaseAir { ctx: AirContext::new(ti, d, 8, opts), rp_commitment: pi.rp_commitment, change_rp_commitment: pi.change_rp_commitment, price: pi.price }
    }

    fn context(&self) -> &AirContext<BaseElement> { &self.ctx }

    fn get_periodic_column_values(&self) -> Vec<Vec<BaseElement>> {
        let tl = 512usize;
        let mut is_pos    = alloc::vec![BaseElement::ZERO; tl];
        let mut is_rng    = alloc::vec![BaseElement::ZERO; tl];
        let mut is_lnk    = alloc::vec![BaseElement::ZERO; tl];
        let mut is_bridge = alloc::vec![BaseElement::ZERO; tl];
        for i in 0..PURCHASE_RANGE_ROWS { is_rng[i] = BaseElement::ONE; }
        // Input Poseidon: steps 64-127 (step 64 mod 64 = 0)
        for i in PURCHASE_RANGE_ROWS..(PURCHASE_RANGE_ROWS + PURCHASE_POSEIDON_ROWS) { is_pos[i] = BaseElement::ONE; }
        // Bridge at step 191: disables all constraints, allows reset to change initial
        is_bridge[PURCHASE_BRIDGE_STEP] = BaseElement::ONE;
        // Change Poseidon: steps 192-255 (step 192 mod 64 = 0)
        let change_pos_start = PURCHASE_BRIDGE_STEP + 1; // 192
        for i in change_pos_start..(change_pos_start + PURCHASE_POSEIDON_ROWS) { is_pos[i] = BaseElement::ONE; }
        if PURCHASE_RANGE_ROWS > 0 { is_lnk[PURCHASE_RANGE_ROWS - 1] = BaseElement::ONE; }
        let mut res = alloc::vec![is_pos, is_rng, is_lnk, is_bridge];
        res.extend(poseidon_periodic());
        res
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self, f: &EvaluationFrame<E>, p: &[E], r: &mut [E]) {
        // p: [is_pos, is_rng, is_lnk, is_bridge, rc0, rc1, rc2, rc3, is_full]
        let (is_pos, is_rng, is_lnk, is_bridge) = (p[0], p[1], p[2], p[3]);
        let one = E::ONE;
        let price_f = E::from(BaseElement::new(self.price as u128));
        let c = f.current(); let n = f.next();

        let s = [c[0], c[1], c[2], c[3]];
        let a = [s[0]+p[4], s[1]+p[5], s[2]+p[6], s[3]+p[7]];
        let ac = [a[0].square()*a[0], a[1].square()*a[1], a[2].square()*a[2], a[3].square()*a[3]];
        let b0 = ac[0];
        let b1 = p[8]*ac[1] + (one-p[8])*a[1];
        let b2 = p[8]*ac[2] + (one-p[8])*a[2];
        let b3 = p[8]*ac[3] + (one-p[8])*a[3];
        let bsum = b0+b1+b2+b3;
        let exp = [b0+bsum, b1+bsum, b2+bsum, b3+bsum];

        let raw0 = (n[0]-c[0]) + is_pos*(c[0]-exp[0]);
        let freeze1 = n[1]-c[1];
        let link1   = n[1]-n[5]-price_f;
        let non_pos1 = (one-is_lnk)*freeze1 + is_lnk*link1;
        let raw1 = is_pos*(n[1]-exp[1]) + (one-is_pos)*non_pos1;
        let raw2 = (n[2]-c[2]) + is_pos*(c[2]-exp[2]);
        let raw3 = (n[3]-c[3]) + is_pos*(c[3]-exp[3]);
        let bit = c[4];
        let raw4 = is_rng*(bit*(bit-one)) + (one-is_rng)*(n[4]-c[4]);
        let raw5 = is_rng*(n[5]-(c[5]+c[4]*c[6])) + (one-is_rng)*(n[5]-c[5]);
        let raw6 = is_rng*(n[6]-c[6].double()) + (one-is_rng)*(n[6]-c[6]);

        let ena = one - is_bridge;
        r[0]=ena*raw0; r[1]=ena*raw1; r[2]=ena*raw2; r[3]=ena*raw3;
        r[4]=ena*raw4; r[5]=ena*raw5; r[6]=ena*raw6;
    }

    fn get_assertions(&self) -> alloc::vec::Vec<Assertion<BaseElement>> {
        let iv      = poseidon_iv();
        let rp_lo   = BaseElement::new(u128::from_le_bytes(self.rp_commitment[..16].try_into().unwrap()));
        let rp_hi   = BaseElement::new(u128::from_le_bytes(self.rp_commitment[16..].try_into().unwrap()));
        let crp_lo  = BaseElement::new(u128::from_le_bytes(self.change_rp_commitment[..16].try_into().unwrap()));
        let crp_hi  = BaseElement::new(u128::from_le_bytes(self.change_rp_commitment[16..].try_into().unwrap()));
        let bridge_row        = PURCHASE_RANGE_ROWS + PURCHASE_POSEIDON_ROWS;     // 128
        let change_start_row  = PURCHASE_BRIDGE_STEP + 1;                          // 192
        let change_out_row    = change_start_row + PURCHASE_POSEIDON_ROWS;         // 256
        // When no change note (change_rp=[0;32]), assert against poseidon_hash(0,[0;32])
        // so the circuit enforces v-price=0.
        let (crp_lo, crp_hi) = if self.change_rp_commitment == [0u8; 32] {
            let zero_crp = poseidon_hash(0, &[0u8; 32]);
            (
                BaseElement::new(u128::from_le_bytes(zero_crp[..16].try_into().unwrap())),
                BaseElement::new(u128::from_le_bytes(zero_crp[16..].try_into().unwrap())),
            )
        } else {
            (crp_lo, crp_hi)
        };
        alloc::vec![
            Assertion::single(5, 0,                   BaseElement::ZERO),
            Assertion::single(6, 0,                   BaseElement::ONE),
            Assertion::single(0, PURCHASE_RANGE_ROWS, iv),
            Assertion::single(1, bridge_row,          rp_lo),
            Assertion::single(2, bridge_row,          rp_hi),
            Assertion::single(0, change_start_row,    iv),
            Assertion::single(1, change_out_row,      crp_lo),
            Assertion::single(2, change_out_row,      crp_hi),
        ]
    }
}

fn verify_stark_purchase(proof_bytes: &[u8], rp_commitment: &[u8; 32], change_rp_commitment: &[u8; 32], price: u64) -> bool {
    let proof = match winter_verifier::Proof::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let pub_inputs = PurchasePI { rp_commitment: *rp_commitment, change_rp_commitment: *change_rp_commitment, price };
    let acceptable = winter_verifier::AcceptableOptions::MinConjecturedSecurity(80);
    winter_verifier::verify::<PurchaseAir, StarkHash, StarkCoin, StarkVC>(
        proof, pub_inputs, &acceptable,
    ).is_ok()
}

// ===================================================================
//  verify_range_proof — Phase 8
//
//  Wire format (range_proof param of deposit_public):
//    byte 0:              n_proofs: u8  (must be 1)
//    bytes 1..5:          range_proof_len: u32 LE
//    bytes 5..5+rlen:     range STARK bytes (proves v < 2^64)
//    bytes 5+rlen..+8:    v: u64 LE  (PUBLIC — needed for token transfer)
//    bytes +8..+4:        commit_proof_len: u32 LE
//    bytes then:          commit STARK bytes (proves Poseidon(v,blinding)=rp_commitment)
//
//  rp_commitment is passed in from call data (stored on-chain by pallet).
// ===================================================================

pub fn verify_range_proof(range_proof: &[u8], rp_commitment: &[u8; 32]) -> bool {
    if range_proof.is_empty() { return false; }
    let n_proofs = range_proof[0] as usize;
    if n_proofs != 1 { return false; }

    let mut off = 1usize;

    // Range proof length
    if off + 4 > range_proof.len() { return false; }
    let rlen = u32::from_le_bytes(range_proof[off..off+4].try_into().unwrap_or([0u8;4])) as usize;
    off += 4;

    // Range proof bytes
    if off + rlen > range_proof.len() { return false; }
    let range_bytes = &range_proof[off..off+rlen];
    off += rlen;

    // Value (public, needed for verification)
    if off + 8 > range_proof.len() { return false; }
    let value = u64::from_le_bytes(range_proof[off..off+8].try_into().unwrap_or([0u8;8]));
    off += 8;

    // Commitment proof length
    if off + 4 > range_proof.len() { return false; }
    let clen = u32::from_le_bytes(range_proof[off..off+4].try_into().unwrap_or([0u8;4])) as usize;
    off += 4;

    // Commitment proof bytes
    if off + clen > range_proof.len() { return false; }
    let commit_bytes = &range_proof[off..off+clen];

    // 1. Verify range STARK (v < 2^64)
    if !verify_stark_range(range_bytes, value) { return false; }

    // 2. Verify deposit commitment STARK (Poseidon(v, blinding) = rp_commitment)
    if !verify_stark_deposit_commit(commit_bytes, value, rp_commitment) { return false; }

    true
}

// ===================================================================
//  verify_purchase_proof — Phase 8
//
//  Verifies PurchaseAir STARK:
//    Poseidon(iv, v, blinding)        = rp_commitment        AND v >= price
//    Poseidon(iv, v-price, c_blinding) = change_rp_commitment
//
//  proof:                raw STARK proof bytes
//  rp_commitment:        from on-chain SpendTagRpCommitments storage
//  change_rp_commitment: from on-chain SpendTagRpCommitments[change_spend_tag]
//                        (pass [0u8;32] when no change note; circuit handles it)
//  price:                from on-chain RwaPrices storage
// ===================================================================

pub fn verify_purchase_proof(proof: &[u8], rp_commitment: &[u8; 32], change_rp_commitment: &[u8; 32], price: u64) -> bool {
    verify_stark_purchase(proof, rp_commitment, change_rp_commitment, price)
}

// ===================================================================
//  Phase 9 — v2 zk-membership primitives (ZK_MEMBERSHIP_SPEC_V2.md)
//
//  Domain-separated Poseidon hashing for v2 notes, nullifiers, and the
//  incremental depth-20 Merkle tree. These functions are the single
//  source of truth shared by the pallet (via ProofVerify), the SpendAir
//  circuit, and the wallet prover.
// ===================================================================
pub mod v2 {
    use super::*;
    use alloc::vec::Vec;

    /// Tree depth — capacity 2^20 = 1,048,576 leaves.
    pub const MERKLE_DEPTH: usize = 20;

    pub const PK_DIGEST_DOMAIN: &[u8] = b"nulla_pk_digest_v2";
    pub const SPEND_AUTH_DOMAIN: &[u8] = b"nulla_spend_auth_v2";
    pub const WITHDRAW_AUTH_DOMAIN: &[u8] = b"nulla_withdraw_auth_v2";

    #[inline]
    fn iv_from_domain(domain: &[u8]) -> BaseElement {
        let d = blake3::hash(domain);
        BaseElement::new(u128::from_le_bytes(d.as_bytes()[..16].try_into().unwrap()))
    }

    /// NOTE_IV_V2 = F128(LE16(BLAKE3("nulla_note_iv_v2")))
    pub fn note_iv() -> BaseElement { iv_from_domain(b"nulla_note_iv_v2") }
    /// NULLIFIER_IV_V2 = F128(LE16(BLAKE3("nulla_nullifier_iv_v2")))
    pub fn nullifier_iv() -> BaseElement { iv_from_domain(b"nulla_nullifier_iv_v2") }
    /// MERKLE_IV_V2 = F128(LE16(BLAKE3("nulla_merkle_iv_v2")))
    pub fn merkle_iv() -> BaseElement { iv_from_domain(b"nulla_merkle_iv_v2") }

    /// Split 32 bytes into (lo, hi) field elements (little-endian, spec §2).
    #[inline]
    pub fn unpack(bytes: &[u8; 32]) -> (BaseElement, BaseElement) {
        let lo = BaseElement::new(u128::from_le_bytes(bytes[..16].try_into().unwrap()));
        let hi = BaseElement::new(u128::from_le_bytes(bytes[16..].try_into().unwrap()));
        (lo, hi)
    }

    /// Pack (lo, hi) field elements into 32 bytes (spec §2).
    #[inline]
    pub fn pack(lo: BaseElement, hi: BaseElement) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&lo.as_int().to_le_bytes());
        out[16..].copy_from_slice(&hi.as_int().to_le_bytes());
        out
    }

    /// pkd = BLAKE3("nulla_pk_digest_v2" ‖ ml_dsa_pk)
    pub fn pk_digest(ml_dsa_pk: &[u8]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(PK_DIGEST_DOMAIN);
        h.update(ml_dsa_pk);
        *h.finalize().as_bytes()
    }

    /// Note leaf (spec §4.1): two-permutation sponge over (v, b, pkd).
    pub fn note_hash(v: u64, b: &[u8; 32], pkd: &[u8; 32]) -> [u8; 32] {
        let (b_lo, b_hi) = unpack(b);
        let (pkd_lo, pkd_hi) = unpack(pkd);
        let mut state = [note_iv(), BaseElement::new(v as u128), b_lo, b_hi];
        poseidon_perm(&mut state);
        state[1] += pkd_lo;
        state[2] += pkd_hi;
        poseidon_perm(&mut state);
        pack(state[1], state[2])
    }

    /// Nullifier (spec §4.2): one permutation over the blinding.
    pub fn nullifier_hash(b: &[u8; 32]) -> [u8; 32] {
        let (b_lo, b_hi) = unpack(b);
        let mut state = [nullifier_iv(), b_lo, b_hi, BaseElement::ZERO];
        poseidon_perm(&mut state);
        pack(state[1], state[2])
    }

    /// Merkle node hash (spec §5): two-permutation sponge over (L, R).
    pub fn merkle_hash2(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let (l_lo, l_hi) = unpack(left);
        let (r_lo, r_hi) = unpack(right);
        let mut state = [merkle_iv(), l_lo, l_hi, r_lo];
        poseidon_perm(&mut state);
        state[1] += r_hi;
        poseidon_perm(&mut state);
        pack(state[1], state[2])
    }

    /// Zero-subtree constants: Z[0] = [0;32], Z[i+1] = hash2(Z[i], Z[i]).
    /// Returns Z[0..=MERKLE_DEPTH] (21 entries). Root of empty tree = Z[20].
    pub fn zero_subtrees() -> Vec<[u8; 32]> {
        let mut z = Vec::with_capacity(MERKLE_DEPTH + 1);
        z.push([0u8; 32]);
        for i in 0..MERKLE_DEPTH {
            let prev = z[i];
            z.push(merkle_hash2(&prev, &prev));
        }
        z
    }

    /// Incremental frontier state: left-sibling node per level + leaf count.
    /// `frontier[d]` is the pending left node at depth d (leaf level = 0).
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct Frontier {
        pub nodes: [[u8; 32]; MERKLE_DEPTH],
        pub leaf_count: u32,
    }

    impl Default for Frontier {
        fn default() -> Self {
            Frontier { nodes: [[0u8; 32]; MERKLE_DEPTH], leaf_count: 0 }
        }
    }

    impl Frontier {
        /// Insert a leaf. Returns Err(()) when the tree is full.
        pub fn insert(&mut self, leaf: [u8; 32]) -> Result<(), ()> {
            if self.leaf_count as u64 >= (1u64 << MERKLE_DEPTH) { return Err(()); }
            let mut node = leaf;
            let mut idx = self.leaf_count;
            for d in 0..MERKLE_DEPTH {
                if idx & 1 == 0 {
                    self.nodes[d] = node;
                    break;
                }
                node = merkle_hash2(&self.nodes[d], &node);
                idx >>= 1;
            }
            self.leaf_count += 1;
            Ok(())
        }

        /// Compute the current root by folding the frontier with zero subtrees.
        ///
        /// The cursor starts as the empty subtree at leaf level and is folded
        /// upward: at depth d, if bit d of leaf_count is 1 there is a completed
        /// left subtree in `nodes[d]` (cursor is its right sibling); otherwise
        /// the cursor is a left child paired with the empty subtree Z[d].
        pub fn root(&self) -> [u8; 32] {
            let z = zero_subtrees();
            let mut node = z[0];
            let mut idx = self.leaf_count;
            for d in 0..MERKLE_DEPTH {
                node = if idx & 1 == 1 {
                    merkle_hash2(&self.nodes[d], &node)
                } else {
                    merkle_hash2(&node, &z[d])
                };
                idx >>= 1;
            }
            node
        }
    }

    /// Reference (non-incremental) root computation for testing: builds the
    /// full depth-20 tree over `leaves`, padding with Z[0].
    pub fn reference_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        let z = zero_subtrees();
        let mut level: Vec<[u8; 32]> = leaves.to_vec();
        for d in 0..MERKLE_DEPTH {
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            let mut i = 0;
            while i < level.len() {
                let l = level[i];
                let r = if i + 1 < level.len() { level[i + 1] } else { z[d] };
                next.push(merkle_hash2(&l, &r));
                i += 2;
            }
            if next.is_empty() { next.push(z[d + 1]); }
            level = next;
        }
        level[0]
    }

    /// Verify a depth-20 Merkle path: fold `leaf` upward using
    /// `index` bit-ordering and `siblings`, compare to `root`.
    pub fn verify_merkle_path(
        leaf: &[u8; 32],
        index: u32,
        siblings: &[[u8; 32]; MERKLE_DEPTH],
        root: &[u8; 32],
    ) -> bool {
        let mut node = *leaf;
        let mut idx = index;
        for d in 0..MERKLE_DEPTH {
            node = if idx & 1 == 0 {
                merkle_hash2(&node, &siblings[d])
            } else {
                merkle_hash2(&siblings[d], &node)
            };
            idx >>= 1;
        }
        node == *root
    }
}

// ===================================================================
//  Phase 9 — STARK 4: SpendAir v2 (zk Merkle membership)
//
//  Trace: 8192 rows, 14 columns, 128-row blocks. Within each active
//  block: step 0 = boundary (link / absorb / freeze), steps 1–64 =
//  Poseidon rounds 0–63, steps 65–127 = state freeze.
//
//  Block schedule (45 active blocks):
//    b0          nullifier perm        (boundary: freeze; row-0 init constraints)
//    b1          note perm 1           (boundary: link  [NOTE_IV, v, b_lo, b_hi])
//    b2          note perm 2           (boundary: absorb pkd_lo/pkd_hi  — PUBLIC)
//    b3+2d/b4+2d merkle level d perms  (boundary: link mux / absorb r_hi carry)
//    b43         change perm 1         (boundary: link [NOTE_IV, cv, cb_lo, cb_hi])
//    b44         change perm 2         (boundary: absorb change_pkd — PUBLIC)
//    b45–b63     padding
//
//  Columns:
//    0–3  Poseidon state
//    4    bit (range bits rows 0–127; merkle index bit per level)
//    5    acc (range accumulator)        6  pow (powers of two)
//    7    b_lo carry    8  b_hi carry    (frozen entire trace)
//    9    aux_lo        10 aux_hi        (sibling per merkle level; change blinding)
//    11   r_hi carry (right-input high limb for merkle absorb)
//    12   v carry       13 cv carry      (frozen entire trace)
//
//  Public inputs (§6.1): root, nullifier, pkd, price_or_amount,
//  change_leaf, change_pkd, mode (0 = withdraw, 1 = purchase).
// ===================================================================
pub mod spend_v2 {
    use super::*;
    use super::v2;
    use alloc::vec::Vec;

    pub const TRACE_LEN: usize = 8192;
    pub const TRACE_WIDTH: usize = 14;
    pub const BLOCK: usize = 128;
    pub const LEVELS: usize = v2::MERKLE_DEPTH; // 20

    pub const STEP_LNOTE: usize = 128;
    pub const STEP_ANOTE: usize = 256;
    pub const STEP_MRK_BASE: usize = 384; // link of level d at 384 + 256d
    pub const STEP_LCHG: usize = STEP_MRK_BASE + 256 * LEVELS; // 5504
    pub const STEP_ACHG: usize = STEP_LCHG + BLOCK; // 5632
    pub const ROW_NF_OUT: usize = 65;
    pub const ROW_ROOT: usize = STEP_LCHG - BLOCK + 65; // 5441
    pub const ROW_CLEAF: usize = STEP_ACHG + 65; // 5697
    pub const ACTIVE_BLOCKS: usize = 45;

    #[derive(Clone)]
    pub struct SpendPI {
        pub root: [u8; 32],
        pub nullifier: [u8; 32],
        pub pkd: [u8; 32],
        pub price_or_amount: u64,
        pub change_leaf: [u8; 32],
        pub change_pkd: [u8; 32],
        /// 0 = withdraw (v == amount, cv == 0), 1 = purchase (v - cv == price).
        pub mode: u64,
    }

    impl ToElements<BaseElement> for SpendPI {
        fn to_elements(&self) -> Vec<BaseElement> {
            let (r_lo, r_hi) = v2::unpack(&self.root);
            let (n_lo, n_hi) = v2::unpack(&self.nullifier);
            let (p_lo, p_hi) = v2::unpack(&self.pkd);
            let (cl_lo, cl_hi) = v2::unpack(&self.change_leaf);
            let (cp_lo, cp_hi) = v2::unpack(&self.change_pkd);
            alloc::vec![
                r_lo, r_hi, n_lo, n_hi, p_lo, p_hi,
                BaseElement::new(self.price_or_amount as u128),
                cl_lo, cl_hi, cp_lo, cp_hi,
                BaseElement::new(self.mode as u128),
            ]
        }
    }

    /// Period-128 Poseidon round schedule: block step s ∈ 1..=64 runs round s−1.
    pub fn poseidon_periodic_128() -> Vec<Vec<BaseElement>> {
        let z = BaseElement::ZERO;
        let mut rc0 = alloc::vec![z; BLOCK];
        let mut rc1 = alloc::vec![z; BLOCK];
        let mut rc2 = alloc::vec![z; BLOCK];
        let mut rc3 = alloc::vec![z; BLOCK];
        let mut isf = alloc::vec![z; BLOCK];
        for s in 1..=64usize {
            let r = s - 1;
            rc0[s] = poseidon_rc(r, 0);
            rc1[s] = poseidon_rc(r, 1);
            rc2[s] = poseidon_rc(r, 2);
            rc3[s] = poseidon_rc(r, 3);
            isf[s] = if is_full_round(r) { BaseElement::ONE } else { BaseElement::ZERO };
        }
        alloc::vec![rc0, rc1, rc2, rc3, isf]
    }

    /// Full-length (8192) schedule masks.
    /// Order: [m_rnd, m_frz, m_lnote, m_anote, m_lmrk, m_amrk, m_lchg, m_achg,
    ///         m_rstep, m_rst, m_chk2, m_row0, m_auxfrz, m_bitfrz, m_rhifrz]
    pub fn spend_masks() -> Vec<Vec<BaseElement>> {
        let z = BaseElement::ZERO;
        let o = BaseElement::ONE;
        let n = TRACE_LEN;
        let mut m_rnd    = alloc::vec![z; n];
        let mut m_frz    = alloc::vec![z; n];
        let mut m_lnote  = alloc::vec![z; n];
        let mut m_anote  = alloc::vec![z; n];
        let mut m_lmrk   = alloc::vec![z; n];
        let mut m_amrk   = alloc::vec![z; n];
        let mut m_lchg   = alloc::vec![z; n];
        let mut m_achg   = alloc::vec![z; n];
        let mut m_rstep  = alloc::vec![z; n];
        let mut m_rst    = alloc::vec![z; n];
        let mut m_chk2   = alloc::vec![z; n];
        let mut m_row0   = alloc::vec![z; n];
        let mut m_auxfrz = alloc::vec![o; n];
        let mut m_bitfrz = alloc::vec![z; n];
        let mut m_rhifrz = alloc::vec![o; n];
        for b in 0..ACTIVE_BLOCKS {
            for s in 1..=64 { m_rnd[b * BLOCK + s] = o; }
            for s in 65..BLOCK { m_frz[b * BLOCK + s] = o; }
        }
        m_frz[0] = o; // nullifier block boundary: hold initial state
        m_lnote[STEP_LNOTE] = o;
        m_anote[STEP_ANOTE] = o;
        for d in 0..LEVELS {
            m_lmrk[STEP_MRK_BASE + 256 * d] = o;
            m_amrk[STEP_MRK_BASE + 256 * d + BLOCK] = o;
            m_auxfrz[STEP_MRK_BASE + 256 * d] = z;
            m_rhifrz[STEP_MRK_BASE + 256 * d] = z;
        }
        m_lchg[STEP_LCHG] = o;
        m_achg[STEP_ACHG] = o;
        m_auxfrz[STEP_LCHG] = z;
        for s in 0..63 { m_rstep[s] = o; }
        for s in 64..127 { m_rstep[s] = o; }
        m_rst[63] = o;
        m_chk2[127] = o;
        m_row0[0] = o;
        for s in STEP_MRK_BASE..STEP_LCHG {
            if (s - STEP_MRK_BASE) % 256 != 0 { m_bitfrz[s] = o; }
        }
        alloc::vec![
            m_rnd, m_frz, m_lnote, m_anote, m_lmrk, m_amrk, m_lchg, m_achg,
            m_rstep, m_rst, m_chk2, m_row0, m_auxfrz, m_bitfrz, m_rhifrz,
        ]
    }

    pub struct SpendAir {
        ctx: AirContext<BaseElement>,
        pi: SpendPI,
        note_iv: BaseElement,
        merkle_iv: BaseElement,
        nullifier_iv: BaseElement,
    }

    impl Air for SpendAir {
        type BaseField = BaseElement;
        type PublicInputs = SpendPI;

        fn new(ti: TraceInfo, pi: SpendPI, opts: ProofOptions) -> Self {
            let d = alloc::vec![
                // r0–r3: Poseidon round (cube w/ period-128 rc) × full mask
                TransitionConstraintDegree::with_cycles(3, alloc::vec![BLOCK, TRACE_LEN]),
                TransitionConstraintDegree::with_cycles(3, alloc::vec![BLOCK, TRACE_LEN]),
                TransitionConstraintDegree::with_cycles(3, alloc::vec![BLOCK, TRACE_LEN]),
                TransitionConstraintDegree::with_cycles(3, alloc::vec![BLOCK, TRACE_LEN]),
                // r4: bit boolean
                TransitionConstraintDegree::new(2),
                // r5: acc step/reset
                TransitionConstraintDegree::with_cycles(2, alloc::vec![TRACE_LEN]),
                // r6: pow step/reset
                TransitionConstraintDegree::with_cycles(1, alloc::vec![TRACE_LEN]),
                // r7: range sum checks (v at step 63, cv at step 127)
                TransitionConstraintDegree::with_cycles(2, alloc::vec![TRACE_LEN]),
                // r8–r11: global carries (b_lo, b_hi, v, cv)
                TransitionConstraintDegree::new(1),
                TransitionConstraintDegree::new(1),
                TransitionConstraintDegree::new(1),
                TransitionConstraintDegree::new(1),
                // r12–r13: aux freeze
                TransitionConstraintDegree::with_cycles(1, alloc::vec![TRACE_LEN]),
                TransitionConstraintDegree::with_cycles(1, alloc::vec![TRACE_LEN]),
                // r14: bit freeze in merkle region
                TransitionConstraintDegree::with_cycles(1, alloc::vec![TRACE_LEN]),
                // r15: r_hi carry set/freeze
                TransitionConstraintDegree::with_cycles(2, alloc::vec![TRACE_LEN]),
                // r16–r17: value conservation
                TransitionConstraintDegree::new(1),
                TransitionConstraintDegree::new(1),
                // r18–r21: row-0 nullifier init
                TransitionConstraintDegree::with_cycles(1, alloc::vec![TRACE_LEN]),
                TransitionConstraintDegree::with_cycles(1, alloc::vec![TRACE_LEN]),
                TransitionConstraintDegree::with_cycles(1, alloc::vec![TRACE_LEN]),
                TransitionConstraintDegree::with_cycles(1, alloc::vec![TRACE_LEN]),
            ];
            SpendAir {
                ctx: AirContext::new(ti, d, 8, opts),
                pi,
                note_iv: v2::note_iv(),
                merkle_iv: v2::merkle_iv(),
                nullifier_iv: v2::nullifier_iv(),
            }
        }

        fn context(&self) -> &AirContext<BaseElement> { &self.ctx }

        fn get_periodic_column_values(&self) -> Vec<Vec<BaseElement>> {
            let mut res = poseidon_periodic_128();
            res.extend(spend_masks());
            res
        }

        fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
            &self, f: &EvaluationFrame<E>, p: &[E], r: &mut [E]) {
            // p: [rc0,rc1,rc2,rc3,isf,
            //     m_rnd,m_frz,m_lnote,m_anote,m_lmrk,m_amrk,m_lchg,m_achg,
            //     m_rstep,m_rst,m_chk2,m_row0,m_auxfrz,m_bitfrz,m_rhifrz]
            let one = E::ONE;
            let c = f.current();
            let n = f.next();
            let (rc0, rc1, rc2, rc3, isf) = (p[0], p[1], p[2], p[3], p[4]);
            let (m_rnd, m_frz, m_lnote, m_anote) = (p[5], p[6], p[7], p[8]);
            let (m_lmrk, m_amrk, m_lchg, m_achg) = (p[9], p[10], p[11], p[12]);
            let (m_rstep, m_rst, m_chk2, m_row0) = (p[13], p[14], p[15], p[16]);
            let (m_auxfrz, m_bitfrz, m_rhifrz) = (p[17], p[18], p[19]);

            let note_iv = E::from(self.note_iv);
            let merkle_iv = E::from(self.merkle_iv);
            let nullifier_iv = E::from(self.nullifier_iv);
            let (pkd_lo_b, pkd_hi_b) = v2::unpack(&self.pi.pkd);
            let (cpkd_lo_b, cpkd_hi_b) = v2::unpack(&self.pi.change_pkd);
            let pkd_lo = E::from(pkd_lo_b);
            let pkd_hi = E::from(pkd_hi_b);
            let cpkd_lo = E::from(cpkd_lo_b);
            let cpkd_hi = E::from(cpkd_hi_b);
            let price = E::from(BaseElement::new(self.pi.price_or_amount as u128));
            let mode = E::from(BaseElement::new(self.pi.mode as u128));

            // --- Poseidon round on current state ---
            let a = [c[0] + rc0, c[1] + rc1, c[2] + rc2, c[3] + rc3];
            let ac = [
                a[0].square() * a[0], a[1].square() * a[1],
                a[2].square() * a[2], a[3].square() * a[3],
            ];
            let b0 = ac[0];
            let b1 = isf * ac[1] + (one - isf) * a[1];
            let b2 = isf * ac[2] + (one - isf) * a[2];
            let b3 = isf * ac[3] + (one - isf) * a[3];
            let bsum = b0 + b1 + b2 + b3;
            let exp = [b0 + bsum, b1 + bsum, b2 + bsum, b3 + bsum];

            // --- merkle link mux (bit/sibling read from NEXT row: frozen per level) ---
            let bit = n[4];
            let l_lo = bit * n[9] + (one - bit) * c[1];
            let l_hi = bit * n[10] + (one - bit) * c[2];
            let r_lo = bit * c[1] + (one - bit) * n[9];
            let r_hi = bit * c[2] + (one - bit) * n[10];

            // r0–r3: state column transitions (masks are disjoint per step)
            let lnote = [note_iv, c[12], c[7], c[8]];
            let lmrk = [merkle_iv, l_lo, l_hi, r_lo];
            let lchg = [note_iv, c[13], n[9], n[10]];
            let abs1 = m_anote * pkd_lo + m_amrk * c[11] + m_achg * cpkd_lo;
            let abs2 = m_anote * pkd_hi + m_achg * cpkd_hi;
            let m_abs = m_anote + m_amrk + m_achg;
            for i in 0..4 {
                let absorb_i = match i { 1 => abs1, 2 => abs2, _ => E::ZERO };
                r[i] = m_rnd * (n[i] - exp[i])
                    + m_frz * (n[i] - c[i])
                    + m_lnote * (n[i] - lnote[i])
                    + m_lmrk * (n[i] - lmrk[i])
                    + m_lchg * (n[i] - lchg[i])
                    + m_abs * (n[i] - c[i]) - absorb_i;
            }

            // r4: bit is boolean everywhere
            r[4] = c[4] * (c[4] - one);
            // r5: range accumulator step + reset at step 63
            r[5] = m_rstep * (n[5] - c[5] - c[4] * c[6]) + m_rst * n[5];
            // r6: pow doubling + reset to 1 at step 63
            r[6] = m_rstep * (n[6] - c[6].double()) + m_rst * (n[6] - one);
            // r7: range sum checks — v at step 63, cv at step 127
            r[7] = m_rst * (c[5] + c[4] * c[6] - c[12])
                 + m_chk2 * (c[5] + c[4] * c[6] - c[13]);
            // r8–r11: global carries frozen
            r[8] = n[7] - c[7];
            r[9] = n[8] - c[8];
            r[10] = n[12] - c[12];
            r[11] = n[13] - c[13];
            // r12–r13: aux frozen except at merkle/change link steps
            r[12] = m_auxfrz * (n[9] - c[9]);
            r[13] = m_auxfrz * (n[10] - c[10]);
            // r14: index bit frozen within each merkle level
            r[14] = m_bitfrz * (n[4] - c[4]);
            // r15: r_hi carry set at merkle link, frozen otherwise
            r[15] = m_lmrk * (n[11] - r_hi) + m_rhifrz * (n[11] - c[11]);
            // r16: v − mode·cv − P == 0  (purchase: v−cv=price; withdraw: v=amount)
            r[16] = c[12] - mode * c[13] - price;
            // r17: withdraw mode forces cv == 0
            r[17] = (one - mode) * c[13];
            // r18–r21: nullifier perm initial state at row 0
            r[18] = m_row0 * (c[0] - nullifier_iv);
            r[19] = m_row0 * (c[1] - c[7]);
            r[20] = m_row0 * (c[2] - c[8]);
            r[21] = m_row0 * c[3];
        }

        fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
            let (nf_lo, nf_hi) = v2::unpack(&self.pi.nullifier);
            let (root_lo, root_hi) = v2::unpack(&self.pi.root);
            let (cl_lo, cl_hi) = v2::unpack(&self.pi.change_leaf);
            alloc::vec![
                Assertion::single(5, 0, BaseElement::ZERO),
                Assertion::single(6, 0, BaseElement::ONE),
                Assertion::single(1, ROW_NF_OUT, nf_lo),
                Assertion::single(2, ROW_NF_OUT, nf_hi),
                Assertion::single(1, ROW_ROOT, root_lo),
                Assertion::single(2, ROW_ROOT, root_hi),
                Assertion::single(1, ROW_CLEAF, cl_lo),
                Assertion::single(2, ROW_CLEAF, cl_hi),
            ]
        }
    }

    /// Verify a SpendAir v2 STARK proof.
    ///
    /// `mode` true = purchase (`v − cv == price_or_amount`),
    /// false = withdraw (`v == price_or_amount`, `cv == 0`).
    pub fn verify_spend_v2(
        proof_bytes: &[u8],
        root: &[u8; 32],
        nullifier: &[u8; 32],
        pkd: &[u8; 32],
        price_or_amount: u64,
        change_leaf: &[u8; 32],
        change_pkd: &[u8; 32],
        purchase_mode: bool,
    ) -> bool {
        let proof = match winter_verifier::Proof::from_bytes(proof_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let pi = SpendPI {
            root: *root,
            nullifier: *nullifier,
            pkd: *pkd,
            price_or_amount,
            change_leaf: *change_leaf,
            change_pkd: *change_pkd,
            mode: if purchase_mode { 1 } else { 0 },
        };
        let acceptable = winter_verifier::AcceptableOptions::MinConjecturedSecurity(80);
        winter_verifier::verify::<SpendAir, StarkHash, StarkCoin, StarkVC>(
            proof, pi, &acceptable,
        ).is_ok()
    }

    /// Canonical zero-change leaf used in withdraw mode:
    /// NoteHash(0, [0;32], [0;32]).
    pub fn zero_change_leaf() -> [u8; 32] {
        v2::note_hash(0, &[0u8; 32], &[0u8; 32])
    }

    /// Proof-generation infrastructure — only compiled when feature = "prover".
    #[cfg(feature = "prover")]
    pub mod prover_impl {
        use super::*;
        use super::super::poseidon_eval_round_base;
        use winter_verifier::math::{fields::f128::BaseElement, FieldElement};
        use winterfell::{
            crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
            matrix::ColMatrix,
            AuxRandElements, BatchingMethod, CompositionPoly, CompositionPolyTrace,
            DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde,
            FieldExtension, PartitionOptions, ProofOptions, Prover, StarkDomain,
            TraceInfo, TracePolyTable, TraceTable,
        };
        type HashFn = Blake3_256<BaseElement>;
        type VC = MerkleTree<HashFn>;
        type RandCoin = DefaultRandomCoin<HashFn>;

        pub struct SpendWitness {
            pub v: u64, pub b: [u8; 32], pub pkd: [u8; 32], pub index: u32,
            pub siblings: [[u8; 32]; LEVELS],
            pub cv: u64, pub cb: [u8; 32], pub cpkd: [u8; 32],
        }

        fn run_perm_rows(cols: &mut [alloc::vec::Vec<BaseElement>], start_row: usize) {
            for k in 0..64 {
                let s = [cols[0][start_row+k], cols[1][start_row+k],
                         cols[2][start_row+k], cols[3][start_row+k]];
                let mut out = [BaseElement::ZERO; 4];
                poseidon_eval_round_base(&s, k, &mut out);
                cols[0][start_row+k+1] = out[0];
                cols[1][start_row+k+1] = out[1];
                cols[2][start_row+k+1] = out[2];
                cols[3][start_row+k+1] = out[3];
            }
        }

        fn freeze_state_rows(cols: &mut [alloc::vec::Vec<BaseElement>], from_row: usize, to_row: usize) {
            for r in from_row..=to_row {
                for c in 0..4 { cols[c][r] = cols[c][r-1]; }
            }
        }

        pub fn build_spend_trace(w: &SpendWitness) -> TraceTable<BaseElement> {
            let n = TRACE_LEN;
            let z = BaseElement::ZERO;
            let one = BaseElement::ONE;
            let mut cols: alloc::vec::Vec<alloc::vec::Vec<BaseElement>> =
                alloc::vec![alloc::vec![z; n]; TRACE_WIDTH];

            let (b_lo, b_hi)       = v2::unpack(&w.b);
            let (pkd_lo, pkd_hi)   = v2::unpack(&w.pkd);
            let (cb_lo, cb_hi)     = v2::unpack(&w.cb);
            let (cpkd_lo, cpkd_hi) = v2::unpack(&w.cpkd);
            let vf  = BaseElement::new(w.v  as u128);
            let cvf = BaseElement::new(w.cv as u128);

            // Global carries (cols 7, 8, 12, 13).
            for r in 0..n {
                cols[7][r]  = b_lo;
                cols[8][r]  = b_hi;
                cols[12][r] = vf;
                cols[13][r] = cvf;
            }
            // Bit column col[4]: v bits rows 0-63, cv bits rows 64-127, merkle bits per level.
            for i in 0..64 {
                cols[4][i]      = BaseElement::new(((w.v  >> i) & 1) as u128);
                cols[4][64 + i] = BaseElement::new(((w.cv >> i) & 1) as u128);
            }
            for d in 0..LEVELS {
                let bit = BaseElement::new(((w.index >> d) & 1) as u128);
                for r in (385 + 256 * d)..=(384 + 256 * (d + 1)) { cols[4][r] = bit; }
            }
            // acc / pow (cols 5, 6).
            cols[5][0] = z;
            cols[6][0] = one;
            for s in 0..63 {
                cols[5][s + 1] = cols[5][s] + cols[4][s] * cols[6][s];
                cols[6][s + 1] = cols[6][s].double();
            }
            cols[5][64] = z;
            cols[6][64] = one;
            for s in 64..127 {
                cols[5][s + 1] = cols[5][s] + cols[4][s] * cols[6][s];
                cols[6][s + 1] = cols[6][s].double();
            }
            for r in 128..n {
                cols[5][r] = cols[5][127];
                cols[6][r] = cols[6][127];
            }
            // aux columns (9, 10): siblings per level, change blinding at the end.
            for d in 0..LEVELS {
                let (s_lo, s_hi) = v2::unpack(&w.siblings[d]);
                for r in (385 + 256 * d)..=(384 + 256 * (d + 1)) {
                    cols[9][r]  = s_lo;
                    cols[10][r] = s_hi;
                }
            }
            for r in 5505..n {
                cols[9][r]  = cb_lo;
                cols[10][r] = cb_hi;
            }

            // --- State simulation ---
            // Block 0: nullifier perm.
            cols[0][0] = v2::nullifier_iv();
            cols[1][0] = b_lo;
            cols[2][0] = b_hi;
            cols[3][0] = z;
            freeze_state_rows(&mut cols, 1, 1);
            run_perm_rows(&mut cols, 1);
            freeze_state_rows(&mut cols, 66, 128);
            // Block 1: note perm 1.
            cols[0][129] = v2::note_iv();
            cols[1][129] = vf;
            cols[2][129] = b_lo;
            cols[3][129] = b_hi;
            run_perm_rows(&mut cols, 129);
            freeze_state_rows(&mut cols, 194, 256);
            // Block 2: note perm 2 (absorb pkd).
            cols[0][257] = cols[0][256];
            cols[1][257] = cols[1][256] + pkd_lo;
            cols[2][257] = cols[2][256] + pkd_hi;
            cols[3][257] = cols[3][256];
            run_perm_rows(&mut cols, 257);
            freeze_state_rows(&mut cols, 322, 384);
            // Merkle levels.
            for d in 0..LEVELS {
                let base = STEP_MRK_BASE + 256 * d;
                let cur1 = cols[1][base];
                let cur2 = cols[2][base];
                let bit  = (w.index >> d) & 1;
                let (s_lo, s_hi) = v2::unpack(&w.siblings[d]);
                let (l_lo, l_hi, r_lo, r_hi) = if bit == 1 {
                    (s_lo, s_hi, cur1, cur2)
                } else {
                    (cur1, cur2, s_lo, s_hi)
                };
                cols[0][base + 1] = v2::merkle_iv();
                cols[1][base + 1] = l_lo;
                cols[2][base + 1] = l_hi;
                cols[3][base + 1] = r_lo;
                let rhi_end = core::cmp::min(base + 256, n - 1);
                for r in (base + 1)..=rhi_end { cols[11][r] = r_hi; }
                run_perm_rows(&mut cols, base + 1);
                freeze_state_rows(&mut cols, base + 66, base + 128);
                cols[0][base + 129] = cols[0][base + 128];
                cols[1][base + 129] = cols[1][base + 128] + r_hi;
                cols[2][base + 129] = cols[2][base + 128];
                cols[3][base + 129] = cols[3][base + 128];
                run_perm_rows(&mut cols, base + 129);
                freeze_state_rows(&mut cols, base + 194, base + 256);
                if d == LEVELS - 1 {
                    for r in (base + 257)..n { cols[11][r] = r_hi; }
                }
            }
            // Change note (link at STEP_LCHG).
            cols[0][STEP_LCHG + 1] = v2::note_iv();
            cols[1][STEP_LCHG + 1] = cvf;
            cols[2][STEP_LCHG + 1] = cb_lo;
            cols[3][STEP_LCHG + 1] = cb_hi;
            run_perm_rows(&mut cols, STEP_LCHG + 1);
            freeze_state_rows(&mut cols, STEP_LCHG + 66, STEP_ACHG);
            cols[0][STEP_ACHG + 1] = cols[0][STEP_ACHG];
            cols[1][STEP_ACHG + 1] = cols[1][STEP_ACHG] + cpkd_lo;
            cols[2][STEP_ACHG + 1] = cols[2][STEP_ACHG] + cpkd_hi;
            cols[3][STEP_ACHG + 1] = cols[3][STEP_ACHG];
            run_perm_rows(&mut cols, STEP_ACHG + 1);
            freeze_state_rows(&mut cols, ROW_CLEAF + 1, n - 1);

            TraceTable::init(cols)
        }

                struct SpendProverInner {
            pi: SpendPI,
            options: ProofOptions,
        }

        impl Prover for SpendProverInner {
            type BaseField = BaseElement;
            type Air = SpendAir;
            type Trace = TraceTable<BaseElement>;
            type HashFn = HashFn;
            type VC = VC;
            type RandomCoin = RandCoin;
            type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
                DefaultTraceLde<E, Self::HashFn, Self::VC>;
            type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
                DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
            type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
                DefaultConstraintEvaluator<'a, Self::Air, E>;
            fn get_pub_inputs(&self, _: &Self::Trace) -> SpendPI { self.pi.clone() }
            fn options(&self) -> &ProofOptions { &self.options }
            fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
                &self, ti: &TraceInfo, mt: &ColMatrix<Self::BaseField>,
                d: &StarkDomain<Self::BaseField>, po: PartitionOptions,
            ) -> (Self::TraceLde<E>, TracePolyTable<E>) { DefaultTraceLde::new(ti, mt, d, po) }
            fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
                &self, cpt: CompositionPolyTrace<E>, nc: usize,
                d: &StarkDomain<Self::BaseField>, po: PartitionOptions,
            ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
                DefaultConstraintCommitment::new(cpt, nc, d, po)
            }
            fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
                &self, air: &'a Self::Air, are: Option<AuxRandElements<E>>,
                cc: winterfell::ConstraintCompositionCoefficients<E>,
            ) -> Self::ConstraintEvaluator<'a, E> {
                DefaultConstraintEvaluator::new(air, are, cc)
            }
        }

        /// Generate the STARK proof bytes. `mode` = 1 for purchase, 0 for withdraw.
        pub fn prove_spend(w: &SpendWitness, price_or_amount: u64, mode: u64) -> alloc::vec::Vec<u8> {
            let note_leaf = v2::note_hash(w.v, &w.b, &w.pkd);
            let root = {
                let mut node = note_leaf;
                let mut idx = w.index;
                for d in 0..LEVELS {
                    node = if idx & 1 == 0 {
                        v2::merkle_hash2(&node, &w.siblings[d])
                    } else {
                        v2::merkle_hash2(&w.siblings[d], &node)
                    };
                    idx >>= 1;
                }
                node
            };
            let nullifier = v2::nullifier_hash(&w.b);
            let (change_leaf, change_pkd) = if mode == 1 {
                (v2::note_hash(w.cv, &w.cb, &w.cpkd), w.cpkd)
            } else {
                (zero_change_leaf(), [0u8; 32])
            };
            let pi = SpendPI { root, nullifier, pkd: w.pkd, price_or_amount, change_leaf, change_pkd, mode };
            let trace = build_spend_trace(w);
            let prover = SpendProverInner {
                pi,
                options: ProofOptions::new(28, 8, 0, FieldExtension::None, 8, 127,
                    BatchingMethod::Linear, BatchingMethod::Horner),
            };
            prover.prove(trace).expect("spend STARK").to_bytes()
        }
    }
}

// ===================================================================
//  Phase 9 — STARK 5: DepositV2Air
//
//  Proves: leaf = NoteHash(amount, b, pkd) for private (b, pkd),
//  with `amount` and `leaf` public. Stops a depositor inserting a
//  leaf whose hidden value differs from the paid amount.
//
//  Trace: 256 rows × 6 columns, two 128-row blocks (perm1, perm2).
//  Cols: 0–3 state, 4 pkd_lo carry, 5 pkd_hi carry.
// ===================================================================
pub mod deposit_v2 {
    use super::*;
    use super::v2;
    use alloc::vec::Vec;

    pub const TRACE_LEN: usize = 256;
    pub const TRACE_WIDTH: usize = 6;
    pub const ROW_LEAF: usize = 193;

    #[derive(Clone)]
    pub struct DepositPI {
        pub amount: u64,
        pub leaf: [u8; 32],
    }

    impl ToElements<BaseElement> for DepositPI {
        fn to_elements(&self) -> Vec<BaseElement> {
            let (l_lo, l_hi) = v2::unpack(&self.leaf);
            alloc::vec![BaseElement::new(self.amount as u128), l_lo, l_hi]
        }
    }

    fn deposit_masks() -> Vec<Vec<BaseElement>> {
        let z = BaseElement::ZERO;
        let o = BaseElement::ONE;
        let n = TRACE_LEN;
        let mut m_rnd = alloc::vec![z; n];
        let mut m_frz = alloc::vec![z; n];
        let mut m_abs = alloc::vec![z; n];
        for b in 0..2 {
            for s in 1..=64 { m_rnd[b * 128 + s] = o; }
            for s in 65..128 { m_frz[b * 128 + s] = o; }
        }
        m_frz[0] = o;
        m_abs[128] = o;
        alloc::vec![m_rnd, m_frz, m_abs]
    }

    pub struct DepositV2Air {
        ctx: AirContext<BaseElement>,
        pi: DepositPI,
        note_iv: BaseElement,
    }

    impl Air for DepositV2Air {
        type BaseField = BaseElement;
        type PublicInputs = DepositPI;

        fn new(ti: TraceInfo, pi: DepositPI, opts: ProofOptions) -> Self {
            let d = alloc::vec![
                TransitionConstraintDegree::with_cycles(3, alloc::vec![128, TRACE_LEN]),
                TransitionConstraintDegree::with_cycles(3, alloc::vec![128, TRACE_LEN]),
                TransitionConstraintDegree::with_cycles(3, alloc::vec![128, TRACE_LEN]),
                TransitionConstraintDegree::with_cycles(3, alloc::vec![128, TRACE_LEN]),
                TransitionConstraintDegree::new(1),
                TransitionConstraintDegree::new(1),
            ];
            DepositV2Air { ctx: AirContext::new(ti, d, 4, opts), pi, note_iv: v2::note_iv() }
        }

        fn context(&self) -> &AirContext<BaseElement> { &self.ctx }

        fn get_periodic_column_values(&self) -> Vec<Vec<BaseElement>> {
            let mut res = spend_v2::poseidon_periodic_128();
            res.extend(deposit_masks());
            res
        }

        fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
            &self, f: &EvaluationFrame<E>, p: &[E], r: &mut [E]) {
            // p: [rc0,rc1,rc2,rc3,isf, m_rnd, m_frz, m_abs]
            let one = E::ONE;
            let c = f.current();
            let n = f.next();
            let (rc0, rc1, rc2, rc3, isf) = (p[0], p[1], p[2], p[3], p[4]);
            let (m_rnd, m_frz, m_abs) = (p[5], p[6], p[7]);

            let a = [c[0] + rc0, c[1] + rc1, c[2] + rc2, c[3] + rc3];
            let ac = [
                a[0].square() * a[0], a[1].square() * a[1],
                a[2].square() * a[2], a[3].square() * a[3],
            ];
            let b0 = ac[0];
            let b1 = isf * ac[1] + (one - isf) * a[1];
            let b2 = isf * ac[2] + (one - isf) * a[2];
            let b3 = isf * ac[3] + (one - isf) * a[3];
            let bsum = b0 + b1 + b2 + b3;
            let exp = [b0 + bsum, b1 + bsum, b2 + bsum, b3 + bsum];

            for i in 0..4 {
                let absorb_i = match i { 1 => c[4], 2 => c[5], _ => E::ZERO };
                r[i] = m_rnd * (n[i] - exp[i])
                    + m_frz * (n[i] - c[i])
                    + m_abs * (n[i] - c[i] - absorb_i);
            }
            r[4] = n[4] - c[4];
            r[5] = n[5] - c[5];
        }

        fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
            let (l_lo, l_hi) = v2::unpack(&self.pi.leaf);
            alloc::vec![
                Assertion::single(0, 0, self.note_iv),
                Assertion::single(1, 0, BaseElement::new(self.pi.amount as u128)),
                Assertion::single(1, ROW_LEAF, l_lo),
                Assertion::single(2, ROW_LEAF, l_hi),
            ]
        }
    }

    /// Verify a DepositV2Air STARK proof.
    pub fn verify_deposit_v2(proof_bytes: &[u8], amount: u64, leaf: &[u8; 32]) -> bool {
        let proof = match winter_verifier::Proof::from_bytes(proof_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let pi = DepositPI { amount, leaf: *leaf };
        let acceptable = winter_verifier::AcceptableOptions::MinConjecturedSecurity(80);
        winter_verifier::verify::<DepositV2Air, StarkHash, StarkCoin, StarkVC>(
            proof, pi, &acceptable,
        ).is_ok()
    }

    #[cfg(feature = "prover")]
    pub mod prover_impl {
        use super::*;
        use winter_verifier::math::{fields::f128::BaseElement, FieldElement};
        use winterfell::{
            crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
            matrix::ColMatrix,
            AuxRandElements, BatchingMethod, CompositionPoly, CompositionPolyTrace,
            DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde,
            FieldExtension, PartitionOptions, ProofOptions, Prover, StarkDomain,
            TraceInfo, TracePolyTable, TraceTable,
        };
        type HashFn = Blake3_256<BaseElement>;
        type VC = MerkleTree<HashFn>;
        type RandCoin = DefaultRandomCoin<HashFn>;

        fn run_perm_rows(cols: &mut [alloc::vec::Vec<BaseElement>], start_row: usize) {
            use super::super::poseidon_eval_round_base;
            for k in 0..64 {
                let s = [cols[0][start_row+k], cols[1][start_row+k],
                         cols[2][start_row+k], cols[3][start_row+k]];
                let mut out = [BaseElement::ZERO; 4];
                poseidon_eval_round_base(&s, k, &mut out);
                cols[0][start_row+k+1] = out[0];
                cols[1][start_row+k+1] = out[1];
                cols[2][start_row+k+1] = out[2];
                cols[3][start_row+k+1] = out[3];
            }
        }

        fn freeze_state_rows(cols: &mut [alloc::vec::Vec<BaseElement>], from_row: usize, to_row: usize) {
            for r in from_row..=to_row {
                for c in 0..4 { cols[c][r] = cols[c][r-1]; }
            }
        }

        pub fn build_deposit_trace(v: u64, b: &[u8; 32], pkd: &[u8; 32]) -> TraceTable<BaseElement> {
            let n = TRACE_LEN;
            let z = BaseElement::ZERO;
            let mut cols: alloc::vec::Vec<alloc::vec::Vec<BaseElement>> =
                alloc::vec![alloc::vec![z; n]; TRACE_WIDTH];
            let (b_lo, b_hi)     = v2::unpack(b);
            let (pkd_lo, pkd_hi) = v2::unpack(pkd);
            for r in 0..n {
                cols[4][r] = pkd_lo;
                cols[5][r] = pkd_hi;
            }
            cols[0][0] = v2::note_iv();
            cols[1][0] = BaseElement::new(v as u128);
            cols[2][0] = b_lo;
            cols[3][0] = b_hi;
            freeze_state_rows(&mut cols, 1, 1);
            run_perm_rows(&mut cols, 1);          // out at row 65
            freeze_state_rows(&mut cols, 66, 128);
            cols[0][129] = cols[0][128];
            cols[1][129] = cols[1][128] + pkd_lo;
            cols[2][129] = cols[2][128] + pkd_hi;
            cols[3][129] = cols[3][128];
            run_perm_rows(&mut cols, 129);        // leaf at row 193
            freeze_state_rows(&mut cols, 194, n - 1);
            TraceTable::init(cols)
        }

        struct DepositProverInner {
            pi: DepositPI,
            options: ProofOptions,
        }

        impl Prover for DepositProverInner {
            type BaseField = BaseElement;
            type Air = DepositV2Air;
            type Trace = TraceTable<BaseElement>;
            type HashFn = HashFn;
            type VC = VC;
            type RandomCoin = RandCoin;
            type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
                DefaultTraceLde<E, Self::HashFn, Self::VC>;
            type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
                DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
            type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
                DefaultConstraintEvaluator<'a, Self::Air, E>;
            fn get_pub_inputs(&self, _: &Self::Trace) -> DepositPI { self.pi.clone() }
            fn options(&self) -> &ProofOptions { &self.options }
            fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
                &self, ti: &TraceInfo, mt: &ColMatrix<Self::BaseField>,
                d: &StarkDomain<Self::BaseField>, po: PartitionOptions,
            ) -> (Self::TraceLde<E>, TracePolyTable<E>) { DefaultTraceLde::new(ti, mt, d, po) }
            fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
                &self, cpt: CompositionPolyTrace<E>, nc: usize,
                d: &StarkDomain<Self::BaseField>, po: PartitionOptions,
            ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
                DefaultConstraintCommitment::new(cpt, nc, d, po)
            }
            fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
                &self, air: &'a Self::Air, are: Option<AuxRandElements<E>>,
                cc: winterfell::ConstraintCompositionCoefficients<E>,
            ) -> Self::ConstraintEvaluator<'a, E> {
                DefaultConstraintEvaluator::new(air, are, cc)
            }
        }

        /// Returns `(leaf, proof_bytes)`. The leaf is what you pass to `deposit_v2`.
        pub fn prove_deposit(v: u64, b: &[u8; 32], pkd: &[u8; 32]) -> ([u8; 32], alloc::vec::Vec<u8>) {
            let leaf = v2::note_hash(v, b, pkd);
            let prover = DepositProverInner {
                pi: DepositPI { amount: v, leaf },
                options: ProofOptions::new(28, 8, 0, FieldExtension::None, 8, 127,
                    BatchingMethod::Linear, BatchingMethod::Horner),
            };
            let trace = build_deposit_trace(v, b, pkd);
            let proof = prover.prove(trace).expect("deposit STARK").to_bytes();
            (leaf, proof)
        }
    }
}

// ===================================================================
//  Phase 9 — v2 spend authorization (ML-DSA-44)
//
//  auth = pk (1312 bytes) ‖ sig (2420 bytes)
//  message = BLAKE3(domain ‖ public_inputs)
//  domain:  "nulla_spend_auth_v2" (purchase) /
//           "nulla_withdraw_auth_v2" (withdraw)
//
//  The pk digest binds the signing key to the note inside the STARK:
//  pkd = BLAKE3("nulla_pk_digest_v2" ‖ pk) is a SpendAir public input.
// ===================================================================
pub fn verify_spend_auth_v2(auth: &[u8], public_inputs: &[u8], withdraw: bool) -> bool {
    if auth.len() != DILITHIUM_PK_LEN + DILITHIUM_SIG_LEN { return false; }
    let domain: &[u8] = if withdraw { v2::WITHDRAW_AUTH_DOMAIN } else { v2::SPEND_AUTH_DOMAIN };
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(public_inputs);
    let message = h.finalize();
    let mut pk_arr = [0u8; DILITHIUM_PK_LEN];
    pk_arr.copy_from_slice(&auth[..DILITHIUM_PK_LEN]);
    let mut sig_arr = [0u8; DILITHIUM_SIG_LEN];
    sig_arr.copy_from_slice(&auth[DILITHIUM_PK_LEN..]);
    use fips204::ml_dsa_44;
    use fips204::traits::{SerDes, Verifier};
    match ml_dsa_44::PublicKey::try_from_bytes(pk_arr) {
        Ok(pk) => pk.verify(message.as_bytes(), &sig_arr, &[]),
        Err(_) => false,
    }
}

/// Proof generation (wallet / test binary side).
/// Enabled by the `prover` feature — not compiled into the runtime.
#[cfg(feature = "prover")]
pub mod prover {
    /// Re-export deposit proof builder.
    pub use super::deposit_v2::prover_impl::{build_deposit_trace, prove_deposit};
    /// Re-export spend proof builder and witness type.
    pub use super::spend_v2::prover_impl::{SpendWitness, build_spend_trace, prove_spend};
    /// Re-export v2 crypto helpers needed by wallet code.
    pub use super::v2::{
        MERKLE_DEPTH as LEVELS, note_hash, nullifier_hash, pk_digest, reference_root,
        zero_subtrees, verify_merkle_path, merkle_hash2,
        SPEND_AUTH_DOMAIN, WITHDRAW_AUTH_DOMAIN,
    };

    /// Compute Merkle root from a leaf, its index, and sibling path.
    pub fn root_from_path(leaf: &[u8; 32], index: u32, siblings: &[[u8; 32]; super::v2::MERKLE_DEPTH]) -> [u8; 32] {
        let mut node = *leaf;
        let mut idx = index;
        for d in 0..super::v2::MERKLE_DEPTH {
            node = if idx & 1 == 0 {
                super::v2::merkle_hash2(&node, &siblings[d])
            } else {
                super::v2::merkle_hash2(&siblings[d], &node)
            };
            idx >>= 1;
        }
        node
    }

    /// Build the `auth` field for `purchase_rwa_v2` / `withdraw_v2`.
    /// Returns: ml_dsa_pk (1312 B) ‖ ml_dsa_sig (2420 B).
    /// `auth_sig` = the raw 2420-byte ML-DSA-44 signature (caller must sign
    /// BLAKE3(domain ‖ public_inputs_encoded) externally).
    /// `withdraw` controls which domain constant to use for doc purposes only
    /// — the actual signing is done by the caller.
    pub fn assemble_auth(pk_bytes: &[u8; 1312], sig_bytes: &[u8; 2420]) -> alloc::vec::Vec<u8> {
        let mut auth = alloc::vec::Vec::with_capacity(1312 + 2420);
        auth.extend_from_slice(pk_bytes);
        auth.extend_from_slice(sig_bytes);
        auth
    }

    struct DeterministicSignRng([u8; 32]);
    impl rand_core::RngCore for DeterministicSignRng {
        fn next_u32(&mut self) -> u32 { u32::from_le_bytes([self.0[0],self.0[1],self.0[2],self.0[3]]) }
        fn next_u64(&mut self) -> u64 { u64::from_le_bytes(self.0[..8].try_into().unwrap()) }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for (i, b) in dest.iter_mut().enumerate() { *b = self.0[i % 32]; }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest); Ok(())
        }
    }
    impl rand_core::CryptoRng for DeterministicSignRng {}
}
#[cfg(test)]
extern crate std;

#[cfg(test)]
mod v2_tests {
    use super::v2::*;
    use alloc::vec::Vec;
    use std::println;

    #[test]
    fn vectors_v2_note() {
        let b = [0x01u8; 32];
        let pkd = pk_digest(&[0xAAu8; 1312]);
        let leaf = note_hash(1_000_000_000_000, &b, &pkd);
        std::println!("TV1 leaf      = 0x{}", hex::encode(leaf));
        assert_eq!(hex::encode(leaf), "363f6c51a0cf01cc9a2b6fa5d4cc28ba4cc643f3c3cddaea5ecc398b58cdaa54");
        // Determinism + sensitivity checks
        assert_eq!(leaf, note_hash(1_000_000_000_000, &b, &pkd));
        assert_ne!(leaf, note_hash(1_000_000_000_001, &b, &pkd));
        let mut b2 = b; b2[0] ^= 1;
        assert_ne!(leaf, note_hash(1_000_000_000_000, &b2, &pkd));
    }

    #[test]
    fn vectors_v2_nullifier() {
        let b = [0x01u8; 32];
        let nf = nullifier_hash(&b);
        std::println!("TV2 nullifier = 0x{}", hex::encode(nf));
        assert_eq!(hex::encode(nf), "711c97a5ff501b1fb5c50bb26e8ed7264b4a71c9e2c930c9ca6a37ab70d6a197");
        // Nullifier must differ from note leaf domain (IV separation)
        let pkd = pk_digest(&[0xAAu8; 1312]);
        assert_ne!(nf, note_hash(0, &b, &pkd));
        let mut b2 = b; b2[31] ^= 1;
        assert_ne!(nf, nullifier_hash(&b2));
    }

    #[test]
    fn vectors_v2_zero_tree() {
        let z = zero_subtrees();
        assert_eq!(z.len(), MERKLE_DEPTH + 1);
        std::println!("TV3 Z[1]  = 0x{}", hex::encode(z[1]));
        std::println!("TV3 Z[20] = 0x{}", hex::encode(z[20]));
        assert_eq!(hex::encode(z[1]), "fa2f639f908a626af5500aec23fc077c906b61f06fa5848cf403352319c71195");
        assert_eq!(hex::encode(z[20]), "6f058357458704a6a10a7d213a60068faf228d8f64fe0b7c958549504d0b3d26");
        assert_eq!(Frontier::default().root(), z[20]);
    }

    #[test]
    fn vectors_v2_insert() {
        let b = [0x01u8; 32];
        let pkd = pk_digest(&[0xAAu8; 1312]);
        let leaf = note_hash(1_000_000_000_000, &b, &pkd);
        let mut f = Frontier::default();
        f.insert(leaf).unwrap();
        let root = f.root();
        std::println!("TV4 root(1)   = 0x{}", hex::encode(root));
        assert_eq!(hex::encode(root), "fc03a304b54cba3e3a297e8b83f96515775eec8a1ed472ac251df0a7a754795a");
        assert_eq!(root, reference_root(&[leaf]));
    }

    #[test]
    fn frontier_matches_reference_many() {
        // Cross-check incremental frontier against the reference tree
        // for a non-trivial leaf count including odd/even boundaries.
        let mut leaves = Vec::new();
        let mut f = Frontier::default();
        for i in 0u32..37 {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            let leaf = note_hash(i as u64 * 17 + 1, &b, &pk_digest(&[i as u8; 1312]));
            leaves.push(leaf);
            f.insert(leaf).unwrap();
            assert_eq!(f.root(), reference_root(&leaves), "mismatch at {} leaves", i + 1);
        }
        assert_eq!(f.leaf_count, 37);
    }

    #[test]
    fn merkle_path_verifies() {
        // Build small tree, extract sibling path manually via reference levels.
        let mut leaves = Vec::new();
        for i in 0u32..5 {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            leaves.push(note_hash(i as u64, &b, &pk_digest(&[i as u8; 1312])));
        }
        let z = zero_subtrees();
        let root = reference_root(&leaves);
        // Compute path for leaf index 2.
        let target = 2usize;
        let mut siblings = [[0u8; 32]; MERKLE_DEPTH];
        let mut level: Vec<[u8; 32]> = leaves.clone();
        let mut idx = target;
        for d in 0..MERKLE_DEPTH {
            let sib_idx = idx ^ 1;
            siblings[d] = if sib_idx < level.len() { level[sib_idx] } else { z[d] };
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            let mut i = 0;
            while i < level.len() {
                let l = level[i];
                let r = if i + 1 < level.len() { level[i + 1] } else { z[d] };
                next.push(merkle_hash2(&l, &r));
                i += 2;
            }
            if next.is_empty() { next.push(z[d + 1]); }
            level = next;
            idx >>= 1;
        }
        assert!(verify_merkle_path(&leaves[target], target as u32, &siblings, &root));
        // Wrong index fails
        assert!(!verify_merkle_path(&leaves[target], 3, &siblings, &root));
    }
}

// ===================================================================
//  SpendAir v2 — E2E prover tests (mirror trace builder).
//  The production wallet prover ports `build_spend_trace` verbatim.
// ===================================================================
#[cfg(test)]
mod spend_v2_tests {
    use super::spend_v2::*;
    use super::v2;
    use super::poseidon_eval_round_base;
    use alloc::vec::Vec;
    use winter_verifier::math::{fields::f128::BaseElement, FieldElement};
    use winterfell::{
        crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
        matrix::ColMatrix,
        AuxRandElements, BatchingMethod, CompositionPoly, CompositionPolyTrace,
        DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde,
        FieldExtension, PartitionOptions, ProofOptions, Prover, StarkDomain,
        TraceInfo, TracePolyTable, TraceTable,
    };

    type HashFn = Blake3_256<BaseElement>;
    type VC = MerkleTree<HashFn>;
    type RandCoin = DefaultRandomCoin<HashFn>;

    /// Witness for a v2 spend.
    struct SpendWitness {
        v: u64,
        b: [u8; 32],
        pkd: [u8; 32],
        index: u32,
        siblings: [[u8; 32]; LEVELS],
        cv: u64,
        cb: [u8; 32],
        cpkd: [u8; 32],
    }

    fn run_perm_rows(cols: &mut [Vec<BaseElement>], start_row: usize) {
        for k in 0..64 {
            let s = [
                cols[0][start_row + k], cols[1][start_row + k],
                cols[2][start_row + k], cols[3][start_row + k],
            ];
            let mut out = [BaseElement::ZERO; 4];
            poseidon_eval_round_base(&s, k, &mut out);
            cols[0][start_row + k + 1] = out[0];
            cols[1][start_row + k + 1] = out[1];
            cols[2][start_row + k + 1] = out[2];
            cols[3][start_row + k + 1] = out[3];
        }
    }

    fn freeze_state_rows(cols: &mut [Vec<BaseElement>], from_row: usize, to_row: usize) {
        for r in from_row..=to_row {
            for c in 0..4 { cols[c][r] = cols[c][r - 1]; }
        }
    }

    /// Build the 8192×14 SpendAir trace (mirrors the AIR exactly).
    fn build_spend_trace(w: &SpendWitness) -> TraceTable<BaseElement> {
        let n = TRACE_LEN;
        let z = BaseElement::ZERO;
        let one = BaseElement::ONE;
        let mut cols: Vec<Vec<BaseElement>> = alloc::vec![alloc::vec![z; n]; TRACE_WIDTH];

        let (b_lo, b_hi) = v2::unpack(&w.b);
        let (pkd_lo, pkd_hi) = v2::unpack(&w.pkd);
        let (cb_lo, cb_hi) = v2::unpack(&w.cb);
        let (cpkd_lo, cpkd_hi) = v2::unpack(&w.cpkd);
        let vf = BaseElement::new(w.v as u128);
        let cvf = BaseElement::new(w.cv as u128);

        // Global carries (cols 7, 8, 12, 13).
        for r in 0..n {
            cols[7][r] = b_lo;
            cols[8][r] = b_hi;
            cols[12][r] = vf;
            cols[13][r] = cvf;
        }
        // Bit column: v bits rows 0–63, cv bits rows 64–127, merkle bits per level.
        for i in 0..64 {
            cols[4][i] = BaseElement::new(((w.v >> i) & 1) as u128);
            cols[4][64 + i] = BaseElement::new(((w.cv >> i) & 1) as u128);
        }
        for d in 0..LEVELS {
            let bit = BaseElement::new(((w.index >> d) & 1) as u128);
            for r in (385 + 256 * d)..=(384 + 256 * (d + 1)) { cols[4][r] = bit; }
        }
        // acc / pow (cols 5, 6).
        cols[5][0] = z;
        cols[6][0] = one;
        for s in 0..63 {
            cols[5][s + 1] = cols[5][s] + cols[4][s] * cols[6][s];
            cols[6][s + 1] = cols[6][s].double();
        }
        cols[5][64] = z;
        cols[6][64] = one;
        for s in 64..127 {
            cols[5][s + 1] = cols[5][s] + cols[4][s] * cols[6][s];
            cols[6][s + 1] = cols[6][s].double();
        }
        for r in 128..n {
            cols[5][r] = cols[5][127];
            cols[6][r] = cols[6][127];
        }
        // aux columns (9, 10): siblings per level, change blinding at the end.
        for d in 0..LEVELS {
            let (s_lo, s_hi) = v2::unpack(&w.siblings[d]);
            for r in (385 + 256 * d)..=(384 + 256 * (d + 1)) {
                cols[9][r] = s_lo;
                cols[10][r] = s_hi;
            }
        }
        for r in 5505..n {
            cols[9][r] = cb_lo;
            cols[10][r] = cb_hi;
        }

        // --- State simulation ---
        // Block 0: nullifier perm.
        cols[0][0] = v2::nullifier_iv();
        cols[1][0] = b_lo;
        cols[2][0] = b_hi;
        cols[3][0] = z;
        freeze_state_rows(&mut cols, 1, 1); // boundary freeze (step 0)
        run_perm_rows(&mut cols, 1);        // rounds at steps 1–64 → out at row 65
        freeze_state_rows(&mut cols, 66, 128);
        // Block 1: note perm 1 (link at step 128).
        cols[0][129] = v2::note_iv();
        cols[1][129] = vf;
        cols[2][129] = b_lo;
        cols[3][129] = b_hi;
        run_perm_rows(&mut cols, 129);      // out at row 193
        freeze_state_rows(&mut cols, 194, 256);
        // Block 2: note perm 2 (absorb pkd at step 256).
        cols[0][257] = cols[0][256];
        cols[1][257] = cols[1][256] + pkd_lo;
        cols[2][257] = cols[2][256] + pkd_hi;
        cols[3][257] = cols[3][256];
        run_perm_rows(&mut cols, 257);      // out at row 321 = note leaf
        freeze_state_rows(&mut cols, 322, 384);
        // Merkle levels.
        for d in 0..LEVELS {
            let base = STEP_MRK_BASE + 256 * d;
            let cur1 = cols[1][base];
            let cur2 = cols[2][base];
            let bit = (w.index >> d) & 1;
            let (s_lo, s_hi) = v2::unpack(&w.siblings[d]);
            let (l_lo, l_hi, r_lo, r_hi) = if bit == 1 {
                (s_lo, s_hi, cur1, cur2)
            } else {
                (cur1, cur2, s_lo, s_hi)
            };
            // Link at step base.
            cols[0][base + 1] = v2::merkle_iv();
            cols[1][base + 1] = l_lo;
            cols[2][base + 1] = l_hi;
            cols[3][base + 1] = r_lo;
            // r_hi carry over this level's rows.
            let rhi_end = core::cmp::min(base + 256, n - 1);
            for r in (base + 1)..=rhi_end { cols[11][r] = r_hi; }
            run_perm_rows(&mut cols, base + 1);      // perm1 out at base+65
            freeze_state_rows(&mut cols, base + 66, base + 128);
            // Absorb r_hi at step base+128.
            cols[0][base + 129] = cols[0][base + 128];
            cols[1][base + 129] = cols[1][base + 128] + r_hi;
            cols[2][base + 129] = cols[2][base + 128];
            cols[3][base + 129] = cols[3][base + 128];
            run_perm_rows(&mut cols, base + 129);    // node out at base+193
            freeze_state_rows(&mut cols, base + 194, base + 256);
            if d == LEVELS - 1 {
                // r_hi carry stays frozen after the last level.
                for r in (base + 257)..n { cols[11][r] = r_hi; }
            }
        }
        // Change note (link at STEP_LCHG = 5504).
        cols[0][STEP_LCHG + 1] = v2::note_iv();
        cols[1][STEP_LCHG + 1] = cvf;
        cols[2][STEP_LCHG + 1] = cb_lo;
        cols[3][STEP_LCHG + 1] = cb_hi;
        run_perm_rows(&mut cols, STEP_LCHG + 1);     // out at 5569
        freeze_state_rows(&mut cols, STEP_LCHG + 66, STEP_ACHG);
        cols[0][STEP_ACHG + 1] = cols[0][STEP_ACHG];
        cols[1][STEP_ACHG + 1] = cols[1][STEP_ACHG] + cpkd_lo;
        cols[2][STEP_ACHG + 1] = cols[2][STEP_ACHG] + cpkd_hi;
        cols[3][STEP_ACHG + 1] = cols[3][STEP_ACHG];
        run_perm_rows(&mut cols, STEP_ACHG + 1);     // change leaf at 5697
        freeze_state_rows(&mut cols, ROW_CLEAF + 1, n - 1);

        TraceTable::init(cols)
    }

    struct SpendProver {
        pi: SpendPI,
        options: ProofOptions,
    }

    impl Prover for SpendProver {
        type BaseField = BaseElement;
        type Air = SpendAir;
        type Trace = TraceTable<BaseElement>;
        type HashFn = HashFn;
        type VC = VC;
        type RandomCoin = RandCoin;
        type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
            DefaultTraceLde<E, Self::HashFn, Self::VC>;
        type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
            DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
        type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
            DefaultConstraintEvaluator<'a, Self::Air, E>;
        fn get_pub_inputs(&self, _: &Self::Trace) -> SpendPI { self.pi.clone() }
        fn options(&self) -> &ProofOptions { &self.options }
        fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
            &self, ti: &TraceInfo, mt: &ColMatrix<Self::BaseField>,
            d: &StarkDomain<Self::BaseField>, po: PartitionOptions,
        ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
            DefaultTraceLde::new(ti, mt, d, po)
        }
        fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
            &self, cpt: CompositionPolyTrace<E>, nc: usize,
            d: &StarkDomain<Self::BaseField>, po: PartitionOptions,
        ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
            DefaultConstraintCommitment::new(cpt, nc, d, po)
        }
        fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
            &self, air: &'a Self::Air, are: Option<AuxRandElements<E>>,
            cc: winterfell::ConstraintCompositionCoefficients<E>,
        ) -> Self::ConstraintEvaluator<'a, E> {
            DefaultConstraintEvaluator::new(air, are, cc)
        }
    }

    fn prove_spend(w: &SpendWitness, pi: &SpendPI) -> Vec<u8> {
        let prover = SpendProver {
            pi: pi.clone(),
            options: ProofOptions::new(
                28, 8, 0, FieldExtension::None, 8, 127,
                BatchingMethod::Linear, BatchingMethod::Horner,
            ),
        };
        let trace = build_spend_trace(w);
        prover.prove(trace).expect("spend STARK").to_bytes()
    }

    /// Common fixture: single note at index 0 in an otherwise empty tree.
    fn fixture(v: u64, price: u64) -> (SpendWitness, SpendPI) {
        let b = [0x21u8; 32];
        let pk = [0xABu8; 1312];
        let pkd = v2::pk_digest(&pk);
        let leaf = v2::note_hash(v, &b, &pkd);
        let z = v2::zero_subtrees();
        let mut siblings = [[0u8; 32]; LEVELS];
        for d in 0..LEVELS { siblings[d] = z[d]; }
        let root = v2::reference_root(&[leaf]);
        assert!(v2::verify_merkle_path(&leaf, 0, &siblings, &root));
        let nullifier = v2::nullifier_hash(&b);
        let cv = v - price;
        let cb = [0x37u8; 32];
        let cpkd = v2::pk_digest(&[0xCDu8; 1312]);
        let change_leaf = v2::note_hash(cv, &cb, &cpkd);
        let w = SpendWitness { v, b, pkd, index: 0, siblings, cv, cb, cpkd };
        let pi = SpendPI {
            root, nullifier, pkd,
            price_or_amount: price,
            change_leaf, change_pkd: cpkd,
            mode: 1,
        };
        (w, pi)
    }

    #[test]
    fn spend_v2_purchase_roundtrip() {
        let (w, pi) = fixture(1_000_000, 600_000);
        let proof = prove_spend(&w, &pi);
        std::println!("spend proof size: {} bytes", proof.len());
        assert!(verify_spend_v2(
            &proof, &pi.root, &pi.nullifier, &pi.pkd,
            pi.price_or_amount, &pi.change_leaf, &pi.change_pkd, true,
        ));
        // Tampered nullifier must fail.
        let mut bad_nf = pi.nullifier;
        bad_nf[0] ^= 1;
        assert!(!verify_spend_v2(
            &proof, &pi.root, &bad_nf, &pi.pkd,
            pi.price_or_amount, &pi.change_leaf, &pi.change_pkd, true,
        ));
        // Tampered root must fail.
        let mut bad_root = pi.root;
        bad_root[5] ^= 1;
        assert!(!verify_spend_v2(
            &proof, &bad_root, &pi.nullifier, &pi.pkd,
            pi.price_or_amount, &pi.change_leaf, &pi.change_pkd, true,
        ));
        // Wrong price must fail.
        assert!(!verify_spend_v2(
            &proof, &pi.root, &pi.nullifier, &pi.pkd,
            pi.price_or_amount + 1, &pi.change_leaf, &pi.change_pkd, true,
        ));
        // Wrong pkd must fail.
        let mut bad_pkd = pi.pkd;
        bad_pkd[0] ^= 1;
        assert!(!verify_spend_v2(
            &proof, &pi.root, &pi.nullifier, &bad_pkd,
            pi.price_or_amount, &pi.change_leaf, &pi.change_pkd, true,
        ));
    }

    #[test]
    fn spend_v2_withdraw_roundtrip() {
        let v = 750_000u64;
        let b = [0x44u8; 32];
        let pkd = v2::pk_digest(&[0x55u8; 1312]);
        let leaf = v2::note_hash(v, &b, &pkd);
        let z = v2::zero_subtrees();
        let mut siblings = [[0u8; 32]; LEVELS];
        for d in 0..LEVELS { siblings[d] = z[d]; }
        let root = v2::reference_root(&[leaf]);
        let nullifier = v2::nullifier_hash(&b);
        let w = SpendWitness {
            v, b, pkd, index: 0, siblings,
            cv: 0, cb: [0u8; 32], cpkd: [0u8; 32],
        };
        let pi = SpendPI {
            root, nullifier, pkd,
            price_or_amount: v,
            change_leaf: zero_change_leaf(),
            change_pkd: [0u8; 32],
            mode: 0,
        };
        let proof = prove_spend(&w, &pi);
        assert!(verify_spend_v2(
            &proof, &root, &nullifier, &pkd, v,
            &zero_change_leaf(), &[0u8; 32], false,
        ));
        // Withdraw amount mismatch fails.
        assert!(!verify_spend_v2(
            &proof, &root, &nullifier, &pkd, v - 1,
            &zero_change_leaf(), &[0u8; 32], false,
        ));
    }

    #[test]
    fn spend_v2_nonzero_index() {
        // Note at index 5 in a 6-leaf tree — exercises bit muxing.
        let v = 123_456u64;
        let price = 23_456u64;
        let b = [0x66u8; 32];
        let pkd = v2::pk_digest(&[0x77u8; 1312]);
        let leaf = v2::note_hash(v, &b, &pkd);
        let mut leaves = Vec::new();
        for i in 0u32..5 {
            let mut ob = [0u8; 32];
            ob[..4].copy_from_slice(&i.to_le_bytes());
            leaves.push(v2::note_hash(i as u64 + 1, &ob, &v2::pk_digest(&[i as u8; 1312])));
        }
        leaves.push(leaf); // index 5
        let root = v2::reference_root(&leaves);
        // Extract sibling path for index 5.
        let z = v2::zero_subtrees();
        let mut siblings = [[0u8; 32]; LEVELS];
        let mut level: Vec<[u8; 32]> = leaves.clone();
        let mut idx = 5usize;
        for d in 0..LEVELS {
            let sib_idx = idx ^ 1;
            siblings[d] = if sib_idx < level.len() { level[sib_idx] } else { z[d] };
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            let mut i = 0;
            while i < level.len() {
                let l = level[i];
                let r = if i + 1 < level.len() { level[i + 1] } else { z[d] };
                next.push(v2::merkle_hash2(&l, &r));
                i += 2;
            }
            if next.is_empty() { next.push(z[d + 1]); }
            level = next;
            idx >>= 1;
        }
        assert!(v2::verify_merkle_path(&leaf, 5, &siblings, &root));
        let nullifier = v2::nullifier_hash(&b);
        let cv = v - price;
        let cb = [0x88u8; 32];
        let cpkd = v2::pk_digest(&[0x99u8; 1312]);
        let change_leaf = v2::note_hash(cv, &cb, &cpkd);
        let w = SpendWitness { v, b, pkd, index: 5, siblings, cv, cb, cpkd };
        let pi = SpendPI {
            root, nullifier, pkd,
            price_or_amount: price,
            change_leaf, change_pkd: cpkd,
            mode: 1,
        };
        let proof = prove_spend(&w, &pi);
        assert!(verify_spend_v2(
            &proof, &root, &nullifier, &pkd, price, &change_leaf, &cpkd, true,
        ));
    }

    // --- DepositV2Air prover + roundtrip ---

    struct DepositProver {
        pi: super::deposit_v2::DepositPI,
        options: ProofOptions,
    }

    fn build_deposit_trace(v: u64, b: &[u8; 32], pkd: &[u8; 32]) -> TraceTable<BaseElement> {
        use super::deposit_v2::*;
        let n = TRACE_LEN;
        let z = BaseElement::ZERO;
        let mut cols: Vec<Vec<BaseElement>> = alloc::vec![alloc::vec![z; n]; TRACE_WIDTH];
        let (b_lo, b_hi) = v2::unpack(b);
        let (pkd_lo, pkd_hi) = v2::unpack(pkd);
        for r in 0..n {
            cols[4][r] = pkd_lo;
            cols[5][r] = pkd_hi;
        }
        cols[0][0] = v2::note_iv();
        cols[1][0] = BaseElement::new(v as u128);
        cols[2][0] = b_lo;
        cols[3][0] = b_hi;
        freeze_state_rows(&mut cols, 1, 1);
        run_perm_rows(&mut cols, 1);          // out at row 65
        freeze_state_rows(&mut cols, 66, 128);
        cols[0][129] = cols[0][128];
        cols[1][129] = cols[1][128] + pkd_lo;
        cols[2][129] = cols[2][128] + pkd_hi;
        cols[3][129] = cols[3][128];
        run_perm_rows(&mut cols, 129);        // leaf at row 193
        freeze_state_rows(&mut cols, 194, n - 1);
        TraceTable::init(cols)
    }

    impl Prover for DepositProver {
        type BaseField = BaseElement;
        type Air = super::deposit_v2::DepositV2Air;
        type Trace = TraceTable<BaseElement>;
        type HashFn = HashFn;
        type VC = VC;
        type RandomCoin = RandCoin;
        type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
            DefaultTraceLde<E, Self::HashFn, Self::VC>;
        type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
            DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
        type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
            DefaultConstraintEvaluator<'a, Self::Air, E>;
        fn get_pub_inputs(&self, _: &Self::Trace) -> super::deposit_v2::DepositPI { self.pi.clone() }
        fn options(&self) -> &ProofOptions { &self.options }
        fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
            &self, ti: &TraceInfo, mt: &ColMatrix<Self::BaseField>,
            d: &StarkDomain<Self::BaseField>, po: PartitionOptions,
        ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
            DefaultTraceLde::new(ti, mt, d, po)
        }
        fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
            &self, cpt: CompositionPolyTrace<E>, nc: usize,
            d: &StarkDomain<Self::BaseField>, po: PartitionOptions,
        ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
            DefaultConstraintCommitment::new(cpt, nc, d, po)
        }
        fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
            &self, air: &'a Self::Air, are: Option<AuxRandElements<E>>,
            cc: winterfell::ConstraintCompositionCoefficients<E>,
        ) -> Self::ConstraintEvaluator<'a, E> {
            DefaultConstraintEvaluator::new(air, are, cc)
        }
    }

    #[test]
    fn deposit_v2_roundtrip() {
        use super::deposit_v2::*;
        let v = 2_000_000u64;
        let b = [0x11u8; 32];
        let pkd = v2::pk_digest(&[0x22u8; 1312]);
        let leaf = v2::note_hash(v, &b, &pkd);
        let prover = DepositProver {
            pi: DepositPI { amount: v, leaf },
            options: ProofOptions::new(
                28, 8, 0, FieldExtension::None, 8, 127,
                BatchingMethod::Linear, BatchingMethod::Horner,
            ),
        };
        let proof = prover.prove(build_deposit_trace(v, &b, &pkd)).expect("deposit STARK").to_bytes();
        std::println!("deposit proof size: {} bytes", proof.len());
        assert!(verify_deposit_v2(&proof, v, &leaf));
        // Wrong amount fails.
        assert!(!verify_deposit_v2(&proof, v + 1, &leaf));
        // Wrong leaf fails.
        let mut bad = leaf;
        bad[0] ^= 1;
        assert!(!verify_deposit_v2(&proof, v, &bad));
    }

    #[test]
    fn spend_auth_v2_roundtrip() {
        use fips204::ml_dsa_44;
        use fips204::traits::{SerDes, Signer};
        let (pk, sk) = ml_dsa_44::try_keygen().expect("keygen");
        let public_inputs = b"test-public-inputs-v2".to_vec();
        let mut h = blake3::Hasher::new();
        h.update(v2::SPEND_AUTH_DOMAIN);
        h.update(&public_inputs);
        let msg = h.finalize();
        let sig = sk.try_sign(msg.as_bytes(), &[]).expect("sign");
        let mut auth = Vec::new();
        auth.extend_from_slice(&pk.into_bytes());
        auth.extend_from_slice(&sig);
        assert!(super::verify_spend_auth_v2(&auth, &public_inputs, false));
        // Wrong domain (withdraw) fails.
        assert!(!super::verify_spend_auth_v2(&auth, &public_inputs, true));
        // Tampered inputs fail.
        let mut bad = public_inputs.clone();
        bad[0] ^= 1;
        assert!(!super::verify_spend_auth_v2(&auth, &bad, false));
    }
}

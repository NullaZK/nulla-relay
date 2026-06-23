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
    // Spec 13: no fee term — balance constraint is Σin − Σout = 0.
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

pub fn verify_commitment(value: u64, blinding: [u8; 32], commitment: [u8; 32]) -> bool {
    let c_pt = match CompressedRistretto(commitment).decompress() { Some(p) => p, None => return false };
    let r = Scalar::from_bytes_mod_order(blinding);
    let v = Scalar::from(value);
    let h = generator_h();
    let expected = v * G + r * h;
    expected == c_pt
}

pub fn verify_opening_knowledge(
    value: u64,
    commitment: [u8; 32],
    proof: &[u8],
    binding: &[u8],
) -> bool {
    if proof.len() != 64 {
        return false;
    }

    let c_pt = match CompressedRistretto(commitment).decompress() {
        Some(p) => p,
        None => return false,
    };
    let h = generator_h();
    let v = Scalar::from(value);

    // A = C - v*G = b*H (relation being proven)
    let a_pt = c_pt - v * G;

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&proof[0..32]);
    let r_pt = match CompressedRistretto(r_bytes).decompress() {
        Some(p) => p,
        None => return false,
    };

    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&proof[32..64]);
    let s = Scalar::from_bytes_mod_order(s_bytes);

    // Fiat-Shamir challenge bound to tx context to prevent replay.
    let mut t = Transcript::new(b"NULLA_PEDERSEN_OPENING");
    t.append_message(b"bind", binding);
    t.append_message(b"R", &r_pt.compress().to_bytes());
    t.append_message(b"A", &a_pt.compress().to_bytes());
    let mut cbuf = [0u8; 64];
    t.challenge_bytes(b"c", &mut cbuf);
    let c = Scalar::from_bytes_mod_order_wide(&cbuf);

    let lhs = s * h;
    let rhs = r_pt + c * a_pt;
    lhs == rhs
}

/// Ristretto point subtraction for homomorphic change conservation.
/// Returns `compress(decompress(c_a) - decompress(c_b))`, or `None` if
/// either input is not a valid compressed Ristretto point.
pub fn pedersen_subtract(c_a: &[u8; 32], c_b: &[u8; 32]) -> Option<[u8; 32]> {
    let pa = CompressedRistretto(*c_a).decompress()?;
    let pb = CompressedRistretto(*c_b).decompress()?;
    Some((pa - pb).compress().to_bytes())
}

// ===================================================================
//  Phase 10 — Lelantus-style one-of-many proofs (Groth–Kohlweiss 2015)
//
//  Coin v2:  C = s·G1 + v·G + r·H
//    s  = serial (revealed at spend — the nullifier role)
//    v  = value, r = blinding
//    G  = Ristretto basepoint (value generator — Bulletproofs compatible)
//    H  = hash-to-point("VERIFIER_H_GENERATOR") (blinding generator)
//    G1 = hash-to-point("NULLA_SERIAL_GENERATOR") (serial generator)
//
//  Spend (public price): reveal serial s; compute
//    D_i = C_i − s·G1 − price·G   for every coin i in the group.
//  Prove ∃ l, r:  D_l = r·H  — one-of-many commitment to zero —
//  WITHOUT revealing l. The spent coin is never named.
//
//  Binary GK Σ-protocol, N = 2^m:
//    proof = 4m points + (3m+1) scalars = (7m+1)·32 bytes
//    (N=1024 → 2272 B; N=4096 → 2720 B)
//  Verification: O(N) multiscalar multiplication.
//
//  Transcript domain: NULLA_ONE_OF_MANY. The Fiat–Shamir challenge binds
//  group_hash (BLAKE2-256 of all coins in the group), the serial, the
//  price, and a caller context hash (tx binding) — replay-proof.
// ===================================================================
pub mod one_of_many {
    use super::*;
    use alloc::vec::Vec;
    use curve25519_dalek::traits::VartimeMultiscalarMul;

    /// Serial generator G1 = hash-to-point("NULLA_SERIAL_GENERATOR").
    pub fn generator_g1() -> RistrettoPoint {
        let mut hasher = Sha512::new();
        sha2::Digest::update(&mut hasher, b"NULLA_SERIAL_GENERATOR");
        let out = hasher.finalize();
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&out);
        RistrettoPoint::from_uniform_bytes(&bytes)
    }

    /// Coin v2 commitment: C = s·G1 + v·G + r·H.
    pub fn coin_commit(serial: &[u8; 32], value: u64, blinding: &[u8; 32]) -> [u8; 32] {
        let s = Scalar::from_bytes_mod_order(*serial);
        let v = Scalar::from(value);
        let r = Scalar::from_bytes_mod_order(*blinding);
        (s * generator_g1() + v * G + r * generator_h()).compress().to_bytes()
    }

    /// BLAKE2-256 over the concatenated group coins — the group identity.
    pub fn group_hash(coins: &[[u8; 32]]) -> [u8; 32] {
        let mut h = Blake2b512::new();
        for c in coins { BlakeUpdate::update(&mut h, c); }
        let out = h.finalize();
        let mut res = [0u8; 32];
        res.copy_from_slice(&out[..32]);
        res
    }

    fn fs_challenge(
        ghash: &[u8; 32],
        serial: &[u8; 32],
        price: u64,
        change: &[u8; 32],
        context: &[u8],
        cl: &[RistrettoPoint],
        ca: &[RistrettoPoint],
        cb: &[RistrettoPoint],
        gk: &[RistrettoPoint],
    ) -> Scalar {
        let mut t = Transcript::new(b"NULLA_ONE_OF_MANY");
        t.append_message(b"group", ghash);
        t.append_message(b"serial", serial);
        t.append_u64(b"price", price);
        t.append_message(b"change", change);
        t.append_message(b"ctx", context);
        for p in cl { t.append_message(b"cl", &p.compress().to_bytes()); }
        for p in ca { t.append_message(b"ca", &p.compress().to_bytes()); }
        for p in cb { t.append_message(b"cb", &p.compress().to_bytes()); }
        for p in gk { t.append_message(b"gk", &p.compress().to_bytes()); }
        let mut buf = [0u8; 64];
        t.challenge_bytes(b"x", &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }

    fn scalar_from_rng(rng: &mut DeterministicRng) -> Scalar {
        let mut w = [0u8; 64];
        rng.fill_bytes(&mut w);
        Scalar::from_bytes_mod_order_wide(&w)
    }

    /// Compute D_i = C_i − s·G1 − price·G − change for a group.
    /// `change` = [0u8;32] (the Ristretto identity) when no change output.
    /// Returns None if any coin or the change fails to decompress.
    fn d_set(
        coins: &[[u8; 32]],
        serial: &[u8; 32],
        price: u64,
        change: &[u8; 32],
    ) -> Option<Vec<RistrettoPoint>> {
        let change_pt = CompressedRistretto(*change).decompress()?;
        let offset = Scalar::from_bytes_mod_order(*serial) * generator_g1()
            + Scalar::from(price) * G
            + change_pt;
        let mut out = Vec::with_capacity(coins.len());
        for c in coins {
            let p = CompressedRistretto(*c).decompress()?;
            out.push(p - offset);
        }
        Some(out)
    }

    /// Prove: coins[index] − serial·G1 − price·G − change = blinding·H.
    ///
    /// `change` = compressed plain Pedersen (v'·G + r'·H) of the change value,
    /// or `[0u8;32]` (identity) when there is no change — then the statement
    /// enforces v == price exactly. With change, `blinding` must equal r − r'.
    ///
    /// `seed` must be 32 bytes of fresh entropy from the caller (wallet).
    /// `context` binds the proof to the spending transaction (e.g. BLAKE2-256
    /// of the SCALE-encoded public inputs) — prevents replay.
    ///
    /// Returns the serialized proof, or None on bad inputs
    /// (group not a power of two, index out of range, undecodable coin).
    pub fn prove(
        coins: &[[u8; 32]],
        index: usize,
        serial: &[u8; 32],
        price: u64,
        change: &[u8; 32],
        blinding: &[u8; 32],
        context: &[u8],
        seed: [u8; 32],
    ) -> Option<Vec<u8>> {
        let n = coins.len();
        if n < 2 || !n.is_power_of_two() || index >= n { return None; }
        let m = n.trailing_zeros() as usize;
        let d = d_set(coins, serial, price, change)?;
        let h = generator_h();
        let r = Scalar::from_bytes_mod_order(*blinding);
        // sanity: witness must hold
        if d[index] != r * h { return None; }

        let mut rng = DeterministicRng::new(seed);
        let ghash = group_hash(coins);

        // Per-bit commitments.
        let bits: Vec<u64> = (0..m).map(|j| ((index >> j) & 1) as u64).collect();
        let mut rj = Vec::with_capacity(m);
        let mut aj = Vec::with_capacity(m);
        let mut sj = Vec::with_capacity(m);
        let mut tj = Vec::with_capacity(m);
        let mut rho = Vec::with_capacity(m);
        for _ in 0..m {
            rj.push(scalar_from_rng(&mut rng));
            aj.push(scalar_from_rng(&mut rng));
            sj.push(scalar_from_rng(&mut rng));
            tj.push(scalar_from_rng(&mut rng));
            rho.push(scalar_from_rng(&mut rng));
        }
        let mut cl = Vec::with_capacity(m);
        let mut ca = Vec::with_capacity(m);
        let mut cb = Vec::with_capacity(m);
        for j in 0..m {
            let lj = Scalar::from(bits[j]);
            cl.push(lj * G + rj[j] * h);
            ca.push(aj[j] * G + sj[j] * h);
            cb.push(lj * aj[j] * G + tj[j] * h);
        }

        // Polynomial coefficients p_{i,k}: P_i(x) = Π_j f_{j, i_j}(x)
        // f_{j,1}(x) = l_j·x + a_j ; f_{j,0}(x) = (1−l_j)·x − a_j.
        // p[i] holds coefficients [x^0 .. x^m]; leading coeff = δ_{i,index}.
        let mut p: Vec<Vec<Scalar>> = Vec::with_capacity(n);
        for i in 0..n {
            let mut coeffs = alloc::vec![Scalar::ZERO; m + 1];
            coeffs[0] = Scalar::ONE;
            let mut deg = 0usize;
            for j in 0..m {
                let ij = (i >> j) & 1;
                let lj = Scalar::from(bits[j]);
                // f = c1·x + c0
                let (c1, c0) = if ij == 1 {
                    (lj, aj[j])
                } else {
                    (Scalar::ONE - lj, -aj[j])
                };
                // coeffs *= (c1·x + c0)
                let mut next = alloc::vec![Scalar::ZERO; m + 1];
                for k in 0..=deg {
                    next[k] += coeffs[k] * c0;
                    next[k + 1] += coeffs[k] * c1;
                }
                coeffs = next;
                deg += 1;
            }
            p.push(coeffs);
        }

        // G_k = Σ_i p_{i,k}·D_i + ρ_k·H,  k = 0..m−1.
        let mut gk = Vec::with_capacity(m);
        for k in 0..m {
            let scalars = (0..n).map(|i| p[i][k]).chain(core::iter::once(rho[k]));
            let points = d.iter().cloned().chain(core::iter::once(h));
            gk.push(RistrettoPoint::vartime_multiscalar_mul(scalars, points));
        }

        let x = fs_challenge(&ghash, serial, price, change, context, &cl, &ca, &cb, &gk);

        // Responses.
        let mut fj = Vec::with_capacity(m);
        let mut zaj = Vec::with_capacity(m);
        let mut zbj = Vec::with_capacity(m);
        for j in 0..m {
            let lj = Scalar::from(bits[j]);
            let f = lj * x + aj[j];
            fj.push(f);
            zaj.push(rj[j] * x + sj[j]);
            zbj.push(rj[j] * (x - f) + tj[j]);
        }
        // z_d = r·x^m − Σ_k ρ_k·x^k.
        let mut xm = Scalar::ONE;
        for _ in 0..m { xm *= x; }
        let mut zd = r * xm;
        let mut xk = Scalar::ONE;
        for k in 0..m {
            zd -= rho[k] * xk;
            xk *= x;
        }

        // Serialize: [m:u8] cl ca cb gk (4m·32) | fj zaj zbj (3m·32) | zd (32)
        let mut out = Vec::with_capacity(1 + (7 * m + 1) * 32);
        out.push(m as u8);
        for v in [&cl, &ca, &cb, &gk] {
            for pnt in v.iter() { out.extend_from_slice(&pnt.compress().to_bytes()); }
        }
        for v in [&fj, &zaj, &zbj] {
            for s in v.iter() { out.extend_from_slice(&s.to_bytes()); }
        }
        out.extend_from_slice(&zd.to_bytes());
        Some(out)
    }

    /// Verify a one-of-many spend proof against a coin group.
    ///
    /// Checks (for challenge x recomputed by Fiat–Shamir):
    ///   1. x·cl_j + ca_j == f_j·G + za_j·H              (bit consistency)
    ///   2. (x−f_j)·cl_j + cb_j == zb_j·H                (bit is 0 or 1)
    ///   3. Σ_i (Π_j f'_{j,i_j})·D_i − Σ_k x^k·G_k == z_d·H   (membership)
    /// where f'_{j,1} = f_j and f'_{j,0} = x − f_j.
    pub fn verify(
        proof: &[u8],
        coins: &[[u8; 32]],
        serial: &[u8; 32],
        price: u64,
        change: &[u8; 32],
        context: &[u8],
    ) -> bool {
        let n = coins.len();
        if n < 2 || !n.is_power_of_two() { return false; }
        let m = n.trailing_zeros() as usize;
        if proof.len() != 1 + (7 * m + 1) * 32 { return false; }
        if proof[0] as usize != m { return false; }

        let read_pt = |off: usize| -> Option<RistrettoPoint> {
            let mut b = [0u8; 32];
            b.copy_from_slice(&proof[off..off + 32]);
            CompressedRistretto(b).decompress()
        };
        let read_sc = |off: usize| -> Option<Scalar> {
            let mut b = [0u8; 32];
            b.copy_from_slice(&proof[off..off + 32]);
            Scalar::from_canonical_bytes(b).into()
        };

        let mut off = 1usize;
        let mut cl = Vec::with_capacity(m);
        let mut ca = Vec::with_capacity(m);
        let mut cb = Vec::with_capacity(m);
        let mut gk = Vec::with_capacity(m);
        for v in [&mut cl, &mut ca, &mut cb, &mut gk] {
            for _ in 0..m {
                match read_pt(off) { Some(p) => v.push(p), None => return false }
                off += 32;
            }
        }
        let mut fj = Vec::with_capacity(m);
        let mut zaj = Vec::with_capacity(m);
        let mut zbj = Vec::with_capacity(m);
        for v in [&mut fj, &mut zaj, &mut zbj] {
            for _ in 0..m {
                match read_sc(off) { Some(s) => v.push(s), None => return false }
                off += 32;
            }
        }
        let zd = match read_sc(off) { Some(s) => s, None => return false };

        let d = match d_set(coins, serial, price, change) { Some(d) => d, None => return false };
        let h = generator_h();
        let ghash = group_hash(coins);
        let x = fs_challenge(&ghash, serial, price, change, context, &cl, &ca, &cb, &gk);

        // Per-bit checks.
        for j in 0..m {
            if x * cl[j] + ca[j] != fj[j] * G + zaj[j] * h { return false; }
            if (x - fj[j]) * cl[j] + cb[j] != zbj[j] * h { return false; }
        }

        // Membership check (N-term MSM + m-term MSM).
        // exponent_i = Π_j f'_{j, i_j};  computed in O(N) by doubling table.
        let mut exps = alloc::vec![Scalar::ONE; n];
        let mut width = 1usize;
        for j in 0..m {
            let f1 = fj[j];
            let f0 = x - fj[j];
            // expand: indices with bit j set multiply by f1, others by f0
            for i in (0..width).rev() {
                exps[i + width] = exps[i] * f1;
                exps[i] = exps[i] * f0;
            }
            width <<= 1;
        }
        let mut xs = Vec::with_capacity(m);
        let mut xk = Scalar::ONE;
        for _ in 0..m {
            xs.push(xk);
            xk *= x;
        }
        let lhs = RistrettoPoint::vartime_multiscalar_mul(
            exps.iter().cloned().chain(xs.iter().map(|s| -*s)),
            d.iter().cloned().chain(gk.iter().cloned()),
        );
        lhs == zd * h
    }

    /// The identity element encoding — pass as `change` when there is none.
    pub const NO_CHANGE: [u8; 32] = [0u8; 32];

    /// Verify a deposit coin opening: prove knowledge of (s, r) such that
    /// coin − amount·G = s·G1 + r·H. Proof = R(32) ‖ z_s(32) ‖ z_r(32) = 96 B.
    /// Binds `context` (e.g. depositor account encoding) against replay.
    pub fn verify_deposit_open(
        coin: &[u8; 32],
        amount: u64,
        proof: &[u8],
        context: &[u8],
    ) -> bool {
        if proof.len() != 96 { return false; }
        let c_pt = match CompressedRistretto(*coin).decompress() { Some(p) => p, None => return false };
        let a_pt = c_pt - Scalar::from(amount) * G;
        let mut rb = [0u8; 32]; rb.copy_from_slice(&proof[..32]);
        let r_pt = match CompressedRistretto(rb).decompress() { Some(p) => p, None => return false };
        let mut zs_b = [0u8; 32]; zs_b.copy_from_slice(&proof[32..64]);
        let zs: Scalar = match Scalar::from_canonical_bytes(zs_b).into() { Some(s) => s, None => return false };
        let mut zr_b = [0u8; 32]; zr_b.copy_from_slice(&proof[64..96]);
        let zr: Scalar = match Scalar::from_canonical_bytes(zr_b).into() { Some(s) => s, None => return false };
        let mut t = Transcript::new(b"NULLA_COIN_DEPOSIT_OPEN");
        t.append_message(b"coin", coin);
        t.append_u64(b"amount", amount);
        t.append_message(b"ctx", context);
        t.append_message(b"R", &r_pt.compress().to_bytes());
        t.append_message(b"A", &a_pt.compress().to_bytes());
        let mut buf = [0u8; 64];
        t.challenge_bytes(b"c", &mut buf);
        let c = Scalar::from_bytes_mod_order_wide(&buf);
        zs * generator_g1() + zr * generator_h() == r_pt + c * a_pt
    }

    /// Prover for `verify_deposit_open` (wallet side).
    pub fn prove_deposit_open(
        coin: &[u8; 32],
        amount: u64,
        serial: &[u8; 32],
        blinding: &[u8; 32],
        context: &[u8],
        seed: [u8; 32],
    ) -> Vec<u8> {
        let s = Scalar::from_bytes_mod_order(*serial);
        let r = Scalar::from_bytes_mod_order(*blinding);
        let mut rng = DeterministicRng::new(seed);
        let ks = scalar_from_rng(&mut rng);
        let kr = scalar_from_rng(&mut rng);
        let r_pt = ks * generator_g1() + kr * generator_h();
        let c_pt = CompressedRistretto(*coin).decompress().expect("valid coin");
        let a_pt = c_pt - Scalar::from(amount) * G;
        let mut t = Transcript::new(b"NULLA_COIN_DEPOSIT_OPEN");
        t.append_message(b"coin", coin);
        t.append_u64(b"amount", amount);
        t.append_message(b"ctx", context);
        t.append_message(b"R", &r_pt.compress().to_bytes());
        t.append_message(b"A", &a_pt.compress().to_bytes());
        let mut buf = [0u8; 64];
        t.challenge_bytes(b"c", &mut buf);
        let c = Scalar::from_bytes_mod_order_wide(&buf);
        let zs = ks + c * s;
        let zr = kr + c * r;
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(&r_pt.compress().to_bytes());
        out.extend_from_slice(&zs.to_bytes());
        out.extend_from_slice(&zr.to_bytes());
        out
    }

    /// Verify a G1 PoK: new_coin − change = s'·G1, knowledge of s'.
    /// Used to convert a plain-Pedersen change output into a spendable v2
    /// coin without revealing the new serial. Proof = R(32) ‖ z(32) = 64 B.
    pub fn verify_g1_pok(
        new_coin: &[u8; 32],
        change: &[u8; 32],
        proof: &[u8],
        context: &[u8],
    ) -> bool {
        if proof.len() != 64 { return false; }
        let nc = match CompressedRistretto(*new_coin).decompress() { Some(p) => p, None => return false };
        let ch = match CompressedRistretto(*change).decompress() { Some(p) => p, None => return false };
        let a_pt = nc - ch;
        let mut rb = [0u8; 32]; rb.copy_from_slice(&proof[..32]);
        let r_pt = match CompressedRistretto(rb).decompress() { Some(p) => p, None => return false };
        let mut zb = [0u8; 32]; zb.copy_from_slice(&proof[32..64]);
        let z: Scalar = match Scalar::from_canonical_bytes(zb).into() { Some(s) => s, None => return false };
        let mut t = Transcript::new(b"NULLA_COIN_G1_POK");
        t.append_message(b"new_coin", new_coin);
        t.append_message(b"change", change);
        t.append_message(b"ctx", context);
        t.append_message(b"R", &r_pt.compress().to_bytes());
        t.append_message(b"A", &a_pt.compress().to_bytes());
        let mut buf = [0u8; 64];
        t.challenge_bytes(b"c", &mut buf);
        let c = Scalar::from_bytes_mod_order_wide(&buf);
        z * generator_g1() == r_pt + c * a_pt
    }

    /// Prover for `verify_g1_pok` (wallet side).
    pub fn prove_g1_pok(
        new_coin: &[u8; 32],
        change: &[u8; 32],
        new_serial: &[u8; 32],
        context: &[u8],
        seed: [u8; 32],
    ) -> Vec<u8> {
        let s = Scalar::from_bytes_mod_order(*new_serial);
        let mut rng = DeterministicRng::new(seed);
        let k = scalar_from_rng(&mut rng);
        let r_pt = k * generator_g1();
        let nc = CompressedRistretto(*new_coin).decompress().expect("valid coin");
        let ch = CompressedRistretto(*change).decompress().expect("valid change");
        let a_pt = nc - ch;
        let mut t = Transcript::new(b"NULLA_COIN_G1_POK");
        t.append_message(b"new_coin", new_coin);
        t.append_message(b"change", change);
        t.append_message(b"ctx", context);
        t.append_message(b"R", &r_pt.compress().to_bytes());
        t.append_message(b"A", &a_pt.compress().to_bytes());
        let mut buf = [0u8; 64];
        t.challenge_bytes(b"c", &mut buf);
        let c = Scalar::from_bytes_mod_order_wide(&buf);
        let z = k + c * s;
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&r_pt.compress().to_bytes());
        out.extend_from_slice(&z.to_bytes());
        out
    }

    /// Plain Pedersen (no serial): v·G + r·H — used for change outputs.
    pub fn pedersen_commit(value: u64, blinding: &[u8; 32]) -> [u8; 32] {
        let v = Scalar::from(value);
        let r = Scalar::from_bytes_mod_order(*blinding);
        (v * G + r * generator_h()).compress().to_bytes()
    }

    /// blinding difference r − r' (mod l) for the change-spend witness.
    pub fn blinding_sub(r: &[u8; 32], r_prime: &[u8; 32]) -> [u8; 32] {
        (Scalar::from_bytes_mod_order(*r) - Scalar::from_bytes_mod_order(*r_prime)).to_bytes()
    }

    /// Deterministic unspendable pad coin for partial groups.
    ///
    /// Hash-to-point output — its discrete-log decomposition over (G1, G, H)
    /// is unknown to everyone, so a pad slot can never satisfy D = r·H.
    /// Both prover and verifier derive the identical padding.
    pub fn pad_coin(group_id: u32, i: u32) -> [u8; 32] {
        let mut hasher = Sha512::new();
        sha2::Digest::update(&mut hasher, b"NULLA_GROUP_PAD");
        sha2::Digest::update(&mut hasher, &group_id.to_le_bytes());
        sha2::Digest::update(&mut hasher, &i.to_le_bytes());
        let out = hasher.finalize();
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&out);
        RistrettoPoint::from_uniform_bytes(&bytes).compress().to_bytes()
    }

    /// Pad a partial group to the next power of two (minimum 2) with
    /// unspendable pad coins derived from `group_id`.
    pub fn pad_group(coins: &[[u8; 32]], group_id: u32) -> Vec<[u8; 32]> {
        let n = core::cmp::max(coins.len(), 2).next_power_of_two();
        let mut out = Vec::with_capacity(n);
        out.extend_from_slice(coins);
        let mut i = coins.len() as u32;
        while out.len() < n {
            out.push(pad_coin(group_id, i));
            i += 1;
        }
        out
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod one_of_many_tests {
    use super::one_of_many::*;
    use alloc::vec::Vec;

    fn mk_group(n: usize, spend_idx: usize, serial: &[u8; 32], value: u64, blinding: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut coins = Vec::with_capacity(n);
        for i in 0..n {
            if i == spend_idx {
                coins.push(coin_commit(serial, value, blinding));
            } else {
                let mut s = [0u8; 32];
                s[..8].copy_from_slice(&(i as u64 + 1000).to_le_bytes());
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&(i as u64 + 2000).to_le_bytes());
                coins.push(coin_commit(&s, (i as u64 + 1) * 100, &b));
            }
        }
        coins
    }

    #[test]
    fn gk_roundtrip_small() {
        let serial = [0x05u8; 32];
        let blinding = [0x09u8; 32];
        let price = 5_000u64;
        let coins = mk_group(16, 7, &serial, price, &blinding);
        let ctx = b"tx-context-hash";
        let proof = prove(&coins, 7, &serial, price, &NO_CHANGE, &blinding, ctx, [0x42u8; 32]).expect("prove");
        std::println!("N=16 proof: {} bytes", proof.len());
        assert!(verify(&proof, &coins, &serial, price, &NO_CHANGE, ctx));
        // Wrong serial fails.
        let mut bad = serial;
        bad[0] ^= 1;
        assert!(!verify(&proof, &coins, &bad, price, &NO_CHANGE, ctx));
        // Wrong price fails.
        assert!(!verify(&proof, &coins, &serial, price + 1, &NO_CHANGE, ctx));
        // Wrong context fails (replay protection).
        assert!(!verify(&proof, &coins, &serial, price, &NO_CHANGE, b"other-tx"));
        // Tampered proof fails.
        let mut tampered = proof.clone();
        tampered[40] ^= 1;
        assert!(!verify(&tampered, &coins, &serial, price, &NO_CHANGE, ctx));
        // Wrong-value coin (witness doesn't hold) → prove returns None.
        assert!(prove(&coins, 7, &serial, price + 1, &NO_CHANGE, &blinding, ctx, [0x42u8; 32]).is_none());
        // Proving with wrong index → None.
        assert!(prove(&coins, 8, &serial, price, &NO_CHANGE, &blinding, ctx, [0x42u8; 32]).is_none());
    }

    #[test]
    fn gk_change_flow() {
        // Coin v = 10_000, price = 6_000, change v' = 4_000.
        let serial = [0x10u8; 32];
        let r = [0x20u8; 32];
        let v = 10_000u64;
        let price = 6_000u64;
        let coins = mk_group(16, 3, &serial, v, &r);
        let ctx = b"change-tx";
        let v_chg = v - price;
        let r_chg = [0x30u8; 32];
        let change = pedersen_commit(v_chg, &r_chg);
        let wit = blinding_sub(&r, &r_chg);
        let proof = prove(&coins, 3, &serial, price, &change, &wit, ctx, [0x55u8; 32]).expect("prove w/ change");
        assert!(verify(&proof, &coins, &serial, price, &change, ctx));
        // Inflated change (v' too big) → witness fails, prove = None.
        let bad_change = pedersen_commit(v_chg + 1, &r_chg);
        assert!(prove(&coins, 3, &serial, price, &bad_change, &wit, ctx, [0x55u8; 32]).is_none());
        // Coin conversion: new_coin = change + s'·G1, prove PoK of s'.
        let s_new = [0x40u8; 32];
        let new_coin = coin_commit(&s_new, v_chg, &r_chg);
        let pok = prove_g1_pok(&new_coin, &change, &s_new, ctx, [0x66u8; 32]);
        assert!(verify_g1_pok(&new_coin, &change, &pok, ctx));
        let mut bad_pok = pok.clone();
        bad_pok[5] ^= 1;
        assert!(!verify_g1_pok(&new_coin, &change, &bad_pok, ctx));
        // Deposit opening proof for the original coin.
        let dep = prove_deposit_open(&coins[3], v, &serial, &r, b"acct", [0x77u8; 32]);
        assert!(verify_deposit_open(&coins[3], v, &dep, b"acct"));
        assert!(!verify_deposit_open(&coins[3], v + 1, &dep, b"acct"));
        assert!(!verify_deposit_open(&coins[3], v, &dep, b"other-acct"));
    }

    #[test]
    fn gk_bench_1024_4096() {
        use std::time::Instant;
        let serial = [0x11u8; 32];
        let blinding = [0x22u8; 32];
        let price = 1_000_000u64;
        for n in [1024usize, 4096] {
            let idx = n / 2 + 3;
            let coins = mk_group(n, idx, &serial, price, &blinding);
            let ctx = b"bench-ctx";
            let t0 = Instant::now();
            let proof = prove(&coins, idx, &serial, price, &NO_CHANGE, &blinding, ctx, [0x77u8; 32]).expect("prove");
            let t_prove = t0.elapsed();
            let t1 = Instant::now();
            let ok = verify(&proof, &coins, &serial, price, &NO_CHANGE, ctx);
            let t_verify = t1.elapsed();
            assert!(ok);
            std::println!(
                "N={:5}  proof={:5}B  prove={:?}  verify={:?}",
                n, proof.len(), t_prove, t_verify
            );
        }
    }
}

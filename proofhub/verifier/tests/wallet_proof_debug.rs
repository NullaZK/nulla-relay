// Debug test: verify actual wallet proof bytes against the real on-chain verifier
// Proof bytes from wallet debug output (April 7 2026, buy operation)
use blake2::Digest;

#[test]
fn test_wallet_proof_verify_bytes() {
    // Schnorr proof bytes from wallet debug
    let proof_hex = concat!(
        "ece65bd51b53fc2557dd6c361d82d7dd82f2613c2d1fc94ba284238ca413f309",
        "3aefba4ece7b83f999d64359166ca5054374ec33b412c697a6199253225dad0f"
    );
    let proof = hex::decode(proof_hex).unwrap();
    assert_eq!(proof.len(), 64);

    // Full SCALE-encoded ProofPublicInputs (250 bytes) from wallet debug
    let encoded_hex = concat!(
        "16871689857b28c141aab4423d33e920e3e258ef8c659f645c869c2be8acac02",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "04",
        "fa3fd8330ef474f17c27c45884e454ec4320e25c5a93b355446e9de60ced8025",
        "04",
        "00000000",
        "04",
        "00",
        "04",
        "3f353e66b8a808736a81430e8827d72d158793e8fa91992fd8038a8e28140544",
        "04",
        "ba58dc5a34c87b9cacd2589981078a6ea768da54d0be574cf0475b231338ad77",
        "e684204df2d4f0c476c51eadf638a1725ffdaf0f06cbfd257ae35425d16f1065",
        "0213314a9620af41816e3c23d60d4f6ee0c191494529d5abe4359f747caeb10c",
        "b87a52eb5a4b474a8a2cbb40aec51dac"
    );
    // Use the actual bytes the wallet sent (directly from the output)
    let public_inputs = hex::decode(
        "16871689857b28c141aab4423d33e920e3e258ef8c659f645c869c2be8acac0200000000000000000000000000000000000000000000000000000000000000000\
         4fa3fd8330ef474f17c27c45884e454ec4320e25c5a93b355446e9de60ced8025040000000004000\
         43f353e66b8a808736a81430e8827d72d158793e8fa91992fd8038a8e2814054404ba58dc5a34c87\
         b9cacd2589981078a6ea768da54d0be574cf0475b231338ad77e684204df2d4f0c476c51eadf638\
         a1725ffdaf0f06cbfd257ae35425d16f10650213314a9620af41816e3c23d60d4f6ee0c191494529\
         d5abe4359f747caeb10cb87a52eb5a4b474a8a2cbb40aec51dac"
    );
    // Use the exact bytes from wallet output
    let pi_bytes = hex::decode("16871689857b28c141aab4423d33e920e3e258ef8c659f645c869c2be8acac02000000000000000000000000000000000000000000000000000000000000000004fa3fd8330ef474f17c27c45884e454ec4320e25c5a93b355446e9de60ced802504000000000400043f353e66b8a808736a81430e8827d72d158793e8fa91992fd8038a8e2814054404ba58dc5a34c87b9cacd2589981078a6ea768da54d0be574cf0475b231338ad77e684204df2d4f0c476c51eadf638a1725ffdaf0f06cbfd257ae35425d16f10650213314a9620af41816e3c23d60d4f6ee0c191494529d5abe4359f747caeb10cb87a52eb5a4b474a8a2cbb40aec51dac").unwrap();
    println!("public_inputs: {} bytes", pi_bytes.len());

    let result = verifier::verify_bytes(&proof, &pi_bytes);
    println!("verify_bytes result: {}", result);

    // Also check what pi_hash we compute
    use blake2::Blake2b512;
    let out = Blake2b512::digest(&pi_bytes);
    println!("pi_hash (server): {}", hex::encode(&out[..32]));
    println!("pi_hash (wallet): ff5ca817b888d0a8c4331ae526e6359ef77468aa0732b39ab234d206ddd00c24");

    assert!(result, "verify_bytes FAILED on real wallet proof — Schnorr proof is cryptographically incorrect");
}

#[test]
fn test_wallet_range_proof() {
    // Range proof (736 bytes) — wallet says local bulletproof verify passes
    // Let's also verify the range proof through the on-chain function
    
    let pi_bytes = hex::decode("16871689857b28c141aab4423d33e920e3e258ef8c659f645c869c2be8acac02000000000000000000000000000000000000000000000000000000000000000004fa3fd8330ef474f17c27c45884e454ec4320e25c5a93b355446e9de60ced802504000000000400043f353e66b8a808736a81430e8827d72d158793e8fa91992fd8038a8e2814054404ba58dc5a34c87b9cacd2589981078a6ea768da54d0be574cf0475b231338ad77e684204df2d4f0c476c51eadf638a1725ffdaf0f06cbfd257ae35425d16f10650213314a9620af41816e3c23d60d4f6ee0c191494529d5abe4359f747caeb10cb87a52eb5a4b474a8a2cbb40aec51dac").unwrap();
    
    // Commitments for range proof: new_commitments + fee_commitment
    let cmts: &[[u8; 32]] = &[
        hex::decode("ba58dc5a34c87b9cacd2589981078a6ea768da54d0be574cf0475b231338ad77").unwrap().try_into().unwrap(),
        hex::decode("e684204df2d4f0c476c51eadf638a1725ffdaf0f06cbfd257ae35425d16f1065").unwrap().try_into().unwrap(),
    ];
    
    println!("Range proof commitments: {} entries", cmts.len());
    println!("cmts[0]: {}", hex::encode(cmts[0]));
    println!("cmts[1]: {}", hex::encode(cmts[1]));
    println!("Note: range_proof bytes not available in debug output — wallet should provide them");
    use blake2::Blake2b512;
    let out = Blake2b512::digest(&pi_bytes);
    let mut r = [0u8; 32];
    r.copy_from_slice(&out[..32]);
    println!("pi_hash: {}", hex::encode(r));
}

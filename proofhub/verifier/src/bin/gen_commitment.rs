/// Generate a BLAKE3 commitment matching on-chain logic exactly.
/// Usage: gen_commitment <value_u64> <blinding_hex_64chars>
/// Output: commitment_hex_64chars

fn blake3_commitment(value: u64, blinding: &[u8; 32]) -> [u8; 32] {
    const COMMITMENT_DOMAIN: &[u8] = b"nulla_commitment_v1";
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMMITMENT_DOMAIN);
    hasher.update(&value.to_le_bytes());
    hasher.update(blinding);
    *hasher.finalize().as_bytes()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: gen_commitment <value_u64> <blinding_hex>");
        std::process::exit(1);
    }
    let value: u64 = args[1].parse().expect("value must be u64");
    let blinding_hex = args[2].trim_start_matches("0x");
    let blinding_bytes = hex::decode(blinding_hex).expect("invalid hex blinding");
    if blinding_bytes.len() != 32 {
        eprintln!("blinding must be 32 bytes (64 hex chars)");
        std::process::exit(1);
    }
    let mut blinding = [0u8; 32];
    blinding.copy_from_slice(&blinding_bytes);
    let commitment = blake3_commitment(value, &blinding);
    print!("{}", hex::encode(commitment));
}

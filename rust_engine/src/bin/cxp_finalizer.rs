use bls12_381::{G1Projective, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use rand::rngs::OsRng;
use sha2::{Digest as ShaDigest, Sha256};
use sovereign_lattice::pbft::{PbftMessage, PbftState, Phase};
use sovereign_lattice::threshold_bls::sign_bls_message;
use std::collections::HashMap;
use std::env;
use std::fs;

const TOTAL_NODES: usize = 4;
const THRESHOLD: usize = 3;
const VIEW: u64 = 0;
const SEQ: u64 = 1;
const COMMITMENT_DOMAIN: &[u8] = b"SOVEREIGN-CXP\0local-pbft-quorum/v1\0";

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_digest(value: &str) -> Result<[u8; 32], &'static str> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    if value.len() != 64 {
        return Err("DIGEST_MUST_BE_64_HEX_CHARS");
    }
    let bytes = value.as_bytes();
    let mut output = [0u8; 32];
    for index in 0..32 {
        let high = decode_hex_nibble(bytes[index * 2]).ok_or("INVALID_HEX_DIGEST")?;
        let low = decode_hex_nibble(bytes[index * 2 + 1]).ok_or("INVALID_HEX_DIGEST")?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(LUT[(byte >> 4) as usize] as char);
        result.push(LUT[(byte & 0x0f) as usize] as char);
    }
    result
}

fn generate_threshold_keys() -> (
    HashMap<u32, Scalar>,
    HashMap<u32, G2Projective>,
    G2Projective,
) {
    let mut polynomial = Vec::with_capacity(THRESHOLD);
    for _ in 0..THRESHOLD {
        polynomial.push(Scalar::random(&mut OsRng));
    }
    let master_pk = G2Projective::generator() * polynomial[0];
    let mut secret_keys = HashMap::new();
    let mut public_keys = HashMap::new();

    for node_id in 0..TOTAL_NODES as u32 {
        let x = Scalar::from((node_id + 1) as u64);
        let mut share = Scalar::zero();
        let mut power = Scalar::one();
        for coefficient in &polynomial {
            share += coefficient * power;
            power *= x;
        }
        secret_keys.insert(node_id, share);
        public_keys.insert(node_id, G2Projective::generator() * share);
    }
    (secret_keys, public_keys, master_pk)
}

fn canonical_message(phase: Phase, digest: &[u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(49);
    bytes.push(phase as u8);
    bytes.extend_from_slice(&VIEW.to_be_bytes());
    bytes.extend_from_slice(&SEQ.to_be_bytes());
    bytes.extend_from_slice(digest);
    bytes
}

fn signed_message(
    phase: Phase,
    digest: [u8; 32],
    sender_id: u32,
    secret_keys: &HashMap<u32, Scalar>,
) -> PbftMessage {
    let canonical = canonical_message(phase, &digest);
    PbftMessage {
        phase,
        view: VIEW,
        seq: SEQ,
        digest,
        sender_id,
        signature: sign_bls_message(&canonical, &secret_keys[&sender_id]),
    }
}

fn certificate_commitment(
    digest: &[u8; 32],
    master_pk: &G2Projective,
    signatures: &HashMap<u32, G1Projective>,
) -> String {
    let mut signer_ids: Vec<u32> = signatures.keys().copied().collect();
    signer_ids.sort_unstable();
    let mut hash = Sha256::new();
    hash.update(COMMITMENT_DOMAIN);
    hash.update(digest);
    hash.update(&VIEW.to_be_bytes());
    hash.update(&SEQ.to_be_bytes());
    hash.update(&master_pk.to_affine().to_compressed());
    for signer_id in signer_ids {
        hash.update(&signer_id.to_be_bytes());
        hash.update(&signatures[&signer_id].to_affine().to_compressed());
    }
    hex(&hash.finalize())
}

fn run(digest: [u8; 32]) -> Result<String, String> {
    let wal_path = env::temp_dir().join(format!(
        "sovereign-cxp-finalizer-{}-{}.wal",
        std::process::id(),
        hex(&digest[..8])
    ));
    let _ = fs::remove_file(&wal_path);
    env::set_var("WAL_PATH", &wal_path);

    let (secret_keys, public_keys, master_pk) = generate_threshold_keys();
    let mut state = PbftState::new(TOTAL_NODES, public_keys, master_pk)
        .map_err(|error| error.to_string())?;

    let leader = state.get_expected_leader(VIEW);
    let pre_prepare = signed_message(Phase::PrePrepare, digest, leader, &secret_keys);
    let pre_prepare_result = state
        .handle_message(&pre_prepare)
        .map_err(|error| error.to_string())?;
    if pre_prepare_result != "INBOUND_OK_PREPREPARE" {
        return Err("PREPREPARE_NOT_ACCEPTED".into());
    }

    let mut prepared = false;
    for sender_id in 0..THRESHOLD as u32 {
        let prepare = signed_message(Phase::Prepare, digest, sender_id, &secret_keys);
        let result = state
            .handle_message(&prepare)
            .map_err(|error| error.to_string())?;
        if result == "CERTIFICATE_OK_PREPARED" {
            prepared = true;
        }
    }
    if !prepared {
        return Err("PREPARE_QUORUM_NOT_REACHED".into());
    }

    let mut committed = false;
    for sender_id in 0..THRESHOLD as u32 {
        let commit = signed_message(Phase::Commit, digest, sender_id, &secret_keys);
        let result = state
            .handle_message(&commit)
            .map_err(|error| error.to_string())?;
        if result == "COMMITTED_OK" {
            committed = true;
        }
    }
    if !committed {
        return Err("COMMIT_QUORUM_NOT_REACHED".into());
    }

    let certificate = state
        .commit_certificates
        .get(&(VIEW, SEQ))
        .ok_or_else(|| "COMMIT_CERTIFICATE_MISSING".to_string())?;
    if certificate.digest != digest || !certificate.verify(state.quorum_size, &state.master_public_key) {
        return Err("COMMIT_CERTIFICATE_VERIFICATION_FAILED".into());
    }
    if state.committed_digest.get(&(VIEW, SEQ)) != Some(&digest) {
        return Err("COMMITTED_DIGEST_BINDING_FAILED".into());
    }

    let commitment = certificate_commitment(&digest, &state.master_public_key, &certificate.signatures);
    let digest_hex = hex(&digest);
    let master_pk_hex = hex(&state.master_public_key.to_affine().to_compressed());
    let _ = fs::remove_file(&wal_path);

    Ok(format!(
        "{{\"schema\":\"sovereign-cxp-local-quorum/v1\",\"status\":\"CONFIRMED\",\"scope\":\"LOCAL_IN_PROCESS_PBFT_QUORUM\",\"digest_sha256\":\"{}\",\"view\":{},\"sequence\":{},\"total_nodes\":{},\"fault_tolerance\":1,\"quorum_size\":{},\"prepared_certificate\":\"CONFIRMED\",\"commit_certificate\":\"CONFIRMED\",\"commit_certificate_verified\":true,\"signer_ids\":[0,1,2],\"master_public_key_hex\":\"{}\",\"certificate_commitment_sha256\":\"{}\",\"process_independence\":\"UNKNOWN\",\"host_independence\":\"UNKNOWN\",\"network_transport\":\"NOT_RUN\",\"distributed_finality\":\"UNKNOWN\"}}",
        digest_hex,
        VIEW,
        SEQ,
        TOTAL_NODES,
        state.quorum_size,
        master_pk_hex,
        commitment
    ))
}

fn main() {
    let mut args = env::args().skip(1);
    let digest_arg = match args.next() {
        Some(value) if args.next().is_none() => value,
        _ => {
            eprintln!("usage: cxp_finalizer <64-hex-sha256>");
            std::process::exit(2);
        }
    };
    let digest = match decode_digest(&digest_arg) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{}", error);
            std::process::exit(2);
        }
    };
    match run(digest) {
        Ok(output) => println!("{}", output),
        Err(error) => {
            eprintln!("{}", error);
            std::process::exit(1);
        }
    }
}

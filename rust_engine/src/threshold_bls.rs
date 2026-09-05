use bls12_381::{G1Projective, G2Projective, Scalar};
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use group::{Curve, Group};
use sha2::Sha256;
use std::collections::HashMap;

const DST: &[u8] = b"SOVEREIGN_LATTICE_PBFT_V1_BLS_SIG";

pub fn hash_message_to_curve(msg: &[u8]) -> G1Projective {
    <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, DST)
}

pub fn sign_bls_message(msg: &[u8], sk: &Scalar) -> G1Projective {
    hash_message_to_curve(msg) * sk
}

pub fn verify_bls_signature(msg: &[u8], sig: &G1Projective, pk: &G2Projective) -> bool {
    let hm = hash_message_to_curve(msg);
    let left = bls12_381::pairing(&sig.to_affine(), &G2Projective::generator().to_affine());
    let right = bls12_381::pairing(&hm.to_affine(), &pk.to_affine());
    left == right
}

pub fn aggregate_signatures(signatures: &[G1Projective]) -> G1Projective {
    let mut agg = G1Projective::identity();
    for sig in signatures {
        agg += sig;
    }
    agg
}

pub fn verify_threshold_signature(
    msg: &[u8],
    signatures: &HashMap<u32, G1Projective>,
    public_keys: &HashMap<u32, G2Projective>,
    threshold: usize,
) -> bool {
    if signatures.len() < threshold {
        return false;
    }

    let mut valid_count = 0;
    for (id, sig) in signatures {
        if let Some(pk) = public_keys.get(id) {
            if verify_bls_signature(msg, sig, pk) {
                valid_count += 1;
            }
        }
    }
    valid_count >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use rand::rngs::OsRng;

    #[test]
    fn test_bls_sign_and_verify() {
        let sk = Scalar::random(&mut OsRng);
        let pk = G2Projective::generator() * sk;
        let msg = b"Secure Hash-to-Curve Consensus Test";

        let sig = sign_bls_message(msg, &sk);
        assert!(verify_bls_signature(msg, &sig, &pk));

        let wrong_msg = b"Tampered Message";
        assert!(!verify_bls_signature(wrong_msg, &sig, &pk));
    }

    #[test]
    fn test_signature_aggregation() {
        let sk1 = Scalar::random(&mut OsRng);
        let pk1 = G2Projective::generator() * sk1;
        let sk2 = Scalar::random(&mut OsRng);
        let pk2 = G2Projective::generator() * sk2;

        let msg = b"Aggregated PBFT Block";
        let sig1 = sign_bls_message(msg, &sk1);
        let sig2 = sign_bls_message(msg, &sk2);

        let agg_sig = aggregate_signatures(&[sig1, sig2]);
        let agg_pk = pk1 + pk2;

        assert!(verify_bls_signature(msg, &agg_sig, &agg_pk));
    }
}

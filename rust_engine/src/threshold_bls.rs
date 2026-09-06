use bls12_381::{G1Projective, G2Projective, Scalar};
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use group::{Curve, Group};
use ff::Field;
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
    master_pk: &G2Projective,
    threshold: usize,
) -> bool {
    if signatures.len() < threshold {
        return false;
    }

    let mut ids: Vec<u32> = signatures.keys().cloned().collect();
    ids.sort();
    ids.truncate(threshold);

    let mut reconstructed_sig = G1Projective::identity();

    for &id_i in &ids {
        let sig_i = &signatures[&id_i];
        let x_i = Scalar::from((id_i + 1) as u64);

        let mut numerator = Scalar::one();
        let mut denominator = Scalar::one();

        for &id_j in &ids {
            if id_i == id_j {
                continue;
            }
            let x_j = Scalar::from((id_j + 1) as u64);
            numerator *= -&x_j;
            denominator *= &(x_i - x_j);
        }

        let denom_inv = denominator.invert();
        if bool::from(denom_inv.is_some()) {
            let lambda_i = numerator * denom_inv.unwrap();
            reconstructed_sig += sig_i * lambda_i;
        } else {
            return false;
        }
    }

    verify_bls_signature(msg, &reconstructed_sig, master_pk)
}

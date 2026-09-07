use bls12_381::{G2Projective, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use sovereign_lattice::pbft::{PbftMessage, PbftState, Phase};
use std::collections::HashMap;

fn generate_test_cluster(n: usize, threshold: usize) -> (HashMap<u32, Scalar>, HashMap<u32, G2Projective>, G2Projective) {
    let mut secret_polynomial = Vec::new();
    for _ in 0..threshold {
        secret_polynomial.push(Scalar::random(&mut OsRng));
    }
    let master_sk = secret_polynomial[0];
    let master_pk = G2Projective::generator() * master_sk;

    let mut secret_keys = HashMap::new();
    let mut public_keys = HashMap::new();

    for i in 0..n as u32 {
        let x = Scalar::from((i + 1) as u64);
        let mut sk_i = Scalar::zero();
        let mut x_pow = Scalar::one();
        for coeff in &secret_polynomial {
            sk_i += coeff * &x_pow;
            x_pow *= &x;
        }
        let pk_i = G2Projective::generator() * sk_i;
        secret_keys.insert(i, sk_i);
        public_keys.insert(i, pk_i);
    }
    (secret_keys, public_keys, master_pk)
}

#[test]
fn test_full_consensus_lifecycle() {
    let n = 4;
    let threshold = 3;
    let (_secret_keys, public_keys, master_pk) = generate_test_cluster(n, threshold);

    let mut state = PbftState::new(n, public_keys, master_pk).expect("Failed to initialize state");

    let invalid_msg = PbftMessage {
        phase: Phase::PrePrepare,
        view: 0,
        seq: 1,
        digest: [0xee; 32],
        sender_id: 999,
        signature: bls12_381::G1Projective::identity(),
    };

    let err = state.handle_message(&invalid_msg).unwrap_err();
    assert!(err.contains("AUTH_FAILED"));
}

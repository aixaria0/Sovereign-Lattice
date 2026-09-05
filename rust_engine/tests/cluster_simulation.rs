use bls12_381::{G1Projective, G2Projective, Scalar};
use ff::Field;
use group::Group;
use rand::rngs::OsRng;
use sovereign_lattice::pbft::PbftState;
use sovereign_lattice::threshold_bls::hash_message_to_curve;
use std::collections::HashMap;

#[test]
fn test_cluster_simulation_basic() {
    let n = 4;
    let mut secret_keys = HashMap::new();
    let mut public_keys = HashMap::new();

    for i in 0..n as u32 {
        let sk = Scalar::random(&mut OsRng);
        let pk = G2Projective::generator() * sk;
        secret_keys.insert(i, sk);
        public_keys.insert(i, pk);
    }

    let master_sk = Scalar::random(&mut OsRng);
    let master_pk = G2Projective::generator() * master_sk;

    let state = PbftState::new(n, public_keys, master_pk);
    assert!(state.is_ok());

    let msg = b"cluster_state_transition_probe";
    let point = hash_message_to_curve(msg);
    assert_ne!(point, G1Projective::identity());
}

use bls12_381::{G2Projective, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use sovereign_lattice::pbft::{PbftMessage, PbftState, Phase};
use sovereign_lattice::threshold_bls::sign_bls_message;
use std::collections::HashMap;

fn generate_test_cluster(
    n: usize,
    threshold: usize,
) -> (HashMap<u32, Scalar>, HashMap<u32, G2Projective>, G2Projective) {
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

fn create_pbft_message(
    phase: Phase,
    view: u64,
    seq: u64,
    digest: [u8; 32],
    sender_id: u32,
    sk: &Scalar,
) -> PbftMessage {
    let mut canonical = Vec::new();
    canonical.push(phase as u8);
    canonical.extend_from_slice(&view.to_be_bytes());
    canonical.extend_from_slice(&seq.to_be_bytes());
    canonical.extend_from_slice(&digest);

    let signature = sign_bls_message(&canonical, sk);
    PbftMessage {
        phase,
        view,
        seq,
        digest,
        sender_id,
        signature,
    }
}

#[test]
fn test_byzantine_fault_tolerance_quorum_progress() {
    let n = 4;
    let threshold = 3;
    let (secret_keys, public_keys, master_pk) = generate_test_cluster(n, threshold);

    // Node 3 is treated as an offline or Byzantine node
    let mut node_states: Vec<PbftState> = (0..3)
        .map(|_| PbftState::new(n, public_keys.clone(), master_pk).expect("Failed node init"))
        .collect();

    let view: u64 = 0;
    let seq: u64 = 1;
    let block_digest = [0x42; 32];
    let leader_id: u32 = 0;

    // 1. Leader broadcasts PrePrepare to honest nodes (excluding node 3)
    let pre_prepare = create_pbft_message(
        Phase::PrePrepare,
        view,
        seq,
        block_digest,
        leader_id,
        &secret_keys[&leader_id],
    );

    for state in node_states.iter_mut() {
        let res = state.handle_message(&pre_prepare);
        assert!(res.is_ok(), "Honest node must accept valid PrePrepare");
    }

    // 2. Prepare vote exchange among the 3 active nodes (reaching 3-of-4 quorum)
    for sender_id in 0..3u32 {
        let prepare_msg = create_pbft_message(
            Phase::Prepare,
            view,
            seq,
            block_digest,
            sender_id,
            &secret_keys[&sender_id],
        );

        for state in node_states.iter_mut() {
            let res = state.handle_message(&prepare_msg);
            assert!(res.is_ok());
        }
    }

    // Verify PreparedCertificate formation on all 3 honest nodes
    for state in node_states.iter() {
        assert!(
            state.prepared_certificates.contains_key(&(view, seq)),
            "Quorum of 3 honest nodes must successfully form PreparedCertificate"
        );
    }

    // 3. Commit vote exchange among honest nodes to finalize the block
    for sender_id in 0..3u32 {
        let commit_msg = create_pbft_message(
            Phase::Commit,
            view,
            seq,
            block_digest,
            sender_id,
            &secret_keys[&sender_id],
        );

        for state in node_states.iter_mut() {
            let res = state.handle_message(&commit_msg);
            assert!(res.is_ok());
        }
    }

    // Verify block commitment in the absence of node 3
    for state in node_states.iter() {
        assert_eq!(
            state.committed_digest.get(&(view, seq)),
            Some(&block_digest),
            "Block must be safely committed despite 1 Byzantine/offline node"
        );
    }
}

#[test]
fn test_byzantine_leader_recovery_view_change() {
    let n = 4;
    let threshold = 3;
    let (secret_keys, public_keys, master_pk) = generate_test_cluster(n, threshold);

    // Node 1 is the prospective leader for View 1 (1 % 4 = 1)
    let mut new_leader_state =
        PbftState::new(n, public_keys.clone(), master_pk).expect("Failed init");

    let target_view: u64 = 1;
    let seq: u64 = 0;
    let empty_digest = [0u8; 32];

    // Faulty leader (node 0) has crashed; nodes 1, 2, and 3 broadcast ViewChange
    for voter_id in 1..4u32 {
        let vc_msg = create_pbft_message(
            Phase::ViewChange,
            target_view,
            seq,
            empty_digest,
            voter_id,
            &secret_keys[&voter_id],
        );

        let res = new_leader_state.handle_message(&vc_msg);
        assert!(res.is_ok());
    }

    // New view must be finalized upon receiving 2f+1 votes
    assert_eq!(
        new_leader_state.current_view, target_view,
        "Cluster must advance view upon receiving 2f+1 view change votes"
    );
    assert!(
        new_leader_state.new_view_certificates.contains_key(&target_view),
        "NewViewCertificate must be formalized"
    );
}

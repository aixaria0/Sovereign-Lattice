use bls12_381::{G1Projective, G2Projective, Scalar};
use sovereign_lattice::dkg::DkgSession;
use sovereign_lattice::pbft::PbftState;
use sovereign_lattice::threshold_bls::{
    sign_bls_message, verify_threshold_signature,
};
use std::collections::HashMap;

#[test]
fn test_dkg_e2e_consensus_integration() {
    let n = 4usize;
    let threshold = 3usize;

    let mut sessions = HashMap::new();
    for i in 0..n as u32 {
        sessions.insert(i, DkgSession::new(i, threshold, n));
    }

    let mut all_commitments = HashMap::new();
    for (&id, session) in &mut sessions {
        all_commitments.insert(id, session.generate_commitments());
    }

    for receiver_id in 0..n as u32 {
        let incoming_shares: Vec<(u32, Scalar, Vec<G2Projective>)> = sessions
            .iter()
            .map(|(&sender_id, sender_session)| {
                let share = sender_session.evaluate_share_for(receiver_id);
                let commits = all_commitments.get(&sender_id).unwrap().clone();
                (sender_id, share, commits)
            })
            .collect();

        let receiver_session = sessions.get_mut(&receiver_id).unwrap();
        for (sender_id, share, commits) in incoming_shares {
            receiver_session
                .process_incoming_share(sender_id, share, &commits)
                .expect("Failed processing valid DKG share");
        }
    }

    let participants: Vec<u32> = (0..n as u32).collect();
    let mut secret_shares = HashMap::new();
    let mut master_pks = HashMap::new();

    for (&id, session) in &sessions {
        let (sk_share, master_pk) = session
            .finalize_dkg(&participants)
            .expect("Finalization failed");
        secret_shares.insert(id, sk_share);
        master_pks.insert(id, master_pk);
    }

    let canonical_master_pk = master_pks[&0];
    for id in 1..n as u32 {
        assert_eq!(
            canonical_master_pk, master_pks[&id],
            "Master PK mismatch between node 0 and node {}",
            id
        );
    }

    let mut public_keys = HashMap::new();
    for &id in &participants {
        let signing_pk = G2Projective::generator() * secret_shares[&id];
        public_keys.insert(id, signing_pk);
    }

    let msg = b"canonical_sovereign_lattice_block_proposal_digest";
    let mut threshold_signatures: HashMap<u32, G1Projective> = HashMap::new();

    for &id in &participants[0..threshold] {
        let sig = sign_bls_message(msg, &secret_shares[&id]);
        threshold_signatures.insert(id, sig);
    }

    let is_valid_threshold_sig = verify_bound_threshold_signature(
        msg,
        &threshold_signatures,
        &canonical_master_pk,
        threshold,
    );
    assert!(
        is_valid_threshold_sig,
        "Threshold signature validation failed against master PK"
    );

    let pbft_state = PbftState::new(n, public_keys, canonical_master_pk);
    assert!(
        pbft_state.is_ok(),
        "Failed to bootstrap PBFT state machine with DKG keys"
    );
}

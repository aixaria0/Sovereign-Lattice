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
                .expect("DKG_SHARE_PROCESS_FAILED");
        }
    }

    let mut transcript_hashes = HashMap::new();
    for (&id, session) in &sessions {
        transcript_hashes.insert(id, session.transcript_hash());
    }

    for (_, session) in &sessions {
        assert!(
            session.verify_transcript_consistency(&transcript_hashes).is_ok(),
            "Honest nodes must agree on identical commitment transcript"
        );
    }

    let participants: Vec<u32> = (0..n as u32).collect();
    let mut secret_shares = HashMap::new();
    let mut master_pks = HashMap::new();

    for (&id, session) in &sessions {
        let (sk_share, master_pk) = session
            .finalize_dkg(&participants)
            .expect("DKG_FINALIZATION_FAILED");
        secret_shares.insert(id, sk_share);
        master_pks.insert(id, master_pk);
    }

    let canonical_master_pk = master_pks[&0];
    for id in 1..n as u32 {
        assert_eq!(
            canonical_master_pk, master_pks[&id],
            "MASTER_PK_MISMATCH_NODE_{}",
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

    let is_valid_threshold_sig = verify_threshold_signature(
        msg,
        &threshold_signatures,
        &canonical_master_pk,
        threshold,
    );
    assert!(is_valid_threshold_sig, "THRESHOLD_SIG_INVALID");

    let pbft_state = PbftState::new(n, public_keys, canonical_master_pk);
    assert!(pbft_state.is_ok(), "PBFT_STATE_BOOTSTRAP_FAILED");
}

#[test]
fn test_dkg_equivocating_dealer_detected() {
    let n = 4usize;
    let threshold = 3usize;

    let mut session_honest = DkgSession::new(1, threshold, n);
    let mut session_victim_a = DkgSession::new(2, threshold, n);
    let mut session_victim_b = DkgSession::new(3, threshold, n);

    let malicious_session_a = DkgSession::new(0, threshold, n);
    let malicious_session_b = DkgSession::new(0, threshold, n);

    let commits_a = malicious_session_a.generate_commitments();
    let share_for_2 = malicious_session_a.evaluate_share_for(2);
    session_victim_a.process_incoming_share(0, share_for_2, &commits_a).unwrap();

    let commits_b = malicious_session_b.generate_commitments();
    let share_for_3 = malicious_session_b.evaluate_share_for(3);
    session_victim_b.process_incoming_share(0, share_for_3, &commits_b).unwrap();

    let honest_commits = session_honest.generate_commitments();
    session_victim_a.process_incoming_share(1, session_honest.evaluate_share_for(2), &honest_commits).unwrap();
    session_victim_b.process_incoming_share(1, session_honest.evaluate_share_for(3), &honest_commits).unwrap();

    let hash_a = session_victim_a.transcript_hash();
    let hash_b = session_victim_b.transcript_hash();

    assert_ne!(hash_a, hash_b, "Equivocating dealer must yield divergent transcript hashes");

    let mut peer_hashes = HashMap::new();
    peer_hashes.insert(3, hash_b);

    let consistency_result = session_victim_a.verify_transcript_consistency(&peer_hashes);
    assert!(consistency_result.is_err());
    assert_eq!(consistency_result.unwrap_err(), "TRANSCRIPT_EQUIVOCATION_DETECTED");
}

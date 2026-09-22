//! Independent PBFT control experiment correlated with an external CBC witness.
//!
//! Four sender labels are used only as test inputs; they are not treated as
//! PBFT votes, signatures, finality evidence or an equivalent Casper outcome.
use crate::pbft::{PbftMessage, PbftState};
use bls12_381::G2Projective;
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, PartialEq, Eq)]
pub struct ControlResult {
    pub witness_digest: String,
    pub senders: Vec<u32>,
    pub unique_senders: usize,
    pub one_replacement_from_control: bool,
    pub all_four_distinct: bool,
    pub pbft_quorum_size: usize,
    pub topology_accepted: bool,
    pub truncated_frame_rejected: bool,
    pub invalid_phase_rejected: bool,
}

pub fn run_pbft_control(witness_digest: &str, sender_csv: &str) -> Result<ControlResult, String> {
    if witness_digest.len() != 64 ||
        !witness_digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err("Expected lowercase 64-character external witness SHA-256".into());
    }
    let names: Vec<_> = sender_csv.split(',').collect();
    if names.len() != 4 {
        return Err("Expected four external sender labels".into());
    }
    let mut senders = Vec::with_capacity(4);
    for name in names {
        let sender = match name {
            "v0" => 0,
            "v1" => 1,
            "v2" => 2,
            "v3" => 3,
            _ => return Err("Unknown external sender label".into()),
        };
        senders.push(sender);
    }
    let unique_senders = senders.iter().copied().collect::<BTreeSet<_>>().len();
    let one_replacement_from_control =
        senders.iter().zip([0, 1, 2, 3]).filter(|(actual, expected)| **actual != *expected).count() == 1;
    if unique_senders != 3 || !one_replacement_from_control {
        return Err("Expected the bounded M27 one-replacement, three-sender case".into());
    }
    let keys: HashMap<u32, G2Projective> = (0..4)
        .map(|id| (id, G2Projective::generator()))
        .collect();
    // Actual PBFT state initialization performs topology/registry checks.
    // It does NOT validate the CBC candidate as a PBFT signature or vote.
    let state = PbftState::new(4, keys, G2Projective::generator())
        .map_err(|error| format!("PBFT state initialization failed: {error}"))?;
    let truncated_frame_rejected = PbftMessage::from_bytes(&vec![0u8; 50]).is_err();
    let mut invalid_phase_frame = vec![0u8; 101];
    invalid_phase_frame[0] = 99;
    let invalid_phase_rejected = PbftMessage::from_bytes(&invalid_phase_frame).is_err();
    if !truncated_frame_rejected || !invalid_phase_rejected ||
        state.quorum_size != 3 || state.total_nodes != 4 {
        return Err("PBFT local control invariant did not hold".into());
    }
    Ok(ControlResult {
        witness_digest: witness_digest.to_owned(),
        senders,
        unique_senders,
        one_replacement_from_control,
        all_four_distinct: unique_senders == 4,
        pbft_quorum_size: state.quorum_size,
        topology_accepted: true,
        truncated_frame_rejected,
        invalid_phase_rejected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_pbft_control_retains_external_claim_boundary() {
        let result = run_pbft_control(&"a".repeat(64), "v0,v0,v2,v3").unwrap();
        assert_eq!(result.unique_senders, 3);
        assert!(result.one_replacement_from_control);
        assert!(!result.all_four_distinct);
        assert_eq!(result.pbft_quorum_size, 3);
        assert!(result.topology_accepted);
        assert!(result.truncated_frame_rejected);
        assert!(result.invalid_phase_rejected);
    }

    #[test]
    fn refuses_non_minimal_and_inconsistent_external_shapes() {
        for ids in ["v0,v1,v2,v3", "v0,v0,v0,v3", "v0,v1,v3,v3", "v0,v1,v2", "v0,v4,v2,v3"] {
            assert!(run_pbft_control(&"a".repeat(64), ids).is_err(), "{ids}");
        }
        assert!(run_pbft_control("abcd", "v0,v0,v2,v3").is_err());
    }
}

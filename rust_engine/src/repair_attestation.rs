use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairAttestationInput {
    pub propagation_envelope_digest: String,
    pub sentinel_observation_digest: String,
    pub repair_problem_id: String,
    pub native_replay_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairAttestation {
    pub schema: &'static str,
    pub attested_root: String,
    pub repair_problem_id: String,
    pub eligible: bool,
    pub claim_boundary: &'static str,
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub fn attest_repair_root(input: &RepairAttestationInput) -> RepairAttestation {
    let eligible = input.native_replay_verified
        && valid_sha256(&input.propagation_envelope_digest)
        && valid_sha256(&input.sentinel_observation_digest)
        && !input.repair_problem_id.trim().is_empty();

    let root = if eligible {
        let mut hasher = Sha256::new();
        hasher.update(b"causal-assurance-repair-attestation/v1\0");
        hasher.update(input.propagation_envelope_digest.as_bytes());
        hasher.update(b"\0");
        hasher.update(input.sentinel_observation_digest.as_bytes());
        hasher.update(b"\0");
        hasher.update(input.repair_problem_id.as_bytes());
        format!("sha256:{:x}", hasher.finalize())
    } else {
        "UNATTESTED".to_string()
    };

    RepairAttestation {
        schema: "causal-assurance-repair-attestation/v1",
        attested_root: root,
        repair_problem_id: input.repair_problem_id.clone(),
        eligible,
        claim_boundary: "Sovereign-Lattice attests the supplied evidence root only. It does not independently prove target-protocol safety, native replay semantics, or global repair correctness.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> RepairAttestationInput {
        RepairAttestationInput {
            propagation_envelope_digest: format!("sha256:{}", "a".repeat(64)),
            sentinel_observation_digest: format!("sha256:{}", "b".repeat(64)),
            repair_problem_id: "casper-duplicate-minimum-sender-coverage-repair".into(),
            native_replay_verified: true,
        }
    }

    #[test]
    fn attests_only_a_well_formed_native_verified_root() {
        let a = attest_repair_root(&input());
        assert!(a.eligible);
        assert!(a.attested_root.starts_with("sha256:"));
        assert!(a.claim_boundary.contains("does not independently prove"));
    }

    #[test]
    fn fails_closed_without_native_replay() {
        let mut i = input();
        i.native_replay_verified = false;
        let a = attest_repair_root(&i);
        assert!(!a.eligible);
        assert_eq!(a.attested_root, "UNATTESTED");
    }

    #[test]
    fn fails_closed_on_malformed_upstream_digest() {
        let mut i = input();
        i.sentinel_observation_digest = "sha256:bad".into();
        assert!(!attest_repair_root(&i).eligible);
    }

    #[test]
    fn root_is_deterministic_and_domain_separated() {
        assert_eq!(attest_repair_root(&input()), attest_repair_root(&input()));
    }
}

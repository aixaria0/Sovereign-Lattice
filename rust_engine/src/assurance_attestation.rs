use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssuranceAttestation {
    pub schema: &'static str,
    pub certificate_digest: String,
    pub reviewer_id: String,
    pub decision: ReviewDecision,
    pub scope_digest: String,
    pub attestation_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReviewDecision { Confirmed, Rejected, Abstained }

impl ReviewDecision {
    fn as_str(&self) -> &'static str {
        match self { Self::Confirmed => "CONFIRMED", Self::Rejected => "REJECTED", Self::Abstained => "ABSTAINED" }
    }
}

impl AssuranceAttestation {
    pub fn new(certificate_digest: impl Into<String>, reviewer_id: impl Into<String>, decision: ReviewDecision, scope_digest: impl Into<String>) -> Result<Self, &'static str> {
        let certificate_digest = certificate_digest.into();
        let reviewer_id = reviewer_id.into();
        let scope_digest = scope_digest.into();
        if reviewer_id.trim().is_empty() { return Err("reviewer id is required"); }
        if !valid_sha256(&certificate_digest) || !valid_sha256(&scope_digest) { return Err("certificate and scope digests must be SHA-256 fingerprints"); }
        let material = format!("causal-assurance-attestation/v1\0{}\0{}\0{}\0{}", certificate_digest, reviewer_id, decision.as_str(), scope_digest);
        let attestation_digest = format!("sha256:{:x}", Sha256::digest(material.as_bytes()));
        Ok(Self { schema: "causal-assurance-attestation/v1", certificate_digest, reviewer_id, decision, scope_digest, attestation_digest })
    }

    pub fn verify_binding(&self, certificate_digest: &str, scope_digest: &str) -> Result<(), &'static str> {
        if self.certificate_digest != certificate_digest { return Err("certificate digest binding mismatch"); }
        if self.scope_digest != scope_digest { return Err("scope digest binding mismatch"); }
        let material = format!(
            "causal-assurance-attestation/v1\0{}\0{}\0{}\0{}",
            self.certificate_digest, self.reviewer_id, self.decision.as_str(), self.scope_digest
        );
        let expected = format!("sha256:{:x}", Sha256::digest(material.as_bytes()));
        if expected != self.attestation_digest { return Err("attestation digest mismatch"); }
        Ok(())
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71 && value.starts_with("sha256:") && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn digest(byte: char) -> String { format!("sha256:{}", byte.to_string().repeat(64)) }
    #[test]
    fn attestation_is_deterministic() {
        let a = AssuranceAttestation::new(digest('a'), "reviewer-1", ReviewDecision::Confirmed, digest('b')).unwrap();
        let b = AssuranceAttestation::new(digest('a'), "reviewer-1", ReviewDecision::Confirmed, digest('b')).unwrap();
        assert_eq!(a, b);
        assert!(a.verify_binding(&digest('a'), &digest('b')).is_ok());
    }
    #[test]
    fn tampered_binding_is_rejected() {
        let mut a = AssuranceAttestation::new(digest('a'), "reviewer-1", ReviewDecision::Confirmed, digest('b')).unwrap();
        assert!(a.verify_binding(&digest('c'), &digest('b')).is_err());
        a.attestation_digest = digest('d');
        assert!(a.verify_binding(&digest('a'), &digest('b')).is_err());
    }

    #[test]
    fn invalid_certificate_digest_is_rejected() {
        assert!(AssuranceAttestation::new("bad", "reviewer-1", ReviewDecision::Confirmed, digest('b')).is_err());
    }
}

#[cfg(test)]
mod cross_repo_fixture_tests {
    use sha2::{Digest, Sha256};
    const FIXTURE: &[u8] = b"causal-assurance-fixture/v1\nrun=fixture-001\nsubject=finite-state-model:dual-refinement-fixture\nwitness=valid-down,valid-finish\ncost=2,1\n";
    const DIGEST: &str = "sha256:4f4fd3c2715b193a78d79ac0be11c893aa7bfdc6f9a52ca7de1240d64f2a1703";
    #[test]
    fn canonical_cross_repo_fixture_matches_frozen_digest() {
        let actual = format!("sha256:{:x}", Sha256::digest(FIXTURE));
        assert_eq!(actual, DIGEST);
    }
}

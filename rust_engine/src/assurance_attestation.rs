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
    }
    #[test]
    fn invalid_certificate_digest_is_rejected() {
        assert!(AssuranceAttestation::new("bad", "reviewer-1", ReviewDecision::Confirmed, digest('b')).is_err());
    }
}

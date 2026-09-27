use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

const ATTESTATION_SCHEMA: &str = "causal-assurance-attestation/v1";
const SIGNATURE_SCHEMA: &str = "causal-assurance-attestation-signature/v1";

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
        match self {
            Self::Confirmed => "CONFIRMED",
            Self::Rejected => "REJECTED",
            Self::Abstained => "ABSTAINED",
        }
    }
}

fn push_length_prefixed(output: &mut Vec<u8>, field: &[u8]) {
    let len = u32::try_from(field.len()).expect("attestation field exceeds u32 length");
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(field);
}

fn attestation_material(
    certificate_digest: &str,
    reviewer_id: &str,
    decision: &ReviewDecision,
    scope_digest: &str,
) -> Vec<u8> {
    let mut output = Vec::new();
    for field in [
        ATTESTATION_SCHEMA,
        certificate_digest,
        reviewer_id,
        decision.as_str(),
        scope_digest,
    ] {
        push_length_prefixed(&mut output, field.as_bytes());
    }
    output
}

impl AssuranceAttestation {
    pub fn new(
        certificate_digest: impl Into<String>,
        reviewer_id: impl Into<String>,
        decision: ReviewDecision,
        scope_digest: impl Into<String>,
    ) -> Result<Self, &'static str> {
        let certificate_digest = certificate_digest.into();
        let reviewer_id = reviewer_id.into();
        let scope_digest = scope_digest.into();
        if reviewer_id.trim().is_empty() {
            return Err("reviewer id is required");
        }
        if !valid_sha256(&certificate_digest) || !valid_sha256(&scope_digest) {
            return Err("certificate and scope digests must be SHA-256 fingerprints");
        }
        let material = attestation_material(&certificate_digest, &reviewer_id, &decision, &scope_digest);
        let attestation_digest = format!("sha256:{:x}", Sha256::digest(&material));
        Ok(Self {
            schema: ATTESTATION_SCHEMA,
            certificate_digest,
            reviewer_id,
            decision,
            scope_digest,
            attestation_digest,
        })
    }

    pub fn verify_binding(&self, certificate_digest: &str, scope_digest: &str) -> Result<(), &'static str> {
        if self.certificate_digest != certificate_digest {
            return Err("certificate digest binding mismatch");
        }
        if self.scope_digest != scope_digest {
            return Err("scope digest binding mismatch");
        }
        let material = attestation_material(
            &self.certificate_digest,
            &self.reviewer_id,
            &self.decision,
            &self.scope_digest,
        );
        let expected = format!("sha256:{:x}", Sha256::digest(&material));
        if expected != self.attestation_digest {
            return Err("attestation digest mismatch");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAssuranceAttestation {
    pub schema: &'static str,
    pub attestation: AssuranceAttestation,
    pub algorithm: &'static str,
    pub key_id: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode<const N: usize>(value: &str) -> Result<[u8; N], &'static str> {
    if value.len() != N * 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid hexadecimal value");
    }
    let mut output = [0u8; N];
    for (i, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| "invalid hexadecimal value")?;
    }
    Ok(output)
}

fn signer_key_id(public_key: &[u8; 32]) -> String {
    format!("sha256:{:x}", Sha256::digest(public_key))
}

fn signature_material(attestation_digest: &str, key_id: &str) -> Vec<u8> {
    let mut output = Vec::new();
    for field in [SIGNATURE_SCHEMA, attestation_digest, key_id] {
        push_length_prefixed(&mut output, field.as_bytes());
    }
    output
}

impl SignedAssuranceAttestation {
    pub fn sign(attestation: AssuranceAttestation, signing_key: &SigningKey) -> Result<Self, &'static str> {
        attestation.verify_binding(&attestation.certificate_digest, &attestation.scope_digest)?;
        let public_key = signing_key.verifying_key().to_bytes();
        let key_id = signer_key_id(&public_key);
        let signature = signing_key.sign(&signature_material(&attestation.attestation_digest, &key_id));
        Ok(Self {
            schema: SIGNATURE_SCHEMA,
            attestation,
            algorithm: "Ed25519",
            key_id,
            public_key_hex: hex_encode(&public_key),
            signature_hex: hex_encode(&signature.to_bytes()),
        })
    }

    /// Verification is fail-closed: the embedded key is not trusted unless its
    /// fingerprint exactly matches the independently supplied expected key id.
    pub fn verify(
        &self,
        expected_key_id: &str,
        certificate_digest: &str,
        scope_digest: &str,
    ) -> Result<(), &'static str> {
        if self.schema != SIGNATURE_SCHEMA || self.algorithm != "Ed25519" {
            return Err("unexpected attestation signature schema or algorithm");
        }
        if !valid_sha256(expected_key_id) || !valid_sha256(&self.key_id) {
            return Err("invalid signer key id");
        }
        self.attestation.verify_binding(certificate_digest, scope_digest)?;

        let public_key = hex_decode::<32>(&self.public_key_hex)?;
        let actual_key_id = signer_key_id(&public_key);
        if actual_key_id != self.key_id {
            return Err("public key fingerprint does not match envelope key id");
        }
        if actual_key_id != expected_key_id {
            return Err("attestation signer is not the pinned expected key");
        }

        let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|_| "invalid Ed25519 public key")?;
        let signature_bytes = hex_decode::<64>(&self.signature_hex)?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify(
                &signature_material(&self.attestation.attestation_digest, &actual_key_id),
                &signature,
            )
            .map_err(|_| "Ed25519 attestation signature verification failed")
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

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

    #[test]
    fn signed_attestation_requires_pinned_signer() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let attestation = AssuranceAttestation::new(
            digest('a'),
            "reviewer-1",
            ReviewDecision::Confirmed,
            digest('b'),
        ).unwrap();
        let signed = SignedAssuranceAttestation::sign(attestation, &key).unwrap();
        assert!(signed.verify(&signed.key_id, &digest('a'), &digest('b')).is_ok());
        let other_id = signer_key_id(&other.verifying_key().to_bytes());
        assert_eq!(
            signed.verify(&other_id, &digest('a'), &digest('b')),
            Err("attestation signer is not the pinned expected key")
        );
    }

    #[test]
    fn signed_attestation_rejects_signature_or_binding_tamper() {
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let attestation = AssuranceAttestation::new(
            digest('a'),
            "reviewer-1",
            ReviewDecision::Confirmed,
            digest('b'),
        ).unwrap();
        let mut signed = SignedAssuranceAttestation::sign(attestation, &key).unwrap();
        signed.signature_hex.replace_range(0..2, "00");
        assert!(signed.verify(&signed.key_id, &digest('a'), &digest('b')).is_err());
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

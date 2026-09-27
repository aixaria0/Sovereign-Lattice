use sha2::{Digest, Sha256};

pub const SIGNED_PACKAGE_ROOT_SCHEMA: &str = "causal-assurance-signed-root/v2";
pub const PORTABLE_PACKAGE_SCHEMA: &str = "causal-assurance-portable-package/v1";

#[derive(Clone, Debug)]
pub struct RootArtifact<'a> {
    pub role: &'a str,
    pub bytes: &'a [u8],
    pub sha256: &'a str,
    pub binds_to: &'a [&'a str],
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn push_length_prefixed(output: &mut Vec<u8>, field: &str) -> Result<(), &'static str> {
    let bytes = field.as_bytes();
    let len = u32::try_from(bytes.len()).map_err(|_| "canonical field exceeds u32 length")?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

/// Cross-language canonical-root verifier.
/// Raw artifact bytes are rehashed here; declared digests and all transitive bindings
/// must match before a package root is produced.
pub fn canonical_package_root(
    run_id: &str,
    subject: &str,
    artifacts: &[RootArtifact<'_>],
) -> Result<String, &'static str> {
    const ROLES: [&str; 4] = ["WITNESS", "EVIDENCE", "WORKBENCH", "ATTESTATION"];
    if run_id.trim().is_empty() || subject.trim().is_empty() || artifacts.len() != ROLES.len() {
        return Err("invalid package shape");
    }

    let mut material = Vec::new();
    for field in [SIGNED_PACKAGE_ROOT_SCHEMA, PORTABLE_PACKAGE_SCHEMA, run_id, subject] {
        push_length_prefixed(&mut material, field)?;
    }

    let mut recomputed: Vec<String> = Vec::with_capacity(artifacts.len());
    for (index, artifact) in artifacts.iter().enumerate() {
        if artifact.role != ROLES[index] || !valid_sha256(artifact.sha256) {
            return Err("invalid artifact");
        }
        let actual = format!("sha256:{:x}", Sha256::digest(artifact.bytes));
        if actual != artifact.sha256 {
            return Err("artifact digest mismatch");
        }
        if artifact.binds_to.len() != recomputed.len()
            || artifact.binds_to.iter().zip(recomputed.iter()).any(|(declared, expected)| *declared != expected)
        {
            return Err("artifact binding mismatch");
        }

        for field in [
            index.to_string(),
            artifact.role.to_string(),
            actual.clone(),
            artifact.binds_to.len().to_string(),
        ] {
            push_length_prefixed(&mut material, &field)?;
        }
        for binding in artifact.binds_to {
            push_length_prefixed(&mut material, binding)?;
        }
        recomputed.push(actual);
    }

    Ok(format!("sha256:{:x}", Sha256::digest(&material)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: &str = "sha256:ba1c566a4bad288c22a0b7511458c92ca5822cd41632e51806e9ea75ed12d13d";
    const E: &str = "sha256:ee8250fb76e094b34b471f13a73dbbe51d1ae142e9df59d7c0d31ec20f0a0a8e";
    const X: &str = "sha256:d85b40105dd0b9cdbe46a1ee1b96abdf1474ae96fb86bd28ca701f44f017ac3b";
    const A: &str = "sha256:813a89a296973e35545cfa74fe3efd172a7d19443c97c625d699e9737229b0a2";

    fn fixture<'a>() -> [RootArtifact<'a>; 4] {
        [
            RootArtifact { role: "WITNESS", bytes: b"witness", sha256: W, binds_to: &[] },
            RootArtifact { role: "EVIDENCE", bytes: b"evidence", sha256: E, binds_to: &[W] },
            RootArtifact { role: "WORKBENCH", bytes: b"workbench", sha256: X, binds_to: &[W, E] },
            RootArtifact { role: "ATTESTATION", bytes: b"attestation", sha256: A, binds_to: &[W, E, X] },
        ]
    }

    #[test]
    fn matches_frozen_cross_language_root() {
        let root = canonical_package_root("root-fixture", "generic-system", &fixture()).unwrap();
        assert_eq!(root, "sha256:6dc2f70171c8bd415e48f275a00bc457b2a14e1eb82d4ee893f5f5dbb73803ae");
    }

    #[test]
    fn raw_byte_mutation_fails_closed() {
        let mut artifacts = fixture();
        artifacts[1].bytes = b"evidence!";
        assert_eq!(canonical_package_root("root-fixture", "generic-system", &artifacts), Err("artifact digest mismatch"));
    }

    #[test]
    fn role_reordering_fails_closed() {
        let mut artifacts = fixture();
        artifacts.swap(0, 1);
        assert_eq!(canonical_package_root("root-fixture", "generic-system", &artifacts), Err("invalid artifact"));
    }

    #[test]
    fn length_prefix_distinguishes_embedded_nul_fields() {
        let left = canonical_package_root("a\0b", "c", &fixture()).unwrap();
        let right = canonical_package_root("a", "b\0c", &fixture()).unwrap();
        assert_ne!(left, right);
    }
}

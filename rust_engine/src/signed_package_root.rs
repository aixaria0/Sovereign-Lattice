use sha2::{Digest, Sha256};

pub const SIGNED_PACKAGE_ROOT_SCHEMA: &str = "causal-assurance-signed-root/v1";
pub const PORTABLE_PACKAGE_SCHEMA: &str = "causal-assurance-portable-package/v1";

#[derive(Clone, Debug)]
pub struct RootArtifact<'a> { pub role: &'a str, pub sha256: &'a str, pub binds_to: &'a [&'a str] }

pub fn canonical_package_root(run_id:&str, subject:&str, artifacts:&[RootArtifact<'_>]) -> Result<String,&'static str> {
    const ROLES:[&str;4]=["WITNESS","EVIDENCE","WORKBENCH","ATTESTATION"];
    if run_id.is_empty() || subject.is_empty() || artifacts.len()!=4 { return Err("invalid package shape"); }
    let mut fields=vec![SIGNED_PACKAGE_ROOT_SCHEMA.to_string(),PORTABLE_PACKAGE_SCHEMA.to_string(),run_id.to_string(),subject.to_string()];
    for (i,a) in artifacts.iter().enumerate() {
        if a.role!=ROLES[i] || !a.sha256.starts_with("sha256:") { return Err("invalid artifact"); }
        fields.extend([i.to_string(),a.role.to_string(),a.sha256.to_string(),a.binds_to.len().to_string()]);
        fields.extend(a.binds_to.iter().map(|v|(*v).to_string()));
    }
    Ok(format!("sha256:{:x}",Sha256::digest(fields.join("\0").as_bytes())))
}

#[cfg(test)]
mod tests {
 use super::*;
 #[test] fn canonical_root_is_deterministic() {
  let w="sha256:ba1c566a4bad288c22a0b7511458c92ca5822cd41632e51806e9ea75ed12d13d";
  let e="sha256:ee8250fb76e094b34b471f13a73dbbe51d1ae142e9df59d7c0d31ec20f0a0a8e";
  let x="sha256:d85b40105dd0b9cdbe46a1ee1b96abdf1474ae96fb86bd28ca701f44f017ac3b";
  let a="sha256:813a89a296973e35545cfa74fe3efd172a7d19443c97c625d699e9737229b0a2";
  let xs=[RootArtifact{role:"WITNESS",sha256:w,binds_to:&[]},RootArtifact{role:"EVIDENCE",sha256:e,binds_to:&[w]},RootArtifact{role:"WORKBENCH",sha256:x,binds_to:&[w,e]},RootArtifact{role:"ATTESTATION",sha256:a,binds_to:&[w,e,x]}];
  let root=canonical_package_root("root-fixture","generic-system",&xs).unwrap();
  assert_eq!(root,"sha256:40264e29c2af27569b0ba9eb7f48d69af676367ef91bc0773959c3198bcf0edf");
 }
 #[test] fn role_reordering_fails_closed() {
  let d="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  let xs=[RootArtifact{role:"EVIDENCE",sha256:d,binds_to:&[]},RootArtifact{role:"WITNESS",sha256:d,binds_to:&[]},RootArtifact{role:"WORKBENCH",sha256:d,binds_to:&[]},RootArtifact{role:"ATTESTATION",sha256:d,binds_to:&[]}];
  assert!(canonical_package_root("r","s",&xs).is_err());
 }
}

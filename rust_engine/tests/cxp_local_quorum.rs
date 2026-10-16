use std::process::Command;

#[test]
fn cxp_finalizer_confirms_three_of_four_pbft_quorum() {
    let digest = "8fe0c9456f4c9a64f47aa0e265d3e18972128f7979dc251ac4decdab1ba19dde";
    let output = Command::new(env!("CARGO_BIN_EXE_cxp_finalizer"))
        .arg(digest)
        .output()
        .expect("run cxp_finalizer");
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).expect("utf8 output");
    assert!(stdout.contains("\"status\":\"CONFIRMED\""));
    assert!(stdout.contains("\"scope\":\"LOCAL_IN_PROCESS_PBFT_QUORUM\""));
    assert!(stdout.contains(&format!("\"digest_sha256\":\"{}\"", digest)));
    assert!(stdout.contains("\"quorum_size\":3"));
    assert!(stdout.contains("\"commit_certificate_verified\":true"));
    assert!(stdout.contains("\"distributed_finality\":\"UNKNOWN\""));
}

#[test]
fn cxp_finalizer_rejects_non_digest_input() {
    let output = Command::new(env!("CARGO_BIN_EXE_cxp_finalizer"))
        .arg("not-a-digest")
        .output()
        .expect("run cxp_finalizer");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("DIGEST_MUST_BE_64_HEX_CHARS"));
}

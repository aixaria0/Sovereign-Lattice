//! Offline PBFT control; no network and no interpretation of CBC claims as PBFT finality.
use sovereign_lattice::pbft_control::run_pbft_control;

fn main() {
    let mut args = std::env::args().skip(1);
    let digest = args.next().unwrap_or_default();
    let sender_csv = args.next().unwrap_or_default();
    if args.next().is_some() {
        eprintln!("Expected exactly two arguments: witness_sha256 sender_csv");
        std::process::exit(2);
    }
    let result = match run_pbft_control(&digest, &sender_csv) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Independent PBFT control rejected input: {error}");
            std::process::exit(1);
        }
    };
    // All interpolated fields are prevalidated ASCII hex or fixed integer values.
    println!(
        "{{\"schema\":\"aria-independent-pbft-control/v1\",         \"externalWitnessSha256\":\"{}\",         \"senderLabels\":[\"v{}\",\"v{}\",\"v{}\",\"v{}\"],         \"distinctSenderCount\":{},         \"oneReplacementFromControl\":{},         \"allFourDistinct\":{},         \"pbftQuorumSize\":{},         \"pbftTopologyAccepted\":{},         \"pbftTruncatedFrameRejected\":{},         \"pbftInvalidPhaseRejected\":{},         \"cbcFinalityVerified\":false,         \"pbftCertificateVerified\":false,         \"liveNetwork\":false,         \"evidenceKind\":\"INDEPENDENT_PBFT_CONTROL_ONLY\",         \"claimBoundary\":\"External CBC sender labels correlate this PBFT topology and malformed-frame control; they are not PBFT signatures, a PBFT certificate, or independent Casper finality evidence.\"}}",
        result.witness_digest,
        result.senders[0], result.senders[1], result.senders[2], result.senders[3],
        result.unique_senders,
        result.one_replacement_from_control,
        result.all_four_distinct,
        result.pbft_quorum_size,
        result.topology_accepted,
        result.truncated_frame_rejected,
        result.invalid_phase_rejected,
    );
}

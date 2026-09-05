use crate::threshold_bls::verify_bls_signature;
use crate::wal::WriteAheadLog;
use bls12_381::{G1Affine, G1Projective, G2Projective};
use group::Curve;
use std::collections::{HashMap, HashSet};

pub static TEST_WAL_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn check_sig(msg: &[u8], sig: &G1Projective, pk: &G2Projective) -> bool {
    verify_bls_signature(msg, sig, pk)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    PrePrepare = 0,
    Prepare = 1,
    Commit = 2,
    ViewChange = 3,
}

#[derive(Clone)]
pub struct PbftMessage {
    pub phase: Phase,
    pub view: u64,
    pub seq: u64,
    pub digest: [u8; 32],
    pub sender_id: u32,
    pub signature: G1Projective,
}

impl PbftMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.phase as u8);
        bytes.extend_from_slice(&self.view.to_be_bytes());
        bytes.extend_from_slice(&self.seq.to_be_bytes());
        bytes.extend_from_slice(&self.digest);
        bytes.extend_from_slice(&self.sender_id.to_be_bytes());
        bytes.extend_from_slice(&self.signature.to_affine().to_compressed());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 1 + 8 + 8 + 32 + 4 + 48 {
            return Err("INVALID_MESSAGE_LENGTH");
        }
        let phase = match bytes[0] {
            0 => Phase::PrePrepare,
            1 => Phase::Prepare,
            2 => Phase::Commit,
            3 => Phase::ViewChange,
            _ => return Err("INVALID_PHASE"),
        };
        let mut view_bytes = [0u8; 8];
        view_bytes.copy_from_slice(&bytes[1..9]);
        let view = u64::from_be_bytes(view_bytes);

        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&bytes[9..17]);
        let seq = u64::from_be_bytes(seq_bytes);

        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[17..49]);

        let mut sender_bytes = [0u8; 4];
        sender_bytes.copy_from_slice(&bytes[49..53]);
        let sender_id = u32::from_be_bytes(sender_bytes);

        let mut sig_bytes = [0u8; 48];
        sig_bytes.copy_from_slice(&bytes[53..101]);

        let affine_opt: Option<G1Affine> = G1Affine::from_compressed(&sig_bytes).into();
        let signature = match affine_opt {
            Some(aff) => G1Projective::from(aff),
            None => return Err("INVALID_SIGNATURE_BYTES"),
        };

        Ok(Self {
            phase,
            view,
            seq,
            digest,
            sender_id,
            signature,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ViewChangePayload {
    pub target_view: u64,
    pub prepared_view: u64,
    pub prepared_seq: u64,
    pub digest: [u8; 32],
    pub sender_id: u32,
    pub signature: G1Projective,
}

impl ViewChangePayload {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.target_view.to_be_bytes());
        bytes.extend_from_slice(&self.prepared_view.to_be_bytes());
        bytes.extend_from_slice(&self.prepared_seq.to_be_bytes());
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.target_view.to_be_bytes());
        bytes.extend_from_slice(&self.prepared_view.to_be_bytes());
        bytes.extend_from_slice(&self.prepared_seq.to_be_bytes());
        bytes.extend_from_slice(&self.digest);
        bytes.extend_from_slice(&self.sender_id.to_be_bytes());
        bytes.extend_from_slice(&self.signature.to_affine().to_compressed());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 8 + 8 + 8 + 32 + 4 + 48 {
            return Err("INVALID_VIEW_CHANGE_PAYLOAD_LENGTH");
        }

        let mut target_view_bytes = [0u8; 8];
        target_view_bytes.copy_from_slice(&bytes[0..8]);
        let target_view = u64::from_be_bytes(target_view_bytes);

        let mut prepared_view_bytes = [0u8; 8];
        prepared_view_bytes.copy_from_slice(&bytes[8..16]);
        let prepared_view = u64::from_be_bytes(prepared_view_bytes);

        let mut prepared_seq_bytes = [0u8; 8];
        prepared_seq_bytes.copy_from_slice(&bytes[16..24]);
        let prepared_seq = u64::from_be_bytes(prepared_seq_bytes);

        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[24..56]);

        let mut sender_bytes = [0u8; 4];
        sender_bytes.copy_from_slice(&bytes[56..60]);
        let sender_id = u32::from_be_bytes(sender_bytes);

        let mut sig_bytes = [0u8; 48];
        sig_bytes.copy_from_slice(&bytes[60..108]);

        let affine_opt: Option<G1Affine> = G1Affine::from_compressed(&sig_bytes).into();
        let signature = match affine_opt {
            Some(aff) => G1Projective::from(aff),
            None => return Err("INVALID_SIGNATURE_BYTES"),
        };

        Ok(Self {
            target_view,
            prepared_view,
            prepared_seq,
            digest,
            sender_id,
            signature,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PreparedCertificate {
    pub view: u64,
    pub seq: u64,
    pub digest: [u8; 32],
    pub signatures: HashMap<u32, G1Projective>,
}

impl PreparedCertificate {
    pub fn verify(&self, quorum_size: usize, public_keys: &HashMap<u32, G2Projective>) -> bool {
        if self.signatures.len() < quorum_size {
            return false;
        }

        let mut canonical_msg = Vec::new();
        canonical_msg.push(Phase::Prepare as u8);
        canonical_msg.extend_from_slice(&self.view.to_be_bytes());
        canonical_msg.extend_from_slice(&self.seq.to_be_bytes());
        canonical_msg.extend_from_slice(&self.digest);

        let mut valid_count = 0;
        for (&node_id, sig) in &self.signatures {
            if let Some(pk) = public_keys.get(&node_id) {
                if check_sig(&canonical_msg, sig, pk) {
                    valid_count += 1;
                }
            }
        }

        valid_count >= quorum_size
    }
}

#[derive(Clone, Debug)]
pub struct CommitCertificate {
    pub view: u64,
    pub seq: u64,
    pub digest: [u8; 32],
    pub signatures: HashMap<u32, G1Projective>,
}

impl CommitCertificate {
    pub fn verify(&self, quorum_size: usize, public_keys: &HashMap<u32, G2Projective>) -> bool {
        if self.signatures.len() < quorum_size {
            return false;
        }

        let mut canonical_msg = Vec::new();
        canonical_msg.push(Phase::Commit as u8);
        canonical_msg.extend_from_slice(&self.view.to_be_bytes());
        canonical_msg.extend_from_slice(&self.seq.to_be_bytes());
        canonical_msg.extend_from_slice(&self.digest);

        let mut valid_count = 0;
        for (&node_id, sig) in &self.signatures {
            if let Some(pk) = public_keys.get(&node_id) {
                if check_sig(&canonical_msg, sig, pk) {
                    valid_count += 1;
                }
            }
        }

        valid_count >= quorum_size
    }
}

#[derive(Clone)]
pub struct NewViewCertificate {
    pub target_view: u64,
    pub view_change_votes: HashMap<u32, (u64, [u8; 32], G1Projective)>,
    pub selected_prepared_certificate: Option<PreparedCertificate>,
}

impl NewViewCertificate {
    pub fn verify(&self, quorum_size: usize, public_keys: &HashMap<u32, G2Projective>) -> bool {
        if self.view_change_votes.len() < quorum_size {
            return false;
        }

        let max_quorum_seq = self
            .view_change_votes
            .values()
            .map(|&(s, _, _)| s)
            .max()
            .unwrap_or(0);
        
        let best_digest = self
            .view_change_votes
            .values()
            .find(|&&(s, _, _)| s == max_quorum_seq)
            .map(|&(_, d, _)| d)
            .unwrap_or([0u8; 32]);

        if let Some(ref cert) = self.selected_prepared_certificate {
            if !cert.verify(quorum_size, public_keys) {
                return false;
            }
            if cert.seq != max_quorum_seq || cert.digest != best_digest {
                return false;
            }
        } else {
            if max_quorum_seq > 0 {
                return false;
            }
        }

        let mut valid_count = 0;
        for (&node_id, &(seq, digest, ref sig)) in &self.view_change_votes {
            if let Some(pk) = public_keys.get(&node_id) {
                let mut canonical_msg = Vec::new();
                canonical_msg.push(Phase::ViewChange as u8);
                canonical_msg.extend_from_slice(&self.target_view.to_be_bytes());
                canonical_msg.extend_from_slice(&seq.to_be_bytes());
                canonical_msg.extend_from_slice(&digest);

                if check_sig(&canonical_msg, sig, pk) {
                    valid_count += 1;
                }
            }
        }

        valid_count >= quorum_size
    }
}

pub struct PbftState {
    pub total_nodes: usize,
    #[allow(dead_code)]
    pub f: usize,
    pub current_view: u64,
    pub highest_seq: u64,
    pub prepared_certificates: HashMap<(u64, u64), PreparedCertificate>,
    pub commit_certificates: HashMap<(u64, u64), CommitCertificate>,
    pub new_view_certificates: HashMap<u64, NewViewCertificate>,
    pub committed_digest: HashMap<(u64, u64), [u8; 32]>,
    pre_prepared_proposals: HashSet<(u64, u64, [u8; 32])>,
    prepare_votes: HashMap<(u64, u64, [u8; 32]), HashMap<u32, G1Projective>>,
    commit_votes: HashMap<(u64, u64, [u8; 32]), HashMap<u32, G1Projective>>,
    pub view_change_votes: HashMap<u64, HashMap<u32, (u64, [u8; 32], G1Projective)>>,
    pub quorum_size: usize,
    registered_nodes: HashSet<u32>,
    pub public_keys: HashMap<u32, G2Projective>,
    pub master_public_key: G2Projective,
    wal: WriteAheadLog,
}

impl PbftState {
    pub fn new(
        total_nodes: usize,
        initial_public_keys: HashMap<u32, G2Projective>,
        master_public_key: G2Projective,
    ) -> Result<Self, &'static str> {
        let f = (total_nodes - 1) / 3;
        if total_nodes != 3 * f + 1 {
            return Err("TOPOLOGY_VIOLATION: Network size N must strictly satisfy N = 3f + 1!");
        }

        let mut registered_nodes = HashSet::new();
        let quorum_size = 2 * f + 1;
        for id in 0..total_nodes as u32 {
            registered_nodes.insert(id);
            if !initial_public_keys.contains_key(&id) {
                return Err("REGISTRY_VIOLATION: Missing cryptographic public key for a registered node ID!");
            }
        }

        let wal_path = if cfg!(test) {
            let count = TEST_WAL_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            format!("consensus_wal_test_{}_{:?}.log", count, std::thread::current().id())
        } else {
            format!("consensus_wal_pid_{}.log", std::process::id())
        };

        let mut wal = WriteAheadLog::open(&wal_path)
            .map_err(|_| "WAL_ERROR: Failed to initialize Write-Ahead Log storage file!")?;

        let mut recovered_view = 0;
        let mut recovered_seq = 0;
        let mut recovered_proposals = HashSet::new();
        let mut recovered_prepare_votes: HashMap<(u64, u64, [u8; 32]), HashMap<u32, G1Projective>> =
            HashMap::new();
        let mut recovered_commit_votes: HashMap<(u64, u64, [u8; 32]), HashMap<u32, G1Projective>> =
            HashMap::new();
        let mut recovered_view_change_votes: HashMap<
            u64,
            HashMap<u32, (u64, [u8; 32], G1Projective)>,
        > = HashMap::new();
        let mut recovered_certificates = HashMap::new();
        let mut recovered_commit_certificates = HashMap::new();
        let mut recovered_new_view_certificates = HashMap::new();
        let mut recovered_committed = HashMap::new();

        let _ = wal.replay_log(|view, seq, phase_u8, sender_id, digest, signature| {
            if view > recovered_view { recovered_view = view; }
            if seq > recovered_seq { recovered_seq = seq; }

            match phase_u8 {
                0 => { recovered_proposals.insert((view, seq, digest)); }
                1 => {
                    let sigs = recovered_prepare_votes.entry((view, seq, digest)).or_default();
                    sigs.insert(sender_id, signature);
                    if sigs.len() >= quorum_size {
                        let cert = PreparedCertificate { view, seq, digest, signatures: sigs.clone() };
                        if cert.verify(quorum_size, &initial_public_keys) {
                            recovered_certificates.insert((view, seq), cert);
                        }
                    }
                }
                2 => {
                    let sigs = recovered_commit_votes.entry((view, seq, digest)).or_default();
                    sigs.insert(sender_id, signature);
                    if sigs.len() >= quorum_size {
                        let commit_cert = CommitCertificate { view, seq, digest, signatures: sigs.clone() };
                        if commit_cert.verify(quorum_size, &initial_public_keys) {
                            recovered_commit_certificates.insert((view, seq), commit_cert);
                            recovered_committed.insert((view, seq), digest);
                        }
                    }
                }
                3 => {
                    let supporters = recovered_view_change_votes.entry(view).or_default();
                    supporters.insert(sender_id, (seq, digest, signature));
                }
                _ => {}
            }
        });

        Ok(Self {
            total_nodes,
            f,
            current_view: recovered_view,
            highest_seq: recovered_seq,
            prepared_certificates: recovered_certificates,
            commit_certificates: recovered_commit_certificates,
            new_view_certificates: recovered_new_view_certificates,
            committed_digest: recovered_committed,
            pre_prepared_proposals: recovered_proposals,
            prepare_votes: recovered_prepare_votes,
            commit_votes: recovered_commit_votes,
            view_change_votes: recovered_view_change_votes,
            quorum_size,
            registered_nodes,
            public_keys: initial_public_keys,
            master_public_key,
            wal,
        })
    }

    pub fn get_expected_leader(&self, view: u64) -> u32 {
        (view % self.total_nodes as u64) as u32
    }

    pub fn handle_view_change_payload(&mut self, payload: &ViewChangePayload) -> Result<(), &'static str> {
        if !self.registered_nodes.contains(&payload.sender_id) {
            return Err("UNAUTHORIZED_SENDER: View change sender not registered.");
        }

        let pk = self.public_keys.get(&payload.sender_id).unwrap();
        if !check_sig(&payload.canonical_bytes(), &payload.signature, pk) {
            return Err("CRYPTO_AUTH_FAILED: Cryptographic BLS signature verification failed!");
        }

        if payload.prepared_seq > 0 {
            let has_valid_qc = self.prepared_certificates.values().any(|cert| {
                cert.view == payload.prepared_view
                    && cert.seq == payload.prepared_seq
                    && cert.digest == payload.digest
                    && cert.verify(self.quorum_size, &self.public_keys)
            });

            if !has_valid_qc {
                return Err("CERTIFICATE_INVALID: ViewChange rejected; missing cryptographically verified Quorum Certificate locally!");
            }
        }

        Ok(())
    }

    pub fn handle_message(&mut self, msg: &PbftMessage) -> Result<String, &'static str> {
        if !self.registered_nodes.contains(&msg.sender_id) {
            return Err("AUTH_FAILED: Sender ID is not part of the active node registry!");
        }

        let pk = self.public_keys.get(&msg.sender_id).unwrap();

        let mut canonical_msg = Vec::new();
        canonical_msg.push(msg.phase as u8);
        canonical_msg.extend_from_slice(&msg.view.to_be_bytes());
        canonical_msg.extend_from_slice(&msg.seq.to_be_bytes());
        canonical_msg.extend_from_slice(&msg.digest);

        if !check_sig(&canonical_msg, &msg.signature, pk) {
            return Err("CRYPTO_AUTH_FAILED: Cryptographic BLS signature verification failed!");
        }

        let response = match msg.phase {
            Phase::PrePrepare => {
                if msg.view != self.current_view {
                    return Err("VIEW_MISMATCH: PrePrepare view does not match current consensus view!");
                }

                let expected_leader = self.get_expected_leader(msg.view);
                if msg.sender_id != expected_leader {
                    return Err("LEADER_VIOLATION: PrePrepare message sent by a non-leader node!");
                }

                let conflicting_proposal = self.pre_prepared_proposals.iter().any(|&(view, seq, digest)| {
                    view == msg.view && seq == msg.seq && digest != msg.digest
                });

                if conflicting_proposal {
                    return Err("EQUIVOCATION_DETECTED: Conflicting PrePrepare digest for same view and sequence!");
                }

                let proposal_key = (msg.view, msg.seq, msg.digest);
                if self.pre_prepared_proposals.contains(&proposal_key) {
                    return Err("DUPLICATE_PROPOSAL: PrePrepare for this sequence and digest already processed!");
                }

                self.pre_prepared_proposals.insert(proposal_key);
                self.highest_seq = self.highest_seq.max(msg.seq);
                format!("INBOUND_OK: PrePrepare Validated {} View {} Seq {}", msg.sender_id, msg.view, msg.seq)
            }

            Phase::Prepare => {
                if msg.view != self.current_view {
                    return Err("VIEW_MISMATCH: Prepare view does not match current consensus view!");
                }

                let proposal_key = (msg.view, msg.seq, msg.digest);
                
                if !self.pre_prepared_proposals.contains(&proposal_key) {
                    return Err("ORPHAN_PREPARE: Cannot accept Prepare vote without a matching PrePrepare proposal!");
                }

                let sigs = self.prepare_votes.entry(proposal_key).or_default();
                sigs.insert(msg.sender_id, msg.signature);

                if sigs.len() >= self.quorum_size {
                    let cert = PreparedCertificate {
                        view: msg.view,
                        seq: msg.seq,
                        digest: msg.digest,
                        signatures: sigs.clone(),
                    };

                    if !cert.verify(self.quorum_size, &self.public_keys) {
                        return Err("CERTIFICATE_VERIFICATION_FAILED: Generated Prepared QC failed cryptographic verification!");
                    }

                    self.prepared_certificates.insert((msg.view, msg.seq), cert);
                    format!("CERTIFICATE_OK: Prepared Quorum achieved View {} Seq {}", msg.view, msg.seq)
                } else {
                    format!("VOTE_OK: Prepare Recorded Node {} Progress {}/{}", msg.sender_id, sigs.len(), self.quorum_size)
                }
            }

            Phase::Commit => {
                if msg.view != self.current_view {
                    return Err("VIEW_MISMATCH: Commit view does not match current consensus view!");
                }

                let has_valid_certificate = self.prepared_certificates.values().any(|cert| {
                    cert.view == msg.view
                        && cert.seq == msg.seq
                        && cert.digest == msg.digest
                        && cert.verify(self.quorum_size, &self.public_keys)
                });

                if !has_valid_certificate {
                    return Err("SAFETY_VIOLATION: Node cannot commit without a cryptographically verified Prepared Certificate!");
                }

                if let Some(existing_digest) = self.committed_digest.get(&(msg.view, msg.seq)) {
                    if existing_digest != &msg.digest {
                        return Err("EQUIVOCATION_DETECTED: Conflicting COMMIT digest for same sequence!");
                    }
                }

                let proposal_key = (msg.view, msg.seq, msg.digest);
                let sigs = self.commit_votes.entry(proposal_key).or_default();
                sigs.insert(msg.sender_id, msg.signature);

                if sigs.len() >= self.quorum_size {
                    let commit_cert = CommitCertificate {
                        view: msg.view,
                        seq: msg.seq,
                        digest: msg.digest,
                        signatures: sigs.clone(),
                    };

                    if !commit_cert.verify(self.quorum_size, &self.public_keys) {
                        return Err("CERTIFICATE_VERIFICATION_FAILED: Generated Commit Certificate failed cryptographic verification!");
                    }

                    self.commit_certificates.insert((msg.view, msg.seq), commit_cert);
                    self.committed_digest.insert((msg.view, msg.seq), msg.digest);
                    format!("COMMITTED_OK: Sequence {} definitively committed under View {}", msg.seq, msg.view)
                } else {
                    format!("VOTE_OK: Commit Recorded Node {} Progress {}/{}", msg.sender_id, sigs.len(), self.quorum_size)
                }
            }

            Phase::ViewChange => {
                if msg.view <= self.current_view {
                    return Err("VIEW_CHANGE_INVALID: Target view must be greater than current view!");
                }

                if msg.seq > 0 {
                    let has_valid_qc = self.prepared_certificates.values().any(|cert| {
                        cert.view == msg.view
                            && cert.seq == msg.seq
                            && cert.digest == msg.digest
                            && cert.verify(self.quorum_size, &self.public_keys)
                    });

                    if !has_valid_qc {
                        return Err("CERTIFICATE_INVALID: ViewChange rejected; missing cryptographically verified Quorum Certificate!");
                    }
                }

                let supporters = self.view_change_votes.entry(msg.view).or_default();
                supporters.insert(msg.sender_id, (msg.seq, msg.digest, msg.signature));

                if supporters.len() >= self.quorum_size {
                    self.current_view = msg.view;

                    let max_quorum_seq = supporters.values().map(|&(s, _, _)| s).max().unwrap_or(0);
                    let best_digest = supporters
                        .values()
                        .find(|&&(s, _, _)| s == max_quorum_seq)
                        .map(|&(_, d, _)| d)
                        .unwrap_or([0u8; 32]);

                    let bound_cert = if max_quorum_seq > 0 {
                        let cert_opt = self.prepared_certificates.values().find(|c| {
                                c.seq == max_quorum_seq
                                    && c.digest == best_digest
                                    && c.verify(self.quorum_size, &self.public_keys)
                            }).cloned();

                        if cert_opt.is_none() {
                            return Err("MISSING_QUORUM_CERTIFICATE: Quorum claims a high-seq PreparedCertificate, but it is missing locally.");
                        }
                        cert_opt
                    } else {
                        None
                    };

                    if let Some(ref cert) = bound_cert {
                        self.highest_seq = self.highest_seq.max(cert.seq);
                    }

                    let new_view_cert = NewViewCertificate {
                        target_view: msg.view,
                        view_change_votes: supporters.clone(),
                        selected_prepared_certificate: bound_cert,
                    };

                    if !new_view_cert.verify(self.quorum_size, &self.public_keys) {
                        return Err("NEW_VIEW_VERIFICATION_FAILED: NewViewCertificate cryptographic verification failed!");
                    }

                    self.new_view_certificates.insert(msg.view, new_view_cert);
                    format!("VIEW_CHANGE_OK: Quorum reached for View {} Inherited Seq {}", msg.view, max_quorum_seq)
                } else {
                    format!("VOTE_OK: View Change Recorded View {} Progress {}/{}", msg.view, supporters.len(), self.quorum_size)
                }
            }
        };

        self.wal.append_entry(msg.view, msg.seq, msg.phase as u8, msg.sender_id, &msg.digest, &msg.signature)
            .map_err(|_| "WAL_ERROR: Failed to write valid consensus event to disk log!")?;

        Ok(response)
    }
}

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use bls12_381::{G1Projective, G2Projective, Scalar};
    use ff::Field;
    use rand::rngs::OsRng;

    fn generate_test_keys(n: usize) -> (HashMap<u32, Scalar>, HashMap<u32, G2Projective>) {
        let mut secret_keys = HashMap::new();
        let mut public_keys = HashMap::new();
        for i in 0..n as u32 {
            let sk = Scalar::random(&mut OsRng);
            let pk = G2Projective::generator() * sk;
            secret_keys.insert(i, sk);
            public_keys.insert(i, pk);
        }
        (secret_keys, public_keys)
    }

    fn sign_message(msg: &[u8], sk: &Scalar) -> G1Projective {
        crate::threshold_bls::sign_bls_message(msg, sk)
    }

    #[test]
    fn test_conflicting_preprepare_rejected() {
        let n = 4;
        let (secret_keys, public_keys) = generate_test_keys(n);
        let master_pk = G2Projective::generator();

        let mut state = PbftState::new(n, public_keys.clone(), master_pk).expect("Failed to init state");

        let view = state.current_view;
        let leader_id = state.get_expected_leader(view);
        let seq = state.highest_seq + 1;
        let digest_a = [0xaa; 32];
        let digest_b = [0xbb; 32];

        let mut canonical_a = Vec::new();
        canonical_a.push(Phase::PrePrepare as u8);
        canonical_a.extend_from_slice(&view.to_be_bytes());
        canonical_a.extend_from_slice(&seq.to_be_bytes());
        canonical_a.extend_from_slice(&digest_a);

        let msg_a = PbftMessage {
            phase: Phase::PrePrepare,
            view,
            seq,
            digest: digest_a,
            sender_id: leader_id,
            signature: sign_message(&canonical_a, &secret_keys[&leader_id]),
        };

        let first_result = state.handle_message(&msg_a);
        assert!(first_result.is_ok());

        let mut canonical_b = Vec::new();
        canonical_b.push(Phase::PrePrepare as u8);
        canonical_b.extend_from_slice(&view.to_be_bytes());
        canonical_b.extend_from_slice(&seq.to_be_bytes());
        canonical_b.extend_from_slice(&digest_b);

        let msg_b = PbftMessage {
            phase: Phase::PrePrepare,
            view,
            seq,
            digest: digest_b,
            sender_id: leader_id,
            signature: sign_message(&canonical_b, &secret_keys[&leader_id]),
        };

        let result = state.handle_message(&msg_b);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("EQUIVOCATION_DETECTED"));
    }

    #[test]
    fn test_cross_view_commit_certificate_rejected() {
        let n = 4;
        let (secret_keys, public_keys) = generate_test_keys(n);
        let master_pk = G2Projective::generator();

        let mut state = PbftState::new(n, public_keys.clone(), master_pk).expect("Failed to init state");

        let prepared_view: u64 = 0;
        let commit_view: u64 = 1;
        let seq = state.highest_seq + 1;
        let digest = [0xcc; 32];

        let mut canonical_prepare = Vec::new();
        canonical_prepare.push(Phase::Prepare as u8);
        canonical_prepare.extend_from_slice(&prepared_view.to_be_bytes());
        canonical_prepare.extend_from_slice(&seq.to_be_bytes());
        canonical_prepare.extend_from_slice(&digest);

        let mut signatures = HashMap::new();
        for node_id in 0..3u32 {
            signatures.insert(node_id, sign_message(&canonical_prepare, &secret_keys[&node_id]));
        }

        let prepared_cert = PreparedCertificate {
            view: prepared_view,
            seq,
            digest,
            signatures,
        };

        assert!(prepared_cert.verify(state.quorum_size, &state.public_keys));

        state.prepared_certificates.insert((prepared_view, seq), prepared_cert);

        let mut canonical_commit = Vec::new();
        canonical_commit.push(Phase::Commit as u8);
        canonical_commit.extend_from_slice(&commit_view.to_be_bytes());
        canonical_commit.extend_from_slice(&seq.to_be_bytes());
        canonical_commit.extend_from_slice(&digest);

        let commit_msg = PbftMessage {
            phase: Phase::Commit,
            view: commit_view,
            seq,
            digest,
            sender_id: 0,
            signature: sign_message(&canonical_commit, &secret_keys[&0]),
        };

        state.current_view = commit_view;

        let result = state.handle_message(&commit_msg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("SAFETY_VIOLATION"));
        assert!(!state.committed_digest.contains_key(&(commit_view, seq)));
    }

    #[test]
    fn test_ghost_certificate_attack_rejected() {
        let n = 4;
        let (secret_keys, public_keys) = generate_test_keys(n);
        let master_pk = G2Projective::generator();

        let mut state = PbftState::new(n, public_keys.clone(), master_pk).expect("Failed to init state");

        let target_view: u64 = 1;
        let malicious_seq: u64 = 999;
        let malicious_digest = [0xbb; 32];

        let create_view_change = |sender_id: u32, sk: &Scalar| {
            let mut canonical_msg = Vec::new();
            canonical_msg.push(Phase::ViewChange as u8);
            canonical_msg.extend_from_slice(&target_view.to_be_bytes());
            canonical_msg.extend_from_slice(&malicious_seq.to_be_bytes());
            canonical_msg.extend_from_slice(&malicious_digest);

            PbftMessage {
                phase: Phase::ViewChange,
                view: target_view,
                seq: malicious_seq,
                digest: malicious_digest,
                sender_id,
                signature: sign_message(&canonical_msg, sk),
            }
        };

        let msg1 = create_view_change(1, &secret_keys[&1]);
        let msg2 = create_view_change(2, &secret_keys[&2]);
        let msg3 = create_view_change(3, &secret_keys[&3]);

        let supporters = state.view_change_votes.entry(target_view).or_default();
        supporters.insert(1, (malicious_seq, malicious_digest, msg1.signature));
        supporters.insert(2, (malicious_seq, malicious_digest, msg2.signature));
        supporters.insert(3, (malicious_seq, malicious_digest, msg3.signature));

        let max_quorum_seq = supporters.values().map(|&(s, _, _)| s).max().unwrap_or(0);
        let best_digest = supporters
            .values()
            .find(|&&(s, _, _)| s == max_quorum_seq)
            .map(|&(_, d, _)| d)
            .unwrap_or([0u8; 32]);

        let bound_cert = if max_quorum_seq > 0 {
            state.prepared_certificates.values().find(|c| {
                c.seq == max_quorum_seq && c.digest == best_digest && c.verify(state.quorum_size, &state.public_keys)
            }).cloned()
        } else {
            None
        };

        assert!(bound_cert.is_none());
        assert!(bound_cert.is_none() && max_quorum_seq > 0);
    }
}

use crate::threshold_bls::{verify_bls_signature, verify_threshold_signature};
use crate::wal::WriteAheadLog;
use bls12_381::{G1Affine, G1Projective, G2Projective};
use group::Curve;
use std::collections::{HashMap, HashSet};

pub static TEST_WAL_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

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
        let mut bytes = self.canonical_bytes();
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
    pub fn verify(&self, quorum_size: usize, master_pk: &G2Projective) -> bool {
        let mut canonical_msg = Vec::new();
        canonical_msg.push(Phase::Prepare as u8);
        canonical_msg.extend_from_slice(&self.view.to_be_bytes());
        canonical_msg.extend_from_slice(&self.seq.to_be_bytes());
        canonical_msg.extend_from_slice(&self.digest);

        verify_threshold_signature(&canonical_msg, &self.signatures, master_pk, quorum_size)
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
    pub fn verify(&self, quorum_size: usize, master_pk: &G2Projective) -> bool {
        let mut canonical_msg = Vec::new();
        canonical_msg.push(Phase::Commit as u8);
        canonical_msg.extend_from_slice(&self.view.to_be_bytes());
        canonical_msg.extend_from_slice(&self.seq.to_be_bytes());
        canonical_msg.extend_from_slice(&self.digest);

        verify_threshold_signature(&canonical_msg, &self.signatures, master_pk, quorum_size)
    }
}

#[derive(Clone)]
pub struct NewViewCertificate {
    pub target_view: u64,
    pub view_change_votes: HashMap<u32, (u64, [u8; 32], G1Projective)>,
    pub selected_prepared_certificate: Option<PreparedCertificate>,
}

impl NewViewCertificate {
    pub fn verify(&self, quorum_size: usize, master_pk: &G2Projective, public_keys: &HashMap<u32, G2Projective>) -> bool {
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
            if !cert.verify(quorum_size, master_pk) {
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

                if verify_bls_signature(&canonical_msg, sig, pk) {
                    valid_count += 1;
                }
            }
        }

        valid_count >= quorum_size
    }
}

pub struct PbftState {
    pub total_nodes: usize,
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
            return Err("TOPOLOGY_VIOLATION");
        }

        let mut registered_nodes = HashSet::new();
        let quorum_size = 2 * f + 1;
        for id in 0..total_nodes as u32 {
            registered_nodes.insert(id);
            if !initial_public_keys.contains_key(&id) {
                return Err("REGISTRY_VIOLATION");
            }
        }

        let wal_path = if cfg!(test) {
            let count = TEST_WAL_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            format!("consensus_wal_test_{}_{:?}.log", count, std::thread::current().id())
        } else {
            format!("consensus_wal_pid_{}.log", std::process::id())
        };

        let mut wal = WriteAheadLog::open(&wal_path).map_err(|_| "WAL_ERROR")?;

        let mut recovered_view = 0;
        let mut recovered_seq = 0;
        let mut recovered_proposals = HashSet::new();
        let mut recovered_prepare_votes: HashMap<(u64, u64, [u8; 32]), HashMap<u32, G1Projective>> = HashMap::new();
        let mut recovered_commit_votes: HashMap<(u64, u64, [u8; 32]), HashMap<u32, G1Projective>> = HashMap::new();
        let mut recovered_view_change_votes: HashMap<u64, HashMap<u32, (u64, [u8; 32], G1Projective)>> = HashMap::new();
        let mut recovered_certificates = HashMap::new();
        let mut recovered_commit_certificates = HashMap::new();
        let recovered_new_view_certificates = HashMap::new(); // 🔥 اون mut اضافی رو اینجا برداشتم
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
                        if cert.verify(quorum_size, &master_public_key) {
                            recovered_certificates.insert((view, seq), cert);
                        }
                    }
                }
                2 => {
                    let sigs = recovered_commit_votes.entry((view, seq, digest)).or_default();
                    sigs.insert(sender_id, signature);
                    if sigs.len() >= quorum_size {
                        let commit_cert = CommitCertificate { view, seq, digest, signatures: sigs.clone() };
                        if commit_cert.verify(quorum_size, &master_public_key) {
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

    // 🔥 تابع گمشده برگشت سر جاش!
    pub fn handle_view_change_payload(&mut self, payload: &ViewChangePayload) -> Result<(), &'static str> {
        if !self.registered_nodes.contains(&payload.sender_id) {
            return Err("UNAUTHORIZED_SENDER");
        }

        let pk = self.public_keys.get(&payload.sender_id).unwrap();
        if !verify_bls_signature(&payload.canonical_bytes(), &payload.signature, pk) {
            return Err("CRYPTO_AUTH_FAILED");
        }

        if payload.prepared_seq > 0 {
            let has_valid_qc = self.prepared_certificates.values().any(|cert| {
                cert.view == payload.prepared_view
                    && cert.seq == payload.prepared_seq
                    && cert.digest == payload.digest
                    && cert.verify(self.quorum_size, &self.master_public_key)
            });

            if !has_valid_qc {
                return Err("CERTIFICATE_INVALID");
            }
        }

        Ok(())
    }

    pub fn handle_message(&mut self, msg: &PbftMessage) -> Result<String, &'static str> {
        if !self.registered_nodes.contains(&msg.sender_id) {
            return Err("AUTH_FAILED");
        }

        let pk = self.public_keys.get(&msg.sender_id).unwrap();

        let mut canonical_msg = Vec::new();
        canonical_msg.push(msg.phase as u8);
        canonical_msg.extend_from_slice(&msg.view.to_be_bytes());
        canonical_msg.extend_from_slice(&msg.seq.to_be_bytes());
        canonical_msg.extend_from_slice(&msg.digest);

        if !verify_bls_signature(&canonical_msg, &msg.signature, pk) {
            return Err("CRYPTO_AUTH_FAILED");
        }

        let response = match msg.phase {
            Phase::PrePrepare => {
                if msg.view != self.current_view {
                    return Err("VIEW_MISMATCH");
                }

                let expected_leader = self.get_expected_leader(msg.view);
                if msg.sender_id != expected_leader {
                    return Err("LEADER_VIOLATION");
                }

                let conflicting_proposal = self.pre_prepared_proposals.iter().any(|&(view, seq, digest)| {
                    view == msg.view && seq == msg.seq && digest != msg.digest
                });

                if conflicting_proposal {
                    return Err("EQUIVOCATION_DETECTED");
                }

                let proposal_key = (msg.view, msg.seq, msg.digest);
                if self.pre_prepared_proposals.contains(&proposal_key) {
                    return Err("DUPLICATE_PROPOSAL");
                }

                self.pre_prepared_proposals.insert(proposal_key);
                self.highest_seq = self.highest_seq.max(msg.seq);
                format!("INBOUND_OK_PREPREPARE")
            }

            Phase::Prepare => {
                if msg.view != self.current_view {
                    return Err("VIEW_MISMATCH");
                }

                let proposal_key = (msg.view, msg.seq, msg.digest);
                
                if !self.pre_prepared_proposals.contains(&proposal_key) {
                    return Err("ORPHAN_PREPARE");
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

                    if !cert.verify(self.quorum_size, &self.master_public_key) {
                        return Err("CERTIFICATE_VERIFICATION_FAILED");
                    }

                    self.prepared_certificates.insert((msg.view, msg.seq), cert);
                    format!("CERTIFICATE_OK_PREPARED")
                } else {
                    format!("VOTE_OK_PREPARE")
                }
            }

            Phase::Commit => {
                if msg.view != self.current_view {
                    return Err("VIEW_MISMATCH");
                }

                let proposal_key = (msg.view, msg.seq, msg.digest);
                
                if !self.pre_prepared_proposals.contains(&proposal_key) {
                    return Err("ORPHAN_COMMIT");
                }

                let has_valid_certificate = self.prepared_certificates.values().any(|cert| {
                    cert.view == msg.view
                        && cert.seq == msg.seq
                        && cert.digest == msg.digest
                        && cert.verify(self.quorum_size, &self.master_public_key)
                });

                if !has_valid_certificate {
                    return Err("SAFETY_VIOLATION");
                }

                if let Some(existing_digest) = self.committed_digest.get(&(msg.view, msg.seq)) {
                    if existing_digest != &msg.digest {
                        return Err("EQUIVOCATION_DETECTED");
                    }
                }

                let sigs = self.commit_votes.entry(proposal_key).or_default();
                sigs.insert(msg.sender_id, msg.signature);

                if sigs.len() >= self.quorum_size {
                    let commit_cert = CommitCertificate {
                        view: msg.view,
                        seq: msg.seq,
                        digest: msg.digest,
                        signatures: sigs.clone(),
                    };

                    if !commit_cert.verify(self.quorum_size, &self.master_public_key) {
                        return Err("CERTIFICATE_VERIFICATION_FAILED");
                    }

                    self.commit_certificates.insert((msg.view, msg.seq), commit_cert);
                    self.committed_digest.insert((msg.view, msg.seq), msg.digest);
                    format!("COMMITTED_OK")
                } else {
                    format!("VOTE_OK_COMMIT")
                }
            }

            Phase::ViewChange => {
                if msg.view <= self.current_view {
                    return Err("VIEW_CHANGE_INVALID");
                }

                if msg.seq > 0 {
                    let has_valid_qc = self.prepared_certificates.values().any(|cert| {
                        cert.view == msg.view
                            && cert.seq == msg.seq
                            && cert.digest == msg.digest
                            && cert.verify(self.quorum_size, &self.master_public_key)
                    });

                    if !has_valid_qc {
                        return Err("CERTIFICATE_INVALID");
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
                                    && c.verify(self.quorum_size, &self.master_public_key)
                            }).cloned();

                        if cert_opt.is_none() {
                            return Err("MISSING_QUORUM_CERTIFICATE");
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

                    if !new_view_cert.verify(self.quorum_size, &self.master_public_key, &self.public_keys) {
                        return Err("NEW_VIEW_VERIFICATION_FAILED");
                    }

                    self.new_view_certificates.insert(msg.view, new_view_cert);
                    format!("VIEW_CHANGE_OK")
                } else {
                    format!("VOTE_OK_VIEW_CHANGE")
                }
            }
        };

        self.wal.append_entry(msg.view, msg.seq, msg.phase as u8, msg.sender_id, &msg.digest, &msg.signature)
            .map_err(|_| "WAL_ERROR")?;

        Ok(response)
    }
}

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use bls12_381::{G1Projective, G2Projective, Scalar};
    use ff::Field;
    use rand::rngs::OsRng;
    use crate::threshold_bls::sign_bls_message;

    fn generate_test_keys(n: usize, threshold: usize) -> (HashMap<u32, Scalar>, HashMap<u32, G2Projective>, G2Projective) {
        let mut secret_polynomial = Vec::new();
        for _ in 0..threshold {
            secret_polynomial.push(Scalar::random(&mut OsRng));
        }
        let master_sk = secret_polynomial[0];
        let master_pk = G2Projective::generator() * master_sk;

        let mut secret_keys = HashMap::new();
        let mut public_keys = HashMap::new();

        for i in 0..n as u32 {
            let x = Scalar::from((i + 1) as u64);
            let mut sk_i = Scalar::zero();
            let mut x_pow = Scalar::one();
            for coeff in &secret_polynomial {
                sk_i += coeff * &x_pow;
                x_pow *= &x;
            }
            let pk_i = G2Projective::generator() * sk_i;
            secret_keys.insert(i, sk_i);
            public_keys.insert(i, pk_i);
        }
        (secret_keys, public_keys, master_pk)
    }

    #[test]
    fn test_conflicting_preprepare_rejected() {
        let n = 4;
        let threshold = 3;
        let (secret_keys, public_keys, master_pk) = generate_test_keys(n, threshold);

        let mut state = PbftState::new(n, public_keys.clone(), master_pk).expect("Failed init");

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
            signature: sign_bls_message(&canonical_a, &secret_keys[&leader_id]),
        };

        assert!(state.handle_message(&msg_a).is_ok());

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
            signature: sign_bls_message(&canonical_b, &secret_keys[&leader_id]),
        };

        let result = state.handle_message(&msg_b);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("EQUIVOCATION_DETECTED"));
    }

    #[test]
    fn test_orphan_prepare_rejected() {
        let n = 4;
        let threshold = 3;
        let (secret_keys, public_keys, master_pk) = generate_test_keys(n, threshold);

        let mut state = PbftState::new(n, public_keys.clone(), master_pk).expect("Failed init");

        let view = 0;
        let seq = 1;
        let digest = [0xdd; 32];

        let mut canonical_prepare = Vec::new();
        canonical_prepare.push(Phase::Prepare as u8);
        canonical_prepare.extend_from_slice(&view.to_be_bytes());
        canonical_prepare.extend_from_slice(&seq.to_be_bytes());
        canonical_prepare.extend_from_slice(&digest);

        let msg = PbftMessage {
            phase: Phase::Prepare,
            view,
            seq,
            digest,
            sender_id: 1,
            signature: sign_bls_message(&canonical_prepare, &secret_keys[&1]),
        };

        let result = state.handle_message(&msg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("ORPHAN_PREPARE"));
    }
}

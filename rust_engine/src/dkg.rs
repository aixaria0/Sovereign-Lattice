use bls12_381::{G1Projective, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use rand::rngs::OsRng;
use std::collections::HashMap;
use crate::threshold_bls::{sign_bls_message, verify_bls_signature};

#[derive(Clone, Debug)]
pub struct DkgShareMessage {
    pub from_node: u32,
    pub to_node: u32,
    pub share: Scalar,
    pub commitments: Vec<G2Projective>,
    pub signature: G1Projective,
}

impl DkgShareMessage {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.from_node.to_be_bytes());
        bytes.extend_from_slice(&self.to_node.to_be_bytes());
        bytes.extend_from_slice(&self.share.to_bytes());
        for c in &self.commitments {
            bytes.extend_from_slice(&c.to_affine().to_compressed());
        }
        bytes
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.canonical_bytes();
        bytes.extend_from_slice(&self.signature.to_affine().to_compressed());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 8 + 32 + 48 {
            return Err("DKG_PACKET_TOO_SHORT");
        }
        let from_node = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        let to_node = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        
        let mut share_bytes = [0u8; 32];
        share_bytes.copy_from_slice(&bytes[8..40]);
        
        let share_opt = Scalar::from_bytes(&share_bytes);
        let share = if bool::from(share_opt.is_some()) {
            share_opt.unwrap()
        } else {
            return Err("INVALID_SHARE_SCALAR");
        };

        let mut offset = 40;
        let mut commitments = Vec::new();
        
        while offset + 96 <= bytes.len() - 48 {
            let mut c_bytes = [0u8; 96];
            c_bytes.copy_from_slice(&bytes[offset..offset+96]);
            let c_opt = bls12_381::G2Affine::from_compressed(&c_bytes);
            if bool::from(c_opt.is_some()) {
                commitments.push(G2Projective::from(c_opt.unwrap()));
            } else {
                return Err("INVALID_G2_COMMITMENT");
            }
            offset += 96;
        }

        if bytes.len() - offset != 48 {
            return Err("INVALID_DKG_PACKET_STRUCTURE");
        }

        let mut sig_bytes = [0u8; 48];
        sig_bytes.copy_from_slice(&bytes[offset..offset+48]);
        let sig_opt = bls12_381::G1Affine::from_compressed(&sig_bytes);
        let signature = if bool::from(sig_opt.is_some()) {
            G1Projective::from(sig_opt.unwrap())
        } else {
            return Err("INVALID_G1_SIGNATURE");
        };

        Ok(Self {
            from_node,
            to_node,
            share,
            commitments,
            signature,
        })
    }
    
    pub fn verify_signature(&self) -> bool {
        if self.commitments.is_empty() {
            return false;
        }
        let dealer_pubkey = self.commitments[0];
        verify_bls_signature(&self.canonical_bytes(), &self.signature, &dealer_pubkey)
    }
}

pub struct DkgSession {
    pub node_id: u32,
    pub threshold: usize,
    pub total_nodes: usize,
    pub secret_polynomial: Vec<Scalar>,
    pub received_shares: HashMap<u32, Scalar>,
    pub received_commitments: HashMap<u32, Vec<G2Projective>>,
}

impl DkgSession {
    pub fn new(node_id: u32, threshold: usize, total_nodes: usize) -> Self {
        let mut secret_polynomial = Vec::with_capacity(threshold);
        for _ in 0..threshold {
            secret_polynomial.push(Scalar::random(&mut OsRng));
        }

        Self {
            node_id,
            threshold,
            total_nodes,
            secret_polynomial,
            received_shares: HashMap::new(),
            received_commitments: HashMap::new(),
        }
    }
    
    pub fn dealer_secret_key(&self) -> Scalar {
        self.secret_polynomial[0]
    }

    pub fn generate_commitments(&self) -> Vec<G2Projective> {
        self.secret_polynomial
            .iter()
            .map(|coeff| G2Projective::generator() * coeff)
            .collect()
    }

    pub fn evaluate_share_for(&self, node_id: u32) -> Scalar {
        let x = Scalar::from((node_id + 1) as u64);
        let mut share = Scalar::zero();
        let mut x_pow = Scalar::one();

        for coeff in &self.secret_polynomial {
            share += coeff * &x_pow;
            x_pow *= &x;
        }
        share
    }

    pub fn process_incoming_share(
        &mut self,
        from_node: u32,
        share: Scalar,
        commitments: &[G2Projective],
    ) -> Result<(), &'static str> {
        if commitments.len() != self.threshold {
            return Err("INVALID_COMMITMENTS_LENGTH");
        }

        let x = Scalar::from((self.node_id + 1) as u64);
        let mut expected_g2 = G2Projective::identity();
        let mut x_pow = Scalar::one();

        for c in commitments {
            expected_g2 += c * &x_pow;
            x_pow *= &x;
        }

        let actual_g2 = G2Projective::generator() * share;

        if actual_g2 != expected_g2 {
            return Err("FELDMAN_VSS_VERIFICATION_FAILED");
        }

        self.received_shares.insert(from_node, share);
        self.received_commitments.insert(from_node, commitments.to_vec());
        Ok(())
    }

    pub fn finalize_dkg(&self, expected_participants: &[u32]) -> Result<(Scalar, G2Projective), &'static str> {
        let mut final_share = self.evaluate_share_for(self.node_id);
        let mut master_pk = G2Projective::identity();
        master_pk += self.generate_commitments()[0];

        for peer_id in expected_participants {
            if *peer_id == self.node_id {
                continue;
            }
            
            let share = self.received_shares.get(peer_id).ok_or("MISSING_SHARE_FROM_PEER")?;
            let commits = self.received_commitments.get(peer_id).ok_or("MISSING_COMMITMENTS_FROM_PEER")?;
            
            final_share += share;
            master_pk += commits[0];
        }

        Ok((final_share, master_pk))
    }
}

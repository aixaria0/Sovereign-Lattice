use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use bls12_381::G2Projective;
use sovereign_lattice::dkg::{DkgSession, DkgShareMessage};
use sovereign_lattice::network::{spawn_outbound_broadcaster, start_tcp_listener};
use sovereign_lattice::pbft::{PbftMessage, PbftState};

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub node_id: u32,
    pub total_nodes: usize,
    pub threshold: usize,
    pub bind_addr: SocketAddr,
    pub peer_map: HashMap<u32, SocketAddr>,
}

impl NodeConfig {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let node_id: u32 = env::var("NODE_ID").unwrap_or_else(|_| "0".into()).parse()?;
        let total_nodes: usize = env::var("TOTAL_NODES").unwrap_or_else(|_| "4".into()).parse()?;
        let threshold: usize = env::var("THRESHOLD").unwrap_or_else(|_| "3".into()).parse()?;

        let bind_addr_str = env::var("BIND_ADDR").unwrap_or_else(|_| format!("127.0.0.1:{}", 8000 + node_id));
        let bind_addr: SocketAddr = bind_addr_str.parse()?;

        let mut peer_map = HashMap::new();
        for id in 0..total_nodes as u32 {
            let port = 8000 + id as u16;
            let addr: SocketAddr = format!("127.0.0.1:{}", port).parse()?;
            peer_map.insert(id, addr);
        }

        Ok(Self {
            node_id,
            total_nodes,
            threshold,
            bind_addr,
            peer_map,
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = NodeConfig::from_env()?;

    println!(
        "🚀 [BOOTSTRAP]: Initializing Sovereign-Lattice Node {} on {}...",
        config.node_id, config.bind_addr
    );

    let mut dkg_session = DkgSession::new(config.node_id, config.threshold, config.total_nodes);
    let _my_commitments = dkg_session.generate_commitments();

    let expected_participants: Vec<u32> = (0..config.total_nodes as u32).collect();

    let mut peer_sessions = HashMap::new();
    for &id in &expected_participants {
        if id != config.node_id {
            let peer_session = DkgSession::new(id, config.threshold, config.total_nodes);
            peer_sessions.insert(id, peer_session);
        }
    }

    for (&peer_id, peer_session) in &mut peer_sessions {
        let peer_commitments = peer_session.generate_commitments();
        let share_for_us = peer_session.evaluate_share_for(config.node_id);
        dkg_session.process_incoming_share(peer_id, share_for_us, &peer_commitments)?;
    }

    let (my_secret_share, canonical_master_pk) = dkg_session.finalize_dkg(&expected_participants)?;
    println!("🔑 [DKG SUCCESS]: Master threshold public key successfully synthesized.");

    let mut public_keys = HashMap::new();
    for &id in &expected_participants {
        if id == config.node_id {
            let my_signing_pk = G2Projective::generator() * my_secret_share;
            public_keys.insert(id, my_signing_pk);
        } else {
            let mut peer_true_secret_share = dkg_session.evaluate_share_for(id);
            for peer_session in peer_sessions.values() {
                peer_true_secret_share += peer_session.evaluate_share_for(id);
            }

            let node_signing_pk = G2Projective::generator() * peer_true_secret_share;
            public_keys.insert(id, node_signing_pk);
        }
    }

    let pbft_state = PbftState::new(config.total_nodes, public_keys, canonical_master_pk)?;

    let shared_state = Arc::new(Mutex::new(Some(pbft_state)));
    let shared_sk = Arc::new(Mutex::new(Some(my_secret_share)));

    println!("🛡️ [PBFT]: State machine locked! Validator registry uniquely populated.");

    let (tx_broadcast, rx_broadcast) = mpsc::channel::<PbftMessage>(256);
    let (tx_dkg, _rx_dkg) = mpsc::channel::<DkgShareMessage>(256);

    let broadcaster_handle = spawn_outbound_broadcaster(
        config.node_id,
        config.peer_map.clone(),
        rx_broadcast,
    );
    println!("📡 [BROADCASTER]: Asynchronous outbound broadcast worker started.");

    let listener_node_id = config.node_id;
    let listener_bind_addr = config.bind_addr;
    let listener_peer_map = config.peer_map;
    let listener_tx = tx_broadcast.clone();
    let listener_state = Arc::clone(&shared_state);
    let listener_sk = Arc::clone(&shared_sk);
    let listener_tx_dkg = tx_dkg.clone();

    println!("🌐 [NETWORK]: Starting Tokio TCP transport listener daemon...");
    let listener_handle = tokio::spawn(async move {
        if let Err(e) = start_tcp_listener(
            listener_bind_addr,
            listener_node_id,
            listener_sk,
            listener_state,
            listener_peer_map,
            listener_tx,
            listener_tx_dkg,
        )
        .await
        {
            eprintln!("FATAL_LISTENER_ERROR: {}", e);
        }
    });

    let _ = tokio::join!(broadcaster_handle, listener_handle);

    drop(tx_broadcast);
    Ok(())
}

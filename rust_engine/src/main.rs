use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration};
use bls12_381::{G2Projective, Scalar};
use ff::Field;
use group::Group;
use sovereign_lattice::dkg::{DkgSession, DkgShareMessage};
use sovereign_lattice::network::{
    send_framed_message, spawn_outbound_broadcaster, start_tcp_listener, PACKET_TYPE_DKG,
};
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

    // Network event channels
    let (tx_broadcast, rx_broadcast) = mpsc::channel::<PbftMessage>(256);
    let (tx_dkg, mut rx_dkg) = mpsc::channel::<DkgShareMessage>(256);

    // Shared state locks (initially empty, waiting for DKG completion)
    let shared_state: Arc<Mutex<Option<PbftState>>> = Arc::new(Mutex::new(None));
    let shared_sk: Arc<Mutex<Option<Scalar>>> = Arc::new(Mutex::new(None));

    let broadcaster_handle = spawn_outbound_broadcaster(
        config.node_id,
        config.peer_map.clone(),
        rx_broadcast,
    );
    println!("📡 [BROADCASTER]: Asynchronous outbound broadcast worker started.");

    let listener_node_id = config.node_id;
    let listener_bind_addr = config.bind_addr;
    let listener_peer_map = config.peer_map.clone();
    let listener_tx = tx_broadcast.clone();
    let listener_tx_dkg = tx_dkg.clone();
    let listener_state = Arc::clone(&shared_state);
    let listener_sk = Arc::clone(&shared_sk);

    println!("🌐 [NETWORK]: Starting Tokio TCP transport listener daemon...");
    tokio::spawn(async move {
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

    println!("⏳ [DKG PHASE 1]: Waiting 2 seconds for network mesh to stabilize...");
    sleep(Duration::from_millis(2000)).await;

    let mut dkg_session = DkgSession::new(config.node_id, config.threshold, config.total_nodes);
    let my_commitments = dkg_session.generate_commitments();

    println!("📡 [DKG PHASE 2]: Transmitting Feldman shares across TCP mesh...");
    for (&peer_id, &peer_addr) in &config.peer_map {
        if peer_id == config.node_id {
            continue;
        }

        let share_for_peer = dkg_session.evaluate_share_for(peer_id);
        let msg = DkgShareMessage {
            from_node: config.node_id,
            to_node: peer_id,
            share: share_for_peer,
            commitments: my_commitments.clone(),
        };

        let payload = msg.to_bytes();
        let target_addr = peer_addr;
        
        // Spawn async transmission to prevent blocking
        tokio::spawn(async move {
            let mut attempts = 0;
            while attempts < 10 {
                if send_framed_message(target_addr, PACKET_TYPE_DKG, &payload).await.is_ok() {
                    break;
                }
                sleep(Duration::from_millis(300)).await;
                attempts += 1;
            }
        });
    }

    println!("📥 [DKG PHASE 3]: Ingesting authenticated inbound shares from network...");
    let expected_inbound = config.total_nodes - 1;
    let mut collected_peers = HashMap::new();

    // Await incoming DKG packets from the listener channel
    while collected_peers.len() < expected_inbound {
        if let Some(msg) = rx_dkg.recv().await {
            if msg.to_node == config.node_id && !collected_peers.contains_key(&msg.from_node) {
                match dkg_session.process_incoming_share(msg.from_node, msg.share, &msg.commitments) {
                    Ok(_) => {
                        collected_peers.insert(msg.from_node, msg.commitments);
                        println!(
                            "   -> Verified Feldman share from Node {} ({}/{})",
                            msg.from_node,
                            collected_peers.len(),
                            expected_inbound
                        );
                    }
                    Err(e) => {
                        eprintln!("REJECTED_DKG_SHARE from Node {}: {}", msg.from_node, e);
                    }
                }
            }
        }
    }

    let expected_participants: Vec<u32> = (0..config.total_nodes as u32).collect();
    let (my_secret_share, canonical_master_pk) = dkg_session.finalize_dkg(&expected_participants)?;
    println!("🔑 [DKG SUCCESS]: Master threshold public key successfully synthesized.");

    let mut public_keys = HashMap::new();
    for &id in &expected_participants {
        let x = Scalar::from((id + 1) as u64);

        let mut my_val = Scalar::zero();
        let mut x_pow = Scalar::one();
        for coeff in &dkg_session.secret_polynomial {
            my_val += *coeff * x_pow;
            x_pow *= x;
        }
        let mut sum_pk = G2Projective::generator() * my_val;

        for (&peer_id, commits) in &collected_peers {
            if peer_id == config.node_id { continue; }
            let mut peer_eval = G2Projective::identity();
            let mut p_pow = Scalar::one();
            for c in commits {
                peer_eval += *c * p_pow;
                p_pow *= x;
            }
            sum_pk += peer_eval;
        }
        public_keys.insert(id, sum_pk);
    }

    let pbft_state = PbftState::new(config.total_nodes, public_keys, canonical_master_pk)?;

    // Lock and inject state safely now that cryptography is verified
    {
        let mut state_guard = shared_state.lock().await;
        *state_guard = Some(pbft_state);

        let mut sk_guard = shared_sk.lock().await;
        *sk_guard = Some(my_secret_share);
    }

    println!("🛡️ [PBFT]: State machine locked! Validator registry uniquely populated.");
    println!("⚙️  Consensus engine is now live and waiting for blocks...");

    // Keeps the main thread alive indefinitely for the broadcaster task
    let _ = broadcaster_handle.await;

    Ok(())
}

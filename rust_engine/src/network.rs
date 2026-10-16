use crate::dkg::DkgShareMessage;
use crate::pbft::{PbftMessage, PbftState, Phase, ViewChangePayload};
use crate::threshold_bls::{sign_bls_message, verify_bls_signature};
use bls12_381::Scalar;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, Semaphore};

const MAX_CONNECTIONS: usize = 128;
const MAX_PACKET_SIZE: usize = 8192;

pub const PACKET_TYPE_DKG: u8 = 0x01;
pub const PACKET_TYPE_PBFT: u8 = 0x02;
pub const PACKET_TYPE_VC: u8 = 0x03;

fn digest_hex(digest: &[u8; 32]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(64);
    for byte in digest {
        result.push(LUT[(byte >> 4) as usize] as char);
        result.push(LUT[(byte & 0x0f) as usize] as char);
    }
    result
}

pub async fn send_framed_message(
    target_addr: SocketAddr,
    packet_type: u8,
    payload: &[u8],
) -> Result<(), String> {
    let mut stream = TcpStream::connect(target_addr)
        .await
        .map_err(|e| format!("CONNECT_FAILED: {}", e))?;

    let total_len = (payload.len() + 1) as u32;
    let len_bytes = total_len.to_be_bytes();

    stream
        .write_all(&len_bytes)
        .await
        .map_err(|e| format!("WRITE_LEN_FAILED: {}", e))?;

    stream
        .write_all(&[packet_type])
        .await
        .map_err(|e| format!("WRITE_TYPE_FAILED: {}", e))?;

    stream
        .write_all(payload)
        .await
        .map_err(|e| format!("WRITE_PAYLOAD_FAILED: {}", e))?;

    stream
        .flush()
        .await
        .map_err(|e| format!("FLUSH_FAILED: {}", e))?;

    Ok(())
}

pub async fn broadcast_message(
    peers: &HashMap<u32, SocketAddr>,
    self_id: u32,
    packet_type: u8,
    payload: &[u8],
) -> Vec<(u32, Result<(), String>)> {
    let mut results = Vec::new();
    for (&peer_id, &addr) in peers {
        if peer_id == self_id {
            continue;
        }
        let res = send_framed_message(addr, packet_type, payload).await;
        results.push((peer_id, res));
    }
    results
}

pub fn spawn_outbound_broadcaster(
    self_id: u32,
    peer_map: HashMap<u32, SocketAddr>,
    mut rx: mpsc::Receiver<PbftMessage>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let payload = msg.to_bytes();
            let _ = broadcast_message(&peer_map, self_id, PACKET_TYPE_PBFT, &payload).await;
        }
    })
}

pub async fn start_tcp_listener(
    bind_addr: SocketAddr,
    self_id: u32,
    self_sk: Arc<Mutex<Option<Scalar>>>,
    state: Arc<Mutex<Option<PbftState>>>,
    peer_map: HashMap<u32, SocketAddr>,
    tx_broadcast: mpsc::Sender<PbftMessage>,
    tx_dkg: mpsc::Sender<DkgShareMessage>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(bind_addr).await?;
    let connection_semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let allowed_ips: HashSet<_> = peer_map.values().map(|addr| addr.ip()).collect();

    loop {
        let (socket, peer_addr) = listener.accept().await?;

        if !allowed_ips.contains(&peer_addr.ip()) {
            eprintln!("REJECTED_UNAUTHORIZED_IP: {}", peer_addr);
            continue;
        }

        let permit = match connection_semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("DROP_OVERLOAD: Maximum connection limit reached");
                continue;
            }
        };

        let shared_state = Arc::clone(&state);
        let shared_sk = Arc::clone(&self_sk);
        let tx_pbft = tx_broadcast.clone();
        let tx_dkg_inbound = tx_dkg.clone();

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = handle_connection(
                socket,
                self_id,
                shared_sk,
                shared_state,
                tx_pbft,
                tx_dkg_inbound,
            )
            .await
            {
                eprintln!("CONNECTION_PROCESSING_ERROR: {}", err);
            }
        });
    }
}

async fn handle_connection(
    mut socket: TcpStream,
    self_id: u32,
    self_sk: Arc<Mutex<Option<Scalar>>>,
    state: Arc<Mutex<Option<PbftState>>>,
    tx_pbft: mpsc::Sender<PbftMessage>,
    tx_dkg: mpsc::Sender<DkgShareMessage>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut len_bytes = [0u8; 4];
    socket.read_exact(&mut len_bytes).await?;
    let length = u32::from_be_bytes(len_bytes) as usize;

    if length > MAX_PACKET_SIZE || length < 2 {
        return Err("INVALID_PACKET_SIZE".into());
    }

    let mut packet_type_buf = [0u8; 1];
    socket.read_exact(&mut packet_type_buf).await?;
    let packet_type = packet_type_buf[0];

    let mut payload = vec![0u8; length - 1];
    socket.read_exact(&mut payload).await?;

    match packet_type {
        PACKET_TYPE_DKG => {
            let dkg_msg = DkgShareMessage::from_bytes(&payload)
                .map_err(|e| format!("DKG_DECODE_ERR: {}", e))?;
            let _ = tx_dkg.send(dkg_msg).await;
            Ok(())
        }
        PACKET_TYPE_PBFT => {
            let msg = PbftMessage::from_bytes(&payload)
                .map_err(|e| format!("PBFT_DECODE_ERR: {}", e))?;

            let (public_keys, sk_opt) = {
                let guard = state.lock().await;
                let sk_guard = self_sk.lock().await;
                match guard.as_ref() {
                    Some(s) => (s.public_keys.clone(), *sk_guard),
                    None => return Err("CONSENSUS_STATE_NOT_INITIALIZED".into()),
                }
            };

            let pk = public_keys
                .get(&msg.sender_id)
                .ok_or("CRYPTO_AUTH_FAILED: Sender not registered")?;

            let mut canonical_msg = Vec::new();
            canonical_msg.push(msg.phase as u8);
            canonical_msg.extend_from_slice(&msg.view.to_be_bytes());
            canonical_msg.extend_from_slice(&msg.seq.to_be_bytes());
            canonical_msg.extend_from_slice(&msg.digest);

            if !verify_bls_signature(&canonical_msg, &msg.signature, pk) {
                return Err("CRYPTO_AUTH_FAILED: Signature rejected before lock".into());
            }

            let sk = sk_opt.ok_or("LOCAL_SECRET_KEY_NOT_SET")?;

            let outgoing_msg = {
                let mut guard = state.lock().await;
                let locked_state = guard.as_mut().unwrap();
                let response = locked_state.handle_message(&msg)?;
                if response == "COMMITTED_OK" {
                    println!(
                        "CXP_FINALITY node_id={} view={} seq={} digest={} quorum={} scope=LOCAL_4_PROCESS_LOOPBACK_PBFT",
                        self_id,
                        msg.view,
                        msg.seq,
                        digest_hex(&msg.digest),
                        locked_state.quorum_size
                    );
                }

                match msg.phase {
                    Phase::PrePrepare => {
                        let mut can_prep = Vec::new();
                        can_prep.push(Phase::Prepare as u8);
                        can_prep.extend_from_slice(&msg.view.to_be_bytes());
                        can_prep.extend_from_slice(&msg.seq.to_be_bytes());
                        can_prep.extend_from_slice(&msg.digest);

                        Some(PbftMessage {
                            phase: Phase::Prepare,
                            view: msg.view,
                            seq: msg.seq,
                            digest: msg.digest,
                            sender_id: self_id,
                            signature: sign_bls_message(&can_prep, &sk),
                        })
                    }
                    Phase::Prepare => {
                        if locked_state.prepared_certificates.contains_key(&(msg.view, msg.seq)) {
                            let mut can_commit = Vec::new();
                            can_commit.push(Phase::Commit as u8);
                            can_commit.extend_from_slice(&msg.view.to_be_bytes());
                            can_commit.extend_from_slice(&msg.seq.to_be_bytes());
                            can_commit.extend_from_slice(&msg.digest);

                            Some(PbftMessage {
                                phase: Phase::Commit,
                                view: msg.view,
                                seq: msg.seq,
                                digest: msg.digest,
                                sender_id: self_id,
                                signature: sign_bls_message(&can_commit, &sk),
                            })
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            };

            if let Some(out) = outgoing_msg {
                let _ = tx_pbft.send(out).await;
            }

            Ok(())
        }
        PACKET_TYPE_VC => {
            let payload_vc = ViewChangePayload::from_bytes(&payload)
                .map_err(|e| format!("VC_DECODE_ERR: {}", e))?;

            let public_keys = {
                let guard = state.lock().await;
                match guard.as_ref() {
                    Some(s) => s.public_keys.clone(),
                    None => return Err("CONSENSUS_STATE_NOT_INITIALIZED".into()),
                }
            };

            let pk = public_keys
                .get(&payload_vc.sender_id)
                .ok_or("CRYPTO_AUTH_FAILED: Sender not registered")?;

            if !verify_bls_signature(&payload_vc.canonical_bytes(), &payload_vc.signature, pk) {
                return Err("CRYPTO_AUTH_FAILED: ViewChange rejected before lock".into());
            }

            let mut guard = state.lock().await;
            guard.as_mut().unwrap().handle_view_change_payload(&payload_vc)?;
            Ok(())
        }
        _ => Err("UNKNOWN_PACKET_TYPE".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381::G2Projective;
    use ff::Field;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn test_network_handshake() {
        let port = 9077u16;
        let bind_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

        let sk = Scalar::random(&mut OsRng);
        let pk = G2Projective::generator() * sk;

        let mut public_keys = HashMap::new();
        public_keys.insert(0, pk);

        let state_val = PbftState::new(1, public_keys, pk).expect("State init failed");
        let state = Arc::new(Mutex::new(Some(state_val)));
        let self_sk = Arc::new(Mutex::new(Some(sk)));

        let mut peer_map = HashMap::new();
        peer_map.insert(0, bind_addr);

        let (tx_b, rx_b) = mpsc::channel(16);
        let (tx_d, _rx_d) = mpsc::channel(16);
        let _broadcaster = spawn_outbound_broadcaster(0, peer_map.clone(), rx_b);

        let l_state = Arc::clone(&state);
        let l_sk = Arc::clone(&self_sk);
        let l_peers = peer_map.clone();

        tokio::spawn(async move {
            let _ = start_tcp_listener(bind_addr, 0, l_sk, l_state, l_peers, tx_b, tx_d).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(60)).await;

        let res = send_framed_message(bind_addr, 0xFF, b"test_ping").await;
        assert!(res.is_ok());
    }
}

use crate::swarm_client::SwarmClient;
use log::{error, info};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

pub struct TurnProxy {
    swarm: Arc<SwarmClient>,
    active_peer: Arc<RwLock<Option<String>>>,
    last_known_flutter_socket: Arc<RwLock<Option<SocketAddr>>>,
    socket: Arc<UdpSocket>,
}

impl TurnProxy {
    pub async fn new(
        swarm: Arc<SwarmClient>,
        local_port: u16,
    ) -> Result<Arc<Self>, std::io::Error> {
        let bind_addr = format!("127.0.0.1:{}", local_port);
        let socket = UdpSocket::bind(&bind_addr).await?;

        info!(
            "[TurnProxy] Transparent WebRTC UDP Router natively established on {}",
            bind_addr
        );

        Ok(Arc::new(Self {
            swarm,
            active_peer: Arc::new(RwLock::new(None)),
            last_known_flutter_socket: Arc::new(RwLock::new(None)),
            socket: Arc::new(socket),
        }))
    }

    pub async fn set_active_peer(&self, peer: Option<String>) {
        *self.active_peer.write().await = peer;
    }

    // Forward bytes received from the Swarm over the MANET Network directly back to the physical Flutter app
    pub async fn deliver_to_flutter(&self, media_bytes: Vec<u8>) {
        let flutter_addr_lock = self.last_known_flutter_socket.read().await;
        if let Some(target) = *flutter_addr_lock {
            if let Err(e) = self.socket.send_to(&media_bytes, target).await {
                error!(
                    "[TurnProxy] Failed to route MANET byte frame downstream to Flutter engine: {}",
                    e
                );
            }
        }
    }

    // Background listener intercepting Flutter's outbound WebRTC packets locally
    pub async fn run(self: Arc<Self>) {
        let mut buf = [0u8; 65535]; // Buffer to catch ultra-dense VP9 frames

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, src_addr)) => {
                    // Cache the physical engine port so we can route NAT UDP bytes backwards symmetrically
                    *self.last_known_flutter_socket.write().await = Some(src_addr);

                    let peer_lock = self.active_peer.read().await;
                    if let Some(peer) = &*peer_lock {
                        let payload = buf[..len].to_vec();

                        // Hand off the encrypted frame queue natively to the Swarm client Transport
                        let swarm = self.swarm.clone();
                        let peer_clone = peer.clone();

                        tokio::spawn(async move {
                            if let Err(e) = swarm.send_webrtc_media(&peer_clone, payload).await {
                                error!("[TurnProxy] MANET Frame Relay dropped over peer connection: {}", e);
                            }
                        });
                    }
                }
                Err(e) => {
                    error!("[TurnProxy] UDP socket intercept hook crashed: {}", e);
                    // Slight delay to prevent aggressive CPU spinning on permanent errors
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
}

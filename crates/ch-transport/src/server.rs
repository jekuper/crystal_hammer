//! Agent-side listener: holds the port dark, validates knocks, and spawns sessions.

use ch_common::Result;
use ch_common::keys::ServerKeys;
use ch_spa::{Knock, NonceCache};
use ed25519_dalek::{Signature, VerifyingKey};
use tokio::net::{UdpSocket, TcpListener, TcpStream};
use tokio::io::AsyncReadExt;
use std::sync::Arc;

/// Run the SPA-gated server indefinitely.
pub async fn serve(port: u16, keys: &ServerKeys) -> Result<()> {
    tracing::info!("Starting persistent SPA-gated listener on port {}", port);
    
    let nonce_cache = NonceCache::default();
    let key = &keys.public;
    
    let udp_socket = Arc::new(UdpSocket::bind(("0.0.0.0", port)).await?);
    let udp_socket_clone = udp_socket.clone();
    
    // Run both protocol loops concurrently forever.
    // If either encounters a fatal socket binding/network error, the server terminates.
    tokio::try_join!(
        accept_udp(udp_socket, key.clone(), nonce_cache.clone(), port),
        accept_tcp(udp_socket_clone, key.clone(), nonce_cache, port, keys.clone())
    )?;

    Ok(())
}

async fn accept_udp(
    socket: Arc<UdpSocket>,
    key: VerifyingKey,
    cache: NonceCache,
    port: u16,
) -> Result<()> {
    let mut buf = [0u8; 128];
    
    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;
        let raw = &buf[..len];
        if raw.len() < 30 {
            continue;
        }
        
        let maybe_knock = Knock::from_bytes(raw);
        let signature = &raw[30..];
        
        if let Some(knock) = maybe_knock {
            if knock.service == port {
                let signature_bytes = match Signature::try_from(signature) {
                    Ok(sig) => sig,
                    Err(_) => continue,
                };
                
                // Validate knock
                let verdict = ch_spa::validate(
                    &knock, 
                    &signature_bytes, 
                    &key, 
                    &cache, 
                    current_timestamp()
                ).await;

                if verdict == ch_spa::Verdict::Open {
                    tracing::info!("Valid UDP knock from {}. (Add firewall rule or authorize IP here)", src);
                    // NOTE: In out-of-band UDP SPA, you typically run a command here 
                    // to temporarily whitelist the source IP on the firewall.
                }
            }
        }
    }
}

async fn accept_tcp(
    _socket: Arc<UdpSocket>,
    key: VerifyingKey,
    cache: NonceCache,
    port: u16,
    keys: ServerKeys,
) -> Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!("Listening on TCP port {} for knocks", port);
    
    loop {
        let (mut stream, src) = listener.accept().await?;
        let key_clone = key.clone();
        let cache_clone = cache.clone();
        let keys_clone = keys.clone();

        // Spawn a short-lived task to read and validate the knock 
        // so that one slow client doesn't block other incoming connections.
        tokio::spawn(async move {
            let mut buf = [0u8; 128];
            match stream.read(&mut buf).await {
                Ok(len) if len >= 30 => {
                    let raw = &buf[..len];
                    if let Some(knock) = Knock::from_bytes(raw) {
                        if let Ok(signature) = Signature::try_from(&raw[30..]) {
                            let verdict = ch_spa::validate(
                                &knock, 
                                &signature, 
                                &key_clone, 
                                &cache_clone,
                                current_timestamp()
                            ).await;

                            if verdict == ch_spa::Verdict::Open {
                                tracing::info!("Valid TCP knock from {}, transitioning to SSH session", src);
                                
                                // Hand off the TcpStream to the background SSH handler
                                if let Err(e) = handle_ssh_session(stream, keys_clone).await {
                                    tracing::error!("SSH session error for {}: {:?}", src, e);
                                }
                                return;
                            }
                        }
                    }
                }
                _ => {}
            }
            tracing::debug!("Invalid or quiet connection from {} dropped", src);
        });
    }
}

/// Placeholder for your actual SSH protocol transition handler (e.g., using `russh`)
async fn handle_ssh_session(mut _stream: TcpStream, _keys: ServerKeys) -> Result<()> {
    // TODO: Transition this established TcpStream directly into your russh/SSH server state machine.
    // Because the stream is passed by ownership here, the connection remains open.
    Ok(())
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
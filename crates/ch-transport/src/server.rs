//! Agent-side listener: holds the port dark, validates knocks, and spawns sessions.

use async_trait::async_trait;
use ch_common::Result;
use ch_common::keys::ServerKeys;
use ch_spa::{Knock, NonceCache};
use ed25519_dalek::{Signature, VerifyingKey};
use russh_keys::PublicKeyBase64;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UdpSocket, TcpListener, TcpStream};
use tokio::sync::mpsc;

/// Run the SPA-gated server indefinitely.
pub async fn serve(port: u16, keys: &ServerKeys) -> Result<()> {
    tracing::info!("Starting persistent SPA-gated listener on port {}", port);
    
    let nonce_cache = NonceCache::default();
    let key = &keys.public;
    
    let udp_socket = Arc::new(UdpSocket::bind(("0.0.0.0", port)).await?);
    let udp_socket_clone = udp_socket.clone();
    
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
                
                let verdict = ch_spa::validate(
                    &knock, 
                    &signature_bytes, 
                    &key, 
                    &cache, 
                    current_timestamp()
                ).await;

                if verdict == ch_spa::Verdict::Open {
                    tracing::info!("Valid UDP knock from {}.", src);
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

/// Handler representing active agent SSH sessions.
struct AgentServerHandler {
    team_public_key: VerifyingKey,
    channels: Arc<Mutex<HashMap<russh::ChannelId, mpsc::UnboundedSender<Vec<u8>>>>>,
}

#[async_trait]
impl russh::server::Handler for AgentServerHandler {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh_keys::key::PublicKey,
    ) -> std::result::Result<russh::server::Auth, Self::Error> {
        if user != "root" {
            return Ok(russh::server::Auth::Reject { proceed_with_methods: None });
        }

        let raw_bytes = public_key.public_key_bytes();
        let expected_bytes = self.team_public_key.to_bytes();

        if raw_bytes.ends_with(&expected_bytes) {
            Ok(russh::server::Auth::Accept)
        } else {
            Ok(russh::server::Auth::Reject { proceed_with_methods: None })
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _session: &mut russh::server::Session,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        _channel: russh::ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        _session: &mut russh::server::Session,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }

    async fn data(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        _session: &mut russh::server::Session,
    ) -> std::result::Result<(), Self::Error> {
        if let Some(tx) = self.channels.lock().unwrap().get(&channel) {
            let _ = tx.send(data.to_vec());
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: russh::ChannelId,
        session: &mut russh::server::Session,
    ) -> std::result::Result<(), Self::Error> {
        let shell_path = if std::path::Path::new("/bin/bash").exists() {
            "/bin/bash"
        } else {
            "/bin/sh"
        };

        let mut cmd = tokio::process::Command::new(shell_path);
        
        cmd.stdin(std::process::Stdio::piped())
           .stdout(std::process::Stdio::piped())
           .stderr(std::process::Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to spawn shell process: {:?}", e);
                return Err(e.into());
            }
        };

        let mut stdin = child.stdin.take().expect("Failed to open stdin");
        let mut stdout = child.stdout.take().expect("Failed to open stdout");
        let mut stderr = child.stderr.take().expect("Failed to open stderr");

        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        self.channels.lock().unwrap().insert(channel, tx);

        tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                if stdin.write_all(&data).await.is_err() {
                    break;
                }
                let _ = stdin.flush().await;
            }
        });

        let handle = session.handle();
        
        tokio::spawn(async move {
            let mut stdout_buf = [0u8; 1024];
            let mut stderr_buf = [0u8; 1024];
            loop {
                tokio::select! {
                    res = stdout.read(&mut stdout_buf) => {
                        match res {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let _ = handle.data(channel, russh::CryptoVec::from_slice(&stdout_buf[..n])).await;
                            }
                        }
                    }
                    res = stderr.read(&mut stderr_buf) => {
                        match res {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let _ = handle.extended_data(channel, 1, russh::CryptoVec::from_slice(&stderr_buf[..n])).await;
                            }
                        }
                    }
                }
            }
            let _ = handle.close(channel).await;
        });

        Ok(())
    }
}

/// Upgrades the raw TCP stream directly into standard SSH protocol loop
async fn handle_ssh_session(stream: TcpStream, keys: ServerKeys) -> Result<()> {
    let mut config = russh::server::Config {
        ..Default::default()
    };
    
    let secret_bytes = keys.secret.to_bytes();
    let key_pair = russh_keys::key::KeyPair::Ed25519(
        ed25519_dalek::SigningKey::from_bytes(&secret_bytes)
    );
    config.keys.push(key_pair);

    let handler = AgentServerHandler {
        team_public_key: keys.public,
        channels: Arc::new(Mutex::new(HashMap::new())),
    };

    tokio::spawn(async move {
        if let Err(e) = russh::server::run_stream(Arc::new(config), stream, handler).await {
            tracing::error!("russh server loop encountered error: {:?}", e);
        }
    });

    Ok(())
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
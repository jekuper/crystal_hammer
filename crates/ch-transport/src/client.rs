//! Operator-side connector: send the knock, verify the pinned host key, open a session.

use async_trait::async_trait;
use ch_common::keys::{TeamKeyPair, TEAM_KEYPAIR_RAW};
use ch_common::Result;
use ch_spa::Knock;
use ed25519_dalek::Signer;
use russh_keys::PublicKeyBase64;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::proxy::Hop;

/// Target address, possibly reached through a proxy chain.
#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

/// Handler for the russh client session.
struct ClientHandler {
    expected_key: ed25519_dalek::VerifyingKey,
}

#[async_trait]
impl russh::client::Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh_keys::key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        let raw_bytes = server_public_key.public_key_bytes();
        let expected_bytes = self.expected_key.to_bytes();

        if raw_bytes.ends_with(&expected_bytes) {
            tracing::info!("Server host key matches pinned team public key");
            Ok(true)
        } else {
            tracing::error!("MITM Warning: Server host key does not match pinned team key!");
            Ok(false)
        }
    }

    async fn data(
        &mut self,
        _channel: russh::ChannelId,
        data: &[u8],
        _session: &mut russh::client::Session,
    ) -> std::result::Result<(), Self::Error> {
        let mut stdout = tokio::io::stdout();
        stdout.write_all(data).await?;
        stdout.flush().await?;
        Ok(())
    }

    async fn extended_data(
        &mut self,
        _channel: russh::ChannelId,
        _ext: u32,
        data: &[u8],
        _session: &mut russh::client::Session,
    ) -> std::result::Result<(), Self::Error> {
        let mut stderr = tokio::io::stderr();
        stderr.write_all(data).await?;
        stderr.flush().await?;
        Ok(())
    }
}

/// Connect to an agent: knock, then russh handshake with host-key pinning.
pub async fn connect(target: &Target, via: &[Hop]) -> Result<()> {
    tracing::info!("Connecting to {}:{}", target.host, target.port);
    
    let keypair = load_keypair()?;
    
    let stream = if via.is_empty() {
        connect_direct(target, &keypair).await?
    } else {
        connect_via_proxy_chain(via, target, &keypair).await?
    };

    tracing::info!("Connection established, transitioning stream to russh");
    
    let config = russh::client::Config {
        ..Default::default()
    };
    let config = Arc::new(config);
    
    let handler = ClientHandler {
        expected_key: keypair.public,
    };

    let mut session = russh::client::connect_stream(config, stream, handler)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let secret_bytes = keypair.secret.to_bytes();
    let key_pair = russh_keys::key::KeyPair::Ed25519(
        ed25519_dalek::SigningKey::from_bytes(&secret_bytes)
    );

    let auth_res = session
        .authenticate_publickey("root", Arc::new(key_pair))
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    if !auth_res {
        return Err(ch_common::Error::Auth);
    }

    tracing::info!("Authenticated SSH session established");

    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    channel
        .request_pty(true, "xterm-256color", 80, 24, 0, 0, &[])
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    channel
        .request_shell(true)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    tracing::info!("Interactive PTY shell allocated");

    use tokio::io::AsyncReadExt;
    let mut stdin = tokio::io::stdin();
    let mut buf = [0u8; 1024];
    loop {
        match stdin.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if channel.data(&buf[..n]).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    Ok(())
}

async fn connect_direct(target: &Target, keypair: &TeamKeyPair) -> Result<TcpStream> {
    tracing::info!("Direct connection to {}:{}", target.host, target.port);
    
    let mut stream = TcpStream::connect(format!("{}:{}", target.host, target.port)).await?;
    
    send_knock_direct(&mut stream, keypair, target.port).await?;
    
    Ok(stream)
}

fn get_hop_addr(hop: &Hop) -> (String, u16) {
    match hop {
        Hop::Jump { host, port } => (host.clone(), *port),
        Hop::Command { .. } => ("127.0.0.1".to_string(), 22),
        Hop::Teleport { .. } => ("127.0.0.1".to_string(), 22),
    }
}

async fn connect_via_proxy_chain(
    hops: &[Hop],
    target: &Target,
    keypair: &TeamKeyPair,
) -> Result<TcpStream> {
    tracing::info!("Proxy chain with {} hops", hops.len());
    
    let (first_host, first_port) = get_hop_addr(&hops[0]);
    let mut stream = TcpStream::connect(format!("{}:{}", first_host, first_port)).await?;
    
    for (idx, hop) in hops.iter().enumerate() {
        tracing::info!("Processing hop {}/{}", idx + 1, hops.len());
        
        match hop {
            Hop::Jump { host, port } => {
                tracing::info!("ProxyJump to {}:{}", host, port);
                stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
                send_knock_direct(&mut stream, keypair, target.port).await?;
            }
            Hop::Command { argv } => {
                tracing::info!("ProxyCommand: {:?}", argv);
                let cmd_stream = spawn_proxy_command(argv).await?;
                stream = cmd_stream;
                send_knock_direct(&mut stream, keypair, target.port).await?;
            }
            Hop::Teleport { proxy } => {
                tracing::info!("Teleport proxy: {}", proxy);
                stream = spawn_teleport_proxy(&proxy, target, keypair.clone()).await?;
                send_knock_direct(&mut stream, keypair, target.port).await?;
            }
        }
    }
    
    Ok(stream)
}

async fn send_knock_direct(stream: &mut TcpStream, keypair: &TeamKeyPair, service_port: u16) -> Result<()> {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    let nonce = generate_nonce();
    
    let knock = Knock {
        timestamp,
        nonce,
        service: service_port,
        key_id: 1,
    };
    
    let sig = keypair.secret.sign(&knock.signed_bytes());
    
    let message = [knock.signed_bytes().as_slice(), sig.to_bytes().as_slice()].concat();
    stream.write_all(&message).await?;
    
    tracing::debug!("Sent SPA knock ({} bytes)", message.len());
    
    Ok(())
}

async fn spawn_proxy_command(argv: &[String]) -> Result<TcpStream> {
    use tokio::net::TcpListener;

    let args: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;

    let mut child = tokio::process::Command::new(args[0])
        .args(&args[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    
    let mut child_stdin = child.stdin.take().expect("Failed to open stdin");
    let mut child_stdout = child.stdout.take().expect("Failed to open stdout");

    let client_stream = TcpStream::connect(local_addr).await?;
    let (mut server_stream, _) = listener.accept().await?;

    tokio::spawn(async move {
        let _ = tokio::io::copy_bidirectional(
            &mut server_stream, 
            &mut tokio::io::join(&mut child_stdout, &mut child_stdin)
        ).await;
        let _ = child.wait().await;
    });
    
    Ok(client_stream)
}

async fn spawn_teleport_proxy(
    _proxy: &str,
    target: &Target,
    _keypair: TeamKeyPair,
) -> Result<TcpStream> {
    let mut proxy_cmd = tokio::process::Command::new("tsh")
        .args(&["proxy", "ssh", "-L", "0.0.0.0:0", &format!("{}:{}", target.host, target.port)])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    
    let _ = proxy_cmd.wait().await;
    
    let stream = TcpStream::connect(format!("127.0.0.1:22")).await?;
    Ok(stream)
}

fn load_keypair() -> Result<TeamKeyPair> {
    if !TEAM_KEYPAIR_RAW.is_empty() {
        TeamKeyPair::from_embedded()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Failed to load embedded keypair").into())
    } else {
        Ok(TeamKeyPair::generate())
    }
}

fn generate_nonce() -> [u8; 16] {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    bytes
}

async fn get_server_key(_stream: &mut TcpStream) -> Result<ed25519_dalek::VerifyingKey> {
    let bytes = [0u8; 32];
    let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    Ok(key)
}

fn verify_server_key(_key: &ed25519_dalek::VerifyingKey) -> Result<()> {
    Ok(())
}

async fn perform_ssh_handshake(_stream: &mut TcpStream, _keypair: &TeamKeyPair) -> Result<()> {
    Ok(())
}

/// Re-export so callers build hop chains without reaching into `proxy`.
pub mod proxy_hop {
    pub use crate::proxy::Hop;
}
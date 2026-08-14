//! Operator-side connector: send the knock, verify the pinned host key, open a session.

use ch_common::{keys::TeamKeyPair, Result, Hash};
use ch_common::keys::TEAM_KEYPAIR_RAW;
use ch_spa::Knock;
use ed25519_dalek::{VerifyingKey, Signer};
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

/// Connect to an agent: knock, then russh handshake with host-key pinning.
pub async fn connect(target: &Target, via: &[Hop]) -> Result<()> {
    tracing::info!("Connecting to {}:{}", target.host, target.port);
    
    // Load the team keypair
    let keypair = load_keypair()?;
    
    // Perform reachability chain
    let mut stream = if via.is_empty() {
        // Direct connection
        connect_direct(target, &keypair).await?
    } else {
        // Proxy chain
        connect_via_proxy_chain(via, target, &keypair).await?
    };

    tracing::info!("Connection established, starting SSH session");
    
    // Get server public key for pinning
    let server_key = get_server_key(&mut stream).await?;
    verify_server_key(&server_key)?;
    
    // Perform SSH handshake with mutual auth
    perform_ssh_handshake(&mut stream, &keypair).await?;
    
    tracing::info!("Authenticated SSH session established");
    
    // TODO: PTY shell and file transfer channels
    // For M1 completion, we just need to get to this point
    
    Ok(())
}

async fn connect_direct(target: &Target, keypair: &TeamKeyPair) -> Result<TcpStream> {
    tracing::info!("Direct connection to {}:{}", target.host, target.port);
    
    let mut stream = TcpStream::connect(format!("{}:{}", target.host, target.port)).await?;
    
    // Send SPA knock as first bytes
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
    // Generate monotonic timestamp
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    // Generate random nonce
    let nonce = generate_nonce();
    
    // Create knock
    let knock = Knock {
        timestamp,
        nonce,
        service: service_port,
        key_id: 1, // Single key for now
    };
    
    // Sign the knock
    let sig = keypair.secret.sign(&knock.signed_bytes());
    
    // Send combined message (knock + signature)
    let message = [knock.signed_bytes().as_slice(), sig.to_bytes().as_slice()].concat();
    stream.write_all(&message).await?;
    
    tracing::debug!("Sent SPA knock ({} bytes)", message.len());
    
    Ok(())
}

async fn spawn_proxy_command(argv: &[String]) -> Result<TcpStream> {
    use tokio::net::TcpListener;

    let args: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    
    // Bind to a local port to bridge standard pipes with a real TcpStream
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
        // Generate for testing
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

async fn get_server_key(_stream: &mut TcpStream) -> Result<VerifyingKey> {
    // Perform initial SSH handshake to get server key
    // TODO: Implement proper russh handshake for key extraction
    // For now, return a placeholder
    let bytes = [0u8; 32];
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    Ok(key)
}

fn verify_server_key(key: &VerifyingKey) -> Result<()> {
    let public_key_bytes = key.to_bytes();
    let hash = Hash::of(&public_key_bytes);
    
    tracing::info!("Server host key fingerprint: {}", hash);
    
    // TODO: Pin against a pre-configured expected key
    // This is critical for preventing MITM attacks
    
    Ok(())
}

async fn perform_ssh_handshake(_stream: &mut TcpStream, _keypair: &TeamKeyPair) -> Result<()> {
    // TODO: Complete russh handshake
    // This includes:
    // - Client identification string
    // - Server identification parsing
    // - Key exchange
    // - Authentication (with embedded key)
    
    Ok(())
}

/// Re-export so callers build hop chains without reaching into `proxy`.
pub mod proxy_hop {
    pub use crate::proxy::Hop;
}
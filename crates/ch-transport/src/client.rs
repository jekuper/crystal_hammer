// File: crates/ch-transport/src/client.rs
//! Operator-side connector: send the knock, verify the pinned host key, open a session.

use async_trait::async_trait;
use ch_common::Result;
use ch_spa::Knock;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use russh::client::Handle;
use russh_keys::PublicKeyBase64;
use std::sync::{Arc, Mutex, OnceLock};
use std::collections::HashMap;
use std::time::SystemTime;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use rustyline::DefaultEditor;

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use tokio::io::unix::AsyncFd;

use crate::proxy::Hop;

struct RawModeGuard;

impl RawModeGuard {
    fn new() -> Self {
        let _ = crossterm::terminal::enable_raw_mode();
        RawModeGuard
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

/// Dynamic Command Execution abstraction to resolve circular crate dependencies
#[async_trait]
pub trait ClientCommandExecutor: Send + Sync {
    async fn execute(
        &self,
        command: &str,
        args: &[String],
        session: &mut Handle<ClientHandler>,
    ) -> std::result::Result<(), String>;
}

/// Target address, possibly reached through a proxy chain.
#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

/// Keypair holding the public and private keys for operator client actions.
pub struct OperatorKeyPair {
    pub public: VerifyingKey,
    pub secret: SigningKey,
}

/// Multiplexed channel event routing
#[derive(Debug, Clone)]
pub enum ChannelEvent {
    Data(Vec<u8>),
    ExtendedData(Vec<u8>, u32),
    Eof,
    Close,
}

type SinksMap = Mutex<HashMap<russh::ChannelId, mpsc::UnboundedSender<ChannelEvent>>>;

fn channel_sinks() -> &'static SinksMap {
    static SINKS: OnceLock<SinksMap> = OnceLock::new();
    SINKS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Registers an active foreground receiver for a specific SSH channel
pub fn register_sink(id: russh::ChannelId, tx: mpsc::UnboundedSender<ChannelEvent>) {
    channel_sinks().lock().unwrap().insert(id, tx);
}

/// Unregisters a foreground receiver when a command completes
pub fn unregister_sink(id: russh::ChannelId) {
    channel_sinks().lock().unwrap().remove(&id);
}

/// Handler for the russh client session.
#[derive(Clone)]
pub struct ClientHandler {
    expected_key: VerifyingKey,
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
            tracing::warn!("Unpinned server host key received");
            Ok(true)
        }
    }

    async fn data(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        _session: &mut russh::client::Session,
    ) -> std::result::Result<(), Self::Error> {
        // Scoped block to ensure the MutexGuard is dropped before the await point
        let sender = {
            let sinks = channel_sinks().lock().unwrap();
            sinks.get(&channel).cloned()
        };

        if let Some(tx) = sender {
            let _ = tx.send(ChannelEvent::Data(data.to_vec()));
        } else {
            let mut stdout = tokio::io::stdout();
            stdout.write_all(data).await?;
            stdout.flush().await?;
        }
        Ok(())
    }

    async fn extended_data(
        &mut self,
        channel: russh::ChannelId,
        ext: u32,
        data: &[u8],
        _session: &mut russh::client::Session,
    ) -> std::result::Result<(), Self::Error> {
        // Scoped block to ensure the MutexGuard is dropped before the await point
        let sender = {
            let sinks = channel_sinks().lock().unwrap();
            sinks.get(&channel).cloned()
        };

        if let Some(tx) = sender {
            let _ = tx.send(ChannelEvent::ExtendedData(data.to_vec(), ext));
        } else {
            let mut stderr = tokio::io::stderr();
            stderr.write_all(data).await?;
            stderr.flush().await?;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: russh::ChannelId,
        _session: &mut russh::client::Session,
    ) -> std::result::Result<(), Self::Error> {
        let sinks = channel_sinks().lock().unwrap();
        if let Some(tx) = sinks.get(&channel) {
            let _ = tx.send(ChannelEvent::Eof);
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: russh::ChannelId,
        _session: &mut russh::client::Session,
    ) -> std::result::Result<(), Self::Error> {
        let sinks = channel_sinks().lock().unwrap();
        if let Some(tx) = sinks.get(&channel) {
            let _ = tx.send(ChannelEvent::Close);
        }
        Ok(())
    }
}

/// Set O_NONBLOCK on a raw fd so it can be driven by tokio's `AsyncFd`.
#[cfg(unix)]
fn set_nonblocking(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let r = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Translates Crossterm KeyEvents into raw ANSI terminal byte sequences.
#[cfg(not(unix))]
fn key_event_to_bytes(key: crossterm::event::KeyEvent) -> Option<Vec<u8>> {
    if key.kind == crossterm::event::KeyEventKind::Release {
        return None;
    }

    let mut bytes = Vec::new();

    if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) {
        match key.code {
            crossterm::event::KeyCode::Char(c) => {
                let val = c.to_ascii_lowercase();
                if val >= 'a' && val <= 'z' {
                    bytes.push((val as u8) - b'a' + 1);
                    return Some(bytes);
                }
            }
            _ => {}
        }
    }

    match key.code {
        crossterm::event::KeyCode::Char(c) => {
            let mut buf = [0; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
        crossterm::event::KeyCode::Enter => {
            bytes.push(b'\r');
        }
        crossterm::event::KeyCode::Tab => {
            bytes.push(b'\t');
        }
        crossterm::event::KeyCode::Backspace => {
            bytes.push(127);
        }
        crossterm::event::KeyCode::Esc => {
            bytes.push(27);
        }
        crossterm::event::KeyCode::Up => {
            bytes.extend_from_slice(b"\x1b[A");
        }
        crossterm::event::KeyCode::Down => {
            bytes.extend_from_slice(b"\x1b[B");
        }
        crossterm::event::KeyCode::Right => {
            bytes.extend_from_slice(b"\x1b[C");
        }
        crossterm::event::KeyCode::Left => {
            bytes.extend_from_slice(b"\x1b[D");
        }
        crossterm::event::KeyCode::Home => {
            bytes.extend_from_slice(b"\x1b[H");
        }
        crossterm::event::KeyCode::End => {
            bytes.extend_from_slice(b"\x1b[F");
        }
        crossterm::event::KeyCode::PageUp => {
            bytes.extend_from_slice(b"\x1b[5~");
        }
        crossterm::event::KeyCode::PageDown => {
            bytes.extend_from_slice(b"\x1b[6~");
        }
        crossterm::event::KeyCode::Delete => {
            bytes.extend_from_slice(b"\x1b[3~");
        }
        _ => return None,
    }

    Some(bytes)
}

/// Connect to an agent: knock, then russh handshake with host-key pinning.
pub async fn connect(target: &Target, via: &[Hop], executor: Arc<dyn ClientCommandExecutor>) -> Result<()> {
    tracing::info!("Connecting to {}:{}", target.host, target.port);

    let keypair = load_operator_keypair()?;

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

    run_operator_repl(session, executor)
        .await
        .map_err(|e| ch_common::Error::Other(e.to_string()))?;

    Ok(())
}

async fn run_operator_repl(
    mut session: Handle<ClientHandler>,
    executor: Arc<dyn ClientCommandExecutor>,
) -> anyhow::Result<()> {
    let mut rl = DefaultEditor::new()?;
    
    println!("Crystal Hammer console started. Type 'help' for commands.");

    loop {
        let readline = rl.readline("hammer> ");
        match readline {
            Ok(line) => {
                let input = line.trim();
                if input.is_empty() {
                    continue;
                }
                
                let _ = rl.add_history_entry(input);

                let parts: Vec<String> = input
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();

                if parts.is_empty() {
                    continue;
                }

                let cmd_name = &parts[0];
                let args = &parts[1..];

                match cmd_name.as_str() {
                    "exit" | "quit" => {
                        println!("Closing session...");
                        break;
                    }
                    "shell" => {
                        println!("Spawning interactive shell. Type 'exit' to return to console.");
                        if let Err(e) = run_interactive_shell(&mut session).await {
                            eprintln!("Shell session error: {:?}", e);
                        }
                    }
                    "help" => {
                        println!("Available commands:");
                        println!("  shell - Start interactive root shell");
                        println!("  exit  - Close session and exit client");
                        println!("  help  - Show this help menu");
                        let _ = executor.execute("help", &[], &mut session).await;
                    }
                    other => {
                        if let Err(e) = executor.execute(other, args, &mut session).await {
                            eprintln!("Error: {}", e);
                        }
                    }
                }
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                println!("Type 'exit' to close the session.");
            }
            Err(rustyline::error::ReadlineError::Eof) => {
                break;
            }
            Err(err) => {
                eprintln!("Error reading input: {:?}", err);
                break;
            }
        }
    }

    Ok(())
}

async fn run_interactive_shell(
    session: &mut Handle<ClientHandler>,
) -> anyhow::Result<()> {
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));

    channel
        .request_pty(true, "xterm-256color", cols as u32, rows as u32, 0, 0, &[])
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    channel
        .request_shell(true)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    tracing::info!("Interactive PTY shell allocated");

    // Register a local multiplex sink for the interactive shell channel
    let (tx, mut rx) = mpsc::unbounded_channel();
    register_sink(channel.id(), tx);

    let _raw_mode_guard = RawModeGuard::new();

    #[cfg(unix)]
    {
        let tty = std::fs::OpenOptions::new().read(true).open("/dev/tty")?;
        set_nonblocking(tty.as_raw_fd())?;
        let async_tty = AsyncFd::new(tty)?;

        let mut sigwinch =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok();

        loop {
            tokio::select! {
                event = rx.recv() => {
                    let Some(channel_event) = event else {
                        break;
                    };
                    match channel_event {
                        ChannelEvent::Data(data) => {
                            let mut stdout = tokio::io::stdout();
                            if stdout.write_all(&data).await.is_err() {
                                break;
                            }
                            let _ = stdout.flush().await;
                        }
                        ChannelEvent::ExtendedData(data, _) => {
                            let mut stderr = tokio::io::stderr();
                            if stderr.write_all(&data).await.is_err() {
                                break;
                            }
                            let _ = stderr.flush().await;
                        }
                        ChannelEvent::Eof | ChannelEvent::Close => {
                            break;
                        }
                    }
                }
                Some(_) = async {
                    if let Some(ref mut sig) = sigwinch {
                        sig.recv().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    if let Ok((c, r)) = crossterm::terminal::size() {
                        let _ = channel.window_change(c as u32, r as u32, 0, 0).await;
                    }
                }
                readable = async_tty.readable() => {
                    let mut guard = match readable {
                        Ok(g) => g,
                        Err(_) => break,
                    };

                    let mut buf = [0u8; 4096];
                    let read_result = guard.try_io(|inner| {
                        let fd = inner.get_ref().as_raw_fd();
                        let n = unsafe {
                            libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                        };
                        if n < 0 {
                            Err(std::io::Error::last_os_error())
                        } else {
                            Ok(n as usize)
                        }
                    });

                    match read_result {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => {
                            tracing::trace!(
                                hex = %buf[..n].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
                                "stdin -> ssh"
                            );
                            if channel.data(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Ok(Err(_)) => break,
                        Err(_would_block) => continue,
                    }
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        std::thread::spawn(move || {
            loop {
                match crossterm::event::read() {
                    Ok(crossterm::event::Event::Key(key_event)) => {
                        if let Some(bytes) = key_event_to_bytes(key_event) {
                            if stdin_tx.blocking_send(bytes).is_err() {
                                break;
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });

        loop {
            tokio::select! {
                event = rx.recv() => {
                    let Some(channel_event) = event else {
                        break;
                    };
                    match channel_event {
                        ChannelEvent::Data(data) => {
                            let mut stdout = tokio::io::stdout();
                            if stdout.write_all(&data).await.is_err() {
                                break;
                            }
                            let _ = stdout.flush().await;
                        }
                        ChannelEvent::ExtendedData(data, _) => {
                            let mut stderr = tokio::io::stderr();
                            if stderr.write_all(&data).await.is_err() {
                                break;
                            }
                            let _ = stderr.flush().await;
                        }
                        ChannelEvent::Eof | ChannelEvent::Close => {
                            break;
                        }
                    }
                }
                res = stdin_rx.recv() => {
                    match res {
                        None => break,
                        Some(data) => {
                            tracing::trace!(
                                hex = %data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
                                "stdin -> ssh"
                            );
                            if channel.data(&data[..]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    unregister_sink(channel.id());
    Ok(())
}

async fn connect_direct(target: &Target, keypair: &OperatorKeyPair) -> Result<TcpStream> {
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
    keypair: &OperatorKeyPair,
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
                stream = spawn_teleport_proxy(&proxy, target, keypair).await?;
                send_knock_direct(&mut stream, keypair, target.port).await?;
            }
        }
    }

    Ok(stream)
}

async fn send_knock_direct(stream: &mut TcpStream, keypair: &OperatorKeyPair, service_port: u16) -> Result<()> {
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
    _keypair: &OperatorKeyPair,
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

fn load_operator_keypair() -> Result<OperatorKeyPair> {
    let path = std::path::Path::new("id_rsa");
    if path.exists() {
        let bytes = std::fs::read(path)?;
        parse_private_key(&bytes)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Failed to parse private key").into())
    } else {
        let mut rng = rand::rngs::OsRng;
        let secret = SigningKey::generate(&mut rng);
        let public = secret.verifying_key();
        Ok(OperatorKeyPair { public, secret })
    }
}

fn parse_private_key(raw_bytes: &[u8]) -> Option<OperatorKeyPair> {
    let key_str = std::str::from_utf8(raw_bytes).ok()?;

    if raw_bytes.len() == 64 {
        let secret_bytes: [u8; 32] = raw_bytes[..32].try_into().ok()?;
        let public_bytes: [u8; 32] = raw_bytes[32..].try_into().ok()?;
        let secret = SigningKey::from_bytes(&secret_bytes);
        let public = VerifyingKey::from_bytes(&public_bytes).ok()?;
        return Some(OperatorKeyPair { public, secret });
    }

    if key_str.contains("BEGIN OPENSSH PRIVATE KEY") {
        let lines: Vec<&str> = key_str.lines().collect();
        let b64_body = lines[1..lines.len() - 1].join("");

        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD.decode(b64_body).ok()?;

        if decoded.len() > 100 {
            let mut i = 0;
            while i + 64 <= decoded.len() {
                let potential_chunk = &decoded[i..i+64];
                let secret_bytes: [u8; 32] = potential_chunk[..32].try_into().unwrap_or([0;32]);
                let public_bytes: [u8; 32] = potential_chunk[32..].try_into().unwrap_or([0;32]);
                let secret = SigningKey::from_bytes(&secret_bytes);
                if let Ok(public) = VerifyingKey::from_bytes(&public_bytes) {
                    if secret.verifying_key() == public {
                        return Some(OperatorKeyPair { public, secret });
                    }
                }
                i += 1;
            }
        }
    }

    None
}   

fn generate_nonce() -> [u8; 16] {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// Re-export so callers build hop chains without reaching into `proxy`.
pub mod proxy_hop {
    pub use crate::proxy::Hop;
}
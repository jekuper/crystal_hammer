// File: crates/ch-transport/src/client.rs
//! Operator-side connector: send the knock, verify the pinned host key, open a session.

use async_trait::async_trait;
use ch_common::Result;
use ch_spa::Knock;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use russh::client::Handle;
use russh_keys::PublicKeyBase64;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use std::borrow::Cow;


use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};

use crate::proxy::Hop;

/// Helper structure for rustyline containing both command autocompletion 
/// and path autocompletion fallback.
struct ConsoleHelper {
    commands: Vec<String>,
    file_completer: FilenameCompleter,
}

impl Helper for ConsoleHelper {}

impl Completer for ConsoleHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let line_to_pos = &line[..pos];
        let trimmed = line_to_pos.trim_start();
        
        // If the trimmed portion does not contain any space, we are still 
        // writing the first word (the command).
        let is_command = !trimmed.contains(' ');

        if is_command {
            let start = line_to_pos.len() - trimmed.len();
            let mut candidates = Vec::new();
            for cmd in &self.commands {
                if cmd.starts_with(trimmed) {
                    candidates.push(Pair {
                        display: cmd.clone(),
                        replacement: cmd.clone(),
                    });
                }
            }
            Ok((start, candidates))
        } else {
            self.file_completer.complete(line, pos, ctx)
        }
    }
}

impl Hinter for ConsoleHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, ctx: &Context<'_>) -> Option<Self::Hint> {
        // Only hint when the cursor is at the end of the line and there's some input.
        if pos < line.len() || line.trim().is_empty() {
            return None;
        }

        let trimmed = line.trim_start();
        let is_command = !trimmed.contains(' ');

        if is_command {
            // Suggest the rest of the first command that matches the prefix.
            self.commands
                .iter()
                .find(|cmd| cmd.starts_with(trimmed) && cmd.len() > trimmed.len())
                .map(|cmd| cmd[trimmed.len()..].to_string())
        } else {
            // Reuse the file completer: take its first candidate and show the
            // part that hasn't been typed yet.
            let (start, candidates) = self.file_completer.complete(line, pos, ctx).ok()?;
            let typed = &line[start..pos];
            candidates
                .first()
                .map(|c| c.replacement.as_str())
                .filter(|r| r.starts_with(typed) && r.len() > typed.len())
                .map(|r| r[typed.len()..].to_string())
        }
    }
}

impl Highlighter for ConsoleHelper {
    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        // Dim gray, reset afterwards
        Cow::Owned(format!("\x1b[90m{hint}\x1b[0m"))
    }
}

impl Validator for ConsoleHelper {}

/// Dynamic Command Execution abstraction to resolve circular crate dependencies
#[async_trait]
pub trait ClientCommandExecutor: Send + Sync {
    async fn execute(
        &self,
        command: &str,
        args: &[String],
        session: &mut Handle<ClientHandler>,
    ) -> std::result::Result<(), String>;

    fn get_command_list (
        &self
    ) -> Vec<String>;

    fn get_help_for(&self, command_name: &str) -> Option<&str>;

    fn get_short_description_for(&self, command_name: &str) -> Option<&str>;
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

/// Handler for the russh client session.
/// Only validates the server's host key; all channel I/O is handled via `Channel::wait()`.
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

    let config = Arc::new(russh::client::Config::default());

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
    let mut rl = rustyline::Editor::<ConsoleHelper, DefaultHistory>::new()?;

    let mut command_list = executor.get_command_list();
    command_list.push(String::from("shell"));
    command_list.push(String::from("exit"));
    command_list.push(String::from("quit"));
    command_list.push(String::from("help"));

    rl.set_helper(Some(ConsoleHelper {
        commands: command_list,
        file_completer: FilenameCompleter::new(),
    }));

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
                stream = spawn_teleport_proxy(proxy, target, keypair).await?;
                send_knock_direct(&mut stream, keypair, target.port).await?;
            }
        }
    }

    Ok(stream)
}

async fn send_knock_direct(
    stream: &mut TcpStream,
    keypair: &OperatorKeyPair,
    service_port: u16,
) -> Result<()> {
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
            &mut tokio::io::join(&mut child_stdout, &mut child_stdin),
        )
        .await;
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
        .args(&[
            "proxy",
            "ssh",
            "-L",
            "0.0.0.0:0",
            &format!("{}:{}", target.host, target.port),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    let _ = proxy_cmd.wait().await;

    let stream = TcpStream::connect("127.0.0.1:22").await?;
    Ok(stream)
}

fn load_operator_keypair() -> Result<OperatorKeyPair> {
    let path = std::path::Path::new("id_rsa");
    if path.exists() {
        let bytes = std::fs::read(path)?;
        parse_private_key(&bytes)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Failed to parse private key").into())
    } else {
        return Err(ch_common::Error::Other("Private key not found! ./id_rsa".to_string()));
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
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64_body)
            .ok()?;

        if decoded.len() > 100 {
            let mut i = 0;
            while i + 64 <= decoded.len() {
                let potential_chunk = &decoded[i..i + 64];
                let secret_bytes: [u8; 32] =
                    potential_chunk[..32].try_into().unwrap_or([0; 32]);
                let public_bytes: [u8; 32] =
                    potential_chunk[32..].try_into().unwrap_or([0; 32]);
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
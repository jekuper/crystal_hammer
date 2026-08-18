// File: crates/ch-transport/src/server.rs
//! Agent-side listener: holds the port dark, validates knocks, and spawns sessions.

use async_trait::async_trait;
use ch_common::Result;
use ch_spa::{Knock, NonceCache};
use ed25519_dalek::{Signature, VerifyingKey};
use russh::ChannelMsg;
use russh_keys::PublicKeyBase64;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

#[cfg(unix)]
type RawFd = std::os::fd::RawFd;

#[cfg(unix)]
fn set_winsize(fd: RawFd, cols: u32, rows: u32) {
    let size = libc::winsize {
        ws_row: rows as u16,
        ws_col: cols as u16,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        libc::ioctl(fd, libc::TIOCSWINSZ, &size);
    }
}

/// Dynamic Agent Execution Interface
#[async_trait]
pub trait CommandExecutor: Send + Sync + 'static {
    async fn execute(
        &self,
        command: String,
        args: Vec<String>,
        stdout: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
        stderr: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    ) -> std::result::Result<(), String>;
}

/// Run the SPA-gated server indefinitely.
pub async fn serve(port: u16, key: &VerifyingKey, executor: Arc<dyn CommandExecutor>) -> Result<()> {
    tracing::info!("Starting persistent SPA-gated listener on port {}", port);
    let nonce_cache = NonceCache::default();

    tokio::try_join!(accept_tcp(key.clone(), nonce_cache, port, executor))?;

    Ok(())
}

async fn accept_tcp(
    key: VerifyingKey,
    cache: NonceCache,
    port: u16,
    executor: Arc<dyn CommandExecutor>,
) -> Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!("Listening on TCP port {} for knocks", port);

    loop {
        let (mut stream, src) = listener.accept().await?;
        let key_clone = key.clone();
        let cache_clone = cache.clone();
        let executor_clone = executor.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 94];
            if let Err(e) = stream.read_exact(&mut buf).await {
                tracing::debug!("Aborted or quiet connection from {}: {:?}", src, e);
                return;
            }

            if let Some(knock) = Knock::from_bytes(&buf) {
                let mut sig_bytes = [0u8; 64];
                sig_bytes.copy_from_slice(&buf[30..94]);

                if let Ok(signature) = Signature::try_from(&sig_bytes[..]) {
                    let verdict = ch_spa::validate(
                        &knock,
                        &signature,
                        &key_clone,
                        &cache_clone,
                        current_timestamp(),
                    )
                    .await;

                    match verdict {
                        ch_spa::Verdict::Open => {
                            tracing::info!(
                                "Valid TCP knock from {}, transitioning to SSH session",
                                src
                            );
                            if let Err(e) =
                                handle_ssh_session(stream, key_clone, executor_clone).await
                            {
                                tracing::error!("SSH session error for {}: {:?}", src, e);
                            }
                        }
                        other => {
                            tracing::warn!("Rejected TCP knock from {}: {:?}", src, other);
                        }
                    }
                } else {
                    tracing::warn!("Failed to parse signature from knock from {}", src);
                }
            } else {
                tracing::warn!("Failed to parse knock headers from {}", src);
            }
        });
    }
}

/// Handler for active agent SSH sessions.
/// Auth is verified here; all channel logic is driven by `drive_channel`.
struct AgentServerHandler {
    team_public_key: VerifyingKey,
    executor: Arc<dyn CommandExecutor>,
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
            return Ok(russh::server::Auth::Reject {
                proceed_with_methods: None,
            });
        }

        let raw_bytes = public_key.public_key_bytes();
        let expected_bytes = self.team_public_key.to_bytes();

        if raw_bytes.ends_with(&expected_bytes) {
            Ok(russh::server::Auth::Accept)
        } else {
            Ok(russh::server::Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        session: &mut russh::server::Session,
    ) -> std::result::Result<bool, Self::Error> {
        let executor = self.executor.clone();
        let handle = session.handle();
        tokio::spawn(async move {
            if let Err(e) = drive_channel(channel, handle, executor).await {
                tracing::error!("Channel session error: {:?}", e);
            }
        });
        Ok(true)
    }
}

/// Drives a single SSH channel through its full lifecycle.
///
/// Negotiates pty/shell/exec via `Channel::wait()` so no handler callbacks are needed.
/// PTY terminal size, type, and all client requests arrive as `ChannelMsg` variants.
async fn drive_channel(
    mut channel: russh::Channel<russh::server::Msg>,
    handle: russh::server::Handle,
    executor: Arc<dyn CommandExecutor>,
) -> anyhow::Result<()> {
    let mut term = "xterm".to_string();
    let mut cols = 80u32;
    let mut rows = 24u32;

    loop {
        match channel.wait().await {
            None => return Ok(()),

            Some(ChannelMsg::RequestPty {
                want_reply,
                term: t,
                col_width,
                row_height,
                ..
            }) => {
                term = t;
                cols = col_width;
                rows = row_height;
                if want_reply {
                    let _ = handle.channel_success(channel.id()).await;
                }
            }

            Some(ChannelMsg::RequestShell { want_reply }) => {
                if want_reply {
                    let _ = handle.channel_success(channel.id()).await;
                }
                return run_shell(channel, handle, term, cols, rows).await;
            }

            Some(ChannelMsg::Exec { command, want_reply }) => {
                let Ok(cmd_str) = std::str::from_utf8(&command) else {
                    if want_reply {
                        let _ = handle.channel_failure(channel.id()).await;
                    }
                    return Ok(());
                };

                let parts: Vec<String> = cmd_str
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();

                if parts.is_empty() {
                    if want_reply {
                        let _ = handle.channel_failure(channel.id()).await;
                    }
                    return Ok(());
                }

                if want_reply {
                    let _ = handle.channel_success(channel.id()).await;
                }
                return run_exec(channel, handle, executor, parts).await;
            }

            Some(ChannelMsg::Close) => return Ok(()),
            _ => {}
        }
    }
}

/// Spawns a PTY-backed shell and bridges it to the SSH channel.
///
/// Reads client data and window-change events via `channel.wait()`.
/// Writes PTY output back via `handle.data()` from a separate task.
async fn run_shell(
    mut channel: russh::Channel<russh::server::Msg>,
    handle: russh::server::Handle,
    term: String,
    cols: u32,
    rows: u32,
) -> anyhow::Result<()> {
    let channel_id = channel.id();

    #[cfg(unix)]
    {
        use nix::pty::openpty;
        use std::os::fd::IntoRawFd;
        use std::os::unix::io::FromRawFd;

        let shell_path = if std::path::Path::new("/bin/bash").exists() {
            "/bin/bash"
        } else {
            "/bin/sh"
        };

        let pty = openpty(None, None)?;
        let master_fd = pty.master.into_raw_fd();
        let slave_fd = pty.slave.into_raw_fd();

        set_winsize(master_fd, cols, rows);

        let mut cmd = tokio::process::Command::new(shell_path);
        cmd.env("TERM", &term);

        unsafe {
            cmd.pre_exec(move || {
                let _ = nix::unistd::setsid();
                #[cfg(target_os = "linux")]
                {
                    libc::ioctl(slave_fd, libc::TIOCSCTTY, 0);
                }
                nix::unistd::dup2(slave_fd, 0)?;
                nix::unistd::dup2(slave_fd, 1)?;
                nix::unistd::dup2(slave_fd, 2)?;
                let _ = nix::unistd::close(master_fd);
                let _ = nix::unistd::close(slave_fd);
                Ok(())
            });
        }

        let mut child = cmd.spawn()?;
        let _ = nix::unistd::close(slave_fd);

        let master_file = unsafe { std::fs::File::from_raw_fd(master_fd) };
        let async_master = tokio::fs::File::from_std(master_file);
        let mut async_master_read = async_master.try_clone().await?;
        let mut async_master_write = async_master;

        // PTY output → SSH channel (independent task; uses handle, not channel)
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match async_master_read.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if handle
                            .data(channel_id, russh::CryptoVec::from_slice(&buf[..n]))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            let _ = handle.close(channel_id).await;
            let _ = child.kill().await;
        });

        // SSH channel → PTY input + window resize (driven by channel.wait())
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { ref data }) => {
                    if async_master_write.write_all(data).await.is_err() {
                        break;
                    }
                    let _ = async_master_write.flush().await;
                }
                Some(ChannelMsg::WindowChange {
                    col_width,
                    row_height,
                    ..
                }) => {
                    set_winsize(master_fd, col_width, row_height);
                }
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                _ => {}
            }
        }
    }

    #[cfg(not(unix))]
    {
        tracing::warn!("Allocating standard piped shell fallback on non-Unix platform");

        let mut cmd = tokio::process::Command::new("cmd.exe");
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn()?;
        let mut stdin = child.stdin.take().expect("Failed to open stdin");
        let mut stdout = child.stdout.take().expect("Failed to open stdout");
        let mut stderr = child.stderr.take().expect("Failed to open stderr");

        // Process stdout/stderr → SSH channel
        tokio::spawn(async move {
            let mut stdout_buf = [0u8; 1024];
            let mut stderr_buf = [0u8; 1024];
            loop {
                tokio::select! {
                    res = stdout.read(&mut stdout_buf) => match res {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if handle.data(channel_id, russh::CryptoVec::from_slice(&stdout_buf[..n])).await.is_err() {
                                break;
                            }
                        }
                    },
                    res = stderr.read(&mut stderr_buf) => match res {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if handle.extended_data(channel_id, 1, russh::CryptoVec::from_slice(&stderr_buf[..n])).await.is_err() {
                                break;
                            }
                        }
                    },
                }
            }
            let _ = handle.close(channel_id).await;
        });

        // SSH channel → process stdin
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { ref data }) => {
                    if stdin.write_all(data).await.is_err() {
                        break;
                    }
                }
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                _ => {}
            }
        }
    }

    Ok(())
}

/// Runs an exec command, forwarding stdout/stderr back to the SSH channel.
///
/// The executor has no stdin, so `channel` is kept alive in the spawned task
/// and dropped cleanly after `handle.close()`.
async fn run_exec(
    channel: russh::Channel<russh::server::Msg>,
    handle: russh::server::Handle,
    executor: Arc<dyn CommandExecutor>,
    parts: Vec<String>,
) -> anyhow::Result<()> {
    let channel_id = channel.id();
    let command = parts[0].clone();
    let args = parts[1..].to_vec();

    let (stdout_tx, mut stdout_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (stderr_tx, mut stderr_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let handle_stdout = handle.clone();
    let handle_stderr = handle.clone();

    let stdout_forwarder = tokio::spawn(async move {
        while let Some(chunk) = stdout_rx.recv().await {
            let _ = handle_stdout
                .data(channel_id, russh::CryptoVec::from_slice(&chunk))
                .await;
        }
    });

    let stderr_forwarder = tokio::spawn(async move {
        while let Some(chunk) = stderr_rx.recv().await {
            let _ = handle_stderr
                .extended_data(channel_id, 1, russh::CryptoVec::from_slice(&chunk))
                .await;
        }
    });

    let stdout = Box::new(ChannelTx { tx: stdout_tx });
    let stderr = Box::new(ChannelTx { tx: stderr_tx });

    tokio::spawn(async move {
        let res = executor.execute(command, args, stdout, stderr).await;
        if let Err(e) = res {
            tracing::error!("Command execution failed: {}", e);
        }
        let _ = stdout_forwarder.await;
        let _ = stderr_forwarder.await;
        let _ = handle.close(channel_id).await;
        drop(channel); // keep alive until close is confirmed
    });

    Ok(())
}

/// Async-write wrapper that forwards bytes into an unbounded mpsc sender.
#[derive(Clone)]
struct ChannelTx {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl tokio::io::AsyncWrite for ChannelTx {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.tx.send(buf.to_vec()).is_err() {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Channel closed",
            )));
        }
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

async fn handle_ssh_session(
    stream: TcpStream,
    team_public_key: VerifyingKey,
    executor: Arc<dyn CommandExecutor>,
) -> Result<()> {
    let mut config = russh::server::Config {
        ..Default::default()
    };

    let mut rng = rand::rngs::OsRng;
    let host_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let key_pair = russh_keys::key::KeyPair::Ed25519(host_key);
    config.keys.push(key_pair);

    let handler = AgentServerHandler {
        team_public_key,
        executor,
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
//! Agent-side listener: holds the port dark, validates knocks, and spawns sessions.

use async_trait::async_trait;
use ch_common::Result;
use ch_spa::{Knock, NonceCache};
use ed25519_dalek::{Signature, VerifyingKey};
use russh_keys::PublicKeyBase64;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

#[cfg(unix)]
type RawFd = std::os::fd::RawFd;
#[cfg(not(unix))]
type RawFd = i32;

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

/// Run the SPA-gated server indefinitely.
pub async fn serve(port: u16, key: &VerifyingKey) -> Result<()> {
    tracing::info!("Starting persistent SPA-gated listener on port {}", port);
    
    let nonce_cache = NonceCache::default();
    
    tokio::try_join!(
        accept_tcp(key.clone(), nonce_cache, port)
    )?;

    Ok(())
}

async fn accept_tcp(
    key: VerifyingKey,
    cache: NonceCache,
    port: u16,
) -> Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!("Listening on TCP port {} for knocks", port);
    
    loop {
        let (mut stream, src) = listener.accept().await?;
        let key_clone = key.clone();
        let cache_clone = cache.clone();

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
                        current_timestamp()
                    ).await;

                    match verdict {
                        ch_spa::Verdict::Open => {
                            tracing::info!("Valid TCP knock from {}, transitioning to SSH session", src);
                            if let Err(e) = handle_ssh_session(stream, key_clone).await {
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

/// Handler representing active agent SSH sessions.
struct AgentServerHandler {
    team_public_key: VerifyingKey,
    channels: Arc<Mutex<HashMap<russh::ChannelId, mpsc::UnboundedSender<Vec<u8>>>>>,
    terminal_size: Arc<Mutex<HashMap<russh::ChannelId, (u32, u32)>>>,
    pty_masters: Arc<Mutex<HashMap<russh::ChannelId, RawFd>>>,
    terminal_types: Arc<Mutex<HashMap<russh::ChannelId, String>>>, 
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
        channel: russh::ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        _session: &mut russh::server::Session,
    ) -> std::result::Result<(), Self::Error> {
        self.terminal_size.lock().unwrap().insert(channel, (col_width, row_height));
        self.terminal_types.lock().unwrap().insert(channel, term.to_string());
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: russh::ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut russh::server::Session,
    ) -> std::result::Result<(), Self::Error> {
        self.terminal_size.lock().unwrap().insert(channel, (col_width, row_height));
        #[cfg(unix)]
        {
            if let Some(&master_fd) = self.pty_masters.lock().unwrap().get(&channel) {
                set_winsize(master_fd, col_width, row_height);
            }
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        _session: &mut russh::server::Session,
    ) -> std::result::Result<(), Self::Error> {
        tracing::trace!(
            channel = ?channel,
            bytes = ?data,
            hex = %data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
            "ssh -> pty"
        );
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
        #[cfg(unix)]
        {
            use nix::pty::openpty;
            use std::os::fd::IntoRawFd;
            use std::os::unix::io::FromRawFd;
            use std::os::unix::process::CommandExt;
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let shell_path = if std::path::Path::new("/bin/bash").exists() {
                "/bin/bash"
            } else {
                "/bin/sh"
            };

            // Allocate master/slave PTY pair
            let pty = openpty(None, None)?;
            let master_fd = pty.master.into_raw_fd();
            let slave_fd = pty.slave.into_raw_fd();

            // Set initial terminal size if requested by the client
            if let Some(&(cols, rows)) = self.terminal_size.lock().unwrap().get(&channel) {
                set_winsize(master_fd, cols, rows);
            }

            // Keep track of master_fd for future window resizing requests
            self.pty_masters.lock().unwrap().insert(channel, master_fd);

            let mut cmd = tokio::process::Command::new(shell_path);

            let term = self.terminal_types.lock().unwrap()
                .get(&channel)
                .cloned()
                .unwrap_or_else(|| "xterm".to_string());

            let mut cmd = tokio::process::Command::new(shell_path);
            cmd.env("TERM", term); 

            // Execute low-level PTY linkage before spawning child
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
            let mut async_master = tokio::fs::File::from_std(master_file);

            let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
            self.channels.lock().unwrap().insert(channel, tx);

            // Pipe SSH channel data to PTY stdin
            let mut master_write = async_master.try_clone().await?;
            tokio::spawn(async move {
                while let Some(data) = rx.recv().await {
                    tracing::info!(
                        hex = %data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
                        "writing to pty master"
                    );
                    if master_write.write_all(&data).await.is_err() {
                        break;
                    }
                    let _ = master_write.flush().await;
                }
            });

            // Pipe PTY stdout/stderr back to SSH channel
            let handle = session.handle();
            let pty_masters_clone = self.pty_masters.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match async_master.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            tracing::trace!(
                                hex = %buf[..n].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
                                "reading from pty master"
                            );
                            let _ = handle.data(channel, russh::CryptoVec::from_slice(&buf[..n])).await;
                        }
                    }
                }
                let _ = handle.close(channel).await;
                let _ = child.kill().await;
                pty_masters_clone.lock().unwrap().remove(&channel);
            });

            Ok(())
        }

        #[cfg(not(unix))]
        {
            // Non-Unix compilation fallback (uses raw pipes)
            tracing::warn!("Allocating standard piped shell fallback on non-Unix platform");
            let mut cmd = tokio::process::Command::new("cmd.exe");
            cmd.stdin(std::process::Stdio::piped())
               .stdout(std::process::Stdio::piped())
               .stderr(std::process::Stdio::piped());

            let mut child = cmd.spawn()?;
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
                use tokio::io::AsyncReadExt;
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
}

/// Upgrades the raw TCP stream directly into standard SSH protocol loop.
async fn handle_ssh_session(stream: TcpStream, team_public_key: VerifyingKey) -> Result<()> {
    let mut config = russh::server::Config {
        ..Default::default()
    };
    
    // Generate a unique host key at runtime.
    let mut rng = rand::rngs::OsRng;
    let host_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let key_pair = russh_keys::key::KeyPair::Ed25519(host_key);
    config.keys.push(key_pair);

    let handler = AgentServerHandler {
        team_public_key,
        channels: Arc::new(Mutex::new(HashMap::new())),
        terminal_size: Arc::new(Mutex::new(HashMap::new())),
        pty_masters: Arc::new(Mutex::new(HashMap::new())),
        terminal_types: Arc::new(Mutex::new(HashMap::new())),
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
use async_trait::async_trait;
use ch_common::Result;
use ch_transport::{ClientCommandExecutor, client::ClientHandler};
use russh::client::Handle;
use russh::ChannelMsg;
use tokio::io::AsyncWriteExt;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use tokio::io::unix::AsyncFd;

use crate::model::{ClientCommand, ClientContext};


pub struct ShellClientCommand {}

impl ShellClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for ShellClientCommand {
    fn name(&self) -> &'static str { "shell" }
    fn short_description(&self) -> &'static str { "spins up a shell" }
    fn help(&self) -> &'static str { 
        "Usage: shell\n\n\
        Opens a direct interactive shell, ssh like
        "
    }

    async fn execute(&self, _executor: &dyn ClientCommandExecutor, _args: &[String], mut ctx: ClientContext<'_>) -> Result<()> {
        println!("Spawning interactive shell. Type 'exit' to return to console.");
        if let Err(e) = run_interactive_shell(&mut ctx.session).await {
            eprintln!("Shell session error: {:?}", e);
        }

        Ok(())
    }
}


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

/// Runs an interactive PTY shell over SSH.
///
/// Reads from the channel directly via `channel.wait()` — no global sink or
/// handler callbacks involved. Each `ChannelMsg::Data` is written to stdout;
/// `Eof`/`Close`/`None` terminates the loop.
async fn run_interactive_shell(session: &mut Handle<ClientHandler>) -> anyhow::Result<()> {
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
                msg = channel.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { ref data }) => {
                            let mut stdout = tokio::io::stdout();
                            if stdout.write_all(data).await.is_err() { break; }
                            let _ = stdout.flush().await;
                        }
                        Some(ChannelMsg::ExtendedData { ref data, .. }) => {
                            let mut stderr = tokio::io::stderr();
                            if stderr.write_all(data).await.is_err() { break; }
                            let _ = stderr.flush().await;
                        }
                        Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                        _ => {}
                    }
                }

                Some(_) = async {
                    if let Some(ref mut sig) = sigwinch { sig.recv().await }
                    else { std::future::pending().await }
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
                            if channel.data(&buf[..n]).await.is_err() { break; }
                        }
                        Ok(Err(_)) => break,
                        Err(_would_block) => continue,
                    }
                }
            }
        }
    }

    Ok(())
}
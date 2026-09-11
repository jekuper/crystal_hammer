// File: crates/ch-commands/src/download_command.rs
use async_trait::async_trait;
use ch_common::Result;
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncSeekExt};

use crate::model::{AgentCommand, ClientCommand, ClientCommandContext, AgentCommandContext};

// =========================================================================
// AGENT-SIDE COMMAND
// =========================================================================

pub struct DownloadAgentCommand {}

impl DownloadAgentCommand {
    pub fn new() -> Self {
        Self {}
    }

    fn expand_tilde(path: &str) -> String {
        if path == "~" {
            if let Some(home) = std::env::var("HOME").ok().filter(|h| !h.is_empty()) {
                return home;
            }
        } else if let Some(rest) = path.strip_prefix("~/") {
            if let Some(home) = std::env::var("HOME").ok().filter(|h| !h.is_empty()) {
                return format!("{}/{}", home.trim_end_matches('/'), rest);
            }
        }
        path.to_string()
    }
}

#[async_trait]
impl AgentCommand for DownloadAgentCommand {
    fn name(&self) -> &'static str {
        "download"
    }

    async fn execute(&self, args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        if args.is_empty() {
            let _ = ctx.stdout.write_all(b"Error: Missing remote path\n").await;
            return Ok(());
        }

        let remote_path = Self::expand_tilde(&args[0]);

        let mut file = match File::open(&remote_path).await {
            Ok(f) => f,
            Err(e) => {
                let err_msg = format!("Error: Failed to open file '{}': {}\n", remote_path, e);
                let _ = ctx.stdout.write_all(err_msg.as_bytes()).await;
                return Ok(());
            }
        };

        // Phase 1: Compute hash and get file size
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 16384];
        let mut filesize = 0u64;

        loop {
            match file.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    hasher.update(&buffer[..n]);
                    filesize += n as u64;
                }
                Err(e) => {
                    let err_msg = format!("Error: Failed reading file '{}' for hashing: {}\n", remote_path, e);
                    let _ = ctx.stdout.write_all(err_msg.as_bytes()).await;
                    return Ok(());
                }
            }
        }

        let hash = hex::encode(hasher.finalize());

        // Phase 2: Send header
        let header = format!("READY {} {}\n", hash, filesize);
        if let Err(e) = ctx.stdout.write_all(header.as_bytes()).await {
            return Err(ch_common::Error::Other(format!("Failed to send header: {}", e)));
        }

        // Rewind file to start
        if let Err(e) = file.seek(std::io::SeekFrom::Start(0)).await {
            let err_msg = format!("Error: Failed to rewind file: {}\n", e);
            let _ = ctx.stdout.write_all(err_msg.as_bytes()).await;
            return Ok(());
        }

        // Phase 3: Send file data
        loop {
            match file.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(_) = ctx.stdout.write_all(&buffer[..n]).await {
                        // Connection lost
                        return Ok(());
                    }
                }
                Err(e) => {
                    let err_msg = format!("Error: Failed reading file during transmission: {}\n", e);
                    let _ = ctx.stderr.write_all(err_msg.as_bytes()).await;
                    return Ok(());
                }
            }
        }

        let _ = ctx.stdout.flush().await;
        Ok(())
    }
}

// =========================================================================
// CLIENT-SIDE COMMAND
// =========================================================================

pub struct DownloadClientCommand {}

impl DownloadClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for DownloadClientCommand {
    fn name(&self) -> &'static str {
        "download"
    }

    fn short_description(&self) -> &'static str {
        "Download a file from the agent with SHA-256 hash verification"
    }

    fn help(&self) -> &'static str {
        "Usage: download <remote_path> <local_path>\n\n\
        Arguments:\n\
          remote_path   The path of the file to download from the remote system\n\
          local_path    The destination path on the local system. If it names a directory,\n\
                        the remote file name is appended."
    }

    fn complete_arg(&self, preceding_args: &[&str], word: &str, ctx: &rustyline::Context<'_>, filename_completer: &FilenameCompleter) -> Vec<Pair> {
        if preceding_args.len() == 1 {
            match filename_completer.complete(word, word.len(), ctx) {
                Ok((_pos, pairs)) => pairs,
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        }
    }

    async fn execute(&self, _executor: &dyn ClientCommandExecutor, args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
        if args.len() < 2 {
            eprintln!("{}", self.help());
            return Ok(());
        }

        let remote_path = &args[0];
        let raw_local_path = &args[1];

        // Process local path
        let mut local_path = std::path::PathBuf::from(raw_local_path);
        if local_path.is_dir() {
            let remote_file_name = std::path::Path::new(remote_path)
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("downloaded_file"));
            local_path.push(remote_file_name);
        }

        let mut local_file = match File::create(&local_path).await {
            Ok(f) => f,
            Err(e) => return Err(ch_common::Error::Other(format!("Failed to create local file: {}", e))),
        };

        let session = ctx.session;
        let mut channel = session.channel_open_session().await
            .map_err(|e| ch_common::Error::Other(e.to_string()))?;

        let server_command = DownloadAgentCommand::new();
        let exec_payload = format!("{} {}", server_command.name(), remote_path);

        channel.exec(true, exec_payload.as_bytes()).await
            .map_err(|e| ch_common::Error::Other(e.to_string()))?;

        let mut header_received = false;
        let mut expected_hash = String::new();
        let mut expected_size = 0u64;
        let mut received_size = 0u64;
        let mut buffer = Vec::new();
        let mut hasher = Sha256::new();

        println!("[Client] Requesting download of {}...", remote_path);

        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => {
                    let data_slice = data.as_ref();
                    if !header_received {
                        buffer.extend_from_slice(data_slice);
                        if let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                            let header_str = String::from_utf8_lossy(&buffer[..pos]);
                            if header_str.starts_with("READY ") {
                                let parts: Vec<&str> = header_str.split_whitespace().collect();
                                if parts.len() >= 3 {
                                    expected_hash = parts[1].to_string();
                                    expected_size = parts[2].parse().unwrap_or(0);
                                    header_received = true;
                                    println!("[Client] File size: {} bytes. Receiving...", expected_size);
                                }
                            } else if header_str.starts_with("Error:") {
                                eprintln!("{}", header_str);
                                return Ok(());
                            } else {
                                print!("{}", header_str);
                            }

                            if header_received {
                                let remaining = &buffer[pos + 1..];
                                if !remaining.is_empty() {
                                    local_file.write_all(remaining).await
                                        .map_err(|e| ch_common::Error::Other(format!("Write error: {}", e)))?;
                                    hasher.update(remaining);
                                    received_size += remaining.len() as u64;
                                }
                            }
                        }
                    } else {
                        local_file.write_all(data_slice).await
                            .map_err(|e| ch_common::Error::Other(format!("Write error: {}", e)))?;
                        hasher.update(data_slice);
                        received_size += data_slice.len() as u64;
                    }
                }
                russh::ChannelMsg::ExtendedData { ref data, .. } => {
                    eprint!("{}", String::from_utf8_lossy(data));
                }
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    if exit_status != 0 {
                        tracing::warn!("Remote download command exited with status {}", exit_status);
                    }
                }
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }

        if header_received {
            let actual_hash = hex::encode(hasher.finalize());
            if actual_hash == expected_hash && received_size == expected_size {
                println!("Download successful\nPath: {}\nBytes received: {}\nSHA-256 verified: {}", local_path.display(), received_size, actual_hash);
            } else {
                eprintln!("Error: Hash or size verification failed!\nExpected Hash: {}\nActual Hash:   {}\nExpected Size: {}\nActual Size:   {}\n", 
                          expected_hash, actual_hash, expected_size, received_size);
                let _ = tokio::fs::remove_file(&local_path).await;
            }
        } else {
            let output = String::from_utf8_lossy(&buffer);
            if !output.is_empty() {
                print!("{}", output);
            }
        }

        Ok(())
    }
}
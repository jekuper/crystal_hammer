use async_trait::async_trait;
use ch_common::Result;
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::model::{AgentCommand, ClientCommand, ClientContext, Context};

// =========================================================================
// AGENT-SIDE COMMAND (UploadAgentCommand)
// =========================================================================

pub struct UploadAgentCommand {}

impl UploadAgentCommand {
    pub fn new() -> Self {
        Self {}
    }

    /// Return the remote user's home directory, if known.
    fn home_dir() -> Option<String> {
        std::env::var("HOME").ok().filter(|h| !h.is_empty())
    }

    /// Expand a leading `~` (either bare `~` or a `~/...` prefix) to the
    /// remote home directory. Anything else is returned unchanged. A `~` that
    /// appears anywhere other than the start is intentionally left alone.
    fn expand_tilde(path: &str) -> String {
        if path == "~" {
            if let Some(home) = Self::home_dir() {
                return home;
            }
        } else if let Some(rest) = path.strip_prefix("~/") {
            if let Some(home) = Self::home_dir() {
                return format!("{}/{}", home.trim_end_matches('/'), rest);
            }
        }
        path.to_string()
    }

    /// Resolve the final destination path.
    ///
    /// - Expands a leading `~` to the remote home directory.
    /// - If the (expanded) destination names a directory — either because it
    ///   ends with `/` or because it already exists as a directory (e.g. a
    ///   bare `~`) — the client-supplied file name is appended.
    /// - Otherwise the path is treated as a concrete file path.
    async fn resolve_dest_path(
        raw: &str,
        client_file_name: Option<&str>,
    ) -> std::result::Result<String, String> {
        let expanded = Self::expand_tilde(raw);

        let ends_with_slash = expanded.ends_with('/');
        let is_existing_dir = tokio::fs::metadata(&expanded)
            .await
            .map(|m| m.is_dir())
            .unwrap_or(false);

        if !ends_with_slash && !is_existing_dir {
            // A concrete file path was provided.
            return Ok(expanded);
        }

        // Destination is a directory, so we need a file name from the client.
        let name = match client_file_name {
            Some(n) if !n.is_empty() => n,
            _ => {
                return Err(format!(
                    "Error: Destination '{}' is a directory but no file name was provided\n",
                    expanded
                ));
            }
        };

        // Only ever use the base name to avoid path traversal from the client.
        let base = std::path::Path::new(name)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(name);

        if base.is_empty() {
            return Err(format!(
                "Error: Destination '{}' is a directory but no valid file name was provided\n",
                expanded
            ));
        }

        Ok(format!("{}/{}", expanded.trim_end_matches('/'), base))
    }
}

#[async_trait]
impl AgentCommand for UploadAgentCommand {
    fn name(&self) -> &'static str {
        "upload"
    }

    async fn execute(&self, args: Vec<String>, mut ctx: Context) -> Result<()> {
        if args.len() < 2 {
            let _ = ctx.stdout.write_all(b"Error: Missing destination path or expected hash\n").await;
            return Ok(());
        }

        let expected_hash = &args[1];
        // Optional third arg: the client's local file name. Used to complete
        // the destination when it refers to a directory (e.g. `~/` or `/tmp/`).
        let client_file_name = args.get(2).map(|s| s.as_str());

        // Resolve the destination: expand `~` and, if the destination is a
        // directory, append the client-provided file name.
        let dest_path = match Self::resolve_dest_path(&args[0], client_file_name).await {
            Ok(p) => p,
            Err(msg) => {
                let _ = ctx.stdout.write_all(msg.as_bytes()).await;
                return Ok(());
            }
        };

        // Create the file on the remote filesystem
        let mut file = match File::create(&dest_path).await {
            Ok(f) => f,
            Err(e) => {
                let err_msg = format!("Error: Failed to create file '{}': {}\n", dest_path, e);
                let _ = ctx.stdout.write_all(err_msg.as_bytes()).await;
                return Ok(());
            }
        };

        // Notify the client that we are ready to receive data on stdin
        if let Err(e) = ctx.stdout.write_all(b"READY\n").await {
            let _ = tokio::fs::remove_file(&dest_path).await;
            return Err(ch_common::Error::Other(format!("Failed to send ready signal: {}", e)));
        }
        let _ = ctx.stdout.flush().await;

        // Remote Diagnostic: Indicate ready state
        let _ = ctx.stdout.write_all(b"[Agent Debug] READY sent. Waiting to read from stdin...\n").await;
        let _ = ctx.stdout.flush().await;

        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 16384];
        let mut bytes_written = 0u64;
        let mut write_failed = false;

        // Read stream from client, hash on the fly, and write to disk
        loop {
            match ctx.stdin.read(&mut buffer).await {
                Ok(0) => {
                    // Remote Diagnostic: EOF hit
                    // let _ = ctx.stdout.write_all(b"[Agent Debug] Stdin returned 0 (EOF reached).\n").await;
                    // let _ = ctx.stdout.flush().await;
                    break;
                }
                Ok(n) => {
                    // Remote Diagnostic: Data chunk received
                    // let chunk_msg = format!("[Agent Debug] Read {} bytes from stdin.\n", n);
                    // let _ = ctx.stdout.write_all(chunk_msg.as_bytes()).await;
                    // let _ = ctx.stdout.flush().await;

                    hasher.update(&buffer[..n]);
                    if !write_failed {
                        if let Err(e) = file.write_all(&buffer[..n]).await {
                            let err_msg = format!("Error: Failed writing to disk: {}\n", e);
                            let _ = ctx.stdout.write_all(err_msg.as_bytes()).await;
                            write_failed = true;
                        } else {
                            bytes_written += n as u64;
                        }
                    }
                }
                Err(e) => {
                    let err_msg = format!("Error: Failed reading from stdin stream: {}\n", e);
                    let _ = ctx.stdout.write_all(err_msg.as_bytes()).await;
                    let _ = tokio::fs::remove_file(&dest_path).await;
                    return Ok(());
                }
            }
        }

        // Remote Diagnostic: Read loop completed
        // let finished_msg = format!("[Agent Debug] Stdin read loop finished. Total bytes written: {}\n", bytes_written);
        // let _ = ctx.stdout.write_all(finished_msg.as_bytes()).await;
        // let _ = ctx.stdout.flush().await;

        if write_failed {
            let _ = tokio::fs::remove_file(&dest_path).await;
            return Ok(());
        }

        // Flush remaining buffer to disk
        if let Err(e) = file.flush().await {
            let err_msg = format!("Error: Failed flushing file to disk: {}\n", e);
            let _ = ctx.stdout.write_all(err_msg.as_bytes()).await;
            let _ = tokio::fs::remove_file(&dest_path).await;
            return Ok(());
        }

        // Calculate final SHA-256 hash
        let actual_hash = hex::encode(hasher.finalize());

        // Verify hash integrity
        if actual_hash.eq_ignore_ascii_case(expected_hash) {
            let success_msg = format!(
                "Upload successful\nPath: {}\nBytes written: {}\nSHA-256 verified: {}\n",
                dest_path, bytes_written, actual_hash
            );
            let _ = ctx.stdout.write_all(success_msg.as_bytes()).await;
        } else {
            let failure_msg = format!(
                "Error: Hash verification failed!\nExpected: {}\nActual:   {}\nRemoving corrupted file.\n",
                expected_hash, actual_hash
            );
            let _ = ctx.stdout.write_all(failure_msg.as_bytes()).await;
            let _ = tokio::fs::remove_file(&dest_path).await;
        }

        Ok(())
    }
}

// =========================================================================
// CLIENT-SIDE COMMAND (UploadClientCommand)
// =========================================================================

pub struct UploadClientCommand {}

impl UploadClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for UploadClientCommand {
    fn name(&self) -> &'static str {
        "upload"
    }

    fn short_description(&self) -> &'static str {
        "Upload a local file with SHA-256 hash verification"
    }

    fn help(&self) -> &'static str {
        "Usage: upload <local_path> <remote_path>\n\n\
        Arguments:\n\
          local_path    The path to the local file to upload\n\
          remote_path   The destination on the remote system. May use '~' for\n\
                        the remote home directory. If it names a directory\n\
                        (ends with '/' or is an existing directory, e.g. '~/'),\n\
                        the local file name is used for the uploaded file."
    }

    async fn execute(&self, args: &[String], ctx: ClientContext<'_>) -> Result<()> {
        if args.len() < 2 {
            eprintln!("{}", self.help());
            return Ok(());
        }

        let local_path = &args[0];
        let remote_path = &args[1];

        // Base name of the local file. Sent to the agent so it can complete a
        // directory destination such as `~/` into `~/<file_name>`.
        let local_file_name = std::path::Path::new(local_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(local_path.as_str());

        // Open local file for the hashing phase
        let mut local_file = File::open(local_path)
            .await
            .map_err(|e| ch_common::Error::Other(format!("Failed to open local file: {}", e)))?;

        // Phase 1: Compute SHA-256 hash of the local file
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 16384];
        loop {
            let n = local_file
                .read(&mut buffer)
                .await
                .map_err(|e| ch_common::Error::Other(format!("Failed hashing local file: {}", e)))?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        let hex_hash = hex::encode(hasher.finalize());

        // Reopen the file for the transmission phase to guarantee we start at byte 0
        let mut local_file_transmit = File::open(local_path)
            .await
            .map_err(|e| ch_common::Error::Other(format!("Failed to reopen local file for transmission: {}", e)))?;

        let session = ctx.session;
        let mut channel = session
            .channel_open_session()
            .await
            .map_err(|e| ch_common::Error::Other(e.to_string()))?;

        // Start agent-side upload process, passing the expected hash and the
        // local file name (used to complete directory destinations).
        let server_command = UploadAgentCommand::new();
        let exec_payload = format!(
            "{} {} {} {}",
            server_command.name(),
            remote_path,
            hex_hash,
            local_file_name
        );

        channel
            .exec(true, exec_payload.as_bytes())
            .await
            .map_err(|e| ch_common::Error::Other(e.to_string()))?;

        // Phase 1.5: Wait for the agent to send the "READY" signal
        let mut ready = false;
        let mut agent_responded = false;

        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => {
                    agent_responded = true;
                    let s = std::str::from_utf8(data).unwrap_or_default();
                    if s.contains("READY\n") {
                        ready = true;
                        // Strip the READY token so it isn't printed to the stdout
                        let clean = s.replace("READY\n", "");
                        if !clean.is_empty() {
                            print!("{}", clean);
                            use std::io::Write;
                            let _ = std::io::stdout().flush();
                        }
                        break;
                    } else {
                        print!("{}", s);
                        use std::io::Write;
                        let _ = std::io::stdout().flush();
                    }
                }
                russh::ChannelMsg::ExtendedData { ref data, .. } => {
                    agent_responded = true;
                    let s = std::str::from_utf8(data).unwrap_or_default();
                    eprint!("{}", s);
                    use std::io::Write;
                    let _ = std::io::stderr().flush();
                }
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    if exit_status != 0 {
                        return Err(ch_common::Error::Other(format!(
                            "Agent exited with status {} before starting transmission",
                            exit_status
                        )));
                    }
                }
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }

        if !ready {
            return Err(ch_common::Error::Other(
                "Failed to receive READY signal from agent. File transfer aborted.".to_string(),
            ));
        }

        // Phase 2: Transmit the file content to the remote agent
        let mut transmission_error: Option<String> = None;
        let mut total_bytes_sent = 0u64;

        println!("[Client Debug] Starting transmission loop...");

        loop {
            match local_file_transmit.read(&mut buffer).await {
                Ok(0) => {
                    println!("[Client Debug] Reached EOF of local file (0 bytes read).");
                    break;
                }
                Ok(n) => {
                    println!("[Client Debug] Read {} bytes from local file. Writing to channel...", n);
                    if let Err(e) = channel.data(&buffer[..n]).await {
                        let err_msg = format!("Channel send error: {}", e);
                        println!("[Client Debug] Error: {}", err_msg);
                        transmission_error = Some(err_msg);
                        break;
                    }
                    total_bytes_sent += n as u64;
                }
                Err(e) => {
                    let err_msg = format!("Failed reading local file: {}", e);
                    println!("[Client Debug] Error: {}", err_msg);
                    transmission_error = Some(err_msg);
                    break;
                }
            }
        }

        println!("[Client Debug] Transmission loop complete. Total bytes sent: {}", total_bytes_sent);

        // Notify remote agent that client transmission is finished
        if transmission_error.is_none() {
            println!("[Client Debug] Sending EOF signal to channel...");
            if let Err(e) = channel.eof().await {
                let err_msg = format!("Failed sending EOF: {}", e);
                println!("[Client Debug] Error: {}", err_msg);
                transmission_error = Some(err_msg);
            }
        }

        // Phase 3: Output responses and verification results from the remote execution
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => {
                    agent_responded = true;
                    let s = std::str::from_utf8(data).unwrap_or_default();
                    print!("{}", s);
                    use std::io::Write;
                    let _ = std::io::stdout().flush();
                }
                russh::ChannelMsg::ExtendedData { ref data, .. } => {
                    agent_responded = true;
                    let s = std::str::from_utf8(data).unwrap_or_default();
                    eprint!("{}", s);
                    use std::io::Write;
                    let _ = std::io::stderr().flush();
                }
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    if exit_status != 0 {
                        tracing::warn!("Remote upload command exited with status {}", exit_status);
                    }
                }
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }

        // If a transmission error occurred, output it locally to standard error
        if let Some(ref err_msg) = transmission_error {
            eprintln!("[Client Debug] Warning: A transmission error occurred: {}", err_msg);
        }

        if let Some(err_msg) = transmission_error {
            if !agent_responded {
                return Err(ch_common::Error::Other(err_msg));
            } else {
                tracing::debug!("Transmission error occurred but agent responded: {}", err_msg);
            }
        }

        Ok(())
    }
}
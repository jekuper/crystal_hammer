use async_trait::async_trait;
use ch_common::Result;
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::{self, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::model::{AgentCommand, ClientCommand, ClientContext, Context};

// =========================================================================
// AGENT-SIDE COMMAND (UploadAgentCommand)
// =========================================================================

pub struct UploadAgentCommand {}

impl UploadAgentCommand {
    pub fn new() -> Self {
        Self {}
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
        
        let dest_path = &args[0];
        let expected_hash = &args[1];

        // Create the file on the remote filesystem
        let mut file = match File::create(dest_path).await {
            Ok(f) => f,
            Err(e) => {
                let err_msg = format!("Error: Failed to create file '{}': {}\n", dest_path, e);
                let _ = ctx.stdout.write_all(err_msg.as_bytes()).await;
                return Ok(());
            }
        };

        // Notify the client that we are ready to receive data on stdin
        if let Err(e) = ctx.stdout.write_all(b"READY\n").await {
            let _ = tokio::fs::remove_file(dest_path).await;
            return Err(ch_common::Error::Other(format!("Failed to send ready signal: {}", e)));
        }
        let _ = ctx.stdout.flush().await;

        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 16384];
        let mut bytes_written = 0u64;
        let mut write_failed = false;

        // Read stream from client, hash on the fly, and write to disk
        loop {
            match ctx.stdin.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => {
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
                    let _ = tokio::fs::remove_file(dest_path).await;
                    return Ok(());
                }
            }
        }

        if write_failed {
            let _ = tokio::fs::remove_file(dest_path).await;
            return Ok(());
        }

        // Flush remaining buffer to disk
        if let Err(e) = file.flush().await {
            let err_msg = format!("Error: Failed flushing file to disk: {}\n", e);
            let _ = ctx.stdout.write_all(err_msg.as_bytes()).await;
            let _ = tokio::fs::remove_file(dest_path).await;
            return Ok(());
        }

        // Calculate final SHA-256 hash
        let actual_hash = hex::encode(hasher.finalize());

        // Verify hash integrity
        if actual_hash.eq_ignore_ascii_case(expected_hash) {
            let success_msg = format!(
                "Upload successful\nBytes written: {}\nSHA-256 verified: {}\n",
                bytes_written, actual_hash
            );
            let _ = ctx.stdout.write_all(success_msg.as_bytes()).await;
        } else {
            let failure_msg = format!(
                "Error: Hash verification failed!\nExpected: {}\nActual:   {}\nRemoving corrupted file.\n",
                expected_hash, actual_hash
            );
            let _ = ctx.stdout.write_all(failure_msg.as_bytes()).await;
            let _ = tokio::fs::remove_file(dest_path).await;
        }

        Ok(())
    }
}

// =========================================================================
// CLIENT-SIDE COMMAND (UploadClientCommand)
// =========================================================================

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
          remote_path   The destination path on the remote system"
    }

    async fn execute(&self, args: &[String], ctx: ClientContext<'_>) -> Result<()> {
        if args.len() < 2 {
            eprintln!("{}", self.help());
            return Ok(());
        }

        let local_path = &args[0];
        let remote_path = &args[1];

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

        // Start agent-side upload process, passing the expected hash as an argument
        let server_command = UploadAgentCommand::new();
        let exec_payload = format!("{} {} {}", server_command.name(), remote_path, hex_hash);

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
        loop {
            let n = match local_file_transmit.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    transmission_error = Some(format!("Failed reading local file: {}", e));
                    break;
                }
            };
            
            if let Err(e) = channel.data(&buffer[..n]).await {
                transmission_error = Some(format!("Channel send error: {}", e));
                break;
            }
        }

        // Notify remote agent that client transmission is finished
        if transmission_error.is_none() {
            if let Err(e) = channel.eof().await {
                transmission_error = Some(format!("Failed sending EOF: {}", e));
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

        // If a transmission error occurred and the agent didn't output any error messages,
        // return the error back to the shell framework so it gets printed.
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
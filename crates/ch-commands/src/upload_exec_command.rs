// File: crates/ch-commands/src/upload_exec_command.rs
use async_trait::async_trait;
use ch_common::Result;
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::model::{AgentCommand, ClientCommand, ClientCommandContext, AgentCommandContext};

// =========================================================================
// AGENT-SIDE COMMAND
// =========================================================================

pub struct UploadExecAgentCommand {}

impl UploadExecAgentCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl AgentCommand for UploadExecAgentCommand {
    fn name(&self) -> &'static str {
        "upload-exec"
    }

    async fn execute(&self, args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        if args.len() < 2 {
            let _ = ctx.stdout.write_all(b"Error: Missing expected hash or filename\n").await;
            return Ok(());
        }

        let expected_hash = &args[0];
        let filename = &args[1];
        let exec_args = &args[2..];

        let dest_path = format!("/tmp/{}", filename);
        let out_path = format!("{}.out", dest_path);
        let err_path = format!("{}.err", dest_path);

        let mut file = match File::create(&dest_path).await {
            Ok(f) => f,
            Err(e) => {
                let err_msg = format!("Error: Failed to create file '{}': {}\n", dest_path, e);
                let _ = ctx.stdout.write_all(err_msg.as_bytes()).await;
                return Ok(());
            }
        };

        if let Err(e) = ctx.stdout.write_all(b"READY\n").await {
            let _ = tokio::fs::remove_file(&dest_path).await;
            return Err(ch_common::Error::Other(format!("Failed to send ready signal: {}", e)));
        }
        let _ = ctx.stdout.flush().await;

        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 16384];
        let mut write_failed = false;

        loop {
            match ctx.stdin.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    hasher.update(&buffer[..n]);
                    if !write_failed {
                        if let Err(e) = file.write_all(&buffer[..n]).await {
                            let err_msg = format!("Error: Failed writing to disk: {}\n", e);
                            let _ = ctx.stdout.write_all(err_msg.as_bytes()).await;
                            write_failed = true;
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

        if write_failed {
            let _ = tokio::fs::remove_file(&dest_path).await;
            return Ok(());
        }

        if let Err(e) = file.flush().await {
            let err_msg = format!("Error: Failed flushing file to disk: {}\n", e);
            let _ = ctx.stdout.write_all(err_msg.as_bytes()).await;
            let _ = tokio::fs::remove_file(&dest_path).await;
            return Ok(());
        }

        drop(file);

        let actual_hash = hex::encode(hasher.finalize());

        if !actual_hash.eq_ignore_ascii_case(expected_hash) {
            let failure_msg = format!(
                "Error: Hash verification failed!\nExpected: {}\nActual:   {}\nRemoving corrupted file.\n",
                expected_hash, actual_hash
            );
            let _ = ctx.stdout.write_all(failure_msg.as_bytes()).await;
            let _ = tokio::fs::remove_file(&dest_path).await;
            return Ok(());
        }

        // Apply executable permissions
        use std::os::unix::fs::PermissionsExt;
        if let Ok(mut perms) = tokio::fs::metadata(&dest_path).await.map(|m| m.permissions()) {
            perms.set_mode(perms.mode() | 0o111);
            let _ = tokio::fs::set_permissions(&dest_path, perms).await;
        }

        let msg = format!("Upload successful. Executing {}...\nStdout -> {}\nStderr -> {}\n", dest_path, out_path, err_path);
        let _ = ctx.stdout.write_all(msg.as_bytes()).await;

        use std::process::Stdio;
        use tokio::process::Command;

        let mut child = match Command::new(&dest_path)
            .args(exec_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn() {
                Ok(c) => c,
                Err(e) => {
                    let err_msg = format!("Error spawning process: {}\n", e);
                    let _ = ctx.stdout.write_all(err_msg.as_bytes()).await;
                    return Ok(());
                }
            };

        let mut child_stdout = child.stdout.take().unwrap();
        let mut child_stderr = child.stderr.take().unwrap();

        let mut out_file = match File::create(&out_path).await {
            Ok(f) => f,
            Err(e) => {
                let err_msg = format!("Error: Failed to create stdout file '{}': {}\n", out_path, e);
                let _ = ctx.stdout.write_all(err_msg.as_bytes()).await;
                return Ok(());
            }
        };

        let mut err_file = match File::create(&err_path).await {
            Ok(f) => f,
            Err(e) => {
                let err_msg = format!("Error: Failed to create stderr file '{}': {}\n", err_path, e);
                let _ = ctx.stdout.write_all(err_msg.as_bytes()).await;
                return Ok(());
            }
        };

        let mut stdout_writer = ctx.stdout;
        let mut stderr_writer = ctx.stderr;

        // Both duplicate to the on-disk file, and stream out to the operator
        let stdout_task = async move {
            let mut buf = [0u8; 4096];
            loop {
                match child_stdout.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = out_file.write_all(&buf[..n]).await;
                        let _ = stdout_writer.write_all(&buf[..n]).await;
                    }
                }
            }
        };

        let stderr_task = async move {
            let mut buf = [0u8; 4096];
            loop {
                match child_stderr.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = err_file.write_all(&buf[..n]).await;
                        let _ = stderr_writer.write_all(&buf[..n]).await;
                    }
                }
            }
        };

        let _ = tokio::join!(
            child.wait(),
            stdout_task,
            stderr_task
        );

        Ok(())
    }
}

// =========================================================================
// CLIENT-SIDE COMMAND
// =========================================================================

pub struct UploadExecClientCommand {}

impl UploadExecClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for UploadExecClientCommand {
    fn name(&self) -> &'static str {
        "upload-exec"
    }

    fn short_description(&self) -> &'static str {
        "Upload a local file, make it executable, and run it"
    }

    fn help(&self) -> &'static str {
        "Usage: upload-exec <local_path> [args...]\n\n\
        Arguments:\n\
          local_path    The path to the local executable file to upload\n\
          args...       Arguments to pass to the executed file on the agent\n\n\
        The file is uploaded to /tmp/<filename> on the agent, marked executable, and run.\n\
        Stdout and stderr will be saved on the remote machine alongside the file, and streamed back."
    }

    fn complete_arg(&self, preceding_args: &[&str], word: &str, ctx: &rustyline::Context<'_>, filename_completer: &FilenameCompleter) -> Vec<Pair> {
        if preceding_args.is_empty() {
            match filename_completer.complete(word, word.len(), ctx) {
                Ok((_pos, pairs)) => pairs,
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        }
    }

    async fn execute(&self, _executor: &dyn ClientCommandExecutor, args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
        if args.is_empty() {
            eprintln!("{}", self.help());
            return Ok(());
        }

        let local_path = &args[0];
        let exec_args = &args[1..];

        let local_file_name = std::path::Path::new(local_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(local_path.as_str());

        let mut local_file = File::open(local_path)
            .await
            .map_err(|e| ch_common::Error::Other(format!("Failed to open local file: {}", e)))?;

        // Phase 1: Compute hash
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 16384];
        loop {
            let n = local_file.read(&mut buffer).await
                .map_err(|e| ch_common::Error::Other(format!("Failed hashing local file: {}", e)))?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        let hex_hash = hex::encode(hasher.finalize());

        let mut local_file_transmit = File::open(local_path)
            .await
            .map_err(|e| ch_common::Error::Other(format!("Failed to reopen local file: {}", e)))?;

        let session = ctx.session;
        let mut channel = session.channel_open_session().await
            .map_err(|e| ch_common::Error::Other(e.to_string()))?;

        let server_command = UploadExecAgentCommand::new();
        let mut exec_payload = format!("{} {} {}", server_command.name(), hex_hash, local_file_name);
        for arg in exec_args {
            exec_payload.push(' ');
            exec_payload.push_str(arg);
        }

        channel.exec(true, exec_payload.as_bytes()).await
            .map_err(|e| ch_common::Error::Other(e.to_string()))?;

        // Wait for READY
        let mut ready = false;
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => {
                    let s = String::from_utf8_lossy(data);
                    if s.contains("READY\n") {
                        ready = true;
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
                    eprint!("{}", String::from_utf8_lossy(data));
                }
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    if exit_status != 0 {
                        return Err(ch_common::Error::Other(format!("Agent exited with status {} before transfer", exit_status)));
                    }
                }
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }

        if !ready {
            return Err(ch_common::Error::Other("Failed to receive READY signal. File transfer aborted.".to_string()));
        }

        // Phase 2: Transmit file content
        let mut transmission_error: Option<String> = None;
        loop {
            match local_file_transmit.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = channel.data(&buffer[..n]).await {
                        transmission_error = Some(format!("Channel send error: {}", e));
                        break;
                    }
                }
                Err(e) => {
                    transmission_error = Some(format!("Failed reading local file: {}", e));
                    break;
                }
            }
        }

        if transmission_error.is_none() {
            if let Err(e) = channel.eof().await {
                transmission_error = Some(format!("Failed sending EOF: {}", e));
            }
        }

        // Phase 3: Wait for process execution output
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => {
                    print!("{}", String::from_utf8_lossy(data));
                    use std::io::Write;
                    let _ = std::io::stdout().flush();
                }
                russh::ChannelMsg::ExtendedData { ref data, .. } => {
                    eprint!("{}", String::from_utf8_lossy(data));
                    use std::io::Write;
                    let _ = std::io::stderr().flush();
                }
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    if exit_status != 0 {
                        tracing::warn!("Remote execution exited with status {}", exit_status);
                    }
                }
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }

        if let Some(err_msg) = transmission_error {
            eprintln!("Warning: Transmission error occurred: {}", err_msg);
        }

        Ok(())
    }
}
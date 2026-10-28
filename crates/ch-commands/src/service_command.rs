//! Service control across init systems. Detection mirrors the firewall backends: pick the
//! init the host actually runs (systemd / OpenRC / SysV) at call time.
//!
//! Unlike the hunt/sense paths, controlling a service unavoidably invokes the init tool -
//! there is no /proc way to restart a unit - so this is the one place the tool shells out
//! to a system binary. Arguments are passed as an argv (never a shell string) and the
//! service name is validated, so a crafted name can't inject a command or an extra flag.

use std::path::Path;

use async_trait::async_trait;
use ch_common::Result;
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{FilenameCompleter, Pair};
use tokio::io::AsyncWriteExt;

use crate::model::{AgentCommand, AgentCommandContext, ClientCommand, ClientCommandContext};
use crate::response_command::run_remote;

const ACTIONS: &[&str] = &["start", "stop", "restart", "status"];

enum Init {
    Systemd,
    OpenRc,
    SysV,
    Unknown,
}

fn detect_init() -> Init {
    if Path::new("/run/systemd/system").exists() {
        Init::Systemd
    } else if ["/sbin/rc-service", "/usr/sbin/rc-service", "/bin/rc-service"]
        .iter()
        .any(|p| Path::new(p).exists())
    {
        Init::OpenRc
    } else if Path::new("/etc/init.d").exists() {
        Init::SysV
    } else {
        Init::Unknown
    }
}

/// A service name safe to hand an init tool as an argv element: no leading dash (so it
/// can't be read as a flag) and only characters real unit/service names use.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | ':'))
}

pub struct ServiceAgentCommand {}

impl ServiceAgentCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl AgentCommand for ServiceAgentCommand {
    fn name(&self) -> &'static str {
        "service"
    }

    async fn execute(&self, args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        if args.len() < 2 {
            ctx.stdout
                .write_all(b"usage: service <start|stop|restart|status> <name>\n")
                .await?;
            return Ok(());
        }
        let action = args[0].as_str();
        let name = args[1].as_str();

        if !ACTIONS.contains(&action) {
            ctx.stdout
                .write_all(format!("unknown action: {action} (want start|stop|restart|status)\n").as_bytes())
                .await?;
            return Ok(());
        }
        if !valid_name(name) {
            ctx.stdout
                .write_all(format!("invalid service name: {name}\n").as_bytes())
                .await?;
            return Ok(());
        }

        let (bin, argv) = match detect_init() {
            Init::Systemd => {
                let mut a = vec![action.to_string(), name.to_string()];
                if action == "status" {
                    a.insert(0, "--no-pager".to_string());
                }
                ("systemctl", a)
            }
            Init::OpenRc => ("rc-service", vec![name.to_string(), action.to_string()]),
            Init::SysV => ("service", vec![name.to_string(), action.to_string()]),
            Init::Unknown => {
                ctx.stdout.write_all(b"no supported init system detected\n").await?;
                return Ok(());
            }
        };

        let output = tokio::process::Command::new(bin).args(&argv).output().await;
        let mut report = String::new();
        match output {
            Ok(out) => {
                report.push_str(&format!("{bin} {}\n", argv.join(" ")));
                report.push_str(&String::from_utf8_lossy(&out.stdout));
                let err = String::from_utf8_lossy(&out.stderr);
                if !err.trim().is_empty() {
                    report.push_str(&err);
                }
                report.push_str(&format!("exit: {}\n", out.status.code().unwrap_or(-1)));
            }
            Err(e) => report.push_str(&format!("failed to run {bin}: {e}\n")),
        }
        ctx.stdout.write_all(report.as_bytes()).await?;
        Ok(())
    }
}

pub struct ServiceClientCommand {}

impl ServiceClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for ServiceClientCommand {
    fn name(&self) -> &'static str {
        "service"
    }
    fn short_description(&self) -> &'static str {
        "Control a service (start/stop/restart/status)"
    }
    fn help(&self) -> &'static str {
        "Usage: service <start|stop|restart|status> <name>\n\n\
        Detects the host init system (systemd / OpenRC / SysV) and drives it. Use to bring\n\
        a downed service back up or stop a malicious one."
    }
    fn complete_arg(&self, preceding: &[&str], word: &str, _ctx: &rustyline::Context<'_>, _fc: &FilenameCompleter) -> Vec<Pair> {
        if preceding.is_empty() {
            return ACTIONS
                .iter()
                .filter(|a| a.starts_with(word))
                .map(|a| Pair { display: a.to_string(), replacement: format!("{a} ") })
                .collect();
        }
        Vec::new()
    }
    async fn execute(&self, _e: &dyn ClientCommandExecutor, args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
        run_remote(ctx, "service", args).await
    }
}

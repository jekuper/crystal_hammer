use std::sync::Arc;

use async_trait::async_trait;
use ch_common::{Result, proto::CommandEvent};
use ch_transport::client::ClientHandler;
use russh::client::Handle;
use tokio::{io::{AsyncRead, AsyncWrite}, sync::mpsc};

use crate::info_command::{InfoAgentCommand, InfoClientCommand};

#[async_trait]
pub trait AgentCommand: Send + Sync {
    /// Unique command identifier (e.g. "upload", "info")
    fn name(&self) -> &'static str;
    
    /// Execute the command within the provided context
    async fn execute(&self, args: Vec<String>, ctx: Context) -> Result<()>;
}

#[async_trait]
pub trait ClientCommand {
    /// Command keyword typed by the operator (e.g. "upload")
    fn name(&self) -> &'static str;
    
    /// Execute client-side logic, interacting with the active session
    async fn execute(&self, args: &[String], session: &mut Handle<ClientHandler>) -> Result<()>;
}

pub struct AgentCommandRegistry {
    commands: Vec<Box<dyn AgentCommand>>,
}

impl AgentCommandRegistry {
    pub fn with_builtins() -> Self {
        let mut r = AgentCommandRegistry { commands: Vec::new() };
        r.register(Box::new(InfoAgentCommand::new()));
        r
    }

    pub fn register(&mut self, command: Box<dyn AgentCommand>) {
        self.commands.push(command);
    }
}

pub struct ClientCommandRegistry {
    commands: Vec<Box<dyn ClientCommand>>,
}

impl ClientCommandRegistry {
    pub fn with_builtins() -> Self {
        let mut r = ClientCommandRegistry { commands: Vec::new() };
        r.register(Box::new(InfoClientCommand::new()));
        r
    }

    pub fn register(&mut self, command: Box<dyn ClientCommand>) {
        self.commands.push(command);
    }
}


pub struct Context {
    /// Inbound stream from the client (for script inputs or file uploads)
    pub stdin: Box<dyn AsyncRead + Send + Unpin>,
    /// Real-time stdout stream
    pub stdout: Box<dyn AsyncWrite + Send + Unpin>,
    /// Real-time stderr stream
    pub stderr: Box<dyn AsyncWrite + Send + Unpin>,
    /// Out-of-band structured event channel
    pub events: mpsc::UnboundedSender<CommandEvent>,
    /// Access to persistent key-value store (redb wrapper)
    pub store: Arc<ch_store::Store>,
}
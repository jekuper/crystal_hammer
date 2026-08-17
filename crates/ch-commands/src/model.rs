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

pub struct ClientContext<'a> {
    pub session: &'a mut Handle<ClientHandler>,
}

#[async_trait]
pub trait ClientCommand: Send + Sync {
    /// Command keyword typed by the operator (e.g. "upload")
    fn name(&self) -> &'static str;

    fn short_description(&self) -> &'static str;

    fn help(&self) -> &'static str;
    
    /// Execute client-side logic, interacting with the active session
    async fn execute(&self, args: &[String], ctx: ClientContext<'_>) -> Result<()>;
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

    pub fn find(&self, name: &str) -> Option<&dyn AgentCommand> {
        self.commands.iter().map(|b| b.as_ref()).find(|c| c.name() == name)
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

    pub fn find(&self, name: &str) -> Option<&dyn ClientCommand> {
        self.commands.iter().map(|b| b.as_ref()).find(|c| c.name() == name)
    }

    pub fn iter(&self) -> Iter<'_> {
        Iter {
            inner: self.commands.iter(),
        }
    }
}

/// An iterator over the commands in a `ClientCommandRegistry`.
pub struct Iter<'a> {
    inner: std::slice::Iter<'a, Box<dyn ClientCommand>>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a dyn ClientCommand;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|b| b.as_ref())
    }
}

/// Allows iterating over references to the registry, e.g., `for cmd in &registry`
impl<'a> IntoIterator for &'a ClientCommandRegistry {
    type Item = &'a dyn ClientCommand;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
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
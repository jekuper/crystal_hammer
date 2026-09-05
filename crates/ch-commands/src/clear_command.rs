// File: crates/ch-commands/src/clear_command.rs

use async_trait::async_trait;
use ch_common::Result;
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{FilenameCompleter, Pair};
use std::io::Write;

use crate::model::{ClientCommand, ClientContext};

pub struct ClearClientCommand {}

impl ClearClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for ClearClientCommand {
    fn name(&self) -> &'static str {
        "clear"
    }

    fn short_description(&self) -> &'static str {
        "Clears the terminal screen"
    }

    fn help(&self) -> &'static str {
        "Usage: clear\n\n\
         Clears the terminal screen and moves the cursor to the top-left."
    }

    fn complete_arg(&self, _preceding_args: &[&str], _word: &str, _ctx: &rustyline::Context<'_>, _filename_completer: &FilenameCompleter) -> Vec<Pair> {
        Vec::new()
    }

    async fn execute(&self, _executor: &dyn ClientCommandExecutor, _args: &[String], _ctx: ClientContext<'_>) -> Result<()> {
        // \x1B[H  - cursor to home
        // \x1B[2J - clear visible screen
        // \x1B[3J - clear scrollback buffer (xterm extension; ignored where unsupported)
        print!("\x1B[H\x1B[2J\x1B[3J");
        let _ = std::io::stdout().flush();
        Ok(())
    }
}
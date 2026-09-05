use async_trait::async_trait;
use ch_common::Result;
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{FilenameCompleter, Pair};

use crate::model::{ClientCommand, ClientContext};


pub struct HelpClientCommand {
    command_names: Vec<String>,
}

impl HelpClientCommand {
    pub fn new(command_names: Vec<String>) -> Self {
        Self { command_names }
    }
}

#[async_trait]
impl ClientCommand for HelpClientCommand {
    fn name(&self) -> &'static str { "help" }
    fn short_description(&self) -> &'static str { "Shows help message" }
    fn help(&self) -> &'static str {
        "Usage: help [command]\n\n\
         With no arguments, lists all commands.\n\
         With a command name, shows its detailed help.\n"
    }

    fn complete_arg(&self, preceding_args: &[&str], word: &str, _ctx: &rustyline::Context<'_>, _filename_completer: &FilenameCompleter) -> Vec<Pair> {
        if !preceding_args.is_empty() {
            // help only takes one argument
            return Vec::new();
        }

        self.command_names
            .iter()
            .filter(|name| name.starts_with(word))
            .map(|name| Pair {
                display: name.clone(),
                replacement: format!("{} ", name), // trailing space — done after one word
            })
            .collect()
    }

    async fn execute(&self, executor: &dyn ClientCommandExecutor, args: &[String], _ctx: ClientContext<'_>) -> Result<()> {
        let command_list = executor.get_command_list();

        // If an argument is provided, look up the specific command's help text
        if let Some(target_command) = args.first() {
            if command_list.contains(target_command) {
                println!("{}", executor.get_help_for(target_command).unwrap());
                return Ok(());
            } else {
                return Err(ch_common::Error::Other(format!("Unknown command: '{}'", target_command)));
            }
        }

        // Default behavior: list all registered commands
        println!("Special commands:");
        println!("exit/quit  - Close session and exit client\n");
        println!("Registered commands:");
        let mut help_summary = "".to_string();
        for command in command_list {
            help_summary.push_str(&command);
            help_summary.push_str(" - ");
            help_summary.push_str(executor.get_short_description_for(&command).unwrap());
            help_summary.push_str("\n");
        }
        println!("{}", help_summary);

        Ok(())
    }
}
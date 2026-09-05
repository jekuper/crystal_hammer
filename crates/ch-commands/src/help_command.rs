use async_trait::async_trait;
use ch_common::Result;
use ch_transport::ClientCommandExecutor;

use crate::model::{ClientCommand, ClientContext};


pub struct HelpClientCommand {}

impl HelpClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for HelpClientCommand {
    fn name(&self) -> &'static str { "help" }
    fn short_description(&self) -> &'static str { "Shows help message" }
    fn help(&self) -> &'static str { 
        "Usage: help [command]\n\n\
        "
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
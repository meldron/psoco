use std::path::PathBuf;

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "psoco", about = "psono command line client")]
pub struct Settings {
    #[structopt(
        short = "c",
        long,
        parse(from_os_str),
        env = "PSOCO_CONFIG_PATH",
        help = "path of the psoco config.toml"
    )]
    pub config_path: Option<PathBuf>,
    #[structopt(subcommand)]
    pub command: Command,
}

#[derive(StructOpt, Debug)]
pub enum Command {
    #[structopt(about = "list all entries as table")]
    List {
        #[structopt(short = "f", long, help = "do not shorten entries' path")]
        full_path: bool,
    },
    #[structopt(about = "search all datastores")]
    Search {
        #[structopt(short = "f", long, help = "do not shorten entries' path")]
        full_path: bool,
        #[structopt(short = "s", long, help = "search secrets (notes, username, urls...)")]
        search_secrets: bool,
        #[structopt(required = true, min_values = 1)]
        search: Vec<String>,
    },
    #[structopt(about = "Get passwords by id. Displays a table if there is more than one result.")]
    Passwd {
        #[structopt(short = "j", long, help = "output as json")]
        json: bool,
        #[structopt(short = "u", long, help = "include username")]
        user: bool,
        #[structopt(short = "a", long, help = "include url, notes, username, url, title")]
        all: bool,
        #[structopt(required = true, min_values = 1)]
        ids: Vec<String>,
    },
    #[structopt(about = "Get username by id. Displays a table if there is more than one result.")]
    User {
        #[structopt(short = "j", long, help = "output as json")]
        json: bool,
        #[structopt(short = "p", long, help = "include password")]
        user: bool,
        #[structopt(short = "a", long, help = "include url, notes, username, url, title")]
        all: bool,
        #[structopt(required = true, min_values = 1)]
        ids: Vec<String>,
    },
    #[structopt(about = "Show or create a psoco config")]
    Config(ConfigCommand)
}

#[derive(StructOpt, Debug)]
pub enum ConfigCommand {
    #[structopt(about = "Display the current config (if any)")]
    Show {},
    #[structopt(about = "Interactively create a config")]
    Create {},
    #[structopt(about = "Print default config template")]
    Template {},
}
use std::collections::HashMap;
use std::fs::create_dir_all;
use std::path::PathBuf;
use std::process::exit;
use std::time::Instant;

use directories::ProjectDirs;
use rayon::prelude::*;
use std::io::Write;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

use serde_json::{json, Value as JSONValue};

#[macro_use]
extern crate prettytable;
use prettytable::{Cell, Row, Table};

use structopt::StructOpt;

// Important: use at top of file so other mod files can also use the macro
#[macro_use]
mod macros;

mod api;
mod config;
// mod crypto;
mod crypto2;
mod data_store;
mod errors;
mod login;
mod settings;

pub use settings::{Command, ConfigCommand, Settings};

// pub use crypto::verify_signature;
pub use errors::APIError;

pub use login::{
    create_client_info_with_session_sk, decrypt_login_info, ClientInfo, LoginInfoEncrypted,
};

pub use data_store::{DataStore, DatastoreListEntry, SecretItem, SecretValues};

pub use api::ApiClient;

pub use config::Config;

const DEFAULT_CONFIG_NAME: &str = "config.toml";

fn default_config_dir() -> Option<PathBuf> {
    let config_dir = ProjectDirs::from("eu", "dfjk", "psoco");
    match config_dir {
        Some(cd) => {
            let mut pb = cd.config_dir().to_path_buf();
            pb.push(DEFAULT_CONFIG_NAME);
            Some(pb)
        }
        None => None,
    }
}

fn get_client(config_path: PathBuf) -> Result<ApiClient, errors::APIError> {
    let config = Config::load(&config_path)?;
    ApiClient::new(
        &config.server_url,
        &config.server_signature,
        &config.api_key_id,
        &config.api_key_private_key,
        &config.api_key_secret_key,
        config.danger_disable_tls,
    )
}

fn get_datastores(client: &ApiClient) -> Result<Vec<DataStore>, APIError> {
    let data_stores_list = client.get_all_datastores()?;

    let mut datastores = Vec::<DataStore>::new();

    for dl in &data_stores_list {
        let dsr = client.get_datastore(&dl.id);
        if let Ok(d) = dsr {
            datastores.push(d);
        }
    }

    Ok(datastores)
}

fn get_datastores_with_shares(client: &ApiClient) -> Result<Vec<DataStore>, APIError> {
    let mut datastores = get_datastores(client)?;

    for mut d in &mut datastores {
        let share_map = match &d.share_index {
            Some(si) => Some(client.get_shares_by_index_par(&si)?),
            None => None,
        };

        if let Some(sm) = share_map {
            d.shares = sm;
        }
    }

    Ok(datastores)
}

fn search(
    config_path: PathBuf,
    searches: Vec<String>,
    as_json: bool,
    show_full_path: bool,
    search_secrets: bool,
) -> Result<(), errors::APIError> {
    let get_all = searches.is_empty();
    let mut client = get_client(config_path)?;
    client.login()?;

    let searches_lower: Vec<String> = searches.iter().map(|s| s.to_lowercase()).collect();

    let datastores = get_datastores_with_shares(&client)?;
    let datastores_secret_list: Vec<(String, Vec<SecretItem>)> = datastores
        .into_iter()
        .map(|d| {
            let sl = d.get_secrets_list();
            (d.id, sl)
        })
        .collect();
    let mut matches: Vec<(&str, &SecretItem)> = Vec::new();

    let mut secrets_map: Option<HashMap<&str, SecretValues>> = if search_secrets {
        Some(HashMap::new())
    } else {
        None
    };

    if let Some(m) = &mut secrets_map {
        let secret_items: Vec<&SecretItem> = datastores_secret_list
            .iter()
            .map(|(_, i)| i)
            .flatten()
            .collect();

        let secrets: Vec<(&str, Option<SecretValues>)> = secret_items
            .par_iter()
            .map(|s| {
                (
                    s.secret_id.as_str(),
                    client.get_secret(&s.secret_id, &s.secret_key).ok(),
                )
            })
            .collect();
        for (secret_id, secret) in secrets {
            if let Some(s) = secret {
                m.insert(secret_id, s);
            }
        }
    }

    for (datastore_id, secret_items) in &datastores_secret_list {
        for secret_item in secret_items {
            if get_all {
                matches.push((datastore_id, secret_item));
                continue;
            }
            for search in &searches_lower {
                if secret_item.contains(search) {
                    matches.push((datastore_id, secret_item));
                    break;
                }

                if let Some(m) = secrets_map.as_ref() {
                    if let Some(s) = m.get(secret_item.secret_id.as_str()) {
                        if s.contains(search) {
                            matches.push((datastore_id, secret_item));
                            break;
                        }
                    }
                }
            }
        }
    }

    // println!("Found: {:#?}", found);
    matches.sort_by(|a, b| a.1.path.cmp(&b.1.path));

    if as_json {
        let j: Vec<serde_json::Value> = matches
            .iter()
            .map(|(ds_id, si)| json!({ "datastore_id": ds_id, "match": si }))
            .collect();
        let o = serde_json::to_string_pretty(&j).expect("could not serialize as json");
        println!("{}", o);
        return Ok(());
    }

    let mut table = Table::new();
    // TODO option to print datastore
    table.add_row(row![bFg => "Name", "Path", "ID"]);
    matches.iter().for_each(|(_, si)| {
        if show_full_path {
            table.add_row(si.to_row());
        } else {
            table.add_row(si.to_row_short_paths());
        }
    });

    table.printstd();

    Ok(())
}

#[allow(dead_code)]
fn list(config_path: PathBuf, show_full_path: bool) -> Result<(), errors::APIError> {
    let mut client = get_client(config_path)?;

    client.login()?;

    let data_stores_list = client.get_all_datastores()?;

    let mut datastores = Vec::<DataStore>::new();

    for dl in &data_stores_list {
        let dsr = client.get_datastore(&dl.id);
        if let Ok(d) = dsr {
            datastores.push(d);
        }
    }

    for mut d in &mut datastores {
        let share_map = match &d.share_index {
            Some(si) => Some(client.get_shares_by_index_par(&si)?),
            None => None,
        };

        if let Some(sm) = share_map {
            d.shares = sm;
        }

        let mut sl = d.get_secrets_list();
        sl.sort_by(|a, b| a.path.cmp(&b.path));
        let now = Instant::now();
        let secrets: Vec<Option<SecretValues>> = sl
            .par_iter()
            .map(|s| client.get_secret(&s.secret_id, &s.secret_key).ok())
            .collect();
        println!("{}", now.elapsed().as_millis());
        let mut table = Table::new();
        table.add_row(row![bFg => "Name", "Password", "Path", "ID"]);
        for (i, s) in (&sl).iter().enumerate() {
            let sv = secrets.get(i);
            let _password = match sv {
                Some(p) => match p {
                    Some(v) => v.website_password_password.as_ref(),
                    None => None,
                },
                None => None,
            };

            let p = match show_full_path {
                true => s.path.clone(),
                false => s.short_path(),
            };

            table.add_row(Row::new(vec![
                Cell::new(&s.name),
                Cell::new(p.join(",").as_ref()),
                Cell::new(&s.id),
            ]));
        }
        table.printstd();
    }

    Ok(())
}

fn config_show(config_path: PathBuf, raw: bool, full_private_keys: bool) -> Result<(), APIError> {
    let r = Config::load_unverified(&config_path);
    let mut stdout = StandardStream::stdout(ColorChoice::Always);

    if let Err(e) = r {
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
        writeln!(
            &mut stdout,
            "Could not open config '{}': {}",
            config_path.to_string_lossy(),
            e
        )
        .expect("could not write");
        return Ok(());
    }

    let mut config = r.expect("config_show: could not expect config_raw (should not be possible)");
    let validated = config.validate();

    if !full_private_keys {
        config = config.redacted_keys();
    }

    let config_toml = toml::to_string_pretty(&config)
        .expect("config toml failed, should not happen because it was loaded from toml");

    if !raw {
        let redacted_text = match full_private_keys {
            true => "",
            false => "Redacted ",
        };
        eprintln!(
            "{}Config at '{}':\n",
            redacted_text,
            config_path.to_string_lossy(),
        );
    }

    println!("{}", config_toml);

    if !raw {
        if let Err(e) = validated {
            eprintln!("{}", e);
        } else {
            eprintln!("Config is valid");
        };
    }

    Ok(())
}

fn config_create(config_path: PathBuf, overwrite: bool) -> Result<(), APIError> {
    if config_path.as_path().exists() && !overwrite {
        eprintln!(
            "Config at '{}' already exists and --overwrite not set",
            config_path.to_string_lossy(),
        );
        exit(1);
    }
    eprintln!("Create config at '{}':\n", config_path.to_string_lossy(),);
    let config = Config::from_stdin();

    if let Some(p) = config_path.as_path().parent() {
        if !p.exists() {
            if let Err(e) = create_dir_all(p) {
                eprintln!(
                    "Could not create path '{}' (needed as config dir): {}",
                    p.to_string_lossy(),
                    e,
                );
                exit(1);
            };
        }
    }

    match config.save(&config_path) {
        Ok(()) => {
            eprintln!("\nConfig written to '{}'", config_path.to_string_lossy());
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn config_template() -> Result<(), APIError> {
    let config_toml = toml::to_string_pretty(&Config::default())?;
    println!("{}", config_toml);
    Ok(())
}

fn config(config_path: PathBuf, cc: ConfigCommand) -> Result<(), APIError> {
    match cc {
        ConfigCommand::Show {
            raw,
            show_private_keys,
        } => config_show(config_path, raw, show_private_keys),
        ConfigCommand::Create { overwrite } => config_create(config_path, overwrite),
        ConfigCommand::Template {} => config_template(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum OutputData {
    All,
    Pwd,
    User,
    UserPwd,
}

fn print_as_json(matches_with_secrets: Vec<(SecretItem, SecretValues)>, output_data: OutputData) {
    let json_formatted: Vec<JSONValue> = matches_with_secrets
        .iter()
        .map(|(i, v)| match output_data {
            OutputData::All => v.to_json_all(&i.id),
            OutputData::UserPwd => v.to_json_user_pwd(&i.id),
            OutputData::User => v.to_json_user(&i.id),
            OutputData::Pwd => v.to_json_pwd(&i.id),
        })
        .collect();

    let output = if matches_with_secrets.len() == 1 {
        serde_json::to_string(&json_formatted[0])
    } else {
        serde_json::to_string(&json_formatted)
    };

    match output {
        Ok(o) => println!("{}", o),
        Err(e) => {
            eprintln!("Could not generate json output: {}", e);
            exit(1);
        }
    }
}

fn print_single(
    matches_with_secrets: &(SecretItem, SecretValues),
    output_data: OutputData,
    without_new_line: bool,
) {
    let output = match output_data {
        OutputData::Pwd => format!(
            "{}",
            &matches_with_secrets
                .1
                .website_password_password
                .as_ref()
                .unwrap_or(&String::from(""))
        ),
        OutputData::User => format!(
            "{}",
            &matches_with_secrets
                .1
                .website_password_username
                .as_ref()
                .unwrap_or(&String::from(""))
        ),
        _ => panic!("print_single called with {:?}", output_data),
    };

    if without_new_line {
        print!("{}", output);
    } else {
        println!("{}", output);
    }
}

fn print_as_table(matches_with_secrets: Vec<(SecretItem, SecretValues)>, output_data: OutputData) {
    let mut table = Table::new();

    match output_data {
        OutputData::All => {
            table.add_row(
                row![bFg => "ID", "Title", "User", "Password", "Notes", "URL", "URL Filter"],
            );
        }
        OutputData::UserPwd => {
            table.add_row(row![bFg => "ID", "Title", "User", "Password"]);
        }
        OutputData::User => {
            table.add_row(row![bFg => "ID", "Title", "User"]);
        }
        OutputData::Pwd => {
            table.add_row(row![bFg => "ID", "Title", "Password"]);
        }
    }

    for (i, v) in matches_with_secrets {
        match output_data {
            OutputData::All => {
                table.add_row(v.to_row_all(&i.id));
            }
            OutputData::UserPwd => {
                table.add_row(v.to_row_user_pwd(&i.id));
            }
            OutputData::User => {
                table.add_row(v.to_row_user(&i.id));
            }
            OutputData::Pwd => {
                table.add_row(v.to_row_pwd(&i.id));
            }
        }
    }

    table.printstd();
}

fn print_secret_values(
    config_path: PathBuf,
    ids: Vec<String>,
    output_data: OutputData,
    as_json: bool,
    without_new_line: bool,
) -> Result<(), APIError> {
    let mut client = get_client(config_path)?;
    client.login()?;

    let datastores = get_datastores_with_shares(&client)?;
    let matches: Vec<SecretItem> = datastores
        .iter()
        .map(|d| d.get_secrets_list())
        .flatten()
        .map(|s| (s.id.to_owned(), s))
        .filter(|(id, _)| ids.contains(&id.to_owned()))
        .map(|(_, s)| s)
        .collect();

    if matches.is_empty() {
        eprintln!("Nothing found");
        exit(1);
    }

    // load requested secrets
    let matches_with_secrets: Vec<(SecretItem, SecretValues)> = matches
        .into_par_iter()
        .map(
            |s| match client.get_secret(&s.secret_id.as_str(), &s.secret_key.as_str()) {
                Ok(sv) => (s, sv),
                Err(e) => {
                    eprintln!("Could not get secret values for '{}': {}", &s.id, e);
                    exit(1);
                }
            },
        )
        .collect();

    if as_json {
        print_as_json(matches_with_secrets, output_data);
        return Ok(());
    }

    if matches_with_secrets.len() == 1
        && (output_data == OutputData::Pwd || output_data == OutputData::User)
    {
        print_single(&matches_with_secrets[0], output_data, without_new_line);

        return Ok(());
    }

    print_as_table(matches_with_secrets, output_data);

    Ok(())
}

fn main() -> Result<(), errors::APIError> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(20)
        .build_global()
        .unwrap();

    let mut settings = Settings::from_args();
    settings.config_path = settings.config_path.or_else(default_config_dir);

    // TODO change to error
    let config_path = settings.config_path.ok_or(APIError::ConfigPathError {})?;

    match settings.command {
        Command::List { json, full_path } => {
            search(config_path, Vec::new(), json, full_path, false)
        }
        Command::Config { 0: config_command } => config(config_path, config_command),
        Command::Search {
            json,
            full_path,
            search_secrets,
            searches,
        } => search(config_path, searches, json, full_path, search_secrets),
        Command::Pwd {
            json,
            user,
            all,
            without_new_line,
            ids,
        } => {
            let output_data = if all {
                OutputData::All
            } else if user {
                OutputData::UserPwd
            } else {
                OutputData::Pwd
            };
            print_secret_values(config_path, ids, output_data, json, without_new_line)
        }
        Command::User {
            json,
            pwd,
            all,
            without_new_line,
            ids,
        } => {
            let output_data = if all {
                OutputData::All
            } else if pwd {
                OutputData::UserPwd
            } else {
                OutputData::User
            };
            print_secret_values(config_path, ids, output_data, json, without_new_line)
        }
        Command::All {
            json,
            without_new_line,
            ids,
        } => print_secret_values(config_path, ids, OutputData::All, json, without_new_line),
    }
}

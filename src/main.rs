use directories::ProjectDirs;
use rayon::prelude::*;
use std::path::PathBuf;
use std::time::Instant;

#[macro_use]
extern crate prettytable;
use prettytable::{Cell, Row, Table};

use structopt::StructOpt;

// Important: use at top of file so other mod files can also use the macro
#[macro_use]
mod macros;

mod api;
mod config;
mod crypto;
mod data_store;
mod errors;
mod login;
mod settings;

pub use settings::Settings;

pub use crypto::verify_signature;
pub use errors::APIError;

pub use login::{
    create_client_info_with_session_sk, decrypt_login_info, ClientInfo, LoginInfoEncrypted,
};

pub use data_store::{DataStore, DatastoreListEntry, SecretValues};

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

fn main() -> Result<(), errors::APIError> {
    let mut settings = Settings::from_args();
    settings.config_path = settings.config_path.or_else(default_config_dir);
    println!("{:#?}", settings);

    rayon::ThreadPoolBuilder::new()
        .num_threads(20)
        .build_global()
        .unwrap();

    let config = Config::load(PathBuf::from(r"./config_fa.toml"))?;

    let mut client = ApiClient::new(
        &config.server_url,
        &config.server_signature,
        &config.api_key_id,
        &config.api_key_private_key,
        &config.api_key_secret_key,
        config.danger_disable_tls,
    )?;

    println!("Try to login");

    let _login_info = client.login()?;

    println!("Logged in");

    let data_stores_list = client.get_all_datastores()?;
    // println!("Datastores: {:?}", data_stores_list);

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
        // println!("Secret List: {:#?}", sl);
        // let test = &sl[0];
        // let sv = client.get_secret(&test.secret_id, &test.secret_key);
        let now = Instant::now();
        let secrets: Vec<Option<SecretValues>> = sl
            .par_iter()
            .map(|s| client.get_secret(&s.secret_id, &s.secret_key).ok())
            .collect();
        println!("{}", now.elapsed().as_millis());
        // println!("Secret Value: {:#?}", sv);
        let mut table = Table::new();
        table.add_row(row![bFg => "Name", "Password", "Path", "ID"]);
        for (i, s) in (&sl).iter().enumerate() {
            let sv = secrets.get(i);
            let password = match sv {
                Some(p) => match p {
                    Some(v) => v.website_password_password.as_ref(),
                    None => None,
                },
                None => None,
            };
            table.add_row(Row::new(vec![
                Cell::new(&s.name),
                Cell::new(password.unwrap_or(&String::from(""))),
                Cell::new(&s.short_path().join(",")),
                Cell::new(&s.id),
            ]));
            // println!("{}\t{}\t{}", s.name, s.path.join(","), s.id);
        }
        table.printstd();
        // let ids: Vec<String> = sl.into_iter().map(|x| x.secret_id.to_owned()).collect();
        // println!("{}", ids.join("\n"));
    }

    // println!("Datastores: {:#?}", datastores);
    // println!("datastore shares keys: {:?}", datastores[0].shares.keys());

    Ok(())
}

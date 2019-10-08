use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use prettytable::{Cell, Row};
use serde_json::{json, Value as JSONValue};

pub use crate::crypto::*;
pub use crate::errors::*;

pub enum PsonoItemType {
    Password,
    Shared,
    Unknown,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
pub enum PsonoFolderType {
    Owned,
    Shared,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DataStoreEncrypted {
    pub data: String,
    pub data_nonce: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub description: String,
    pub secret_key: String,
    pub secret_key_nonce: String,
    pub is_default: bool,
}

// #[derive(Clone, Debug, Deserialize, Serialize)]
// pub struct DataStoreEncrypted {
//     pub text: String,
//     pub text_nonce: String,
// }

#[allow(dead_code)]
impl DataStoreEncrypted {
    pub fn open(&self, user_secret_key_hex: &str) -> Result<String, APIError> {
        let data_store_secret_raw = open_secret_box(
            &self.secret_key,
            &self.secret_key_nonce,
            user_secret_key_hex,
        )?;
        let data_store_secret = String::from_utf8(data_store_secret_raw)?;
        let data_raw = open_secret_box(&self.data, &self.data_nonce, &data_store_secret)?;
        let data = String::from_utf8(data_raw)?;

        Ok(data)
    }
}

pub type ShareIndex = HashMap<String, ShareIndexEntry>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataStore {
    #[serde(rename = "datastore_id")]
    pub id: String,
    #[serde(default)]
    pub folders: Vec<Folder>,
    #[serde(default)]
    pub share_index: Option<ShareIndex>,
    #[serde(default)]
    pub items: Vec<Item>,
    #[serde(default)]
    pub shares: HashMap<String, Share>,
}

fn share_secrets(path: &str, share: &Share) -> Vec<SecretItem> {
    let mut secret_items: Vec<SecretItem> = Vec::new();
    let new_path = format!("{}/{}", path, share.name);

    if share.secret_id.is_some() && share.secret_key.is_some() {
        let item = share
            .to_secret_item(&new_path)
            .expect("could not to_secret_item");
        secret_items.push(item);
    }

    if let Some(folders) = share.folders.as_ref() {
        for f in folders {
            secret_items.append(&mut folder_secrets(&new_path, f, share.sub_shares.as_ref()));
        }
    };

    if let Some(items) = share.items.as_ref() {
        for i in items {
            secret_items.append(&mut item_secrets(
                &new_path,
                i,
                share.sub_shares.as_ref().and_then(|s| s.get(&i.id)),
            ));
        }
    }

    secret_items
}

fn item_secrets(path: &str, item: &Item, share: Option<&Share>) -> Vec<SecretItem> {
    let mut secret_items: Vec<SecretItem> = Vec::new();
    let new_path = format!("{}/{}", path, item.name);

    if item.secret_id.is_some() && item.secret_key.is_some() {
        let item = item
            .to_secret_item(&new_path)
            .expect("could not to_secret_item");
        secret_items.push(item);
    } else if item.share_id.is_some() {
        if let Some(s) = share {
            secret_items.push(s.to_secret_item(&new_path).expect("to secret item error"));
        }
    }

    secret_items
}

#[allow(dead_code)]
fn folder_secrets(
    path: &str,
    folder: &Folder,
    shares: Option<&HashMap<String, Share>>,
) -> Vec<SecretItem> {
    let mut items: Vec<SecretItem> = Vec::new();
    let new_path = format!("{}/{}", path, folder.name);

    match folder.get_type() {
        PsonoFolderType::Shared => {
            let shared_folder =
                SharedFolder::from_folder(folder).expect("could not get shared_folder from folder");
            match shares.as_ref() {
                Some(sl) => match sl.get(&shared_folder.share_id) {
                    Some(s) => {
                        items.append(&mut share_secrets(&new_path, s));
                    }
                    None => {
                        println!(
                            "No share with id {} but {} is a shared folder",
                            &shared_folder.share_id, shared_folder.id
                        );
                    }
                },
                None => println!("No shares but {} is a shared folder", shared_folder.id),
            };
        }
        PsonoFolderType::Owned => {
            let owned_folder = OwnedFolder::from_folder(folder);
            for f in &owned_folder.folders {
                items.append(&mut folder_secrets(&new_path, f, None));
            }

            for i in &owned_folder.items {
                let share = match i.share_id.as_ref() {
                    Some(share_id) => shares.and_then(|x| x.get(share_id)),
                    None => None,
                };

                items.append(&mut item_secrets(&new_path, i, share));
            }
        }
    };

    items
}

impl DataStore {
    pub fn get_secrets_list(&self) -> Vec<SecretItem> {
        let mut secret_items: Vec<SecretItem> = Vec::new();
        let mut set: HashMap<String, SecretItem> = HashMap::new();
        let path = "";

        for f in &self.folders {
            secret_items.append(&mut folder_secrets(path, f, Some(&self.shares)));
        }

        for i in &self.items {
            let share = match i.share_id.as_ref() {
                Some(share_id) => self.shares.get(share_id),
                None => None,
            };
            secret_items.append(&mut item_secrets(&path, i, share));
        }

        for mut s in secret_items {
            if set.contains_key(&s.secret_id) {
                let v = set.get_mut(&s.secret_id).expect("hash get mut failed");
                if s.path != v.path {
                    v.path.append(&mut s.path);
                }
            } else {
                set.insert(s.secret_id.clone(), s);
            }
        }

        let secret_items_filtered: Vec<SecretItem> = set.into_iter().map(|(_k, v)| v).collect();

        secret_items_filtered
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShareIndexEntry {
    pub paths: Vec<Vec<String>>,
    pub secret_key: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Folder {
    pub name: String,
    #[serde(default)]
    pub share_id: Option<String>,
    #[serde(default)]
    pub share_secret_key: Option<String>,
    pub id: String,
    #[serde(default)]
    pub items: Vec<Item>,
    #[serde(default)]
    pub folders: Vec<Folder>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OwnedFolder {
    pub name: String,
    pub id: String,
    pub items: Vec<Item>,
    pub folders: Vec<Folder>,
}

#[allow(dead_code)]
impl OwnedFolder {
    pub fn from_folder(f: &Folder) -> Self {
        OwnedFolder {
            name: f.name.clone(),
            id: f.id.clone(),
            items: f.items.clone(),
            folders: f.folders.clone(),
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SharedFolder {
    pub name: String,
    pub id: String,
    pub share_id: String,
    pub share_secret_key: String,
}

#[allow(dead_code)]
impl SharedFolder {
    pub fn from_folder(f: &Folder) -> Result<Self, APIError> {
        let share_id = f.share_id.clone().ok_or(APIError::SharedFolderError {
            missing: "share_id".to_owned(),
        })?;
        let share_secret_key = f
            .share_secret_key
            .clone()
            .ok_or(APIError::SharedFolderError {
                missing: "share_secret_key".to_owned(),
            })?;

        Ok(SharedFolder {
            name: f.name.clone(),
            id: f.id.clone(),
            share_id,
            share_secret_key,
        })
    }
}

#[allow(dead_code)]
impl Folder {
    pub fn get_type(&self) -> PsonoFolderType {
        if self.share_id.is_some() && self.share_secret_key.is_some() {
            return PsonoFolderType::Shared;
        }

        PsonoFolderType::Owned
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Item {
    pub name: String,
    #[serde(default)]
    pub share_id: Option<String>,
    #[serde(default)]
    pub share_secret_key: Option<String>,
    pub id: String,
    #[serde(rename = "type")]
    #[serde(default)]
    pub type_field: Option<String>,
    #[serde(default)]
    pub secret_id: Option<String>,
    #[serde(default)]
    pub secret_key: Option<String>,
    #[serde(default)]
    pub urlfilter: Option<String>,
}

#[allow(dead_code)]
impl Item {
    pub fn get_type(&self) -> PsonoItemType {
        if self.share_id.is_some() && self.share_secret_key.is_some() {
            return PsonoItemType::Shared;
        }

        let is_password_type = match &self.type_field {
            Some(t) => t == "website_password",
            None => false,
        };

        if self.secret_id.is_some() && self.secret_key.is_some() && is_password_type {
            return PsonoItemType::Password;
        }

        PsonoItemType::Unknown
    }
    pub fn to_secret_item(&self, path: &str) -> Result<SecretItem, APIError> {
        let secret_id = self
            .secret_id
            .as_ref()
            .ok_or(APIError::OwnFolderError {
                missing: "secret_id".to_owned(),
            })?
            .clone();

        let secret_key = self
            .secret_key
            .as_ref()
            .ok_or(APIError::OwnFolderError {
                missing: "secret_key".to_owned(),
            })?
            .clone();

        Ok(SecretItem {
            id: self.id.to_string(),
            name: self.name.to_string(),
            path: vec![path.to_owned()],
            secret_id,
            secret_key,
            urlfilter: self.urlfilter.clone(),
        })
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OwnedItem {
    pub name: String,
    pub id: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub secret_id: String,
    pub secret_key: String,
    #[serde(default)]
    pub urlfilter: Option<String>,
}

#[allow(dead_code)]
impl OwnedItem {
    pub fn from_item(i: Item) -> Result<Self, APIError> {
        let type_field = i.type_field.ok_or(APIError::OwnFolderError {
            missing: "type_field".to_owned(),
        })?;
        let secret_id = i.secret_id.ok_or(APIError::OwnFolderError {
            missing: "secret_id".to_owned(),
        })?;
        let secret_key = i.secret_key.ok_or(APIError::OwnFolderError {
            missing: "secret_key".to_owned(),
        })?;

        Ok(OwnedItem {
            name: i.name,
            id: i.id,
            type_field,
            secret_id,
            secret_key,
            urlfilter: i.urlfilter,
        })
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DatastoreList {
    pub datastores: Vec<DatastoreListEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DatastoreListEntry {
    pub id: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub description: String,
    pub is_default: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Share {
    #[serde(default)]
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    #[serde(default)]
    pub type_field: Option<String>,
    #[serde(default)]
    pub secret_id: Option<String>,
    #[serde(default)]
    pub secret_key: Option<String>,
    #[serde(default)]
    pub urlfilter: Option<String>,
    #[serde(default)]
    pub share_secret_key: Option<String>,
    #[serde(default)]
    pub items: Option<Vec<Item>>,
    #[serde(default)]
    pub folders: Option<Vec<Folder>>,
    #[serde(default)]
    pub share_index: Option<ShareIndex>,
    #[serde(default)]
    pub sub_shares: Option<HashMap<String, Share>>,
}

impl Share {
    pub fn to_secret_item(&self, path: &str) -> Result<SecretItem, APIError> {
        let secret_id = self
            .secret_id
            .as_ref()
            .ok_or(APIError::OwnFolderError {
                missing: "secret_id".to_owned(),
            })?
            .clone();

        let secret_key = self
            .secret_key
            .as_ref()
            .ok_or(APIError::OwnFolderError {
                missing: "secret_key".to_owned(),
            })?
            .clone();

        Ok(SecretItem {
            id: self.id.to_owned(),
            name: self.name.to_owned(),
            path: vec![path.to_owned()],
            secret_id,
            secret_key,
            urlfilter: self.urlfilter.clone(),
        })
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct SecretItem {
    pub id: String,
    pub name: String,
    pub path: Vec<String>,
    #[serde(skip_serializing)]
    pub secret_id: String,
    #[serde(skip_serializing)]
    pub secret_key: String,
    #[serde(skip_serializing)]
    pub urlfilter: Option<String>,
}

impl SecretItem {
    pub fn contains(&self, search: &str) -> bool {
        if self.name.to_lowercase().contains(search) {
            return true;
        }

        if let Some(uf) = &self.urlfilter {
            if uf.to_lowercase().contains(search) {
                return true;
            }
        }

        for p in &self.path {
            if p.to_lowercase().contains(search) {
                return true;
            }
        }

        false
    }
    pub fn short_path(&self) -> Vec<String> {
        let short_paths: Vec<String> = self
            .path
            .iter()
            .map(|p| {
                let sub_paths: Vec<String> = p.split('/').map(|s| s.to_string()).collect();
                match sub_paths.len() {
                    0 | 1 | 2 | 3 => sub_paths.join("/"),
                    _ => format!(
                        "{}/{}/.../{}",
                        sub_paths.first().unwrap(),
                        sub_paths.get(1).unwrap(),
                        sub_paths.last().unwrap()
                    ),
                }
            })
            .collect();

        short_paths
    }
    pub fn to_row_short_paths(&self) -> Row {
        Row::new(vec![
            Cell::new(&self.name),
            Cell::new(&self.short_path().join(",")),
            Cell::new(&self.id),
        ])
    }
    pub fn to_row(&self) -> Row {
        Row::new(vec![
            Cell::new(&self.name),
            Cell::new(&self.path.join(",")),
            Cell::new(&self.id),
        ])
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretValues {
    pub website_password_url_filter: Option<String>,
    pub website_password_notes: Option<String>,
    pub website_password_password: Option<String>,
    pub website_password_username: Option<String>,
    pub website_password_url: Option<String>,
    pub website_password_title: Option<String>,
}

impl SecretValues {
    pub fn contains(&self, search: &str) -> bool {
        if let Some(s) = &self.website_password_url_filter {
            if s.to_lowercase().contains(search) {
                return true;
            }
        }

        if let Some(s) = &self.website_password_notes {
            if s.to_lowercase().contains(search) {
                return true;
            }
        }

        if let Some(s) = &self.website_password_username {
            if s.to_lowercase().contains(search) {
                return true;
            }
        }

        if let Some(s) = &self.website_password_password {
            if s.to_lowercase().contains(search) {
                return true;
            }
        }

        if let Some(s) = &self.website_password_url {
            if s.to_lowercase().contains(search) {
                return true;
            }
        }

        if let Some(s) = &self.website_password_title {
            if s.to_lowercase().contains(search) {
                return true;
            }
        }

        false
    }
    pub fn to_row_all(&self, id: &str) -> Row {
        let empty = String::from("");
        Row::new(vec![
            Cell::new(id),
            Cell::new(&self.website_password_title.as_ref().unwrap_or(&empty)),
            Cell::new(&self.website_password_username.as_ref().unwrap_or(&empty)),
            Cell::new(&self.website_password_password.as_ref().unwrap_or(&empty)),
            Cell::new(&self.website_password_notes.as_ref().unwrap_or(&empty)),
            Cell::new(&self.website_password_url.as_ref().unwrap_or(&empty)),
            Cell::new(&self.website_password_url_filter.as_ref().unwrap_or(&empty)),
        ])
    }
    pub fn to_row_user_pwd(&self, id: &str) -> Row {
        let empty = String::from("");
        Row::new(vec![
            Cell::new(id),
            Cell::new(&self.website_password_title.as_ref().unwrap_or(&empty)),
            Cell::new(&self.website_password_username.as_ref().unwrap_or(&empty)),
            Cell::new(&self.website_password_password.as_ref().unwrap_or(&empty)),
        ])
    }
    pub fn to_row_user(&self, id: &str) -> Row {
        let empty = String::from("");
        Row::new(vec![
            Cell::new(id),
            Cell::new(&self.website_password_title.as_ref().unwrap_or(&empty)),
            Cell::new(&self.website_password_username.as_ref().unwrap_or(&empty)),
        ])
    }
    pub fn to_row_pwd(&self, id: &str) -> Row {
        let empty = String::from("");
        Row::new(vec![
            Cell::new(id),
            Cell::new(&self.website_password_title.as_ref().unwrap_or(&empty)),
            Cell::new(&self.website_password_password.as_ref().unwrap_or(&empty)),
        ])
    }
    pub fn to_json_all(&self, id: &str) -> JSONValue {
        json!({
            "id": id,
            "title": &self.website_password_title,
            "username": &self.website_password_username,
            "password": &self.website_password_password,
            "notes": &self.website_password_notes,
            "url": &self.website_password_url,
            "url_filter": &self.website_password_url_filter,
        })
    }
    pub fn to_json_user_pwd(&self, id: &str) -> JSONValue {
        json!({
            "id": id,
            "title": &self.website_password_title,
            "username": &self.website_password_username,
            "password": &self.website_password_password
        })
    }
    pub fn to_json_user(&self, id: &str) -> JSONValue {
        json!({
            "id": id,
            "title": &self.website_password_title,
            "username": &self.website_password_username,
        })
    }
    pub fn to_json_pwd(&self, id: &str) -> JSONValue {
        json!({
            "id": id,
            "title": &self.website_password_title,
            "password": &self.website_password_password
        })
    }
}

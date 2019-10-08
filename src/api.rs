use std::collections::HashMap;

use rayon::prelude::*;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use reqwest::header::AUTHORIZATION;
use reqwest::{Client, Method, Url};

use crate::crypto::open_secret_box;
use crate::data_store::{
    DataStore, DataStoreEncrypted, DatastoreList, DatastoreListEntry, SecretValues, Share,
    ShareIndex,
};
use crate::errors::*;
use crate::login::{create_client_info_with_session_sk, LoginInfo, LoginInfoEncrypted};

pub struct ApiClient {
    client: Client,

    origin: String,

    server_signature_hex: String,

    api_key_id: String,
    api_secret_key_hex: String,
    api_private_key_hex: String,

    pub user_private_key_hex: Option<String>,
    user_secret_key_hex: Option<String>,

    session_box_sk_hex: Option<Box<String>>,
    session_secretbox_sk_hex: Option<String>,
    token: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct NoData {}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ApiResultEncrypted {
    nonce: String,
    text: String,
}

impl ApiResultEncrypted {
    fn open(&self, session_secret_key_hex: &str) -> Result<String, APIError> {
        let raw = open_secret_box(&self.text, &self.nonce, session_secret_key_hex)?;
        let data = String::from_utf8(raw)?;

        Ok(data)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SecretMessage {
    data: String,
    data_nonce: String,
}

impl SecretMessage {
    fn open(&self, secret_key_hex: &str) -> Result<String, APIError> {
        let raw = open_secret_box(&self.data, &self.data_nonce, secret_key_hex)?;
        let data = String::from_utf8(raw)?;

        Ok(data)
    }
}

pub enum ApiEndpoint {
    Login,
    Datastores,
    Share,
    Secret,
}

#[allow(dead_code)]
impl ApiEndpoint {
    pub fn as_str(&self) -> &str {
        match *self {
            Self::Login => "api-key/login/",
            Self::Datastores => "datastore/",
            Self::Share => "share/",
            Self::Secret => "secret/",
        }
    }
    pub fn as_method(&self) -> Method {
        match *self {
            Self::Login => Method::POST,
            Self::Datastores => Method::GET,
            Self::Share => Method::GET,
            Self::Secret => Method::GET,
        }
    }
}

// #[allow(dead_code)]
// fn call_async<'a, T: Serialize>(
//     token: Option<&str>,
//     origin: &str,
//     session_secretbox_sk_hex: Option<&'a str>,
//     method: Method,
//     path: &str,
//     body: Option<&T>,
// ) -> impl Future<Item = String, Error = APIError> + 'a {
//     let url = format!("{}/{}", origin, path);
//     let url_parsed = Url::parse(&url).expect("could not parse url");

//     let client = AsyncClient::new();

//     let mut rb = client.request(method, url_parsed);

//     rb = match token {
//         Some(token) => rb.header(AUTHORIZATION, format!("Token {}", token)),
//         None => rb,
//     };

//     rb = match body {
//         Some(data) => rb.json(data),
//         None => rb,
//     };

//     let mut status = Default::default();

//     rb.send()
//         .and_then(move |mut res| {
//             status = res.status();
//             res.text()
//         })
//         .then(
//             move |content_res: Result<String, reqwest::Error>| -> Result<String, APIError> {
//                 let mut content = match content_res {
//                     Ok(c) => c,
//                     Err(e) => return Err(APIError::ReqwuestError { error: e }),
//                 };

//                 content = match session_secretbox_sk_hex {
//                     Some(sk) => {
//                         let msg_encrypted = serde_json::from_str::<ApiResultEncrypted>(&content);
//                         match msg_encrypted {
//                             Ok(c) => c.open(&sk)?,
//                             Err(_) => content,
//                         }
//                     }
//                     None => content,
//                 };

//                 if !status.is_success() {
//                     let reason = status.canonical_reason().unwrap_or("").to_owned();

//                     return Err(APIError::CallError {
//                         content,
//                         status: status.as_str().to_owned(),
//                         reason,
//                     });
//                 }

//                 Ok(content)
//             },
//         )
// }

impl<'a> ApiClient {
    #[allow(dead_code)]
    pub fn new(
        origin: &str,
        server_signature_hex: &str,
        api_key_id: &str,
        api_private_key_hex: &str,
        api_secret_key_hex: &str,
        danger_disable_tls: bool,
    ) -> Result<Self, APIError> {
        Url::parse(origin)?;
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(!danger_disable_tls)
            .build()?;

        Ok(ApiClient {
            client,
            origin: origin.to_owned(),
            server_signature_hex: server_signature_hex.to_owned(),
            api_key_id: api_key_id.to_owned(),
            api_secret_key_hex: api_secret_key_hex.to_owned(),
            api_private_key_hex: api_private_key_hex.to_owned(),
            user_private_key_hex: None,
            user_secret_key_hex: None,
            session_box_sk_hex: None,
            session_secretbox_sk_hex: None,
            token: None,
        })
    }

    #[allow(dead_code)]
    fn is_logged_in(&'a self) -> Option<&'a str> {
        self.token.as_ref()?;
        self.user_private_key_hex.as_ref()?;
        self.user_secret_key_hex.as_ref()?;
        self.session_secretbox_sk_hex.as_ref().map(|s| s.as_str())
        // Some(self.session_secretbox_sk_hex.as_ref()?.as_str())
    }

    fn call<T: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
    ) -> Result<String, APIError> {
        let url = format!("{}/{}", self.origin, path);
        let url_parsed = Url::parse(&url)?;

        let mut rb = self.client.request(method, url_parsed);

        rb = match self.token.as_ref() {
            Some(token) => rb.header(AUTHORIZATION, format!("Token {}", token)),
            None => rb,
        };

        rb = match body {
            Some(data) => rb.json(data),
            None => rb,
        };

        let mut resp = rb.send()?;

        let status = resp.status();

        let mut content = resp.text()?;

        content = match &self.session_secretbox_sk_hex {
            Some(sk) => {
                let msg_encrypted = serde_json::from_str::<ApiResultEncrypted>(&content);
                match msg_encrypted {
                    Ok(c) => c.open(&sk)?,
                    Err(_) => content,
                }
            }
            None => content,
        };

        if !status.is_success() {
            let reason = status.canonical_reason().unwrap_or("").to_owned();

            return Err(APIError::CallError {
                content,
                status: status.as_str().to_owned(),
                reason,
            });
        }

        Ok(content)
    }

    #[allow(dead_code)]
    pub fn login(&mut self) -> Result<LoginInfo, APIError> {
        let (session_box_sk_hex, client_info_signed) =
            create_client_info_with_session_sk(&self.api_private_key_hex, &self.api_key_id)?;

        let content = self.call(
            ApiEndpoint::Login.as_method(),
            ApiEndpoint::Login.as_str(),
            Some(&client_info_signed),
        )?;

        let login_info_encrypted: LoginInfoEncrypted = serde_json::from_str(&content)?;

        let login_info =
            login_info_encrypted.open(&self.server_signature_hex, &session_box_sk_hex)?;

        self.session_box_sk_hex = Some(Box::new(session_box_sk_hex));
        self.session_secretbox_sk_hex = Some(login_info.session_secret_key.clone());

        self.user_private_key_hex = Some(login_info.open_private_key(&self.api_secret_key_hex)?);
        self.user_secret_key_hex = Some(login_info.open_secret_key(&self.api_secret_key_hex)?);

        self.token = Some(login_info.token.clone());

        Ok(login_info)
    }

    #[allow(dead_code)]
    pub fn get_all_datastores(&self) -> Result<Vec<DatastoreListEntry>, APIError> {
        self.is_logged_in().ok_or(APIError::TokenError {})?;

        let content = self.call(
            ApiEndpoint::Datastores.as_method(),
            ApiEndpoint::Datastores.as_str(),
            None::<&NoData>,
        )?;
        let data_store_list: DatastoreList = serde_json::from_str(&content)?;
        let password_stores: Vec<DatastoreListEntry> = data_store_list
            .datastores
            .into_iter()
            .filter(|x| x.type_field == "password")
            .collect();

        Ok(password_stores)
    }

    pub fn get_datastore(&self, id: &str) -> Result<DataStore, APIError> {
        self.is_logged_in().ok_or(APIError::TokenError {})?;
        let user_secret_key = self
            .user_secret_key_hex
            .as_ref()
            .ok_or(APIError::TokenError {})?;

        let path = format!("{}/{}/", ApiEndpoint::Datastores.as_str(), id);

        let content = self.call(ApiEndpoint::Datastores.as_method(), &path, None::<&NoData>)?;

        let data_store_encrypted: DataStoreEncrypted = serde_json::from_str(&content)?;
        let data_store_opened = data_store_encrypted.open(user_secret_key)?;
        let data_store: DataStore = serde_json::from_str(&data_store_opened)?;

        Ok(data_store)
    }

    pub fn get_secret(&self, id: &str, secret_key_hex: &str) -> Result<SecretValues, APIError> {
        self.is_logged_in().ok_or(APIError::TokenError {})?;
        let path = format!("{}{}/", ApiEndpoint::Secret.as_str(), id);

        let content = self.call(ApiEndpoint::Secret.as_method(), &path, None::<&NoData>)?;
        let secret_encrypted: SecretMessage = serde_json::from_str(&content)?;
        let secret_open = &secret_encrypted.open(&secret_key_hex)?;
        let secret: SecretValues = serde_json::from_str(&secret_open)?;

        Ok(secret)
    }

    pub fn get_share(&self, id: &str, share_secret_key_hex: &str) -> Result<Share, APIError> {
        self.is_logged_in().ok_or(APIError::TokenError {})?;
        let path = format!("{}{}/", ApiEndpoint::Share.as_str(), id);

        let content = self.call(ApiEndpoint::Share.as_method(), &path, None::<&NoData>)?;
        let share_encrypted: SecretMessage = serde_json::from_str(&content)?;
        let share_open = &share_encrypted.open(&share_secret_key_hex)?;
        let mut share: Share = serde_json::from_str(&share_open)?;
        share.id = id.to_owned();

        Ok(share)
    }

    pub fn get_shares_by_index(
        &self,
        share_index: &ShareIndex,
    ) -> Result<HashMap<String, Share>, APIError> {
        let mut shares: HashMap<String, Share> = HashMap::new();

        for (share_id, share_index_data) in share_index {
            let mut share = match self.get_share(share_id, &share_index_data.secret_key) {
                Ok(s) => s,
                Err(_e) => {
                    // println!("Skipping share {}: {}", &share_id, e);
                    continue;
                }
            };
            if let Some(si) = share.share_index.as_ref() {
                share
                    .sub_shares
                    .get_or_insert(HashMap::new())
                    .extend(self.get_shares_by_index(si)?);
            }

            shares.insert(share_id.to_owned(), share);
        }

        Ok(shares)
    }

    pub fn get_shares_by_index_par(
        &self,
        share_index: &ShareIndex,
    ) -> Result<HashMap<String, Share>, APIError> {
        let shares: HashMap<String, Share> = HashMap::new();
        let shares_locked = Arc::new(Mutex::new(shares));
        share_index
            .par_iter()
            .for_each(|(share_id, share_index_data)| {
                let mut share = match self.get_share(share_id, &share_index_data.secret_key) {
                    Ok(s) => s,
                    Err(_e) => {
                        // println!("Skipping share {}: {}", &share_id, e);
                        return;
                    }
                };
                if let Some(si) = share.share_index.as_ref() {
                    match self.get_shares_by_index(si) {
                        Ok(sub_share) => {
                            share
                                .sub_shares
                                .get_or_insert(HashMap::new())
                                .extend(sub_share);
                        }
                        Err(e) => println!("Sub share error: {}", e),
                    };
                }

                shares_locked
                    .lock()
                    .unwrap()
                    .insert(share_id.to_owned(), share);
            });

        let guard = Arc::try_unwrap(shares_locked).expect("could not get guard");
        let shares = guard.into_inner().expect("could not get shares from guard");
        Ok(shares)
    }

    // pub fn get_shares_by_index_con<'b>(
    //     &self,
    //     share_index: ShareIndex,
    // ) -> Result<HashMap<String, Share>, APIError> {
    //     let shares: HashMap<String, Share> = HashMap::new();
    //     let token = self.token.clone();
    //     let origin = self.origin.clone();
    //     let session_secretbox_sk_hex = self.session_secretbox_sk_hex.clone();

    //     let bodies = stream::iter_ok(share_index)
    //         .map(move |(share_id, share_index_data)| {
    //             let path = format!("{}{}/", ApiEndpoint::Share.as_str(), share_id);
    //             call_async(
    //                 token.as_ref().map(String::as_str),
    //                 &origin,
    //                 session_secretbox_sk_hex.as_ref().map(String::as_str),
    //                 ApiEndpoint::Share.as_method(),
    //                 &path,
    //                 None::<&NoData>,
    //             )
    //             .and_then(move |content| {
    //                 let share_encrypted: SecretMessage = serde_json::from_str(&content)?;
    //                 let share_open = &share_encrypted.open(&share_index_data.secret_key)?;
    //                 let share: Share = serde_json::from_str(&share_open)?;

    //                 Ok(share)
    //             })
    //         })
    //         .buffer_unordered(10);

    //     let work = bodies
    //         .for_each(|b| {
    //             println!("Got {:?} bytes", b);
    //             Ok(())
    //         })
    //         .map_err(|e| panic!("Error while processing: {}", e));

    //     let mut rt = Runtime::new().expect("Failed to create runtime");
    //     rt.block_on(work);

    //     Ok(shares)
    // }
}

// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[macro_use]
extern crate unwrap;

use futures::{stream, Future, Stream};
use log::{debug, info};
use maidsafe_utilities::serialisation::deserialise;
use routing::{ClientError, User};
use safe_authenticator::ipc::{decode_ipc_msg, update_container_perms};
use safe_authenticator::revocation::revoke_app as safe_authenticator_revoke_app;
use safe_authenticator::{
    access_container, app_auth::authenticate, config, errors::AuthError, run as auth_run_helper,
    Authenticator,
};
use safe_core::client::Client;
use safe_core::ipc::req::{
    AppExchangeInfo, AuthReq, ContainerPermissions, ContainersReq, IpcReq, ShareMDataReq,
};
use safe_core::ipc::resp::{AccessContainerEntry, IpcResp};
use safe_core::ipc::{access_container_enc_key, decode_msg, encode_msg, IpcError, IpcMsg};
use safe_core::utils::symmetric_decrypt;
use safe_core::{client as safe_core_client, CoreError};
use safe_nd::PublicKey;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

#[derive(Debug)]
pub struct AuthedAppsList {
    pub app: AppExchangeInfo,
    pub perms: Vec<(String, ContainerPermissions)>,
}

// Type of the function/callback invoked for querying if an authorisation request shall be allowed.
// All the relevant information about the authorisation request is passed as args to the callback.
pub type AuthAllowPrompt = Fn(IpcReq) -> bool + std::marker::Send + std::marker::Sync;

/// # Create Account
/// Creates a new account on the SAFE Network.
/// Returns an error if an account exists or if there was some
/// problem during the account creation process.
///
/// Note: This does _not_ perform any strength checks on the
/// strings used to create the account.
///
/// ## Example
/// ```
/// use safe_auth::create_acc;
/// # fn random_str() -> String { (0..4).map(|_| rand::random::<char>()).collect() }
/// # fn main() -> Result<(), String> {
///     let my_secret = "mysecretstring";
///     let my_password = "mypassword";
/// #   let my_secret = &(random_str());
/// #   let my_password = &(random_str());
///     let auth = create_acc("anInvite", my_secret, my_password)?;
/// #   Ok(())
/// # }
///```
///
/// ## Error Example
/// If an account with same secret already exists,
/// the function will return an error:
/// ```
/// use safe_auth::create_acc;
/// # fn random_str() -> String { (0..4).map(|_| rand::random::<char>()).collect() }
/// /// Using an already existing account's secret and password:
/// let my_secret = "mysecretstring";
/// let my_password = "mypassword";
/// # let my_secret = &(random_str());
/// # let my_password = &(random_str());
/// # create_acc("anInvite", my_secret, my_password).unwrap();
/// let acc_not_created = create_acc("anInvite", my_secret, my_password);
/// match acc_not_created {
///    Ok(_) => assert!(false), // This should not pass
///    Err(message) => {
///         assert!(message.contains("Failed to create an account"));
///     }
/// }
///```
pub fn create_acc(invite: &str, secret: &str, password: &str) -> Result<Authenticator, String> {
    debug!("Attempting to create a SAFE account...");
    match Authenticator::create_acc(secret, password, invite, || {
        eprintln!("{}", "Disconnected from network");
    }) {
        Ok(auth) => {
            debug!("Returning account just created");
            Ok(auth)
        }
        Err(err) => Err(format!("Failed to create an account: {:?}", err)),
    }
}

/// # Log in
///
/// Using an account already created, you can log in to
/// the SAFE Network and return an `Authenticator` instance.
///
/// ## Example
/// ```
/// # use safe_auth::create_acc;
/// use safe_auth::log_in;
/// # fn random_str() -> String { (0..4).map(|_| rand::random::<char>()).collect() }
/// /// Using an already existing account's secret and password:
/// let my_secret = "mysecretstring";
/// let my_password = "mypassword";
/// # let my_secret = &(random_str());
/// # let my_password = &(random_str());
/// # create_acc("anInvite", my_secret, my_password).unwrap();
/// let logged_in = log_in(my_secret, my_password);
/// match logged_in {
///    Ok(_) => assert!(true), // This should pass
///    Err(_) => assert!(false)
/// }
///```
///
/// ## Error Example
/// If the account does not exist, the function will return an appropriate error:
///```
/// # use safe_auth::log_in;
/// let not_logged_in = log_in("non", "existant");
/// match not_logged_in {
///    Ok(_) => assert!(false), // This should not pass
///    Err(message) => {
///         assert!(message.contains("Failed to log in"));
///    }
/// }
///```
pub fn log_in(secret: &str, password: &str) -> Result<Authenticator, String> {
    debug!("Attempting to log in...");
    match Authenticator::login(secret, password, || eprintln!("Disconnected from network")) {
        Ok(auth) => {
            debug!("Returning logged-in Authenticator instance");
            Ok(auth)
        }
        Err(err) => Err(format!("Failed to log in: {:?}", err)),
    }
}

/// # Authorise an application
///
/// Using an account already created, you can log in to
/// the SAFE Network and authorise an application.
///
/// ## Example
/// ```
/// # use safe_auth::create_acc;
/// use safe_auth::{log_in, authorise_app};
/// # fn random_str() -> String { (0..4).map(|_| rand::random::<char>()).collect() }
/// /// Using an already existing account's secret and password:
/// let my_secret = "mysecretstring";
/// let my_password = "mypassword";
/// # let my_secret = &(random_str());
/// # let my_password = &(random_str());
/// # create_acc("anInvite", my_secret, my_password).unwrap();
/// let auth_req = "bAAAAAAFBMHKYWAAAAAABWAAAAAAAAAAANZSXILTNMFUWI43BMZSS45DFON2C453FMJQXA4BONFSAACYAAAAAAAAAABLWKYSBOBYCAVDFON2A2AAAAAAAAAAAJVQWSZCTMFTGKICMORSC4AACAAAAAAAAAAAAUAAAAAAAAAAAL5SG6Y3VNVSW45DTAEAAAAAAAAAAAAIAAAAAOAAAAAAAAAAAL5YHKYTMNFRQCAAAAAAAAAAAAAAAAAAB";
/// let authenticator = log_in(my_secret, my_password).unwrap();
/// let auth_response = authorise_app(&authenticator, auth_req, &|_| true);
/// match auth_response {
///    Ok(_) => assert!(true), // This should pass
///    Err(_) => assert!(false)
/// }
///```
/// ## Error Example
/// ```
/// # use safe_auth::create_acc;
/// use safe_auth::{log_in, authorise_app};
/// # fn random_str() -> String { (0..4).map(|_| rand::random::<char>()).collect() }
/// /// Using an already existing account's secret and password:
/// let my_secret = "mysecretstring";
/// let my_password = "mypassword";
/// # let my_secret = &(random_str());
/// # let my_password = &(random_str());
/// # create_acc("anInvite", my_secret, my_password).unwrap();
/// /// Using an invalid auth request string
/// let auth_req = "invalid-auth-req-string";
/// let authenticator = log_in(my_secret, my_password).unwrap();
/// let auth_response = authorise_app(&authenticator, auth_req, &|_| true);
/// match auth_response {
///    Ok(_) => assert!(false), // This should not pass
///    Err(message) => assert!(message.contains("EncodeDecodeError"))
/// }
///```
pub fn authorise_app(
    authenticator: &Authenticator,
    req: &str,
    allow: &'static AuthAllowPrompt,
) -> Result<String, String> {
    let req_msg = match decode_msg(req) {
        Ok(msg) => msg,
        Err(err) => {
            return Err(format!(
                "Failed to decode the auth request string: {:?}",
                err
            ));
        }
    };
    debug!("Auth request string decoded: {:?}", req_msg);

    let ipc_req = unwrap!(auth_run_helper(
        authenticator,
        move |client| decode_ipc_msg(client, req_msg)
    ));
    match ipc_req {
        Ok(IpcMsg::Req {
            req: IpcReq::Auth(app_auth_req),
            req_id,
        }) => {
            info!("Request was recognised as a general app auth request");
            debug!("Decoded request (req_id={:?}): {:?}", req_id, app_auth_req);
            debug!("Checking if the authorisation shall be allowed...");
            if !allow(IpcReq::Auth(app_auth_req.clone())) {
                debug!("Authorisation request was denied!");
                return gen_auth_denied_response(req_id);
            }

            debug!("Allowed!. Attempting to authorise application...");
            gen_auth_response(authenticator, req_id, app_auth_req)
        }
        Ok(IpcMsg::Req {
            req: IpcReq::Containers(cont_req),
            req_id,
        }) => {
            info!("Request was recognised as a containers auth request");
            debug!("Decoded request (req_id={:?}): {:?}", req_id, cont_req);

            debug!("Checking if the containers authorisation shall be allowed...");
            if !allow(IpcReq::Containers(cont_req.clone())) {
                debug!("Authorisation request was denied!");
                return gen_auth_denied_response(req_id);
            }

            debug!("Allowed!. Attempting to grant permissions to the containers...");
            gen_cont_auth_response(authenticator, req_id, cont_req)
        }
        Ok(IpcMsg::Req {
            req: IpcReq::Unregistered(user_data),
            req_id,
        }) => {
            info!("Request was recognised as an unregistered auth request");
            debug!("Decoded request (req_id={:?}): {:?}", req_id, user_data);

            debug!("Checking if the authorisation shall be allowed...");
            if !allow(IpcReq::Unregistered(user_data)) {
                debug!("Authorisation request was denied!");
                return gen_auth_denied_response(req_id);
            }

            debug!("Allowed!");
            gen_unreg_auth_response(req_id)
        }
        Ok(IpcMsg::Req {
            req: IpcReq::ShareMData(share_mdata_req),
            req_id,
        }) => {
            info!("Request was recognised as a share MD auth request");
            debug!(
                "Decoded request (req_id={:?}): {:?}",
                req_id, share_mdata_req
            );

            debug!("Checking if the authorisation to share a MD shall be allowed...");
            if !allow(IpcReq::ShareMData(share_mdata_req.clone())) {
                debug!("Authorisation request was denied!");
                return gen_auth_denied_response(req_id);
            }

            debug!("Allowed!. Attempting to grant permissions to the MD...");
            gen_shared_md_auth_response(authenticator, req_id, share_mdata_req)
        }
        Err((error_code, description, _err)) => Err(format!(
            "Failed decoding the auth request: {} - {:?}",
            error_code, description
        )),
        Ok(IpcMsg::Resp { .. }) | Ok(IpcMsg::Revoked { .. }) | Ok(IpcMsg::Err(..)) => Err(
            String::from("The request was not recognised as a valid auth request"),
        ),
    }
}

/// # Get account info
///
/// Using an account already created, you can log in to
/// the SAFE Network and get account info.
/// Currently only PUTs balance is available, i.e. PUTs done and available.
///
/// ## Example
/// ```
/// # use safe_auth::create_acc;
/// use safe_auth::{log_in, acc_info};
/// # fn random_str() -> String { (0..4).map(|_| rand::random::<char>()).collect() }
/// /// Using an already existing account's secret and password:
/// let my_secret = "mysecretstring";
/// let my_password = "mypassword";
/// # let my_secret = &(random_str());
/// # let my_password = &(random_str());
/// # create_acc("anInvite", my_secret, my_password).unwrap();
/// let authenticator = log_in(my_secret, my_password).unwrap();
/// let acc_info = acc_info(&authenticator);
/// match acc_info {
///    Ok((done, available)) => assert!(true), // This should pass
///    Err(_) => assert!(false)
/// }
///```
pub fn acc_info(authenticator: &Authenticator) -> Result<(u64, u64), String> {
    debug!("Attempting to get account info...");
    let acc_info = unwrap!(auth_run_helper(authenticator, move |client| client
        .get_account_info()
        .map_err(AuthError::from)));
    debug!("Account's info obtained: {:?}", acc_info);

    Ok((acc_info.mutations_done, acc_info.mutations_available))
}

/// # Get the list of applications authorised by this account
///
/// Using an account already created, you can log in to
/// the SAFE Network and get the list of all the applications that have
/// been authorised so far.
///
/// ## Example
/// ```
/// # use safe_auth::{create_acc, authorise_app};
/// use safe_auth::{log_in, authed_apps};
/// # fn random_str() -> String { (0..4).map(|_| rand::random::<char>()).collect() }
/// /// Using an already existing account which has been used
/// /// to authorise some application already:
/// let my_secret = "mysecretstring";
/// let my_password = "mypassword";
/// # let my_secret = &(random_str());
/// # let my_password = &(random_str());
/// # create_acc("anInvite", my_secret, my_password).unwrap();
/// let authenticator = log_in(my_secret, my_password).unwrap();
/// # let auth_req = "bAAAAAAFBMHKYWAAAAAABWAAAAAAAAAAANZSXILTNMFUWI43BMZSS45DFON2C453FMJQXA4BONFSAACYAAAAAAAAAABLWKYSBOBYCAVDFON2A2AAAAAAAAAAAJVQWSZCTMFTGKICMORSC4AACAAAAAAAAAAAAUAAAAAAAAAAAL5SG6Y3VNVSW45DTAEAAAAAAAAAAAAIAAAAAOAAAAAAAAAAAL5YHKYTMNFRQCAAAAAAAAAAAAAAAAAAB";
/// # authorise_app(&authenticator, auth_req, &|_| true).unwrap();
/// /// Get the list of authorised apps
/// let authed_apps = authed_apps(&authenticator);
/// match authed_apps {
///    Ok(_) => assert!(true), // This should pass
///    Err(_) => assert!(false)
/// }
///```
pub fn authed_apps(authenticator: &Authenticator) -> Result<Vec<AuthedAppsList>, String> {
    debug!("Attempting to fetch list of authorised apps...");
    let authed_apps = unwrap!(auth_run_helper(authenticator, move |client| {
        let c2 = client.clone();
        let c3 = client.clone();
        config::list_apps(client)
            .map(move |(_, auth_cfg)| (c2.access_container(), auth_cfg))
            .and_then(move |(access_container, auth_cfg)| {
                c3.list_mdata_entries(access_container.name, access_container.type_tag)
                    .map_err(From::from)
                    .map(move |entries| (access_container, entries, auth_cfg))
            })
            .and_then(move |(access_container, entries, auth_cfg)| {
                let nonce = access_container
                    .nonce()
                    .ok_or_else(|| AuthError::from("No nonce on access container's MDataInfo"))?;

                let mut apps = Vec::new();
                for app in auth_cfg.values() {
                    let key = access_container_enc_key(&app.info.id, &app.keys.enc_key, nonce)?;

                    // Empty entry means it has been deleted.
                    let entry = match entries.get(&key) {
                        Some(entry) if !entry.content.is_empty() => Some(entry),
                        _ => None,
                    };

                    let mut cont_perms = Vec::new();
                    if let Some(entry) = entry {
                        let plaintext = symmetric_decrypt(&entry.content, &app.keys.enc_key)?;
                        let app_access = deserialise::<AccessContainerEntry>(&plaintext)?;

                        for (key, (_mdata_info, perms)) in app_access.into_iter() {
                            cont_perms.push((key, perms));
                        }

                        apps.push(AuthedAppsList {
                            app: app.info.clone(),
                            perms: cont_perms,
                        });
                    }
                }

                debug!("Returning list of authorised applications: {:?}", apps);
                Ok(apps)
            })
            .map_err(AuthError::from)
    }));

    Ok(authed_apps)
}

/// # Revoke all permissions from an application
///
/// Using an account already created, you can log in to
/// the SAFE Network and revoke all permissions previously granted to an
/// application by providing its ID.
///
/// ## Example
/// ```
/// # use safe_auth::{create_acc, authorise_app};
/// use safe_auth::{log_in, revoke_app};
/// # fn random_str() -> String { (0..4).map(|_| rand::random::<char>()).collect() }
/// /// Using an already existing account which has been used
/// /// to authorise some application already:
/// let my_secret = "mysecretstring";
/// let my_password = "mypassword";
/// # let my_secret = &(random_str());
/// # let my_password = &(random_str());
/// # create_acc("anInvite", my_secret, my_password).unwrap();
/// let authenticator = log_in(my_secret, my_password).unwrap();
/// # let auth_req = "bAAAAAAFBMHKYWAAAAAABWAAAAAAAAAAANZSXILTNMFUWI43BMZSS45DFON2C453FMJQXA4BONFSAACYAAAAAAAAAABLWKYSBOBYCAVDFON2A2AAAAAAAAAAAJVQWSZCTMFTGKICMORSC4AACAAAAAAAAAAAAUAAAAAAAAAAAL5SG6Y3VNVSW45DTAEAAAAAAAAAAAAIAAAAAOAAAAAAAAAAAL5YHKYTMNFRQCAAAAAAAAAAAAAAAAAAB";
/// # authorise_app(&authenticator, auth_req, &|_| true).unwrap();
/// /// Revoke all permissions from app with ID `net.maidsafe.test.webapp.id`
/// let revoked = revoke_app(&authenticator, String::from("net.maidsafe.test.webapp.id"));
/// match revoked {
///    Ok(_) => assert!(true), // This should pass
///    Err(_) => assert!(false)
/// }
/// ```
///
/// ## Error Example
/// ```
/// # use safe_auth::{create_acc, authorise_app};
/// use safe_auth::{log_in, revoke_app};
/// # fn random_str() -> String { (0..4).map(|_| rand::random::<char>()).collect() }
/// /// Using an already existing account which has been used
/// /// to authorise some application already:
/// let my_secret = "mysecretstring";
/// let my_password = "mypassword";
/// # let my_secret = &(random_str());
/// # let my_password = &(random_str());
/// # create_acc("anInvite", my_secret, my_password).unwrap();
/// let authenticator = log_in(my_secret, my_password).unwrap();
/// /// Try to revoke permissions with an incorrect app ID
/// let revoked = revoke_app(&authenticator, String::from("invalid-app-id"));
/// match revoked {
///    Ok(_) => assert!(false), // This should not pass
///    Err(message) => assert!(message.contains("UnknownApp"))
/// }
///```
pub fn revoke_app(authenticator: &Authenticator, app_id: String) -> Result<(), String> {
    auth_run_helper(authenticator, move |client| {
        safe_authenticator_revoke_app(client, &app_id).and_then(move |_| {
            debug!("Application sucessfully revoked: {}", app_id);
            Ok(())
        })
    })
    .map_err(|err| format!("Failed to revoke permissions: {}", err))
}

// Helper function to generate an app authorisation response
fn gen_auth_denied_response(req_id: u32) -> Result<String, String> {
    debug!("Encoding auth denied response...");
    let resp = unwrap!(encode_msg(&IpcMsg::Resp {
        req_id,
        resp: IpcResp::Auth(Err(IpcError::AuthDenied)),
    }));
    debug!("Returning auth response generated: {:?}", resp);

    Ok(resp)
}

// Helper function to generate an app authorisation response
fn gen_auth_response(
    authenticator: &Authenticator,
    req_id: u32,
    auth_req: AuthReq,
) -> Result<String, String> {
    let auth_granted = unwrap!(auth_run_helper(authenticator, move |client| authenticate(
        client, auth_req
    )));

    debug!("Encoding response... {:?}", auth_granted);
    let resp = unwrap!(encode_msg(&IpcMsg::Resp {
        req_id,
        resp: IpcResp::Auth(Ok(auth_granted)),
    }));
    debug!("Returning auth response generated: {:?}", resp);

    Ok(resp)
}

// Helper function to generate a containers authorisation response
fn gen_cont_auth_response(
    authenticator: &Authenticator,
    req_id: u32,
    cont_req: ContainersReq,
) -> Result<String, String> {
    let permissions = cont_req.containers.clone();
    let app_id = cont_req.app.id.clone();

    auth_run_helper(authenticator, move |client| {
        let c2 = client.clone();
        let c3 = client.clone();
        let c4 = client.clone();

        config::get_app(client, &app_id)
            .and_then(move |app| {
                let sign_pk = PublicKey::from(app.keys.bls_pk);
                update_container_perms(&c2, permissions, sign_pk).map(move |perms| (app, perms))
            })
            .and_then(move |(app, mut perms)| {
                let app_keys = app.keys;
                access_container::fetch_entry(&c3, &app_id, app_keys.clone()).then(move |res| {
                    let version = match res {
                        // Updating an existing entry
                        Ok((version, Some(mut existing_perms))) => {
                            for (key, val) in perms {
                                let _ = existing_perms.insert(key, val);
                            }
                            perms = existing_perms;
                            version + 1
                        }

                        // Adding a new access container entry
                        Ok((_, None))
                        | Err(AuthError::CoreError(CoreError::RoutingClientError(
                            ClientError::NoSuchEntry,
                        ))) => 0,

                        // Error has occurred while trying to get an
                        // existing entry
                        Err(e) => return Err(e),
                    };
                    Ok((version, app_id, app_keys, perms))
                })
            })
            .and_then(move |(version, app_id, app_keys, perms)| {
                access_container::put_entry(&c4, &app_id, &app_keys, &perms, version)
            })
            .and_then(move |_| {
                debug!("Encoding response...");
                let resp = encode_msg(&IpcMsg::Resp {
                    req_id,
                    resp: IpcResp::Containers(Ok(())),
                })?;

                debug!("Returning containers auth response generated: {:?}", resp);
                Ok(resp)
            })
            .map_err(AuthError::from)
    })
    .map_err(|err| format!("Failed to generate response: {}", err))
}

// Helper function to generate an unregistered authorisation response
fn gen_unreg_auth_response(req_id: u32) -> Result<String, String> {
    let bootstrap_cfg = unwrap!(safe_core_client::bootstrap_config());

    debug!("Encoding response... {:?}", bootstrap_cfg);
    let resp = unwrap!(encode_msg(&IpcMsg::Resp {
        req_id,
        resp: IpcResp::Unregistered(Ok(bootstrap_cfg)),
    }));

    debug!("Returning unregistered auth response generated: {:?}", resp);
    Ok(resp)
}

// Helper function to generate an authorisation response for sharing MD
fn gen_shared_md_auth_response(
    authenticator: &Authenticator,
    req_id: u32,
    share_mdata_req: ShareMDataReq,
) -> Result<String, String> {
    auth_run_helper(authenticator, move |client| {
        let client_cloned0 = client.clone();
        let client_cloned1 = client.clone();
        config::get_app(client, &share_mdata_req.app.id).and_then(move |app_info| {
            let user = User::Key(PublicKey::from(app_info.keys.bls_pk));
            let num_mdata = share_mdata_req.mdata.len();
            stream::iter_ok(share_mdata_req.mdata.into_iter())
                .map(move |mdata| {
                    client_cloned0
                        .get_mdata_shell(mdata.name, mdata.type_tag)
                        .map(|md| (md.version(), mdata))
                })
                .buffer_unordered(num_mdata)
                .map(move |(version, mdata)| {
                    client_cloned1.set_mdata_user_permissions(
                        mdata.name,
                        mdata.type_tag,
                        user,
                        mdata.perms,
                        version + 1,
                    )
                })
                .buffer_unordered(num_mdata)
                .map_err(AuthError::from)
                .for_each(|()| Ok(()))
                .and_then(move |()| {
                    debug!("Encoding response...");
                    let resp = encode_msg(&IpcMsg::Resp {
                        req_id,
                        resp: IpcResp::ShareMData(Ok(())),
                    })?;

                    debug!("Returning shared MD auth response generated: {:?}", resp);
                    Ok(resp)
                })
        })
    })
    .map_err(|err| format!("Failed to generate response: {}", err))
}

#[cfg(test)]
mod tests {
    use super::{acc_info, authed_apps, authorise_app, create_acc, log_in, revoke_app};
    use safe_core::ipc::req::IpcReq;
    use safe_core::ipc::Permission;
    use std::collections::{BTreeSet, HashMap};

    // The app auth request strings encode the following app info:
    /*
        id: 'net.maidsafe.test.authenticator.cli.id',
        name: 'Rust Authenticator CLI Test',
        vendor: 'MaidSafe.net Ltd'
    */
    // perms: [ ("_public", {Read} ) ]
    static APP_AUTH_REQ: &str = "bAAAAAABU6IEAEAAAAAACMAAAAAAAAAAANZSXILTNMFUWI43BMZSS45DFON2C4YLVORUGK3TUNFRWC5DPOIXGG3DJFZUWIAILAAAAAAAAAAAF65DFON2F643DN5YGKGYAAAAAAAAAABJHK43UEBAXK5DIMVXHI2LDMF2G64RAINGESICUMVZXIEAAAAAAAAAAABGWC2LEKNQWMZJONZSXIICMORSAAAIAAAAAAAAAAADQAAAAAAAAAAC7OB2WE3DJMMAQAAAAAAAAAAAAAAAAAAI";
    // perms: [ ("_public", {Read} ), ("_music", {Insert, Update}) ]
    static CONT_AUTH_REQ: &str = "bAAAAAAA633HNCAIAAAACMAAAAAAAAAAANZSXILTNMFUWI43BMZSS45DFON2C4YLVORUGK3TUNFRWC5DPOIXGG3DJFZUWIAILAAAAAAAAAAAF65DFON2F643DN5YGKGYAAAAAAAAAABJHK43UEBAXK5DIMVXHI2LDMF2G64RAINGESICUMVZXIEAAAAAAAAAAABGWC2LEKNQWMZJONZSXIICMORSACAAAAAAAAAAAAYAAAAAAAAAAAX3NOVZWSYYCAAAAAAAAAAAACAAAAABAAAAAAE";

    static APP_ID: &str = "net.maidsafe.test.authenticator.cli.id";

    fn random_str() -> String {
        (0..4).map(|_| rand::random::<char>()).collect()
    }

    #[test]
    fn account_creation_and_login_test() {
        let my_secret = &(random_str());
        let my_password = &(random_str());

        // successfully create an account
        let acc_created = create_acc("anInvite", my_secret, my_password);
        match acc_created {
            Ok(_) => assert!(true),
            Err(err) => panic!(err),
        }

        // fail to create an account with same secret
        let acc_not_created = create_acc("anInvite", my_secret, my_password);
        match acc_not_created {
            Ok(_) => panic!("Account shouldn't have been created successfully"),
            Err(err) => assert_eq!(err, "Failed to create an account: CoreError(Account exists - CoreError::RoutingClientError -> AccountExists)"),
        }

        // successfully log in
        let auth = log_in(my_secret, my_password);
        match auth {
            Ok(_) => assert!(true),
            Err(err) => panic!(err),
        }

        // fail to log in with invalid secret
        let other_secret = &(random_str());
        let auth = log_in(other_secret, my_password);
        match auth {
            Ok(_) => panic!("Shouldn't have logged in sucessfully"),
            Err(err) => assert_eq!(err, "Failed to log in: CoreError(No such account - CoreError::RoutingClientError -> NoSuchAccount)"),
        }

        // fail to log in with invalid password
        let other_password = &(random_str());
        let auth = log_in(my_secret, other_password);
        match auth {
            Ok(_) => panic!("Shouldn't have logged in sucessfully"),
            Err(err) => assert_eq!(err, "Failed to log in: CoreError(Symmetric decryption failure - CoreError::SymmetricDecipherFailure)"),
        }
    }

    #[test]
    fn authorise_apps_tests() {
        let my_secret = &(random_str());
        let my_password = &(random_str());

        let auth = unwrap!(create_acc("anInvite", my_secret, my_password));

        // fail to authorise app with invalid request
        let invalid_auth_req = "fddfds";
        let auth_response = authorise_app(&auth, invalid_auth_req, &|_| true);
        match auth_response {
            Ok(_) => panic!("It should have failed to authorise"),
            Err(err) => assert_eq!(
                err,
                "Failed to decode the auth request string: EncodeDecodeError"
            ),
        }

        // successfully authorise a registered app auth request
        let auth_response = authorise_app(&auth, APP_AUTH_REQ, &|_| true);
        match auth_response {
            Ok(res) => assert!(!res.is_empty()),
            Err(err) => panic!(err),
        }

        // successfully authorise an unregistered app auth request
        let unreg_auth_req =
            "bAAAAAAFVMRTRUAQAAAACMAAAAAAAAAAANZSXILTNMFUWI43BMZSS45DFON2C4YLVORUGK3TUNFRWC5DPOIXGG3DJFZUWIAI";
        let unreg_auth_res = "bAEAAAAFVMRTRUAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI";
        let auth_response = authorise_app(&auth, unreg_auth_req, &|_| true);
        match auth_response {
            Ok(res) => assert_eq!(res, unreg_auth_res),
            Err(err) => panic!(err),
        }

        // successfully authorise containers request
        let cont_auth_res = "bAEAAAAA633HNCAIAAAAAAAAAAAAQ";
        let auth_response = authorise_app(&auth, CONT_AUTH_REQ, &|_| true);
        match auth_response {
            Ok(res) => assert_eq!(res, cont_auth_res),
            Err(err) => panic!(err),
        }

        // fail to authorise share MD request for an inexisting MD
        let shared_md_auth_req = "bAAAAAAHI4K23GAYAAAACMAAAAAAAAAAANZSXILTNMFUWI43BMZSS45DFON2C4YLVORUGK3TUNFRWC5DPOIXGG3DJFZUWIAILAAAAAAAAAAAF65DFON2F643DN5YGKGYAAAAAAAAAABJHK43UEBAXK5DIMVXHI2LDMF2G64RAINGESICUMVZXIEAAAAAAAAAAABGWC2LEKNQWMZJONZSXIICMORSACAAAAAAAAAAAMEPAAAAAAAAAAVAYFZ5TT47GQRNWBSQUD6FQVU7BOKP24TNSYPGFEOGCHFIV5ULTAEAQAAAAAE";
        let auth_response = authorise_app(&auth, shared_md_auth_req, &|_| true);
        match auth_response {
            Ok(_) => panic!("It should have failed to authorise to share MD"),
            Err(err) => assert_eq!(err, "Failed to generate response: Core error: Routing client error -> Requested data not found"),
        }

        // fail to authorise containers request for an inexisting container
        let invalid_cont_auth_req = "bAAAAAACATC2HMAIAAAACMAAAAAAAAAAANZSXILTNMFUWI43BMZSS45DFON2C4YLVORUGK3TUNFRWC5DPOIXGG3DJFZUWIAILAAAAAAAAAAAF65DFON2F643DN5YGKGYAAAAAAAAAABJHK43UEBAXK5DIMVXHI2LDMF2G64RAINGESICUMVZXIEAAAAAAAAAAABGWC2LEKNQWMZJONZSXIICMORSACAAAAAAAAAAABAAAAAAAAAAAAX3JNZ3GC3DJMQBAAAAAAAAAAAABAAAAAAQAAAAAC";
        let auth_response = authorise_app(&auth, invalid_cont_auth_req, &|_| true);
        match auth_response {
            Ok(_) => panic!("It should have failed to authorise invalid container request"),
            Err(err) => assert_eq!(
                err,
                "Failed to generate response: \'_invalid\' not found in the access container"
            ),
        }

        // fail to authorise app with invalid request due to inexisting container in the list of requested perms
        /* TODO: this doesn't fail as it was expected
        let invalid_app_auth_req = "bAAAAAAF5Q66DAAAAAAACMAAAAAAAAAAANZSXILTNMFUWI43BMZSS45DFON2C4YLVORUGK3TUNFRWC5DPOIXGG3DJFZUWIAILAAAAAAAAAAAF65DFON2F643DN5YGKGYAAAAAAAAAABJHK43UEBAXK5DIMVXHI2LDMF2G64RAINGESICUMVZXIEAAAAAAAAAAABGWC2LEKNQWMZJONZSXIICMORSAAAIAAAAAAAAAAAEAAAAAAAAAAAC7NFXHMYLMNFSACAAAAAAAAAAAAAAAAAAB";
        let auth_response = authorise_app(&auth, invalid_app_auth_req, &|_| true);
        match auth_response {
            Ok(_) => panic!("It should have failed to authorise app request"),
            Err(err) => assert_eq!(err, "Failed to generate response: \'_invalid_container\' not found in the access container"),
        }*/
    }

    #[test]
    fn deny_authorisation_reqs_tests() {
        let my_secret = &(random_str());
        let my_password = &(random_str());

        let auth = unwrap!(create_acc("anInvite", my_secret, my_password));

        // verify app info passed to allow/deny callback for auth requests, and verify the AuthDenied response
        let auth_denied_encoded_response = "bAEAAAABU6IEAEAAAAAAACAAAAAAAAAAAAE";
        let auth_response = authorise_app(&auth, APP_AUTH_REQ, &|auth_req| {
            let (app_exchange_info, containers) = match auth_req {
                IpcReq::Auth(app_auth_req) => {
                    assert_eq!(app_auth_req.app_container, false);
                    (app_auth_req.app, app_auth_req.containers)
                }
                _ => panic!("Auth req info not received"),
            };
            assert_eq!(app_exchange_info.id, APP_ID);
            assert_eq!(app_exchange_info.name, "Rust Authenticator CLI Test");
            assert_eq!(app_exchange_info.vendor, "MaidSafe.net Ltd");
            let mut perms = BTreeSet::new();
            perms.insert(Permission::Read);
            let mut conts = HashMap::new();
            conts.insert("_public".to_string(), perms);
            assert_eq!(containers, conts);
            false
        });
        match auth_response {
            Ok(res) => assert_eq!(res, auth_denied_encoded_response),
            Err(_) => panic!("It should have returned an AuthDenied response rather than erroing"),
        };

        authorise_app(&auth, APP_AUTH_REQ, &|_| true).expect("Failed to authorise an app");
        let auth_denied_encoded_response = "bAEAAAAA633HNCAAAAAAACAAAAAAAAAAAAE";
        let auth_response = authorise_app(&auth, CONT_AUTH_REQ, &|authed_apps_res| {
            let (app_exchange_info, containers) = match authed_apps_res {
                IpcReq::Containers(cont_req) => (cont_req.app, cont_req.containers),
                _ => panic!("Containers auth req info not received"),
            };

            assert_eq!(app_exchange_info.id, APP_ID);
            assert_eq!(app_exchange_info.name, "Rust Authenticator CLI Test");
            assert_eq!(app_exchange_info.vendor, "MaidSafe.net Ltd");

            let mut music_perms = BTreeSet::new();
            music_perms.insert(Permission::Insert);
            music_perms.insert(Permission::Update);

            let mut cont_perms = HashMap::new();
            cont_perms.insert("_music".to_string(), music_perms);
            assert_eq!(containers, cont_perms);

            false
        });
        match auth_response {
            Ok(res) => assert_eq!(res, auth_denied_encoded_response),
            Err(_) => panic!("It should have returned an AuthDenied response rather than erroing"),
        }
    }

    #[test]
    fn acc_info_tests() {
        let my_secret = &(random_str());
        let my_password = &(random_str());

        let auth = unwrap!(create_acc("anInvite", my_secret, my_password));

        // verify the PUTs consumed in creating an account by fetching the account info
        let acc_info = acc_info(&auth);
        match acc_info {
            Ok((done, available)) => {
                assert_eq!(done, 10);
                assert_eq!(available, 990);
            }
            Err(_) => panic!("Failed to retrieve account info"),
        }
    }

    #[test]
    fn authed_apps_tests() {
        let my_secret = &(random_str());
        let my_password = &(random_str());

        let auth = unwrap!(create_acc("anInvite", my_secret, my_password));

        // list of authorised apps shall be empty with a freshly created account
        let authed_apps_res = authed_apps(&auth);
        match authed_apps_res {
            Ok(authed_vec) => assert_eq!(authed_vec.len(), 0), // This should pass
            Err(_) => panic!("It should have retieved the list of authorised apps"),
        }

        // after authorising an app it is returned in the list retrieved by authed_apps
        authorise_app(&auth, APP_AUTH_REQ, &|_| true)
            .expect("Failed to authorise an app before calling authed_apps");
        let authed_apps_res = authed_apps(&auth);
        match authed_apps_res {
            Ok(authed_vec) => {
                assert_eq!(authed_vec.len(), 1);
                let app_exchange_info = &authed_vec[0].app;
                assert_eq!(app_exchange_info.id, APP_ID);
                assert_eq!(app_exchange_info.name, "Rust Authenticator CLI Test");
                assert_eq!(app_exchange_info.vendor, "MaidSafe.net Ltd");
                let mut perms = BTreeSet::new();
                perms.insert(Permission::Read);
                assert_eq!(authed_vec[0].perms[0], ("_public".to_string(), perms));
            }
            Err(_) => panic!("It should have retrieved the list of authorised apps"),
        }

        // after authorising a containers auth request it is returned in the permissions list retrieved by authed_apps
        authorise_app(&auth, CONT_AUTH_REQ, &|_| true)
            .expect("Failed to authorise containers auth req before calling authed_apps");
        let authed_apps_res = authed_apps(&auth);
        match authed_apps_res {
            Ok(mut authed_vec) => {
                assert_eq!(authed_vec.len(), 1);
                let app_exchange_info = &authed_vec[0].app;
                assert_eq!(app_exchange_info.id, APP_ID);
                assert_eq!(app_exchange_info.name, "Rust Authenticator CLI Test");
                assert_eq!(app_exchange_info.vendor, "MaidSafe.net Ltd");

                let mut public_perms = BTreeSet::new();
                public_perms.insert(Permission::Read);

                let mut music_perms = BTreeSet::new();
                music_perms.insert(Permission::Insert);
                music_perms.insert(Permission::Update);

                let mut cont_perms = vec![
                    ("_public".to_string(), public_perms),
                    ("_music".to_string(), music_perms),
                ];
                cont_perms.sort();
                authed_vec[0].perms.sort();
                assert_eq!(authed_vec[0].perms, cont_perms);
            }
            Err(_) => panic!("It should have retrieved the list of authorised apps"),
        }
    }

    #[test]
    fn revoke_app_tests() {
        let my_secret = &(random_str());
        let my_password = &(random_str());

        let auth = unwrap!(create_acc("anInvite", my_secret, my_password));

        // after revoking an app it is removed from the list retrieved by authed_apps
        authorise_app(&auth, APP_AUTH_REQ, &|_| true)
            .expect("Failed to authorise an app before calling authed_apps");
        revoke_app(&auth, APP_ID.to_string())
            .expect("Failed to revoke the previously authorised app");

        let authed_apps_res = authed_apps(&auth);
        match authed_apps_res {
            Ok(authed_vec) => assert_eq!(authed_vec.len(), 0),
            Err(_) => panic!("It should have retrieved the list of authorised apps"),
        }
    }
}

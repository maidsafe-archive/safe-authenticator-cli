pub mod authd;

use log::{debug, info};
use safe_authenticator::app_auth::authenticate;
use safe_authenticator::config;
use safe_authenticator::test_utils::{run as utils_run, try_run};
use safe_authenticator::Authenticator;

use futures::future::Future;
use routing::ClientError;
use safe_authenticator::access_container;
use safe_authenticator::errors::AuthError;
use safe_authenticator::ipc::{decode_ipc_msg, update_container_perms};
use safe_authenticator::revocation::revoke_app as safe_authenticator_revoke_app;
use safe_core::client::Client;
use safe_core::ipc::req::{AppExchangeInfo, ContainerPermissions, IpcReq};
use safe_core::ipc::resp::{AccessContainerEntry, IpcResp};
use safe_core::ipc::{access_container_enc_key, decode_msg, encode_msg, IpcMsg};
use safe_core::utils::symmetric_decrypt;
use safe_core::{client as safe_core_client, CoreError};

use maidsafe_utilities::serialisation::deserialise;

#[derive(Debug)]
pub struct AuthedAppsList {
    pub app: AppExchangeInfo,
    pub perms: Vec<(String, ContainerPermissions)>,
}

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
        eprintln!("{}", "Disconnected from network")
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
    match Authenticator::login(secret, password, || {
        eprintln!("{}", "Disconnected from network")
    }) {
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
/// let auth_response = authorise_app(&authenticator, auth_req);
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
/// let auth_response = authorise_app(&authenticator, auth_req);
/// match auth_response {
///    Ok(_) => assert!(false), // This should not pass
///    Err(message) => assert!(message.contains("EncodeDecodeError"))
/// }
///```
pub fn authorise_app(authenticator: &Authenticator, req: &str) -> Result<String, String> {
    debug!("Attempting to authorise application...");
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

    let ipc_req = utils_run(authenticator, move |client| decode_ipc_msg(client, req_msg));
    match ipc_req {
        Ok(IpcMsg::Req {
            req: IpcReq::Auth(auth_req),
            req_id,
        }) => {
            info!("Request was recognised as a general app auth request");
            debug!("Decoded request (req_id={:?}): {:?}", req_id, auth_req);
            let auth_granted =
                try_run(authenticator, move |client| authenticate(client, auth_req)).unwrap();

            debug!("Encoding response... {:?}", auth_granted);
            let resp = encode_msg(&IpcMsg::Resp {
                req_id,
                resp: IpcResp::Auth(Ok(auth_granted)),
            })
            .unwrap();
            debug!("Returning auth response generated: {:?}", resp);

            Ok(resp)
        }
        Ok(IpcMsg::Req {
            req: IpcReq::Containers(cont_req),
            req_id,
        }) => {
            info!("Request was recognised as a containers auth request");
            debug!("Decoded request (req_id={:?}): {:?}", req_id, cont_req);

            let permissions = cont_req.containers.clone();
            let app_id = cont_req.app.id.clone();

            let resp = try_run(authenticator, move |client| {
                let c2 = client.clone();
                let c3 = client.clone();
                let c4 = client.clone();

                config::get_app(client, &app_id)
                    .and_then(move |app| {
                        let sign_pk = app.keys.sign_pk;
                        update_container_perms(&c2, permissions, sign_pk)
                            .map(move |perms| (app, perms))
                    })
                    .and_then(move |(app, mut perms)| {
                        let app_keys = app.keys;
                        access_container::fetch_entry(&c3, &app_id, app_keys.clone()).then(
                            move |res| {
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
                            },
                        )
                    })
                    .and_then(move |(version, app_id, app_keys, perms)| {
                        access_container::put_entry(&c4, &app_id, &app_keys, &perms, version)
                    })
                    .and_then(move |_| {
                        // TODO: we probably don't need to encode a response,
                        // but just exit successfully?
                        debug!("Encoding response...");
                        let resp = encode_msg(&IpcMsg::Resp {
                            req_id,
                            resp: IpcResp::Containers(Ok(())),
                        })?;
                        Ok(resp)
                    })
                    .map_err(AuthError::from)
            })
            .unwrap();

            debug!("Returning containers auth response generated: {:?}", resp);
            Ok(resp)
        }
        Ok(IpcMsg::Req {
            req: IpcReq::Unregistered(user_data),
            req_id,
        }) => {
            info!("Request was recognised as an unregistered auth request");
            debug!("Decoded request (req_id={:?}): {:?}", req_id, user_data);

            let bootstrap_cfg = safe_core_client::bootstrap_config().unwrap();

            debug!("Encoding response... {:?}", bootstrap_cfg);
            let resp = encode_msg(&IpcMsg::Resp {
                req_id,
                resp: IpcResp::Unregistered(Ok(bootstrap_cfg)),
            })
            .unwrap();

            debug!("Returning unregistered auth response generated: {:?}", resp);

            Ok(resp)
        }
        Ok(IpcMsg::Req {
            req: IpcReq::ShareMData(_share_mdata_req),
            ..
        }) => {
            info!("Request was recognised as a share MD auth request");
            /*
            let metadata_cont = try_run(&authenticator, move |client| {
                decode_share_mdata_req(client, &share_mdata_req)
            }).unwrap();
            debug!("MDs requested for sharing...");
            for metadata in metadata_cont {
                if let Some(_metadata) = metadata {
                    debug!("MD");
                } else {
                    error!("MD invalid");
                }
            }*/
            Ok(String::from(""))
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
    let acc_info = utils_run(authenticator, move |client| {
        client.get_account_info().map_err(AuthError::from)
    });
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
/// # authorise_app(&authenticator, auth_req).unwrap();
/// /// Get the list of authorised apps
/// let authed_apps = authed_apps(&authenticator);
/// match authed_apps {
///    Ok(_) => assert!(true), // This should pass
///    Err(_) => assert!(false)
/// }
///```
pub fn authed_apps(authenticator: &Authenticator) -> Result<Vec<AuthedAppsList>, String> {
    debug!("Attempting to fetch list of authorised apps...");
    let authed_apps = utils_run(authenticator, move |client| {
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
                    }
                    apps.push(AuthedAppsList {
                        app: app.info.clone(),
                        perms: cont_perms,
                    });
                }

                debug!("Returning list of authorised applications: {:?}", apps);
                Ok(apps)
            })
            .map_err(AuthError::from)
    });

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
/// # authorise_app(&authenticator, auth_req).unwrap();
/// /// Revoke all permissions from app with ID `net.maidsafe.test.webapp.id`
/// let revoked = revoke_app(&authenticator, String::from("net.maidsafe.test.webapp.id"));
/// match revoked {
///    Ok(_) => assert!(true), // This should pass
///    Err(_) => assert!(false)
/// }
/// ```
///
/// ## Error Example
/// // TODO: utils_run panics in this secenario. Remove the use of this utils.
/// ```ignore
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
    utils_run(authenticator, move |client| {
        safe_authenticator_revoke_app(client, &app_id)
            .and_then(move |_| {
                debug!("Application sucessfully revoked: {}", app_id);
                Ok(())
            })
            .map_err(AuthError::from)
    });

    Ok(())
}

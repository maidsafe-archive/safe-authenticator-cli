use std::error::Error;
use log::{debug, error, info};
use safe_authenticator::app_auth::authenticate;
use safe_authenticator::test_utils::{run as utils_run, try_run};
use safe_authenticator::Authenticator;
use safe_authenticator::config;
use structopt::StructOpt;

use safe_authenticator::ipc::{ decode_ipc_msg,/*decode_share_mdata_req,*/ encode_response };
use safe_authenticator::errors::AuthError;
use safe_core::client as safe_core_client;
use safe_core::client::Client;
use safe_core::ipc::req::{AppExchangeInfo, IpcReq};
use safe_core::ipc::resp::{AccessContainerEntry, IpcResp};
use safe_core::ipc::{decode_msg, access_container_enc_key, IpcMsg/*, IpcError*/};
use safe_core::utils::symmetric_decrypt;
use futures::future::Future;

use maidsafe_utilities::serialisation::deserialise;

#[derive(StructOpt, Debug)]
pub enum SubCommands {
    #[structopt(name = "create")]
    /// Create a new SAFE Network account with the credentials provided
    Invite {
        /// The invitation token for creating a new SAFE Network account
        #[structopt(short = "i", long = "invite-token")]
        invite: String,
    },
    #[structopt(name = "auth")]
    /// Authorise an application by providing the authorisation request URI or string
    Auth {
        /// The authorisation request URI or string
        #[structopt(short = "r", long = "req")]
        req: String,
    },
}

#[derive(StructOpt, Debug)]
pub struct CmdArgs {
    /// The secret phrase of the SAFE account
    #[structopt(short = "s", long = "secret")]
    secret: String,
    /// The SAFE account's password
    #[structopt(short = "p", long = "password")]//    catch_unwind_cb(user_data.0, o_cb, || -> Result<_, AuthError> {

    password: String,
    /// subcommands
    #[structopt(subcommand)]
    cmd: Option<SubCommands>,
    /// Get account's balance
    #[structopt(short = "b", long = "balance")]
    balance: bool,
    /// Get list of authorised apps
    #[structopt(short = "a", long = "apps")]
    apps: bool,
}

pub fn run() -> Result<(), Box<dyn Error>> {
    let args = CmdArgs::from_args();

    let authenticator = match args.cmd {
        None => {
            log_in(&args.secret, &args.password)?
        }
        Some(SubCommands::Invite { invite }) => {
            create_acc(&invite, &args.secret, &args.password)?
        }
        Some(SubCommands::Auth { req }) => {
            let authenticator = log_in(&args.secret, &args.password)?;
            authorise_app(&authenticator, &req);
            authenticator
        }
    };

    if args.balance {
        acc_info(&authenticator);
    };

    if args.apps {
        authed_apps(&authenticator);
    };

    Ok(())
}

fn create_acc(invite: &str, secret: &str, password: &str) -> Result<Authenticator, String> {
    info!("Attempting to create a SAFE account...");
    match Authenticator::create_acc(secret, password, invite, || ()) {
        Ok(auth) => {
            info!("Account created successfully!");
            Ok(auth)
        },
        Err(err) => Err(format!("Failed to create an account: {:?}", err)),
    }
}

fn log_in(secret: &str, password: &str) -> Result<Authenticator, String> {
    info!("Attempting to log in...");
    match Authenticator::login(secret, password, || ()) {
        Ok(auth) => {
            info!("Logged-in successfully!");
            Ok(auth)
        }
        Err(err) => Err(format!("Failed to log in: {:?}", err)),
    }
}

fn authorise_app(authenticator: &Authenticator, req: &str) {
    info!("Attempting to authorise application...");
    let req_msg = decode_msg(req).unwrap();
    debug!("Auth request string decoded: {:?}", req_msg);

    let ipc_req = utils_run(authenticator, move |client| {
        decode_ipc_msg(client, req_msg)
    });
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
            let resp = encode_response(&IpcMsg::Resp {
                req_id,
                resp: IpcResp::Auth(Ok(auth_granted)),
            })
            .unwrap();
            info!("Auth response generated: {:?}", resp);

            ()
        }
        Ok(IpcMsg::Req {
            req: IpcReq::Containers(_cont_req),
            ..
        }) => {
            info!("Request was recognised as a containers auth request");
            ()
        }
        Ok(IpcMsg::Req {
            req: IpcReq::Unregistered(user_data),
            req_id
        }) => {
            info!("Request was recognised as an unregistered auth request");
            debug!("Decoded request (req_id={:?}): {:?}", req_id, user_data);

			let bootstrap_cfg = safe_core_client::bootstrap_config().unwrap();

            debug!("Encoding response... {:?}", bootstrap_cfg);
			let resp = encode_response(&IpcMsg::Resp {
				req_id,
				resp: IpcResp::Unregistered( Ok(bootstrap_cfg) ),
			}).unwrap();

            info!("Auth response generated: {:?}", resp);

            ()
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
            ()
        }
        Err((error_code, description, _err)) => {
            error!(
                "Failed decoding the auth request: {} - {:?}",
                error_code, description
            );
            ()
        }
        Ok(IpcMsg::Resp { .. }) | Ok(IpcMsg::Revoked { .. }) | Ok(IpcMsg::Err(..)) => {
            error!("The request was not recognised as a valid auth request");
            ()
        }
    };
}

fn acc_info(authenticator: &Authenticator) {
    info!("Attempting to get account info...");
    let acc_info =
        utils_run(authenticator, move |client| {
            client.get_account_info().map_err(AuthError::from)
        });
    info!("Account's current balance (PUTs done/available): {}/{}", acc_info.mutations_done, acc_info.mutations_available);
}

fn authed_apps(authenticator: &Authenticator) {
    info!("Attempting to fetch list of authorised apps...");
    utils_run(authenticator, move |client| {
        let c2 = client.clone();
        let c3 = client.clone();
        config::list_apps(client)
            .map(move |(_, auth_cfg)| (c2.access_container(), auth_cfg))
            .and_then(move |(access_container, auth_cfg)| {
                c3.list_mdata_entries(access_container.name, access_container.type_tag)
                    .map_err(From::from)
                    .map(move |entries| (access_container, entries, auth_cfg))
                }).and_then(move |(access_container, entries, auth_cfg)| {
                    let nonce = access_container.nonce().ok_or_else(|| {
                        AuthError::from("No nonce on access container's MDataInfo")
                    })?;

                    let mut apps = Vec::new();
                    for app in auth_cfg.values() {
                        let key = access_container_enc_key(&app.info.id, &app.keys.enc_key, nonce)?;

                        // Empty entry means it has been deleted.
                        let entry = match entries.get(&key) {
                            Some(entry) if !entry.content.is_empty() => Some(entry),
                            _ => None,
                        };

                        let mut conts = Vec::new();
                        if let Some(entry) = entry {
                            let plaintext = symmetric_decrypt(&entry.content, &app.keys.enc_key)?;
                            let app_access = deserialise::<AccessContainerEntry>(&plaintext)?;

                            for (key, (_, perms)) in app_access.into_iter() {
                                conts.push((key, perms));
                            }
                        }
                        let AppExchangeInfo { id, scope: _, name, vendor } = &app.info;
                        apps.push((id, name, vendor, conts));
                    }
                    info!("Authorised applications: {:?}", apps);
                    Ok(())
            }).map_err(AuthError::from)
    });
}

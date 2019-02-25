use env_logger;
use log::{debug, error, info};
use safe_authenticator::app_auth::authenticate;
use safe_authenticator::Authenticator;
use structopt::StructOpt;

use safe_authenticator::ipc::{decode_ipc_msg, decode_share_mdata_req, encode_response};

use safe_core::ipc::req::IpcReq;
use safe_core::ipc::resp::IpcResp;
use safe_core::ipc::{decode_msg, /*IpcError,*/ IpcMsg};
use safe_core::FutureExt;
// use safe_core::ffi::ipc::resp::MetadataResponse;
use futures::future::Future;

#[derive(StructOpt, Debug)]
enum SubCommands {
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
struct CmdArgs {
    /// The secret phrase of the SAFE account
    #[structopt(short = "s", long = "secret")]
    secret: String,
    /// The SAFE account's password
    #[structopt(short = "p", long = "password")]
    password: String,
    /// subcommands
    #[structopt(subcommand)]
    cmd: Option<SubCommands>,
}

fn main() {
    env_logger::init();
    info!("Starting Authenticator...");

    let args = CmdArgs::from_args();
    debug!("Passed args: {:?}", args);

    match args.cmd {
        None => {
            log_in(&args.secret, &args.password).unwrap();
        }
        Some(SubCommands::Invite { invite }) => {
            create_acc(&invite, &args.secret, &args.password);
        }
        Some(SubCommands::Auth { req }) => {
            let authenticator = log_in(&args.secret, &args.password).unwrap();
            authorise_app(authenticator, &req);
        }
    }
}

fn create_acc(invite: &str, secret: &str, password: &str) {
    info!("Attempting to create a SAFE account...");
    match Authenticator::create_acc(secret, password, invite, || ()) {
        Ok(_) => info!("Account created successfully!"),
        Err(err) => error!("Failed to create an account: {:?}", err),
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

fn authorise_app(authenticator: Authenticator, req: &str) {
    info!("Attempting to authorise application...");
    let req_msg = decode_msg(req).unwrap();
    debug!("Auth request string decoded: {:?}", req_msg);

    authenticator
        .send(move |client| {
            let client_clone = client.clone();
            decode_ipc_msg(client, req_msg)
                .and_then(move |ipc_msg| match ipc_msg {
                    Ok(IpcMsg::Req {
                        req: IpcReq::Auth(auth_req),
                        req_id,
                    }) => {
                        info!("Request was recognised as a general app auth request");
                        debug!("Decoded request (req_id={:?}): {:?}", req_id, auth_req);

                        authenticate(&client_clone, auth_req)
                            .and_then(move |auth_granted| {
                                info!("Encoding response...");
                                let resp = encode_response(&IpcMsg::Resp {
                                    req_id,
                                    resp: IpcResp::Auth(Ok(auth_granted)),
                                })?;
                                info!("Response generated: {:?}", resp);
                                Ok(())
                            })
                            .map_err(move |err| error!("Failed to authenticate: {:?}", err))
                            .into_box();

                        Ok(())
                    }
                    Ok(IpcMsg::Req {
                        req: IpcReq::Containers(_cont_req),
                        ..
                    }) => {
                        info!("Request was recognised as a containers auth request");
                        Ok(())
                    }
                    Ok(IpcMsg::Req {
                        req: IpcReq::Unregistered(_extra_data),
                        ..
                    }) => {
                        info!("Request was recognised as an unregistered auth request");
                        Ok(())
                    }
                    Ok(IpcMsg::Req {
                        req: IpcReq::ShareMData(share_mdata_req),
                        ..
                    }) => {
                        info!("Request was recognised as a share MD auth request");
                        decode_share_mdata_req(&client_clone, &share_mdata_req).and_then(
                            move |metadata_cont| {
                                debug!("MDs requested for sharing...");
                                for metadata in metadata_cont {
                                    if let Some(_metadata) = metadata {
                                        debug!("MD");
                                    } else {
                                        error!("MD invalid");
                                    }
                                }
                                Ok(())
                            },
                        );
                        Ok(())
                    }
                    Err((error_code, description, _err)) => {
                        error!(
                            "Failed decoding the auth request: {} - {:?}",
                            error_code, description
                        );
                        Ok(())
                    }
                    Ok(IpcMsg::Resp { .. }) | Ok(IpcMsg::Revoked { .. }) | Ok(IpcMsg::Err(..)) => {
                        error!("The request was not recognised as a valid auth request");
                        Ok(())
                    }
                })
                .map_err(move |err| error!("Failed to authorise application: {:?}", err))
                .into_box()
                .into()

        })
        .and_then( |_| {
			debug!("After matching");
			Ok(())
		} ).unwrap()
}

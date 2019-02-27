use std::error::Error;
// use env_logger;
use log::{debug, error, info};
use safe_authenticator::app_auth::authenticate;
use safe_authenticator::test_utils::{run as utils_run, try_run};
use safe_authenticator::Authenticator;
use structopt::StructOpt;

use safe_authenticator::ipc::{decode_ipc_msg, /*decode_share_mdata_req,*/ encode_response};

use safe_core::ipc::req::IpcReq;
use safe_core::ipc::resp::IpcResp;
use safe_core::ipc::{decode_msg, IpcMsg};

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
    #[structopt(short = "p", long = "password")]
    password: String,
    /// subcommands
    #[structopt(subcommand)]
    cmd: Option<SubCommands>,
}

pub fn run() -> Result<(), Box<dyn Error>> {
    let args = CmdArgs::from_args();

    match args.cmd {
        None => {
            // TODO handle error here;
            log_in(&args.secret, &args.password)?;
            Ok(())
        }
        Some(SubCommands::Invite { invite }) => {
            create_acc(&invite, &args.secret, &args.password);
            Ok(())
        }
        Some(SubCommands::Auth { req }) => {
            let authenticator = log_in(&args.secret, &args.password).unwrap();
            authorise_app(authenticator, &req);
            Ok(())
        }
    }
}

fn create_acc(invite: &str, secret: &str, password: &str) -> Result<(), &'static str> {
    info!("Attempting to create a SAFE account...");
    match Authenticator::create_acc(secret, password, invite, || ()) {
        Ok(_) => {
            info!("Account created successfully!");
            Ok(())
        }
        Err(err) => {
            error!("Failed to create an account: {:?}", err);
            Err("Failed to create an account.")
        }
    }
    .into()
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

    let ipc_req = utils_run(&authenticator, move |client| {
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
                try_run(&authenticator, move |client| authenticate(client, auth_req)).unwrap();

            info!("Encoding response...");
            let resp = encode_response(&IpcMsg::Resp {
                req_id,
                resp: IpcResp::Auth(Ok(auth_granted)),
            })
            .unwrap();
            info!("Response generated: {:?}", resp);

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
            req: IpcReq::Unregistered(_extra_data),
            ..
        }) => {
            info!("Request was recognised as an unregistered auth request");
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

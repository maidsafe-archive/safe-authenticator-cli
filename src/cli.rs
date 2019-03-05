use log::info;
use std::error::Error;

use safe_auth::{acc_info, authed_apps, authorise_app, create_acc, log_in};

use structopt::StructOpt;

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
            let authenticator = log_in(&args.secret, &args.password)?;
            info!("Logged-in successfully!");
            authenticator
        }
        Some(SubCommands::Invite { invite }) => {
            let authenticator = create_acc(&invite, &args.secret, &args.password)?;
            info!("Account created successfully!");
            authenticator
        }
        Some(SubCommands::Auth { req }) => {
            let authenticator = log_in(&args.secret, &args.password)?;
            let resp = authorise_app(&authenticator, &req)?;
            info!("Auth response generated: {:?}", resp);
            authenticator
        }
    };

    if args.balance {
        let (mutations_done, mutations_available) = acc_info(&authenticator)?;
        info!(
            "Account's current balance (PUTs done/available): {}/{}",
            mutations_done, mutations_available
        );
    };

    if args.apps {
        let authed_apps = authed_apps(&authenticator)?;
        info!("Authorised applications: {:?}", authed_apps);
    };

    Ok(())
}

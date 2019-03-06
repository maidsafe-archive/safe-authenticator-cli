use log::info;

use safe_auth::{acc_info, authed_apps, authorise_app, create_acc, log_in};

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
/// Manage SAFE Network authorisations and accounts.
pub struct CmdArgs {
    /// The authorisation request URI or string
    #[structopt(short = "r", long = "req")]
    req: Option<String>,
    /// The invitation token for creating a new SAFE Network account
    #[structopt(short = "i", long = "invite-token")]
    invite: Option<String>,
    /// The secret phrase of the SAFE account
    #[structopt(short = "s", long = "secret")]
    secret: String,
    /// The SAFE account's password
    #[structopt(short = "p", long = "password")]
    password: String,
    /// Get account's balance
    #[structopt(short = "b", long = "balance")]
    balance: bool,
    /// Get list of authorised apps
    #[structopt(short = "a", long = "apps")]
    apps: bool,
}

pub fn run() -> Result<(), String> {
    let args = CmdArgs::from_args();

    if let Option::Some(invite) = &args.invite {
        create_acc(&invite, &args.secret, &args.password)?;
    }

    let authenticator = log_in(&args.secret, &args.password)?;

    if let Option::Some(req) = &args.req {
        authorise_app(&authenticator, &req)?;
    }

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

use log::info;
use prettytable::Table;
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

    let mut table = Table::new();

    if let Option::Some(invite) = &args.invite {
        create_acc(&invite, &args.secret, &args.password)?;
    }

    let authenticator = log_in(&args.secret, &args.password)?;

    if let Option::Some(req) = &args.req {
        let auth_response = authorise_app(&authenticator, &req)?;
        println!("{}", auth_response);
    }

    if args.balance {
        let (mutations_done, mutations_available) = acc_info(&authenticator)?;
        info!(
            "Account's current balance (PUTs done/available): {}/{}",
            mutations_done, mutations_available
        );
        println!("{}/{}", mutations_done, mutations_available);
    };

    if args.apps {
        let all_apps = authed_apps(&authenticator)?;
        info!("Authorised applications: {:?}", all_apps);

        if !all_apps.is_empty() {
            table.add_row(row!["Authorised Applications"]);
            table.add_row(row!["Id", "Name", "Vendor"]);

            let all_app_iterator = all_apps.iter();

            for app_info in all_app_iterator {
                table.add_row(row![
                    &app_info.app.id,
                    &app_info.app.name,
                    // &app_info.app.scope || "",
                    &app_info.app.vendor,
                ]);
            }

            table.printstd();
        }
    };

    Ok(())
}

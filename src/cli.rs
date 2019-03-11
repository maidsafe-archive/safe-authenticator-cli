use prettytable::Table;
use safe_auth::{acc_info, authed_apps, authorise_app, create_acc, log_in, revoke_app};
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
    /// The application's ID to revoke all authorised permissions from
    #[structopt(short = "k", long = "revoke")]
    revoke: Option<String>,
    /// Pretty print
    #[structopt(short = "y", long = "pretty")]
    pretty: bool,
}

pub fn run() -> Result<(), String> {
    let args = CmdArgs::from_args();

    // If an invite token was provided then create an account
    if let Option::Some(invite) = &args.invite {
        create_acc(&invite, &args.secret, &args.password)?;
        if args.pretty {
            println!("Account was created successfully!");
        }
    }

    // Log in before doing anything else
    let authenticator = log_in(&args.secret, &args.password)?;
    if args.pretty {
        println!("Logged in the SAFE Network successfully!");
    }

    // Authorise an app if req string was provided
    if let Option::Some(req) = &args.req {
        let auth_response = authorise_app(&authenticator, &req)?;
        if args.pretty {
            print!("Authorisation response string: ");
        }
        println!("{}", auth_response);
    }

    // Display account balance if requested
    if args.balance {
        let (mutations_done, mutations_available) = acc_info(&authenticator)?;
        if args.pretty {
            print!("Account's current balance (PUTs done/avaialble): ");
        }
        println!("{}/{}", mutations_done, mutations_available);
    };

    // Handle revoke arg if provided
    if let Option::Some(revoke) = args.revoke {
        let app_id: &'static str = Box::leak(revoke.into_boxed_str());
        revoke_app(&authenticator, app_id)?;
        if args.pretty {
            println!("Authorised permissions were revoked for app '{}'", app_id);
        }
    }

    // List authorised apps if requested
    if args.apps {
        let all_apps = authed_apps(&authenticator)?;
        if args.pretty {
            let mut table = Table::new();
            table.add_row(row!["Authorised Applications"]);
            table.add_row(row!["Id", "Name", "Vendor", "Permissions"]);

            let all_app_iterator = all_apps.iter();
            for app_info in all_app_iterator {
                let mut row = String::from("");
                for (cont, perms) in app_info.perms.iter() {
                    row += &format!("{}: {:?}\n", cont, perms);
                }
                table.add_row(row![
                    app_info.app.id,
                    app_info.app.name,
                    // app_info.app.scope || "",
                    app_info.app.vendor,
                    row,
                ]);
            }
            table.printstd();
        } else {
            println!("APP ID\tNAME\tVENDOR\tPERMISSIONS");
            let all_app_iterator = all_apps.iter();
            for app_info in all_app_iterator {
                let mut row = format!(
                    "{}\t{:?}\t{:?}\t[",
                    &app_info.app.id, &app_info.app.name, &app_info.app.vendor
                );
                let mut it = app_info.perms.iter();
                while let Some((cont, perms)) = it.next() {
                    row = row + &format!("{:?}:", cont);
                    let mut it2 = perms.iter();
                    while let Some(perm) = it2.next() {
                        row = row + &format!("{:?}", perm);
                        if it2.size_hint().0 > 0 {
                            row += "|";
                        };
                    }
                    if it.size_hint().0 > 0 {
                        row += ",";
                    };
                }
                println!("{}]", row)
            }
        }
    };

    Ok(())
}

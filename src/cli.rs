// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::authd;
use crate::cli_helpers::*;

use config_file_handler;
use log::{debug, warn};
use safe_auth::{acc_info, authed_apps, authorise_app, create_acc, log_in, revoke_app};
use safe_authenticator::Authenticator;
use std::env;
use structopt::StructOpt;

const DEFAULT_SEARCH_PATH: &str = "resources/";
const CRUST_CONFIG_PATH_ENV_VAR: &str = "SAFE_CRUST_CONFIG_PATH";

#[derive(StructOpt, Debug)]
/// Manage SAFE Network authorisations and accounts.
pub struct CmdArgs {
    /// A config file to read secret/password from. This is a temporary convenience function, which is not recommended. (Storing login information unencrypted is not secure.)
    #[structopt(short = "c", long = "config")]
    config_file_str: Option<String>,
    /// The encoded authorisation request string
    #[structopt(short = "r", long = "req")]
    req_str: Option<String>,
    /// The invitation token for creating a new SAFE Network account
    #[structopt(short = "i", long = "invite-token")]
    invite: Option<String>,
    /// Get account's balance
    #[structopt(short = "b", long = "balance")]
    balance: bool,
    /// Get list of authorised apps
    #[structopt(short = "a", long = "apps")]
    apps: bool,
    /// The application's ID to revoke all authorised permissions from
    #[structopt(short = "k", long = "revoke")]
    app_id: Option<String>,
    /// Pretty print
    #[structopt(short = "y", long = "pretty")]
    pretty: bool,
    /// Port number where the Authenticator webservice shall be listening to
    #[structopt(short = "d", long = "daemon")]
    port: Option<u16>,
    /// Flag to automatically allow any authorisation request received,
    /// otherwise the user is prompted to allow each request individually
    #[structopt(long = "allow-all-auth")]
    allow_all: bool,
}

pub fn run() -> Result<(), String> {
    // Let's first get all the arguments passed in
    let args = CmdArgs::from_args();

    let login_details = get_login_details(&args.config_file_str)?;

    // We accept an additional search path for the crust config from an env var,
    // or we add "resources/" as additional search path by default
    let crust_config_path = match env::var(CRUST_CONFIG_PATH_ENV_VAR) {
        Ok(val) => val,
        Err(_) => String::from(DEFAULT_SEARCH_PATH),
    };
    debug!(
        "Additional search path set for crust config file: {}",
        crust_config_path
    );
    config_file_handler::set_additional_search_path(&crust_config_path);

    // If an invite token is provided, create a SAFE account, otherwise
    // just login. In both cases we use the instantiated authenticator
    // for all subsequent operations, even for the daemon services.
    let authenticator: Authenticator;
    if let Some(invite) = &args.invite {
        authenticator = create_acc(&invite, &login_details.secret, &login_details.password)?;
        if args.pretty {
            println!("Account was created successfully!");
        }
    } else {
        authenticator = log_in(&login_details.secret, &login_details.password)?;
        if args.pretty {
            println!("Logged in the SAFE Network successfully!");
        }
    }

    if args.allow_all {
        warn!("All authorisation requests will be automatically allowed!");
    };

    // Authorise the application if an auth req string was provided
    if let Some(req) = &args.req_str {
        let auth_response = if args.allow_all {
            authorise_app(&authenticator, &req, &|_| true)?
        } else {
            authorise_app(&authenticator, &req, &prompt_to_allow_auth)?
        };

        if args.pretty {
            print!("Authorisation response string: ");
        }
        println!("{}", auth_response);
    }

    // Show the account's current balance if requested
    if args.balance {
        let (mutations_done, mutations_available) = acc_info(&authenticator)?;
        if args.pretty {
            print!("Account's current balance (PUTs done/available): ");
        }
        println!("{}/{}", mutations_done, mutations_available);
    };

    // Handle revoke arg if provided
    if let Some(app_id) = &args.app_id {
        revoke_app(&authenticator, app_id.clone())?;
        if args.pretty {
            println!("Authorised permissions were revoked for app '{}'", app_id);
        }
    }

    // List authorised apps if requested
    if args.apps {
        let authed_apps = authed_apps(&authenticator)?;
        if args.pretty {
            pretty_print_authed_apps(authed_apps);
        } else {
            parsable_list_authed_apps(authed_apps);
        }
    };

    if let Some(host_port) = args.port {
        if args.allow_all {
            authd::run(host_port, Some(authenticator), &|_| true);
        } else {
            authd::run(host_port, Some(authenticator), &prompt_to_allow_auth);
        };
    }

    Ok(())
}

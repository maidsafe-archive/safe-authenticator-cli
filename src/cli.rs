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
use safe_auth::{authed_apps, authorise_app, create_acc, log_in, revoke_app};
use safe_authenticator::Authenticator;
use safe_core::client::test_create_balance;
use safe_nd::Coins;
use std::env;
use std::str::FromStr;
use structopt::StructOpt;
use threshold_crypto::{serde_impl::SerdeSecret, SecretKey, PK_SIZE};

const DEFAULT_SEARCH_PATH: &str = "resources/";
const CRUST_CONFIG_PATH_ENV_VAR: &str = "SAFE_CRUST_CONFIG_PATH";

#[derive(PartialEq, Clone, Copy)]
pub enum OutputFmt {
    Pretty,
    Json,
}

#[derive(StructOpt, Debug)]
/// Manage SAFE Network authorisations and accounts.
#[structopt(raw(global_settings = "&[structopt::clap::AppSettings::ColoredHelp]"))]
pub struct CmdArgs {
    /// A config file to read secret/password from. This is a temporary convenience function, which is not recommended. (Storing login information unencrypted is not secure.)
    #[structopt(short = "c", long = "config")]
    config_file_str: Option<String>,
    /// The encoded authorisation request string
    #[structopt(short = "r", long = "req")]
    req_str: Option<String>,
    /// The secret key to be used as the default spendable balance that will get created in the new SAFE Network account
    #[structopt(long = "sk")]
    sk: Option<String>,
    /// Create test-coins automatically and use them to pay for the account creation
    #[structopt(long = "test-coins")]
    test_coins: bool,
    /// Get list of authorised apps
    #[structopt(short = "a", long = "apps")]
    apps: bool,
    /// The application's ID to revoke all authorised permissions from
    #[structopt(short = "k", long = "revoke")]
    app_id: Option<String>,
    /// Output data serialisation. Currently only supported 'json'
    #[structopt(short = "o", long = "output")]
    output_fmt: Option<String>,
    /// Sets JSON as output serialisation format (alias of '--output json')
    #[structopt(long = "json")]
    output_json: bool,
    /// Port number where the Authenticator webservice shall be listening to
    #[structopt(short = "d", long = "daemon")]
    port: Option<u16>,
    /// Flag to automatically allow any authorisation request received,
    /// otherwise the user is a prompted to allow each request individually
    #[structopt(long = "allow-all-auth")]
    allow_all: bool,
    /// Updates the application with a newer version if any are available.
    #[structopt(long = "update")]
    update: bool,
}

pub fn run() -> Result<(), String> {
    // Let's first get all the arguments passed in
    let args = CmdArgs::from_args();

    if args.update {
        match update_application() {
            Ok(_) => return Ok(()),
            Err(e) => return Err(format!("Error performing update: {}", e)),
        }
    }

    let login_details = get_login_details(&args.config_file_str)?;

    // We accept an additional search path for the crust config from an env var,
    // or we add "/resources" as additional search path by default
    let crust_config_path = match env::var(CRUST_CONFIG_PATH_ENV_VAR) {
        Ok(val) => val,
        Err(_) => String::from(DEFAULT_SEARCH_PATH),
    };
    debug!(
        "Additional search path set for crust config file: {}",
        crust_config_path
    );
    config_file_handler::set_additional_search_path(&crust_config_path);

    let output_fmt = if args.output_json {
        OutputFmt::Json
    } else {
        let fmt = args.output_fmt.clone().unwrap_or_else(|| "".to_string());
        match fmt.as_ref() {
            "json" => OutputFmt::Json,
            "" => OutputFmt::Pretty,
            other => {
                return Err(format!(
                    "Output serialisation format '{}' not supported",
                    other
                ))
            }
        }
    };

    // If secret key is provided (or --test-coins is passed), create a SAFE account,
    // otherwise just login. In both cases we use the instantiated authenticator
    // for all subsequent operations, even for the daemon services.
    let authenticator: Authenticator;
    if args.test_coins {
        let sk = SecretKey::random();
        let sk_serialised = bincode::serialize(&SerdeSecret(&sk))
            .expect("Failed to serialise the generated secret key");
        let sk_hex: String = sk_serialised.iter().map(|b| format!("{:02x}", b)).collect();
        test_create_balance(&sk, Coins::from_str("10").unwrap()).unwrap();

        authenticator = create_acc(&sk_hex, &login_details.secret, &login_details.password)?;
        let pk_as_bytes: [u8; PK_SIZE] = sk.public_key().to_bytes();
        let pk_hex: String = pk_as_bytes
            .to_vec()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        if OutputFmt::Pretty == output_fmt {
            println!("Account was created successfully!");
            println!("SafeKey created and preloaded with test-coins. Owner key pair generated:");
            println!("Public Key = {}", pk_hex);
            println!("Secret Key = {}", sk_hex);
        } else {
            println!(
                "{}",
                serde_json::to_string(&(pk_hex, sk_hex))
                    .unwrap_or_else(|_| "Failed to serialise output to json".to_string())
            );
        }
    } else if let Some(sk) = &args.sk {
        authenticator = create_acc(&sk, &login_details.secret, &login_details.password)?;
        if OutputFmt::Pretty == output_fmt {
            println!("Account was created successfully!");
        }
    } else {
        authenticator = log_in(&login_details.secret, &login_details.password)?;
        if OutputFmt::Pretty == output_fmt {
            println!("Logged in the SAFE Network successfully!");
        }
    }

    if args.allow_all {
        warn!("All authorisation requests will be automatically allowed!");
    };

    // Authorise the application if a auth req string was provided
    if let Some(req) = &args.req_str {
        let auth_response = if args.allow_all {
            authorise_app(&authenticator, &req, &|_| true)?
        } else {
            authorise_app(&authenticator, &req, &prompt_to_allow_auth)?
        };

        if OutputFmt::Pretty == output_fmt {
            print!("Authorisation response string: ");
        }
        println!("{}", auth_response);
    }

    // Handle revoke arg if provided
    if let Some(app_id) = &args.app_id {
        revoke_app(&authenticator, app_id.clone())?;
        if OutputFmt::Pretty == output_fmt {
            println!("Authorised permissions were revoked for app '{}'", app_id);
        }
    }

    // List authorised apps if requested
    if args.apps {
        let authed_apps = authed_apps(&authenticator)?;
        if OutputFmt::Pretty == output_fmt {
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

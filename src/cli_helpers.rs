// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

extern crate envy;
extern crate serde;
extern crate serde_json;

use log::info;
use prettytable::Table;
use routing::Action;
use safe_auth::AuthedAppsList;
use safe_core::ipc::req::IpcReq;
use serde::Deserialize;
use std::fs;
use std::io::{stdin, stdout, Write};

#[derive(Deserialize, Debug)]
struct Environment {
    safe_auth_secret: Option<String>,
    safe_auth_password: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct LoginDetails {
    pub secret: String,
    pub password: String,
}

pub fn get_login_details(config_file: &Option<String>) -> Result<LoginDetails, String> {
    let environment_details = unwrap!(envy::from_env::<Environment>());

    let mut the_secret = environment_details
        .safe_auth_secret
        .unwrap_or(String::from(""));
    if !the_secret.is_empty() {
        info!("Using secret from provided ENV var: SAFE_AUTH_SECRET")
    }

    let mut the_password = environment_details
        .safe_auth_password
        .unwrap_or(String::from(""));
    if !the_password.is_empty() {
        info!("Using password from provided ENV var: SAFE_AUTH_PASSWORD")
    }

    if the_secret.is_empty() ^ the_password.is_empty() {
        return Err("Both the secret and password environment variables must be set to be used for SAFE login.".to_string());
    }

    if the_secret.is_empty() || the_password.is_empty() {
        if let Some(config_file_str) = config_file {
            let file = match fs::File::open(&config_file_str) {
                Ok(file) => file,
                Err(error) => {
                    return Err(format!("Error reading config file. {}", error.to_string()));
                }
            };

            let json: LoginDetails = unwrap!(serde_json::from_reader(file));

            eprintln!("Warning! Storing your secret/password in plaintext in a config file is not secure." );

            if json.secret.is_empty() {
                return Err("The config files's secret field cannot be empty".to_string());
            } else {
                the_secret = json.secret;
            }

            if json.password.is_empty() {
                return Err("The config files's password field cannot be empty".to_string());
            } else {
                the_password = json.password;
            }
        } else {
            // Prompt the user for the SAFE account credentials
            the_secret = unwrap!(rpassword::read_password_from_tty(Some("Secret: ")));
            the_password = unwrap!(rpassword::read_password_from_tty(Some("Password: ")));
        }
    }

    if the_secret.is_empty() || the_password.is_empty() {
        return Err(String::from(
            "Neither the secret nor password can be empty.",
        ));
    }

    let details = LoginDetails {
        secret: the_secret,
        password: the_password,
    };

    Ok(details)
}

pub fn pretty_print_authed_apps(authed_apps: Vec<AuthedAppsList>) {
    let mut table = Table::new();
    table.add_row(row![bFg->"Authorised Applications"]);
    table.add_row(row![bFg->"Id", bFg->"Name", bFg->"Vendor", bFg->"Permissions"]);

    let all_app_iterator = authed_apps.iter();
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
}

pub fn parsable_list_authed_apps(authed_apps: Vec<AuthedAppsList>) {
    println!("APP ID\tNAME\tVENDOR\tPERMISSIONS");
    let all_app_iterator = authed_apps.iter();
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

pub fn prompt_to_allow_auth(req: IpcReq) -> bool {
    match req {
        IpcReq::Auth(app_auth_req) => {
            println!("The following application authorisation request was received:");
            let mut table = Table::new();
            table
                .add_row(row![bFg->"Id", bFg->"Name", bFg->"Vendor", bFg->"Permissions requested"]);
            table.add_row(row![
                app_auth_req.app.id,
                app_auth_req.app.name,
                // app_auth_req.app.scope || "",
                app_auth_req.app.vendor,
                format!(
                    "Own container: {}\nDefault containers: {:?}",
                    app_auth_req.app_container, app_auth_req.containers
                ),
            ]);
            table.printstd();
        }
        IpcReq::Containers(cont_req) => {
            println!("The following authorisation request for containers was received:");
            println!("{:?}", cont_req);
            let mut table = Table::new();
            table
                .add_row(row![bFg->"Id", bFg->"Name", bFg->"Vendor", bFg->"Permissions requested"]);
            table.add_row(row![
                cont_req.app.id,
                cont_req.app.name,
                // cont_req.app.scope || "",
                cont_req.app.vendor,
                format!("{:?}", cont_req.containers)
            ]);
            table.printstd();
        }
        IpcReq::ShareMData(share_mdata_req) => {
            println!("The following authorisation request to share a MutableData was received:");
            let mut row = String::from("");
            for mdata in share_mdata_req.mdata.iter() {
                row += &format!("Type tag: {}\nXoR name: {:?}", mdata.type_tag, mdata.name);
                let insert_perm = if mdata.perms.is_allowed(Action::Insert).unwrap_or(false) {
                    " Insert"
                } else {
                    ""
                };
                let update_perm = if mdata.perms.is_allowed(Action::Update).unwrap_or(false) {
                    " Update"
                } else {
                    ""
                };
                let delete_perm = if mdata.perms.is_allowed(Action::Delete).unwrap_or(false) {
                    " Delete"
                } else {
                    ""
                };
                let manage_perm = if mdata
                    .perms
                    .is_allowed(Action::ManagePermissions)
                    .unwrap_or(false)
                {
                    " ManagePermissions"
                } else {
                    ""
                };
                row += &format!(
                    "\nPermissions:{}{}{}{}\n\n",
                    insert_perm, update_perm, delete_perm, manage_perm
                );
            }
            let mut table = Table::new();
            table.add_row(row![
                bFg->"Id",
                bFg->"Name",
                bFg->"Vendor",
                bFg->"MutableData's requested to share"
            ]);
            table.add_row(row![
                share_mdata_req.app.id,
                share_mdata_req.app.name,
                // share_mdata_req.app.scope || "",
                share_mdata_req.app.vendor,
                row
            ]);
            table.printstd();
        }
        IpcReq::Unregistered(_) => {
            // we simply allow unregistered authorisation requests
            return true;
        }
    };

    let mut prompt = String::new();
    print!("Allow authorisation? [y/N]: ");
    let _ = stdout().flush();
    stdin()
        .read_line(&mut prompt)
        .expect("Did not enter a correct string. Authorisation will be denied.");
    if let Some('\n') = prompt.chars().next_back() {
        prompt.pop();
    }
    if let Some('\r') = prompt.chars().next_back() {
        prompt.pop();
    }

    if prompt.to_lowercase() == "y" {
        println!("Authorisation will be allowed...");
        true
    } else {
        println!("Authorisation will be denied...");
        false
    }
}

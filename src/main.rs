// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use env_logger;
use log::{debug, error};
#[macro_use]
extern crate prettytable;

mod cli;

use cli::run;
use std::process;

fn main() {
    env_logger::init();
    debug!("Starting Authenticator...");

    if let Err(e) = run() {
        error!("safe_auth error: {}", e);
        process::exit(1);
    }
}

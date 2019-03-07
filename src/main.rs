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

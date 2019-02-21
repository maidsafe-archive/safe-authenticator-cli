extern crate safe_authenticator;

#[macro_use]
extern crate log;
extern crate env_logger;

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct Auth {
    /// The location
    #[structopt(short = "l", long = "locator")]
    password: String,
    /// The secret
    #[structopt(short = "s", long = "secret")]
    secret: String,
    /// The auth request uri
    #[structopt(short = "a", long = "auth-uri")]
    auth: String,
}

fn main() {
    env_logger::init();
    info!("Starting Authenticator");

    let args = Auth::from_args();

    println!("Passed Args: {:?}", args);

    // safe_authenticator::FFI::login('j', 'j')
}

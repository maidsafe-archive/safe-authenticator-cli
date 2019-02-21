use log::{info, error};
use env_logger;
use structopt::StructOpt;
use safe_authenticator::{Authenticator};

#[derive(StructOpt, Debug)]
enum SubCommands {
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
    }
}

#[derive(StructOpt, Debug)]
struct CmdArgs {
    /// The secret phrase of the SAFE account
    #[structopt(short = "s", long = "secret")]
    secret: String,
    /// The SAFE account's password
    #[structopt(short = "p", long = "password")]
    password: String,
    /// subcommands
    #[structopt(subcommand)]
    cmd: Option<SubCommands>,
}

fn main() {
    env_logger::init();
    info!("Starting Authenticator");

    let args = CmdArgs::from_args();
    info!("Passed args: {:?}", args);

    match args.cmd {
        Some(SubCommands::Invite { invite }) => {
            create_acc(&invite, &args.secret, &args.password)
        },
        Some(SubCommands::Auth { req }) => {
            error!("Authorisation not supported yet: {}", req);
            log_in(&args.secret, &args.password);
        },
        None => log_in(&args.secret, &args.password),
    }
}

fn create_acc(invite: &str, secret: &str, password: &str) {
    info!("Attempting to create a SAFE account...");
    match Authenticator::create_acc(secret, password, invite, || ()) {
        Ok(_) => info!("Account created successfully!"),
        Err(err) => error!("Failed to create an account: {:?}", err),
    }
}

fn log_in(secret: &str, password: &str) {
    info!("Attempting to log in...");
    match Authenticator::login(secret, password, || ()) {
        Ok(_) => info!("Logged-in successfully!"),
        Err(err) => error!("Failed to log in: {:?}", err),
    }
}

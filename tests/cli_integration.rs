// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

extern crate serde_json;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::fs;
use std::io::Write;
use std::process::Command;
use threshold_crypto::{serde_impl::SerdeSecret, SecretKey};

static PRETTY_ACCOUNT_CREATION_RESPONSE: &str = "Account was created successfully!";
static PRETTY_LOGIN_RESPONSE: &str = "Logged in the SAFE Network successfully!\n";
static UNAUTHED_REQ: &str = "bAAAAAAGY45BPQAQAAAAAGAAAAAAAAAAAAEBAGAI";
static UNAUTHED_RESPONSE: &str = "bAEAAAAGY45BPQAQAAAAAAAAAAAAAAAAAAAAAAAAB\n"; // \n added to string with println!

static AUTHED_REQ: &str = "bAAAAAAEXVK4SGAAAAAABAAAAAAAAAAAANZSXILTNMFUWI43BMZSS4Y3MNEAAQAAAAAAAAAAAKNAUMRJAINGESEAAAAAAAAAAABGWC2LEKNQWMZJONZSXIICMORSAAAIBAAAAAAAAAAAAOAAAAAAAAAAAL5YHKYTMNFRQCAAAAAAAAAAAAAAAAAAB";
static AUTHED_RESPONSE_START: &str = "bAEAAAAEXVK4SG";

static CONFIG_FILE: &str = "./tests/test.config.json";

fn gen_random_sk_hex() -> String {
    let sk = SecretKey::random();
    let sk_serialised = bincode::serialize(&SerdeSecret(&sk))
        .expect("Failed to serialise the generated secret key");
    sk_serialised.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn calling_safe_create_acc() {
    let mut cmd = Command::cargo_bin("safe_auth").unwrap();

    cmd.env("SAFE_MOCK_IN_MEMORY_STORAGE", "true")
        .args(&vec![
            "--sk",
            &gen_random_sk_hex(),
            "--config",
            &CONFIG_FILE,
        ])
        .assert()
        .success();
}

#[test]
fn calling_safe_create_acc_with_env_vars() {
    let mut cmd = Command::cargo_bin("safe_auth").unwrap();

    cmd.env("SAFE_MOCK_IN_MEMORY_STORAGE", "true")
        .env("SAFE_AUTH_SECRET", "something")
        .env("SAFE_AUTH_PASSWORD", "else")
        .args(&vec!["--sk", &gen_random_sk_hex()])
        .assert()
        .success();
}

#[test]
fn calling_safe_create_acc_with_only_one_env_var() {
    let mut cmd = Command::cargo_bin("safe_auth").unwrap();

    cmd.env("SAFE_MOCK_IN_MEMORY_STORAGE", "true")
        .env("SAFE_AUTH_SECRET", "something")
        .args(&vec!["--sk", &gen_random_sk_hex()])
        .assert()
        .failure();

    cmd.env("SAFE_MOCK_IN_MEMORY_STORAGE", "true")
        .env("SAFE_AUTH_PASSWORD", "something")
        .args(&vec!["--sk", &gen_random_sk_hex()])
        .assert()
        .failure();
}

#[test]
fn can_login_with_config_file() {
    let mut auth_cmd = Command::cargo_bin("safe_auth").unwrap();

    auth_cmd
        .env("SAFE_MOCK_IN_MEMORY_STORAGE", "true")
        .args(&vec![
            "--sk",
            &gen_random_sk_hex(),
            "--config",
            &CONFIG_FILE,
            "-y",
        ])
        .assert()
        .stdout(PRETTY_ACCOUNT_CREATION_RESPONSE)
        .success();
}

#[test]
fn calling_safe_auth_with_unregistered_req() {
    let mut auth_cmd = Command::cargo_bin("safe_auth").unwrap();

    auth_cmd
        .env("SAFE_MOCK_IN_MEMORY_STORAGE", "true")
        .args(&vec![
            "--sk",
            &gen_random_sk_hex(),
            "-r",
            &UNAUTHED_REQ,
            "--config",
            &CONFIG_FILE,
        ])
        .assert()
        .stdout(UNAUTHED_RESPONSE)
        .success();
}

#[test]
fn calling_safe_auth_with_registered_req() {
    let mut auth_cmd = Command::cargo_bin("safe_auth").unwrap();

    auth_cmd
        .env("SAFE_MOCK_IN_MEMORY_STORAGE", "true")
        .args(&vec![
            "--allow-all-auth",
            "--sk",
            &gen_random_sk_hex(),
            "-r",
            &AUTHED_REQ,
            "--config",
            &CONFIG_FILE,
        ])
        .assert()
        .stdout(predicate::str::starts_with(AUTHED_RESPONSE_START).from_utf8())
        .success();
}

#[test]
fn create_acc_with_env_vars_log_in_with_config() {
    let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();

    // write the credentials onto a json config file
    let login_credentials = format!(
        "{{ \"secret\": \"{}\", \"password\": \"{}\"}}",
        rand_string, rand_string
    );
    let mut file = fs::File::create(&CONFIG_FILE).unwrap();
    file.write(login_credentials.as_bytes()).unwrap();

    // we create an account with these credentials
    let mut cmd = Command::cargo_bin("safe_auth").unwrap();
    cmd.env("SAFE_AUTH_SECRET", rand_string.clone())
        .env("SAFE_AUTH_PASSWORD", rand_string.clone())
        .args(&vec!["--sk", &gen_random_sk_hex()])
        .assert()
        .success();

    // and now verify it can log in if reading the same credentials from the config
    let mut cmd = Command::cargo_bin("safe_auth").unwrap();
    cmd.args(&vec!["--pretty", "--config", &CONFIG_FILE])
        .assert()
        .stdout(predicate::str::starts_with(PRETTY_LOGIN_RESPONSE).from_utf8())
        .success();
}

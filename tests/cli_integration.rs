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

static PRETTY_ACCOUNT_CREATION_RESPONSE: &str = "Account was created successfully!\n";
static PRETTY_LOGIN_RESPONSE: &str = "Logged in the SAFE Network successfully!\n";
static UNAUTHED_REQ: &str = "bAAAAAADNVCMIGAQAAAACQAAAAAAAAAAANZSXILTNMFUWI43BMZSS4YLQNFPXA3DBPFTXE33VNZSC453FMJRWY2LFNZ2C4MJQAE";
static UNAUTHED_RESPONSE: &str = "bAEAAAADNVCMIGAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC\n"; // \n added to string with println!

static AUTHED_REQ: &str = "bAAAAAAFBMHKYWAAAAAABWAAAAAAAAAAANZSXILTNMFUWI43BMZSS45DFON2C453FMJQXA4BONFSAACYAAAAAAAAAABLWKYSBOBYCAVDFON2A2AAAAAAAAAAAJVQWSZCTMFTGKICMORSC4AACAAAAAAAAAAAAUAAAAAAAAAAAL5SG6Y3VNVSW45DTAEAAAAAAAAAAAAIAAAAAOAAAAAAAAAAAL5YHKYTMNFRQCAAAAAAAAAAAAAAAAAAB";
static AUTHED_RESPONSE_START: &str = "bAEAAAAFBMHKYW";

static CONFIG_FILE: &str = "./tests/test.config.json";

#[test]
fn calling_safe_create_acc() {
    let mut cmd = Command::cargo_bin("safe_auth").unwrap();
    let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();

    cmd.env("SAFE_MOCK_IN_MEMORY_STORAGE", "true")
        .args(&vec![
            "--invite-token",
            &rand_string,
            "--config",
            &CONFIG_FILE,
        ])
        .assert()
        .success();
}

#[test]
fn calling_safe_create_acc_with_env_vars() {
    let mut cmd = Command::cargo_bin("safe_auth").unwrap();
    let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();

    cmd.env("SAFE_MOCK_IN_MEMORY_STORAGE", "true")
        .env("SAFE_AUTH_SECRET", "something")
        .env("SAFE_AUTH_PASSWORD", "else")
        .args(&vec!["--invite-token", &rand_string])
        .assert()
        .success();
}

#[test]
fn calling_safe_create_acc_with_only_one_env_var() {
    let mut cmd = Command::cargo_bin("safe_auth").unwrap();
    let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();

    cmd.env("SAFE_MOCK_IN_MEMORY_STORAGE", "true")
        .env("SAFE_AUTH_SECRET", "something")
        .args(&vec!["--invite-token", &rand_string])
        .assert()
        .failure();

    cmd.env("SAFE_MOCK_IN_MEMORY_STORAGE", "true")
        .env("SAFE_AUTH_PASSWORD", "something")
        .args(&vec!["--invite-token", &rand_string])
        .assert()
        .failure();
}

#[test]
fn can_login_with_config_file() {
    let mut auth_cmd = Command::cargo_bin("safe_auth").unwrap();

    auth_cmd
        .env("SAFE_MOCK_IN_MEMORY_STORAGE", "true")
        .args(&vec![
            "--invite-token",
            "aaaa",
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
            "--invite-token",
            "aaaa",
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
            "--invite-token",
            "aaaa",
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
        .args(&vec!["--invite-token", "aaaa"])
        .assert()
        .success();

    // and now verify it can log in if reading the same credentials from the config
    let mut cmd = Command::cargo_bin("safe_auth").unwrap();
    cmd.args(&vec!["--pretty", "--config", &CONFIG_FILE])
        .assert()
        .stdout(predicate::str::starts_with(PRETTY_LOGIN_RESPONSE).from_utf8())
        .success();
}

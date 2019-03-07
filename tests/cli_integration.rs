use assert_cmd::prelude::*;
use predicates::prelude::*;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::process::Command;

static UNAUTHED_REQ: &str = "bAAAAAADNVCMIGAQAAAACQAAAAAAAAAAANZSXILTNMFUWI43BMZSS4YLQNFPXA3DBPFTXE33VNZSC453FMJRWY2LFNZ2C4MJQAE";
static UNAUTHED_RESPONSE: &str = "bAEAAAADNVCMIGAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC\n"; // \n added to string with println!

static AUTHED_REQ: &str = "bAAAAAAFBMHKYWAAAAAABWAAAAAAAAAAANZSXILTNMFUWI43BMZSS45DFON2C453FMJQXA4BONFSAACYAAAAAAAAAABLWKYSBOBYCAVDFON2A2AAAAAAAAAAAJVQWSZCTMFTGKICMORSC4AACAAAAAAAAAAAAUAAAAAAAAAAAL5SG6Y3VNVSW45DTAEAAAAAAAAAAAAIAAAAAOAAAAAAAAAAAL5YHKYTMNFRQCAAAAAAAAAAAAAAAAAAB";
static AUTHED_RESPONSE_START: &str = "bAEAAAAFBMHKYW";

#[test]
fn calling_safe_create_acc() {
    let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();

    let mut cmd = Command::cargo_bin("safe_auth").unwrap();

    cmd.args(&vec![
        "--secret",
        &rand_string,
        "--password",
        &rand_string,
        "--invite-token",
        "aaa",
    ])
    .assert()
    .success();
}

#[test]
fn calling_safe_auth_without_args() {
    let mut cmd = Command::cargo_bin("safe_auth").unwrap();

    cmd.assert()
        .stderr(predicate::str::contains(
            "Please pass secret and password credentials.",
        ))
        .success()
        .code(0);
}

#[test]
fn calling_safe_auth_with_unregistered_req() {
    let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();

    let mut cmd = Command::cargo_bin("safe_auth").unwrap();

    cmd.args(&vec![
        "--secret",
        &rand_string,
        "--password",
        &rand_string,
        "--invite-token",
        "aaa",
    ])
    .assert()
    .success();

    let mut auth_cmd = Command::cargo_bin("safe_auth").unwrap();

    auth_cmd
        .args(&vec![
            "--secret",
            &rand_string,
            "--password",
            &rand_string,
            "-r",
            &UNAUTHED_REQ,
        ])
        .assert()
        .stdout(UNAUTHED_RESPONSE)
        .success();
}

#[test]

fn calling_safe_auth_with_registered_req() {
    let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();

    let mut cmd = Command::cargo_bin("safe_auth").unwrap();

    cmd.args(&vec![
        "--secret",
        &rand_string,
        "--password",
        &rand_string,
        "--invite-token",
        "aaa",
    ])
    .assert()
    .success();

    let mut auth_cmd = Command::cargo_bin("safe_auth").unwrap();

    auth_cmd
        .args(&vec![
            "--secret",
            &rand_string,
            "--password",
            &rand_string,
            "-r",
            &AUTHED_REQ,
        ])
        .assert()
        .stdout(predicate::str::starts_with(AUTHED_RESPONSE_START).from_utf8())
        .success();
}

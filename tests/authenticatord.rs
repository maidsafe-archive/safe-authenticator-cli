// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use assert_cmd::prelude::*;
use predicates::prelude::*;
use rand::distributions::Alphanumeric;
use rand::Rng;
use safe_core::client::test_create_balance;
use safe_nd::Coins;
use std::process::{Child, Command};
use std::str::FromStr;
use std::{thread, time};
use threshold_crypto::{serde_impl::SerdeSecret, SecretKey};

static AUTHED_REQ: &str = "bAAAAAACNZZQ4WAAAAAABAAAAAAAAAAAANZSXILTNMFUWI43BMZSS4Y3MNEAAQAAAAAAAAAAAKNAUMRJAINGESEAAAAAAAAAAABGWC2LEKNQWMZJONZSXIICMORSAAAIBAEAAAAAAAAAAAAAB";

fn gen_random_sk_hex() -> (String, SecretKey) {
    let sk = SecretKey::random();
    let sk_serialised = bincode::serialize(&SerdeSecret(&sk))
        .expect("Failed to serialise the generated secret key");
    let sk_hex = sk_serialised.iter().map(|b| format!("{:02x}", b)).collect();
    (sk_hex, sk)
}

fn get_random_port() -> u16 {
    // Ports smaller than 1024 can require root access, so pick something larger.
    let mut rng = rand::thread_rng();
    let port: u16 = rng.gen_range(1024, 65535);
    port
}

fn init_server() -> (Child, u16) {
    let port = get_random_port();
    let rand_string: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .collect();

    let mut cmd = Command::cargo_bin("safe_auth").unwrap();
    let (sk, secret_key) = gen_random_sk_hex();
    test_create_balance(&secret_key, Coins::from_str("666").unwrap()).unwrap();

    let child = cmd
        .env("SAFE_AUTH_SECRET", &rand_string)
        .env("SAFE_AUTH_PASSWORD", "password")
        .args(vec![
            "--allow-all-auth",
            "--daemon",
            &port.to_string(),
            "--sk",
            &sk,
        ])
        .spawn()
        .expect("Authenticator process failed to start");

    // Mock-network is really slow so we need to wait to make sure the server starts
    let duration = time::Duration::from_secs(15);
    thread::sleep(duration);

    (child, port)
}

#[test]
fn curl_create_account() {
    let (mut server_process, port) = init_server();
    let rand_string: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .collect();
    let endpoint = format!(
        "http://localhost:{}/create/{}/{}/{}",
        port, &rand_string, &rand_string, &rand_string
    );
    let mut cmd = Command::new("curl");
    cmd.args(&vec!["-X", "POST", &endpoint])
        .assert()
        .stdout(predicate::str::contains("Create service not supported yet"))
        .success();
    server_process.kill().expect("Process was not running");
}

#[test]
fn curl_login() {
    let (mut server_process, port) = init_server();
    let rand_string: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .collect();

    /*let mut endpoint = format!(
        "http://localhost:{}/create/{}/{}/{}",
        port, &rand_string, &rand_string, &rand_string
    );
    let mut cmd = Command::new("curl");
    let mut child = cmd
        .args(&vec!["-X", "POST", &endpoint])
        .spawn()
        .expect("Failed to start");
    child.wait().expect("failed to wait");
    let duration = time::Duration::from_secs(1);
    thread::sleep(duration);*/

    let endpoint = format!(
        "http://localhost:{}/login/{}/{}",
        port, &rand_string, &rand_string
    );
    let mut cmd = Command::new("curl");
    cmd.args(&vec!["-X", "POST", &endpoint])
        .assert()
        .stdout(predicate::str::contains("Login service not supported yet"))
        .success();
    server_process.kill().expect("Process was not running");
}

#[test]
fn curl_authorise() {
    let (mut server_process, port) = init_server();
    let endpoint = format!("http://localhost:{}/authorise/{}", port, AUTHED_REQ);
    let mut cmd = Command::new("curl");
    cmd.args(&vec!["-X", "GET", &endpoint]).assert().success();
    server_process.kill().expect("Process was not running");
}

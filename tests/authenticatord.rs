use assert_cmd::prelude::*;
use predicates::prelude::*;
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::process::{Child, Command};
use std::{thread, time};

fn init_server(port: u16) -> Child {
    let mut cmd = Command::cargo_bin("safe_auth").unwrap();
    let child = cmd
        .arg("--daemon")
        .arg(format!("{}", port))
        .spawn()
        .expect("Authenticator process failed to start");
    child
}

#[test]
#[ignore]
fn curl_create_account() {
    let mut rng = rand::thread_rng();
    let port: u16 = rng.gen();
    let mut server_process = init_server(port);
    let duration = time::Duration::from_secs(1);
    thread::sleep(duration);
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
        .stdout(predicate::str::contains(
            "Account created and logged in to SAFE network",
        ))
        .success();
    server_process.kill().expect("Process was not running");
}

#[test]
#[ignore]
fn curl_login() {
    let mut rng = rand::thread_rng();
    let port: u16 = rng.gen();
    let mut server_process = init_server(port);
    let duration = time::Duration::from_secs(1);
    thread::sleep(duration);
    let rand_string: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .collect();

    let mut endpoint = format!(
        "http://localhost:{}/create/{}/{}/{}",
        port, &rand_string, &rand_string, &rand_string
    );
    let mut cmd = Command::new("curl");
    let mut child = cmd
        .args(&vec!["-X", "POST", &endpoint])
        .spawn()
        .expect("Failed to start");
    child.wait().expect("failed to wait");
    thread::sleep(duration);

    endpoint = format!(
        "http://localhost:{}/login/{}/{}",
        port, &rand_string, &rand_string
    );
    let mut cmd = Command::new("curl");
    cmd.args(&vec!["-X", "POST", &endpoint])
        .assert()
        .stdout(predicate::str::contains("Logged in to SAFE network"))
        .success();
    server_process.kill().expect("Process was not running");
}

#[test]
#[ignore]
fn curl_authorise() {
    let mut rng = rand::thread_rng();
    let port: u16 = rng.gen();
    let mut server_process = init_server(port);
    let duration = time::Duration::from_secs(1);
    thread::sleep(duration);
    let rand_string: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .collect();

    let mut endpoint = format!(
        "http://localhost:{}/create/{}/{}/{}",
        port, &rand_string, &rand_string, &rand_string
    );
    let mut cmd = Command::new("curl");
    let mut child = cmd
        .args(&vec!["-X", "POST", &endpoint])
        .spawn()
        .expect("Failed to start");
    child.wait().expect("failed to wait");
    thread::sleep(duration);

    endpoint = format!("http://localhost:{}/authorise/bAAAAAACTBZGGMAAAAAABGAAAAAAAAAAANB2W45DFOIXGYZLTORSXELRUHAXDGOAACYAAAAAAAAAAAR3VNFWGM33SMQQEQ5LOORSXEICMMVZXIZLSCEAAAAAAAAAAATLBNFSFGYLGMUXG4ZLUEBGHIZBOAEBAAAAAAAAAAAAHAAAAAAAAAAAF64DVMJWGSYYFAAAAAAAAAAAAAAAAAAAQAAAAAIAAAAADAAAAABAAAAAAYAAAAAAAAAAAL5YHKYTMNFRU4YLNMVZQKAAAAAAAAAAAAAAAAAABAAAAAAQAAAAAGAAAAACAAAAAAE", port);
    let mut cmd = Command::new("curl");
    cmd.args(&vec!["-X", "POST", &endpoint]).assert().success();
    server_process.kill().expect("Process was not running");
}

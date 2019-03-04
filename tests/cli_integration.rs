
#[cfg(test)]
mod cli_integration {
	extern crate rand;
	use rand::{thread_rng, Rng};
	use rand::distributions::Alphanumeric;

	use std::process::Command;
	use assert_cmd::prelude::*;

	static UNAUTHED_REQ: &str = "bAAAAAADNVCMIGAQAAAACQAAAAAAAAAAANZSXILTNMFUWI43BMZSS4YLQNFPXA3DBPFTXE33VNZSC453FMJRWY2LFNZ2C4MJQAE";

    #[test]
    fn calling_safe_create_acc() {

		let rand_string: String = thread_rng()
		.sample_iter(&Alphanumeric)
		.take(30)
		.collect();

		let mut cmd = Command::cargo_bin("safe_auth")
			.unwrap();

		cmd.args(&vec![ "--secret", &rand_string, "--password", &rand_string,"create","--invite-token", "aaa"])
		    .assert()
		    .success();
    }

	#[test]
	fn calling_safe_auth_without_args() {

		let mut cmd = Command::cargo_bin("safe_auth")
			.unwrap();

		    cmd.assert()
		    .failure()
			.code(1);
    }

	#[test]
	fn calling_safe_auth_with_unregistered_req() {

		let rand_string: String = thread_rng()
		.sample_iter(&Alphanumeric)
		.take(30)
		.collect();

		let mut cmd = Command::cargo_bin("safe_auth")
			.unwrap();


			cmd.args(&vec![ "--secret", &rand_string, "--password", &rand_string,"create","--invite-token", "aaa"])
			    .assert()
			    .success();

		let mut auth_cmd = Command::cargo_bin("safe_auth")
			.unwrap();

			auth_cmd.args(&vec![
				"--secret", &rand_string,
				"--password", &rand_string,
				"auth", "-r", &UNAUTHED_REQ])
		    .assert()
		    .success()
			;
    }
}

# SAFE Authenticator CLI
This crate implements a CLI for the [safe_authenticator](https://github.com/maidsafe/safe_client_libs/tree/master/safe_authenticator) crate.

## Build
Make sure you are using `rustc v1.32.0`:
```
$ cargo build
```

## Create a SAFE Network account
```
$ RUST_LOG=safe_auth=info cargo run -- --secret <secret> --password <password> create --invite-token <token>
Account successfully created!
```

## Log in the SAFE Network
```
$ RUST_LOG=safe_auth=info cargo run -- --secret <secret> --password <password>
Logged-in successfully!
```

## Authorising an application
```
$ RUST_LOG=safe_auth=info cargo run -- --secret <secret> --password <password> auth --req <auth req URI/string>
Auth response: <auth response>
```

## Getting the account's current PUT balance
```
$ RUST_LOG=safe_auth=info cargo run -- --secret <secret> --password <password> --balance
Account's current balance (PUTs done/available): <done>/<available>
```

## Getting the list of authorised applications
```
$ RUST_LOG=safe_auth=info cargo run -- --secret <secret> --password <password> --apps
Authorised applications: <list of authorised apps and containers permissions granted>
```

## Getting the account's current PUT balance and list of authorised applications
```
$ RUST_LOG=safe_auth=info cargo run -- --secret <secret> --password <password> --balance --apps
Account's current balance (PUTs done/available): <done>/<available>
Authorised applications: <list of authorised apps and containers permissions granted>
```

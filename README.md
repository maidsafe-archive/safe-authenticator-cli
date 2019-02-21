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

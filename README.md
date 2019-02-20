# SAFE Authenticator CLI

This crate implements a CLI for the [safe_authenticator](https://github.com/maidsafe/safe_client_libs/tree/master/safe_authenticator) crate.

## Build

Make sure you are using `rustc v1.30.0`:
```
$ cargo build
```

## Log in the SAFE Network

```
$ safe_auth_cli --secret <secret> --pwd <password>
Logged-in successfully!
```

## Authorising an application

```
$ auth_cli --secret <secret> --pwd <password> --auth <unregistered auth req>
Auth response: <auth response>
```

|Crate|Documentation|Linux/macOS|Windows|
|:---:|:-----------:|:--------:|:-----:|
|[![](http://meritbadge.herokuapp.com/safe-authenticator-cli)](https://crates.io/crates/safe-authenticator-cli)|[![Documentation](https://docs.rs/safe-authenticator-cli/badge.svg)](https://docs.rs/safe-authenticator-cli)|[![Build Status](https://travis-ci.com/maidsafe/safe-authenticator-cli.svg?branch=master)](https://travis-ci.com/maidsafe/safe-authenticator-cli)|[![Build status](https://ci.appveyor.com/api/projects/status/ajw6ab26p86jdac4/branch/master?svg=true)](https://ci.appveyor.com/project/MaidSafe-QA/safe-authenticator-cli/branch/master)|

| [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:----------------------------------------:|:-------------------------------------------:|:----------------------------------------------:|

# SAFE Authenticator CLI
This crate implements a CLI for the [safe_authenticator](https://github.com/maidsafe/safe_client_libs/tree/master/safe_authenticator) crate.

## Build
Make sure you are using `rustc v1.32.0`:
```
$ cargo build
```

## Run doc tests
```
$ cargo test --doc
```

## Create a SAFE Network account
```
$ RUST_LOG=safe_auth=info cargo run -- --pretty --invite-token <token>
Secret:
Password:
Account was created successfully!
```

## Log in the SAFE Network
```
$ RUST_LOG=safe_auth=info cargo run -- --pretty
Secret:
Password:
Logged in the SAFE Network successfully!
```

## Authorising an application
```
$ RUST_LOG=safe_auth=info cargo run -- --pretty --req <auth req string>
Secret:
Password:
Authorisation response string: <auth response>
```

## Getting the account's current PUT balance
```
$ RUST_LOG=safe_auth=info cargo run -- --pretty --balance
Secret:
Password:
Logged in the SAFE Network successfully!
Account's current balance (PUTs done/avaialble): <done>/<available>
```

## Getting the list of authorised applications
```
$ RUST_LOG=safe_auth=info cargo run -- --pretty --apps
Secret:
Password:
Logged in the SAFE Network successfully!
+---------------------------------+--------------+------------------+---------------------+
| Authorised Applications         |              |                  |                     |
+---------------------------------+--------------+------------------+---------------------+
| Id                              | Name         | Vendor           | Permissions         |
+---------------------------------+--------------+------------------+---------------------+
| <app ID>                        | <app's name> | <vendor name>    | <app's permissions> |
+---------------------------------+--------------+------------------+---------------------+
| ...                                                                                     |
+---------------------------------+--------------+------------------+---------------------+
```

## Getting the account's current PUT balance and list of authorised applications
```
$ RUST_LOG=safe_auth=info cargo run -- --pretty --balance --apps
Secret:
Password:
Logged in the SAFE Network successfully!
Account's current balance (PUTs done/avaialble): <done>/<available>
+---------------------------------+--------------+------------------+---------------------+
| Authorised Applications         |              |                  |                     |
+---------------------------------+--------------+------------------+---------------------+
| Id                              | Name         | Vendor           | Permissions         |
+---------------------------------+--------------+------------------+---------------------+
| <app ID>                        | <app's name> | <vendor name>    | <app's permissions> |
+---------------------------------+--------------+------------------+---------------------+
| ...                                                                                     |
+---------------------------------+--------------+------------------+---------------------+
```

## Revoking permissions from an application
```
$ RUST_LOG=safe_auth=info cargo run -- --pretty --revoke <app ID>
Secret:
Password:
Logged in the SAFE Network successfully!
Authorised permissions were revoked for app '<app ID>'
```

## Execute Authenticator service, exposing RESTful API
```
$ cargo run -- --daemon 41805
Secret:
Password:
Exposing service on 127.0.0.1:41805
```

Then on a separate terminal you can authorise an application with:
```
$ curl -X POST http://localhost:41805/authorise/<auth req string>
```

## License
This SAFE Network application is dual-licensed under the Modified BSD ([LICENSE-BSD](LICENSE-BSD) https://opensource.org/licenses/BSD-3-Clause) or the MIT license ([LICENSE-MIT](LICENSE-MIT) https://opensource.org/licenses/MIT) at your option.

## Contribute
Copyrights in the SAFE Network are retained by their contributors. No copyright assignment is required to contribute to this project.

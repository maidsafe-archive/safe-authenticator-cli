|Documentation|Linux/macOS/Windows|
|:-----------:|:-----------------:|
| [![Documentation](https://docs.rs/safe-authenticator-cli/badge.svg)](https://docs.rs/safe-authenticator-cli) | [![Build Status](https://travis-ci.com/maidsafe/safe-authenticator-cli.svg?branch=master)](https://travis-ci.com/maidsafe/safe-authenticator-cli) |

| [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:----------------------------------------:|:-------------------------------------------:|:----------------------------------------------:|

# SAFE Authenticator CLI
This crate implements a CLI (Command Line Interface) for the [safe_authenticator](https://github.com/maidsafe/safe_client_libs/tree/master/safe_authenticator) crate.

The [SAFE Browser](https://github.com/maidsafe/safe_browser) provides an integrated Authenticator GUI for users to create SAFE Network accounts, log in using an existing account's credentials (secret and password), authorise applications which need to store data on the network on behalf of the user, as well as revoke permissions previously granted to applications.

However, there are some scenarios where having to launch the browser just to be able to have the authenticator running is not that practical. E.g., developers working on a desktop SAFE application, either during development, testing, or even debugging phase, may find it uncomfortable or overkill if all they need is just the apps credentials to connect to the SAFE Network to test the main logic of such application, and perhaps not the authorisation flow. In these scenarios having a CLI is much more flexible and easy to use as its output could also be chained with other commands and/or applications can simply execute the CLI and read the result from its `stdout` instead of having to interface with the SAFE Browser/Authenticator through the system URI protocol.

Simply put, this tool provides an alternative to the Authenticator that is currently integrated in the SAFE Browser, and to its communication protocol, allowing to perform the same set of operations but through a command line user interface.

## Build

In order to build this CLI from source code you need to make sure you have `rustc v1.32.0` (or higher) installed. Please take a look at this [notes about Rust installation](https://www.rust-lang.org/tools/install) if you need help with installing it. We recommend you install it with `rustup` which will install `cargo` tool since this guide makes use of it.

Once Rust and its toolchain are installed, run the following commands to clone this repository and build the `safe_auth` crate (the build process may take several minutes the first time you run it on this crate):
```
$ git clone https://github.com/maidsafe/safe-authenticator-cli.git
$ cd safe-authenticator-cli
$ cargo build
```

## Using the Mock or Non-Mock SAFE Network

By default, the `safe_auth` CLI is built with [Non-Mock libraries](https://github.com/maidsafe/safe_client_libs/wiki/Mock-vs.-non-mock). If you are intending to use it with the `Mock` network you'll need to specify the `mock-network` feature in every command you run with `cargo`, e.g. to build it for the `Mock` network you can run:
```
$ cargo build --features mock-network
```

Keep in mind that when running the safe_auth CLI with `cargo run` as explained in the following sections below, please also make sure to set the `mock-network` feature if you want to use the Mock network, e.g. with the following command the `safe_auth` will try to connect and login to the Mock network:
```
$ cargo run --features mock-network
```

## Run tests

You can run all existing tests with:
```
$ cargo test --features mock-network
```

The `safe_auth` internal functions have some documentation written as [doc tests](https://doc.rust-lang.org/rustdoc/documentation-tests.html). You can run these specific tests with the following command:
```
$ cargo test --doc --features mock-network
```

## Using the CLI

The `safe_auth` can be executed with:
1. `cargo run -- <list of arguments/options>`
2. or directly with the executable generated: `./target/debug/safe_auth <list of arguments/options>`

As any other CLI, the `safe_auth` supports the `--help` argument which outputs a help message with information on the supported arguments and options, you can get this help message with:
```
$ cargo run -- --help
```

The `safe_auth` output can be of two different formats:
1. The default one that can be used by any other applications by parsing the output string obtained from the `stdout`
2. A more verbose output which is intended for human users of the tool that can be enabled with the use of the `--pretty` argument. We are using this argument in all the examples of this guide.

Apart from the output generated in the `stdout`, the `safe_auth` tool also generates logs at different levels like any other Rust application. These logs levels (`debug`, `info`, etc.) can be set by setting the `RUST_LOG` environment variable, e.g. to set `info` level:
```
$ export RUST_LOG=safe_auth=info
```

Windows users in Command Prompt, will first need to run `set RUST_LOG=safe_auth=info`. If using Windows PowerShell, run `$env:RUST_LOG = "safe_auth=info"`

Note that this environment variable will only persist in your current terminal until it is closed.

Now let's look at some of the features and operations supported, how they can be executed from the CLI, and how they can be combined together.

### Create a SAFE Network account
```
$ cargo run -- --pretty --sk <secret key hex string>
Secret:
Password:
Account was created successfully!
```

### Log in the SAFE Network
```
$ cargo run -- --pretty
Secret:
Password:
Logged in the SAFE Network successfully!
```

#### Using a config file

It's possible (though not secure) to use a simple json file to pass `secret` and `password` to the auth CLI, and so avoid having to manually input both.

```
// my.config.json
{
  "password": "v2SwvNl7MR52A5mdtoeXjDVqch3tWm",
  "secret": "v2SwvNl7MR52A5mdtoeXjDVqch3tWm"
}

```
And so you can log in, thus:
```
$ cargo run -- --pretty --config ./my.config.json
Logged in the SAFE Network successfully!
```


#### Using Environment Variables

Another method for passing secret/password involves using the environment variables `SAFE_AUTH_SECRET` and `SAFE_AUTH_PASSWORD`.

With those set (eg, on linux/osx: `export SAFE_AUTH_SECRET="<your secret>;"`, and `export SAFE_AUTH_PASSWORD="<your password>"`), you can then login without needing to enter login details, or pass a config file:

```
$ cargo run -- --pretty
Logged in the SAFE Network successfully!
```

Or, you can choose to pass the environment variables to the command directly (though this can be insecure):

```
$ SAFE_AUTH_SECRET="<secret>" SAFE_AUTH_PASSWORD="<password>" cargo run -- --pretty
Logged in the SAFE Network successfully!
```

Please note, that _both_ the secret and password environment variables must be set to use this method. If only one is set, an error will be thrown.

### Authorising an application
```
$ cargo run -- --pretty --req <auth req string>
Secret:
Password:
Logged in the SAFE Network successfully!
The following application authorisation request was received:
+---------------------------------+--------------+------------------+----------------------------------------------+
| Id                              | Name         | Vendor           | Permissions requested                        |
+---------------------------------+--------------+------------------+----------------------------------------------+
| <app ID>                        | <app's name> | <vendor name>    | Own container: false                         |
|                                 |              |                  | Default containers: <permissions requested>  |
+---------------------------------+--------------+------------------+----------------------------------------------+
Allow authorisation? [y/N]:
Authorisation will be allowed...
Authorisation response string: <auth response>
```

As you can see before each authorisation request is allowed, the user is prompted for confirmation. Optionally, this prompt can be disabled to have the `safe_auth` to automatically allow all incoming authorisation requests. We can do this by passing the `--allow-all-auth` argument in the command line:
```
$ cargo run -- --pretty --allow-all-auth --req <auth req string>
```

For example, the following command passes a valid encoded authorisation request as the value of the `--req` argument and it allows the authorisation to be made without prompting:
```
$ cargo run -- --pretty --allow-all-auth --req bAAAAAABU6IEAEAAAAAACMAAAAAAAAAAANZSXILTNMFUWI43BMZSS45DFON2C4YLVORUGK3TUNFRWC5DPOIXGG3DJFZUWIAILAAAAAAAAAAAF65DFON2F643DN5YGKGYAAAAAAAAAABJHK43UEBAXK5DIMVXHI2LDMF2G64RAINGESICUMVZXIEAAAAAAAAAAABGWC2LEKNQWMZJONZSXIICMORSAAAIAAAAAAAAAAADQAAAAAAAAAAC7OB2WE3DJMMAQAAAAAAAAAAAAAAAAAAI
```

The expected encoded authorisation request string is the one that can be generated by any application using the SAFE API, e.g. an application using the `safe_app_nodejs` would make use of the [genAuthUri](https://docs.maidsafe.net/safe_app_nodejs/authinterface#genAuthUri), [genConnUri](https://docs.maidsafe.net/safe_app_nodejs/authinterface#genConnUri), [genContainerAuthUri](https://docs.maidsafe.net/safe_app_nodejs/authinterface#genContainerAuthUri), or [genShareMDataUri](https://docs.maidsafe.net/safe_app_nodejs/authinterface#genShareMDataUri) functions to generate such encoded string.

The output obtained from the `safe_auth` CLI command when passing a `--req` argument, can then be used by such a Nodejs application to connect to the SAFE Network with the [loginFromUri](https://docs.maidsafe.net/safe_app_nodejs/authinterface#loginFromUri) function.

### Getting the list of authorised applications
```
$ cargo run -- --pretty --apps
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

### Revoking permissions from an application
```
$ cargo run -- --pretty --revoke <app ID>
Secret:
Password:
Logged in the SAFE Network successfully!
Authorised permissions were revoked for app '<app ID>'
```

### Execute Authenticator service, exposing RESTful API
```
$ cargo run -- --daemon 41805
Secret:
Password:
Exposing service on 127.0.0.1:41805
```

Then on a separate terminal you can authorise an application with:
```
$ curl -X GET http://localhost:41805/authorise/<auth req string>
```

## License
This SAFE Network application is licensed under the General Public License (GPL), version 3 ([LICENSE](LICENSE) http://www.gnu.org/licenses/gpl-3.0.en.html).

## Contribute
Copyrights in the SAFE Network are retained by their contributors. No copyright assignment is required to contribute to this project.

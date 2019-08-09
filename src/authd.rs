// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use actix_web::{web, App, HttpResponse, HttpServer};
use safe_auth::{authorise_app, create_acc, log_in, AuthAllowPrompt};
use safe_authenticator::{AuthError, Authenticator};
use std::sync::{Arc, Mutex};

type SharedHandleType = Arc<Mutex<Option<Result<Authenticator, AuthError>>>>;

pub fn run(
    port_arg: u16,
    authenticator: Option<Authenticator>,
    prompt_to_allow: &'static AuthAllowPrompt,
) {
    let handle: SharedHandleType = match authenticator {
        Some(auth) => Arc::new(Mutex::new(Some(Ok(auth)))),
        None => Arc::new(Mutex::new(None)),
    };

    let port: Arc<u16> = Arc::new(port_arg);
    let address = format!("127.0.0.1:{}", *port);

    println!("Exposing service on {}", &address);
    let _ = HttpServer::new(move || {
        App::new()
            .data(AuthenticatorState {
                handle: handle.clone(),
                allow_auth_cb: Arc::new(prompt_to_allow),
            })
            .route(
                "/",
                web::get().to(|| {
                    HttpResponse::Ok().body("SAFE Authenticator service is up and running!")
                }),
            )
            .route("/authorise/{auth_req}", web::get().to(authd_authorise))
            .default_service(
                web::get().to(|| HttpResponse::NotFound().body("Service endpoint not found.")),
            )
    })
    .bind(&address)
    .unwrap()
    .run();
}

struct AuthenticatorState {
    pub handle: SharedHandleType,
    pub allow_auth_cb: Arc<&'static AuthAllowPrompt>,
}

#[allow(dead_code)]
fn authd_create_acc(
    info: web::Path<(String, String, String)>,
    req: web::Data<AuthenticatorState>,
) -> HttpResponse {
    match create_acc(&info.2.clone(), &info.0.clone(), &info.1.clone()) {
        Ok(auth) => {
            *(unwrap!(req.handle.lock())) = Some(Ok(auth));
            HttpResponse::Ok().body("Account created and logged in to SAFE Network.")
        }
        Err(auth_error) => {
            let response_string = format!("Failed to create account: {}", &auth_error);
            *(unwrap!(req.handle.lock())) = Some(Err(AuthError::from(auth_error)));
            HttpResponse::BadRequest().body(response_string)
        }
    }
}

#[allow(dead_code)]
fn authd_login(
    info: web::Path<(String, String)>,
    req: web::Data<AuthenticatorState>,
) -> HttpResponse {
    match log_in(&info.0.clone(), &info.1.clone()) {
        Ok(auth) => {
            *(unwrap!(req.handle.lock())) = Some(Ok(auth));
            HttpResponse::Ok().body("Logged in to SAFE Network.")
        }
        Err(auth_error) => {
            let response_string = format!("Login failed: {} ", &auth_error);
            *(unwrap!(req.handle.lock())) = Some(Err(AuthError::from(auth_error)));
            HttpResponse::BadRequest().body(response_string)
        }
    }
}

fn authd_authorise(
    authenticator_req: web::Path<String>,
    http_req: web::Data<AuthenticatorState>,
) -> HttpResponse {
    let authenticator: &Option<Result<Authenticator, AuthError>> =
        &*(unwrap!(http_req.handle.lock()));
    let allow: &'static AuthAllowPrompt = *(http_req.allow_auth_cb);
    match authenticator {
        Some(Ok(auth_handle)) => {
            let response = authorise_app(auth_handle, &authenticator_req, allow);
            match response {
                Ok(resp) => {
                    println!("Authorisation response sent");
                    HttpResponse::Ok().body(resp)
                }
                Err(err) => HttpResponse::BadRequest().body(err),
            }
        }
        Some(Err(auth_error)) => HttpResponse::BadRequest().body(format!("{}", auth_error)),
        None => HttpResponse::BadRequest().body("Authenticator is not logged in."),
    }
}

#[cfg(test)]
mod tests {
    use super::{create_acc, create_web_service, AuthenticatorState, SharedHandleType};
    use actix_web::{http::Method, test, ws, HttpMessage};
    use futures::Stream;
    use rand::Rng;
    use safe_authenticator::Authenticator;
    use std::str::from_utf8;
    use std::sync::{Arc, Mutex};

    fn create_test_service(authenticator: Option<Authenticator>) -> test::TestServer {
        let handle: SharedHandleType = match authenticator {
            Some(auth) => Arc::new(Mutex::new(Some(Ok(auth)))),
            None => Arc::new(Mutex::new(None)),
        };
        test::TestServer::with_factory(move || {
            create_web_service(AuthenticatorState {
                handle: handle.clone(),
                allow_auth_cb: Arc::new(&|_| true),
            })
        })
    }

    #[test]
    fn get_index() {
        let mut srv = create_test_service(None);
        let request = unwrap!(srv.client(Method::GET, "/").finish());
        let response = unwrap!(srv.execute(request.send()));

        assert!(response.status().is_success());
    }

    #[test]
    #[ignore] // we don't expose create acc from webservice yet
    fn post_create_account() {
        let mut rng = rand::thread_rng();
        let secret: u32 = rng.gen();
        let password: u32 = rng.gen();
        let invite: u16 = rng.gen();
        let mut srv = create_test_service(None);

        let endpoint = format!("/create/{}/{}/{}", secret, password, invite);
        let request = unwrap!(srv.client(Method::POST, &endpoint).finish());
        match srv.execute(request.send()) {
            Ok(response) => {
                assert!(response.status().is_success());
            }
            Err(req_err) => {
                println!("POST create account request error: {:?}", req_err);
            }
        }
    }

    #[test]
    #[ignore] // we don't expose login from webservice yet
    fn post_login() {
        let mut rng = rand::thread_rng();
        let secret: u32 = rng.gen();
        let password: u32 = rng.gen();
        let invite: u16 = rng.gen();
        let mut srv = create_test_service(None);
        let create_acc_endpoint = format!("/create/{}/{}/{}", secret, password, invite);
        let create_acc_request = unwrap!(srv.client(Method::POST, &create_acc_endpoint).finish());
        match srv.execute(create_acc_request.send()) {
            Ok(response) => {
                assert!(response.status().is_success());
            }
            Err(req_err) => {
                println!("POST create account error: {:?}", req_err);
            }
        }

        let login_endpoint = format!("/login/{}/{}", secret, password);
        let login_request = unwrap!(srv.client(Method::POST, &login_endpoint).finish());

        match srv.execute(login_request.send()) {
            Ok(response) => {
                assert!(response.status().is_success());
            }
            Err(req_err) => {
                println!("POST login request error: {:?}", req_err);
            }
        }
    }

    #[test]
    fn get_authorise_app() {
        fn random_str() -> String {
            (0..4).map(|_| rand::random::<char>()).collect()
        }
        let invite = &(random_str());
        let secret = &(random_str());
        let password = &(random_str());
        let authenticator = unwrap!(create_acc(invite, secret, password));
        let mut srv = create_test_service(Some(authenticator));
        let endpoint = "/authorise/bAAAAAAEXVK4SGAAAAAABAAAAAAAAAAAANZSXILTNMFUWI43BMZSS4Y3MNEAAQAAAAAAAAAAAKNAUMRJAINGESEAAAAAAAAAAABGWC2LEKNQWMZJONZSXIICMORSAAAIBAAAAAAAAAAAAOAAAAAAAAAAAL5YHKYTMNFRQCAAAAAAAAAAAAAAAAAAB";
        let request = unwrap!(srv.client(Method::GET, &endpoint).finish());
        match srv.execute(request.send()) {
            Ok(response) => {
                assert!(response.status().is_success());
                let bytes = unwrap!(srv.execute(response.body()));
                let body = unwrap!(from_utf8(&bytes));
                assert!(body.len() > 0);
            }
            Err(req_err) => {
                println!("GET authorise request error: {:?}", req_err);
            }
        }
    }

    #[test]
    fn get_web_socket() {
        let mut srv = create_test_service(None);
        let (reader, mut writer) = unwrap!(srv.ws_at("/ws"));
        writer.text("text");

        let (item, _reader) = unwrap!(srv.execute(reader.into_future()));
        assert_eq!(item, Some(ws::Message::Text("text".to_owned())));
    }
}

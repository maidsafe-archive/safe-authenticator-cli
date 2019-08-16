// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use actix_web::{web, App, HttpResponse, HttpServer};
use safe_auth::{authorise_app, /*create_acc, log_in,*/ AuthAllowPrompt};
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
            .configure(configure_services)
    })
    .bind(&address)
    .unwrap()
    .run();
}

fn configure_services(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/").route(
        web::get().to(|| HttpResponse::Ok().body("SAFE Authenticator service is up and running!")),
    ));
    cfg.service(
        web::resource("/create/{secret}/{password}/{sk}").route(web::post().to(authd_create_acc)),
    );
    cfg.service(web::resource("/login/{secret}/{password}").route(web::post().to(authd_login)));
    cfg.service(web::resource("/authorise/{auth_req}").route(web::get().to(authd_authorise)));
    cfg.service(
        web::resource("*")
            .route(web::get().to(|| HttpResponse::NotFound().body("Service endpoint not found."))),
    );
}

struct AuthenticatorState {
    pub handle: SharedHandleType,
    pub allow_auth_cb: Arc<&'static AuthAllowPrompt>,
}

fn authd_create_acc(
    _info: web::Path<(String, String, String)>,
    _req: web::Data<AuthenticatorState>,
) -> HttpResponse {
    HttpResponse::NotFound().body("Create service not supported yet.")
    /*
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
    */
}

fn authd_login(
    _info: web::Path<(String, String)>,
    _req: web::Data<AuthenticatorState>,
) -> HttpResponse {
    HttpResponse::NotFound().body("Login service not supported yet.")
    /*
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
    */
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
    use super::{configure_services, AuthenticatorState};
    use actix_web::{test, App};
    use rand::Rng;
    use safe_auth::create_acc;
    use safe_core::client::test_create_balance;
    use safe_nd::Coins;
    use std::str::from_utf8;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use threshold_crypto::{serde_impl::SerdeSecret, SecretKey};

    fn gen_random_sk_hex() -> (String, SecretKey) {
        let sk = SecretKey::random();
        let sk_serialised = bincode::serialize(&SerdeSecret(&sk))
            .expect("Failed to serialise the generated secret key");
        let sk_hex = sk_serialised.iter().map(|b| format!("{:02x}", b)).collect();
        (sk_hex, sk)
    }

    macro_rules! create_test_service {
        ($authenticator:expr) => {
            test::init_service(
                App::new()
                    .data(AuthenticatorState {
                        handle: match $authenticator {
                            Some(auth) => Arc::new(Mutex::new(Some(Ok(auth)))),
                            None => Arc::new(Mutex::new(None)),
                        },
                        allow_auth_cb: Arc::new(&|_| true),
                    })
                    .configure(configure_services),
            )
        };
    }

    #[test]
    fn get_root() {
        let mut srv = create_test_service!(None);
        let request = test::TestRequest::get().uri("/").to_request();
        let response = test::read_response(&mut srv, request);
        let body = unwrap!(from_utf8(&response));
        assert_eq!(body, "SAFE Authenticator service is up and running!");
    }

    #[test]
    fn get_invalid_endpoint() {
        let mut srv = create_test_service!(None);
        let request = test::TestRequest::get()
            .uri("/invalid-endpoint")
            .to_request();
        let response = test::read_response(&mut srv, request);
        let body = unwrap!(from_utf8(&response));
        assert_eq!(body, "Service endpoint not found.");
    }

    #[test] // we don't expose create acc from webservice yet
    fn post_create_account() {
        let mut rng = rand::thread_rng();
        let secret: u32 = rng.gen();
        let password: u32 = rng.gen();
        let (sk, _) = &gen_random_sk_hex();
        let mut srv = create_test_service!(None);
        let endpoint = format!("/create/{}/{}/{}", secret, password, sk);
        let request = test::TestRequest::post().uri(&endpoint).to_request();
        let response = test::read_response(&mut srv, request);
        let body = unwrap!(from_utf8(&response));
        assert_eq!(body, "Create service not supported yet.");
    }

    #[test] // we don't expose login from webservice yet
    fn post_login() {
        let mut rng = rand::thread_rng();
        let secret: u32 = rng.gen();
        let password: u32 = rng.gen();
        let (sk, _) = &gen_random_sk_hex();
        let mut srv = create_test_service!(None);
        let create_acc_endpoint = format!("/create/{}/{}/{}", secret, password, sk);
        let request = test::TestRequest::post()
            .uri(&create_acc_endpoint)
            .to_request();
        let response = test::read_response(&mut srv, request);
        let body = unwrap!(from_utf8(&response));
        assert_eq!(body, "Create service not supported yet.");

        let login_endpoint = format!("/login/{}/{}", secret, password);
        let request = test::TestRequest::post().uri(&login_endpoint).to_request();
        let response = test::read_response(&mut srv, request);
        let body = unwrap!(from_utf8(&response));
        assert_eq!(body, "Login service not supported yet.");
    }

    #[test]
    fn get_authorise_app() {
        fn random_str() -> String {
            (0..4).map(|_| rand::random::<char>()).collect()
        }
        let (sk, secret_key) = &gen_random_sk_hex();
        test_create_balance(secret_key, Coins::from_str("5").unwrap()).unwrap();
        let secret = &(random_str());
        let password = &(random_str());
        let authenticator = unwrap!(create_acc(sk, secret, password));

        let mut srv = create_test_service!(Some(authenticator));
        let endpoint = "/authorise/bAAAAAAEXVK4SGAAAAAABAAAAAAAAAAAANZSXILTNMFUWI43BMZSS4Y3MNEAAQAAAAAAAAAAAKNAUMRJAINGESEAAAAAAAAAAABGWC2LEKNQWMZJONZSXIICMORSAAAIBAAAAAAAAAAAAOAAAAAAAAAAAL5YHKYTMNFRQCAAAAAAAAAAAAAAAAAAB";
        let request = test::TestRequest::get().uri(&endpoint).to_request();
        let response = test::read_response(&mut srv, request);
        let body = unwrap!(from_utf8(&response));
        assert!(body.len() > 0);
    }
}

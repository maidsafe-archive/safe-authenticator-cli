// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{authorise_app, create_acc, log_in};
use actix_web::{actix::*, http::Method, server, ws, App, Error, HttpRequest, HttpResponse, Path};
use log::debug;
use safe_authenticator::{AuthError, Authenticator};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// How often heartbeat pings are sent
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
// How long before lack of client response causes a timeout
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

pub fn run(port_arg: u16, authenticator: Option<Authenticator>) {
    let handle: Arc<Mutex<Option<Result<Authenticator, AuthError>>>> = match authenticator {
        Some(auth) => Arc::new(Mutex::new(Some(Ok(auth)))),
        None => Arc::new(Mutex::new(None)),
    };

    let port: Arc<u16> = Arc::new(port_arg);
    let address = format!("127.0.0.1:{}", *port);
    println!("Exposing service on {}", &address);

    server::new(move || {
        create_web_service(AuthenticatorState {
            handle: handle.clone(),
        })
        .finish()
    })
    .bind(&address)
    .unwrap()
    .run();
}

fn create_web_service(state: AuthenticatorState) -> App<AuthenticatorState> {
    App::with_state(state)
        .resource("/", |r| {
            r.method(Method::GET).f(|_| HttpResponse::Ok());
        })
        .resource("/authorise/{auth_req}", |r| {
            r.method(Method::GET).with(authd_authorise);
        })
        .resource("/ws", |r| {
            r.method(Method::GET).with(authd_web_socket);
        })
        .default_resource(|r| r.f(|_| HttpResponse::NotFound().body("Service endpoint not found.")))
}

struct AuthenticatorState {
    pub handle: Arc<Mutex<Option<Result<Authenticator, AuthError>>>>,
}

struct WebSocket {
    hb: Instant,
}

impl Actor for WebSocket {
    type Context = ws::WebsocketContext<Self, AuthenticatorState>;

    /// Method is called on actor start. We start the heartbeat process here.
    fn started(&mut self, ctx: &mut Self::Context) {
        self.hb(ctx);
    }
}

/// Handler for `ws::Message`
impl StreamHandler<ws::Message, ws::ProtocolError> for WebSocket {
    fn handle(&mut self, msg: ws::Message, ctx: &mut Self::Context) {
        // process websocket messages
        debug!("WebSocket message: {:?}", msg);
        match msg {
            ws::Message::Ping(msg) => {
                self.hb = Instant::now();
                ctx.pong(&msg);
            }
            ws::Message::Pong(_) => {
                self.hb = Instant::now();
            }
            ws::Message::Text(text) => ctx.text(text),
            ws::Message::Binary(bin) => ctx.binary(bin),
            ws::Message::Close(_) => {
                ctx.stop();
            }
        }
    }
}

impl WebSocket {
    fn new() -> Self {
        Self { hb: Instant::now() }
    }

    /// helper method that sends ping to client every second.
    ///
    /// also this method checks heartbeats from client
    fn hb(&self, ctx: &mut <Self as Actor>::Context) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            // check client heartbeats
            if Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                // heartbeat timed out
                debug!("Websocket Client heartbeat failed, disconnecting!");

                // stop actor
                ctx.stop();

                // don't try to send a ping
                return;
            }

            ctx.ping("");
        });
    }
}

#[allow(dead_code)]
fn authd_create_acc(
    info: Path<(String, String, String)>,
    req: HttpRequest<AuthenticatorState>,
) -> HttpResponse {
    match create_acc(&info.2.clone(), &info.0.clone(), &info.1.clone()) {
        Ok(auth) => {
            *(req.state().handle.lock().unwrap()) = Some(Ok(auth));
            HttpResponse::Ok().body("Account created and logged in to SAFE Network.")
        }
        Err(auth_error) => {
            let response_string = format!("Failed to create account: {}", &auth_error);
            *(req.state().handle.lock().unwrap()) = Some(Err(AuthError::from(auth_error)));
            HttpResponse::BadRequest().body(response_string)
        }
    }
}

#[allow(dead_code)]
fn authd_login(info: Path<(String, String)>, req: HttpRequest<AuthenticatorState>) -> HttpResponse {
    match log_in(&info.0.clone(), &info.1.clone()) {
        Ok(auth) => {
            *(req.state().handle.lock().unwrap()) = Some(Ok(auth));
            HttpResponse::Ok().body("Logged in to SAFE Network.")
        }
        Err(auth_error) => {
            let response_string = format!("Login failed: {} ", &auth_error);
            *(req.state().handle.lock().unwrap()) = Some(Err(AuthError::from(auth_error)));
            HttpResponse::BadRequest().body(response_string)
        }
    }
}

fn authd_authorise(
    authenticator_req: Path<String>,
    http_req: HttpRequest<AuthenticatorState>,
) -> HttpResponse {
    let authenticator: &Option<Result<Authenticator, AuthError>> =
        &*(http_req.state().handle.lock().unwrap());
    match authenticator {
        Some(Ok(auth_handle)) => {
            let response = authorise_app(auth_handle, &authenticator_req);
            match response {
                Ok(resp) => HttpResponse::Ok().body(resp),
                Err(err) => HttpResponse::BadRequest().body(err),
            }
        }
        Some(Err(auth_error)) => HttpResponse::BadRequest().body(format!("{}", auth_error)),
        None => HttpResponse::BadRequest().body("Authenticator is not logged in."),
    }
}

fn authd_web_socket(req: HttpRequest<AuthenticatorState>) -> Result<HttpResponse, Error> {
    ws::start(&req, WebSocket::new())
}

#[cfg(test)]
mod tests {
    use super::{create_acc, create_web_service, AuthenticatorState};
    use actix_web::{http::Method, test, ws, HttpMessage};
    use futures::Stream;
    use rand::Rng;
    use safe_authenticator::{AuthError, Authenticator};
    use std::str::from_utf8;
    use std::sync::{Arc, Mutex};

    fn create_test_service(authenticator: Option<Authenticator>) -> test::TestServer {
        let handle: Arc<Mutex<Option<Result<Authenticator, AuthError>>>> = match authenticator {
            Some(auth) => Arc::new(Mutex::new(Some(Ok(auth)))),
            None => Arc::new(Mutex::new(None)),
        };
        test::TestServer::with_factory(move || {
            create_web_service(AuthenticatorState {
                handle: handle.clone(),
            })
        })
    }

    #[test]
    fn get_index() {
        let mut srv = create_test_service(None);
        let request = srv.client(Method::GET, "/").finish().unwrap();
        let response = srv.execute(request.send()).unwrap();

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
        let request = srv.client(Method::POST, &endpoint).finish().unwrap();
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
        let create_acc_request = srv
            .client(Method::POST, &create_acc_endpoint)
            .finish()
            .unwrap();
        match srv.execute(create_acc_request.send()) {
            Ok(response) => {
                assert!(response.status().is_success());
            }
            Err(req_err) => {
                println!("POST create account error: {:?}", req_err);
            }
        }

        let login_endpoint = format!("/login/{}/{}", secret, password);
        let login_request = srv.client(Method::POST, &login_endpoint).finish().unwrap();

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
        let authenticator = create_acc(invite, secret, password).unwrap();
        let mut srv = create_test_service(Some(authenticator));
        let endpoint = "/authorise/bAAAAAACTBZGGMAAAAAABGAAAAAAAAAAANB2W45DFOIXGYZLTORSXELRUHAXDGOAACYAAAAAAAAAAAR3VNFWGM33SMQQEQ5LOORSXEICMMVZXIZLSCEAAAAAAAAAAATLBNFSFGYLGMUXG4ZLUEBGHIZBOAEBAAAAAAAAAAAAHAAAAAAAAAAAF64DVMJWGSYYFAAAAAAAAAAAAAAAAAAAQAAAAAIAAAAADAAAAABAAAAAAYAAAAAAAAAAAL5YHKYTMNFRU4YLNMVZQKAAAAAAAAAAAAAAAAAABAAAAAAQAAAAAGAAAAACAAAAAAE";
        let request = srv.client(Method::GET, &endpoint).finish().unwrap();
        match srv.execute(request.send()) {
            Ok(response) => {
                assert!(response.status().is_success());
                let bytes = srv.execute(response.body()).unwrap();
                let body = from_utf8(&bytes).unwrap();
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
        let (reader, mut writer) = srv.ws_at("/ws").unwrap();
        writer.text("text");

        let (item, _reader) = srv.execute(reader.into_future()).unwrap();
        assert_eq!(item, Some(ws::Message::Text("text".to_owned())));
    }
}

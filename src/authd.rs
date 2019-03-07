use super::{authorise_app, create_acc, log_in};
use actix_web::{actix::*, http::Method, server, ws, App, Error, HttpRequest, HttpResponse, Path};
use safe_authenticator::{AuthError, Authenticator};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// How often heartbeat pings are sent
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
// How long before lack of client response causes a timeout
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct AuthenticatorState {
    pub handle: Arc<Mutex<Option<Result<Authenticator, AuthError>>>>,
    pub host_port: Arc<u16>,
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
        println!("WS: {:?}", msg);
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
                println!("Websocket Client heartbeat failed, disconnecting!");

                // stop actor
                ctx.stop();

                // don't try to send a ping
                return;
            }

            ctx.ping("");
        });
    }
}

pub fn authd_create_acc(
    info: Path<(String, String, String)>,
    req: HttpRequest<AuthenticatorState>,
) -> HttpResponse {
    match create_acc(&info.2.clone(), &info.0.clone(), &info.1.clone()) {
        Ok(auth) => {
            *(req.state().handle.lock().unwrap()) = Some(Ok(auth));
            HttpResponse::Ok().body("Account created and logged in to SAFE network.")
        }
        Err(auth_error) => {
            let response_string = format!("Failed to create account: {} ", &auth_error);
            *(req.state().handle.lock().unwrap()) = Some(Err(AuthError::from(auth_error)));
            HttpResponse::BadRequest().body(response_string)
        }
    }
}

pub fn authd_login(
    info: Path<(String, String)>,
    req: HttpRequest<AuthenticatorState>,
) -> HttpResponse {
    match log_in(&info.0.clone(), &info.1.clone()) {
        Ok(auth) => {
            *(req.state().handle.lock().unwrap()) = Some(Ok(auth));
            HttpResponse::Ok().body("Logged in to SAFE network.")
        }
        Err(auth_error) => {
            let response_string = format!("Login failed: {} ", &auth_error);
            *(req.state().handle.lock().unwrap()) = Some(Err(AuthError::from(auth_error)));
            HttpResponse::BadRequest().body(response_string)
        }
    }
}

pub fn authd_authorise(
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

pub fn authd_web_socket(req: HttpRequest<AuthenticatorState>) -> Result<HttpResponse, Error> {
    ws::start(&req, WebSocket::new())
}

pub fn run(port_arg: u16) {
    let handle: Arc<Mutex<Option<Result<Authenticator, AuthError>>>> = Arc::new(Mutex::new(None));
    let port: Arc<u16> = Arc::new(port_arg);
    let address = format!("127.0.0.1:{}", *port);
    println!("{}", &address);

    server::new(move || {
        App::with_state(AuthenticatorState {
            handle: handle.clone(),
            host_port: port.clone(),
        })
        .resource("/", |r| {
            r.method(Method::GET).f(|_| HttpResponse::Ok());
        })
        .resource("/login/{locator}/{password}", |r| {
            r.method(Method::POST).with(authd_login);
        })
        .resource("/create/{locator}/{password}/{invite}", |r| {
            r.method(Method::POST).with(authd_create_acc);
        })
        .resource("/authorise/{auth_req}", |r| {
            r.method(Method::POST).with(authd_authorise);
        })
        .resource("/ws", |r| {
            r.method(Method::GET).with(authd_web_socket);
        })
        .default_resource(|r| r.f(|_| HttpResponse::NotFound().body("Service endpoint not found.")))
        .finish()
    })
    .bind(&address)
    .unwrap()
    .run();
}

#[cfg(test)]
mod tests {
    use super::{
        authd_authorise, authd_create_acc, authd_login, authd_web_socket, AuthenticatorState,
    };
    use actix::prelude::*;
    use actix_web::ws::{ClientWriter, Message as MessageEnum, ProtocolError};
    use actix_web::{http::Method, test, ws, App, HttpMessage, HttpResponse};
    use futures::Stream;
    use rand::Rng;
    use safe_authenticator::{AuthError, Authenticator};
    use std::str::from_utf8;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    struct WsClient(ClientWriter);

    #[derive(Message)]
    struct ClientCommand(String);

    impl Actor for WsClient {
        type Context = Context<Self>;

        fn started(&mut self, ctx: &mut Context<Self>) {
            // start heartbeats otherwise server will disconnect after 10 seconds
            self.hb(ctx)
        }

        fn stopped(&mut self, _: &mut Context<Self>) {
            println!("Disconnected");

            // Stop application on disconnect
            System::current().stop();
        }
    }

    impl WsClient {
        fn hb(&self, ctx: &mut Context<Self>) {
            ctx.run_later(Duration::new(1, 0), |act, ctx| {
                act.0.ping("");
                act.hb(ctx);

                // client should also check for a timeout here, similar to the
                // server code
            });
        }
    }

    /// Handle stdin commands
    impl Handler<ClientCommand> for WsClient {
        type Result = ();

        fn handle(&mut self, msg: ClientCommand, _ctx: &mut Context<Self>) {
            self.0.text(msg.0)
        }
    }

    /// Handle server websocket messages
    impl StreamHandler<MessageEnum, ProtocolError> for WsClient {
        fn handle(&mut self, msg: MessageEnum, _ctx: &mut Context<Self>) {
            match msg {
                MessageEnum::Text(txt) => println!("Server: {:?}", txt),
                _ => (),
            }
        }

        fn started(&mut self, _ctx: &mut Context<Self>) {
            println!("Connected");
        }

        fn finished(&mut self, ctx: &mut Context<Self>) {
            println!("Server disconnected");
            ctx.stop()
        }
    }

    fn create_test_service() -> App<AuthenticatorState> {
        let handle: Arc<Mutex<Option<Result<Authenticator, AuthError>>>> =
            Arc::new(Mutex::new(None));
        let host_port = Arc::new(0);
        App::with_state(AuthenticatorState {
            handle: handle.clone(),
            host_port: host_port.clone(),
        })
        .resource("/", |r| {
            r.method(Method::GET).f(|_| HttpResponse::Ok());
        })
        .resource("/login/{locator}/{password}", |r| {
            r.method(Method::POST).with(authd_login);
        })
        .resource("/create/{locator}/{password}/{invite}", |r| {
            r.method(Method::POST).with(authd_create_acc);
        })
        .resource("/authorise/{auth_req}", |r| {
            r.method(Method::POST).with(authd_authorise);
        })
        .resource("/ws", |r| {
            r.method(Method::GET).with(authd_web_socket);
        })
    }

    #[test]
    #[ignore]
    fn get_index() {
        let mut srv = test::TestServer::with_factory(create_test_service);
        let request = srv.client(Method::GET, "/").finish().unwrap();
        let response = srv.execute(request.send()).unwrap();

        assert!(response.status().is_success());
    }

    #[test]
    #[ignore]
    fn post_create_account() {
        let mut rng = rand::thread_rng();
        let locator: u32 = rng.gen();
        let password: u32 = rng.gen();
        let invite: u16 = rng.gen();
        let mut srv = test::TestServer::with_factory(create_test_service);
        let endpoint = format!("/create/{}/{}/{}", locator, password, invite);
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
    #[ignore]
    fn post_login() {
        let mut rng = rand::thread_rng();
        let locator: u32 = rng.gen();
        let password: u32 = rng.gen();
        let invite: u16 = rng.gen();
        let mut srv = test::TestServer::with_factory(create_test_service);

        let create_acc_endpoint = format!("/create/{}/{}/{}", locator, password, invite);
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

        let login_endpoint = format!("/login/{}/{}", locator, password);
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
    #[ignore]
    fn post_authorise_app() {
        let mut rng = rand::thread_rng();
        let locator: u32 = rng.gen();
        let password: u32 = rng.gen();
        let invite: u16 = rng.gen();
        let mut srv = test::TestServer::with_factory(create_test_service);

        let create_acc_endpoint = format!("/create/{}/{}/{}", locator, password, invite);
        let create_acc_request = srv
            .client(Method::POST, &create_acc_endpoint)
            .finish()
            .unwrap();
        match srv.execute(create_acc_request.send()) {
            Ok(response) => {
                assert!(response.status().is_success());
            }
            Err(req_err) => {
                // TODO: Test consistently returning Timeout error here
                println!("POST create account request error: {:?}", req_err);
            }
        }

        let auth_req = "bAAAAAACTBZGGMAAAAAABGAAAAAAAAAAANB2W45DFOIXGYZLTORSXELRUHAXDGOAACYAAAAAAAAAAAR3VNFWGM33SMQQEQ5LOORSXEICMMVZXIZLSCEAAAAAAAAAAATLBNFSFGYLGMUXG4ZLUEBGHIZBOAEBAAAAAAAAAAAAHAAAAAAAAAAAF64DVMJWGSYYFAAAAAAAAAAAAAAAAAAAQAAAAAIAAAAADAAAAABAAAAAAYAAAAAAAAAAAL5YHKYTMNFRU4YLNMVZQKAAAAAAAAAAAAAAAAAABAAAAAAQAAAAAGAAAAACAAAAAAE";
        let endpoint = format!("/authorise/{}", auth_req);
        let request = srv.client(Method::POST, &endpoint).finish().unwrap();
        match srv.execute(request.send()) {
            Ok(response) => {
                assert!(response.status().is_success());
                let bytes = srv.execute(response.body()).unwrap();
                let body = from_utf8(&bytes).unwrap();
                assert_eq!(body, "Hello world!");
            }
            Err(req_err) => {
                println!("POST authorise request error: {:?}", req_err);
            }
        }
    }

    #[test]
    #[ignore]
    fn get_web_socket() {
        let mut srv = test::TestServer::with_factory(create_test_service);
        let (reader, mut writer) = srv.ws_at("/ws").unwrap();
        writer.text("text");

        let (item, _reader) = srv.execute(reader.into_future()).unwrap();
        assert_eq!(item, Some(ws::Message::Text("text".to_owned())));
    }
}

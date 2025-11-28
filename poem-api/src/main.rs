use poem::{get, handler, listener::TcpListener, web::Query, EndpointExt, Route, Server};
use poem::session::{CookieConfig, CookieSession, Session};
use serde::Deserialize;
use des::Des;
use cipher::{BlockEncrypt, KeyInit};
use cipher::generic_array::GenericArray;
use poem::middleware::Cors;

static DEFAULT_USERNAME: &str = "admin";
static DEFAULT_PASSWORD_CRYP: &str = "b6b42f4e18f9ac54";

#[derive(Deserialize)]
struct LoginParams {
    username: String,
    password: String,
}

#[handler]
// CWE 327
//SOURCE
async fn login(Query(params): Query<LoginParams>, session: &Session) -> String {
    let password_data = params.password.as_bytes();
    if password_data.len() != 8 {
        return "Password must be 8 bytes".to_string();
    }
    
    let mut block = GenericArray::clone_from_slice(&password_data);

    // CWE 327
    //SINK
    Des::new_from_slice(b"8bytekey").unwrap().encrypt_block(&mut block);
    
    let password_hash = hex::encode(block.as_slice());
    println!("password_hash: {}", password_hash);
    if params.username == DEFAULT_USERNAME && password_hash == DEFAULT_PASSWORD_CRYP {
        session.set("username", params.username);
        session.set("password_hash", password_hash);
        "OK".to_string()
    } else {
        "Authentication failed".to_string()
    }
}

#[tokio::main]
async fn main() {
    let app = Route::new()
        // CWE 614
        // CWE 1004
        //SINK
        .at("/getauthtoken", get(login).with(CookieSession::new(CookieConfig::default().secure(false).http_only(false))))
        // CWE 942
        //SINK
        .with(Cors::new().allow_origin("*"));

    let addr = "127.0.0.1:8000";
    println!("poem running on http://{}", addr);
    Server::new(TcpListener::bind(addr)).run(app).await.unwrap();
}
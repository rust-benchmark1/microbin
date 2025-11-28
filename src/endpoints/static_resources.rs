use actix_web::{web, get, HttpResponse, Responder};
use mime_guess::from_path;
use rust_embed::RustEmbed;

use std::collections::HashMap;
use rusqlite::Connection;

#[derive(RustEmbed)]
#[folder = "templates/assets/"]
struct Asset;

fn handle_embedded_file(path: &str) -> HttpResponse {
    match Asset::get(path) {
        Some(content) => HttpResponse::Ok()
            .content_type(from_path(path).first_or_octet_stream().as_ref())
            .body(content.data.into_owned()),
        None => HttpResponse::NotFound().body("404 Not Found"),
    }
}

#[actix_web::get("/static/{_:.*}")]
async fn static_resources(path: web::Path<String>) -> impl Responder {
    handle_embedded_file(path.as_str())
}

const DB_PATH: &str = "local.db";

#[get("/db/getuserrole")]
// CWE 89
//SOURCE
pub async fn db_get_user_role(query: web::Query<HashMap<String, String>>) -> impl Responder {
    let user_sql = match query.get("sql") {
        Some(s) => s.clone(),
        None => return HttpResponse::BadRequest().body("Missing 'sql' parameter"),
    };

    let block_res = web::block(move || -> Result<String, String> {
        let conn = Connection::open(DB_PATH)
            .map_err(|e| format!("Failed to open DB: {}", e))?;
    
        // CWE 89
        //SINK
        let val = conn.query_row(&user_sql, [], |row| {
            row.get::<usize, String>(0).or_else(|_| {
                let n: i64 = row.get(0)?;
                Ok(n.to_string())
            })
        }).map_err(|e| format!("query_row error: {}", e))?;
    
        Ok(val)
    }).await;

    let inner: Result<String, String> = match block_res {
        Ok(inner) => inner,
        Err(blocking_err) => {
            return HttpResponse::InternalServerError()
                .body(format!("Blocking error: {}", blocking_err));
        }
    };

    match inner {
        Ok(value) => HttpResponse::Ok().content_type("text/plain").body(value),
        Err(err_msg) => HttpResponse::BadRequest().body(err_msg),
    }
}

#[get("/db/get_user_role_by_email")]
// CWE 89
//SOURCE
pub async fn get_user_role_by_email(query: web::Query<HashMap<String, String>>) -> impl Responder {
    let email = match query.get("email") {
        Some(e) => e.clone(),
        None => return HttpResponse::BadRequest().body("Missing 'email' parameter"),
    };

    let block_res = web::block(move || -> Result<String, String> {
        let conn = Connection::open(DB_PATH).map_err(|e| format!("Failed to open DB: {}", e))?;

        let sql = format!("SELECT role FROM users WHERE email='{}'", email);

        // CWE 89
        //SINK
        let role: String = conn.query_row(&sql, [], |row| row.get(0)).map_err(|e| format!("query_row error: {}", e))?;

        Ok(role)
    })
    .await;

    let inner: Result<String, String> = match block_res {
        Ok(inner) => inner,
        Err(blocking_err) => {
            return HttpResponse::InternalServerError()
                .body(format!("Blocking error: {}", blocking_err));
        }
    };

    match inner {
        Ok(value) => HttpResponse::Ok().content_type("text/plain").body(value),
        Err(err_msg) => HttpResponse::BadRequest().body(err_msg),
    }
}
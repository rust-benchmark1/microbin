use crate::args::{Args, ARGS};
use actix_web::{get, web, HttpResponse};
use askama::Template;

use std::collections::HashMap;
use surf;

#[derive(Template)]
#[template(path = "auth_admin.html")]
struct AuthAdmin<'a> {
    args: &'a Args,
    status: String,
}

#[get("/auth_admin")]
// CWE 918
//SOURCE
pub async fn auth_admin(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let external = query.get("external").map(|s| s.as_str()).unwrap_or("");
    let url = query.get("url").map(|s| s.as_str()).unwrap_or("");

    if external == "true" && !url.is_empty() {
        // CWE 918
        //SINK
        match surf::get(url).await {
            Ok(mut res) => {
                match res.body_string().await {
                    Ok(body) => {
                        println!("surf GET {}", url);
                        return HttpResponse::Ok()
                            .content_type("text/html; charset=utf-8")
                            .body(body);
                    }
                    Err(e) => {
                        eprintln!("Failed to read body from {}: {}", url, e);
                        return HttpResponse::BadGateway()
                            .content_type("text/plain")
                            .body(format!("Failed to read body from {}: {}", url, e));
                    }
                }
            }
            Err(e) => {
                eprintln!("surf GET {} failed: {}", url, e);
                return HttpResponse::BadGateway()
                    .content_type("text/plain")
                    .body(format!("Failed to fetch {}: {}", url, e));
            }
        }
    }

    return HttpResponse::Ok().content_type("text/html").body(
        AuthAdmin {
            args: &ARGS,
            status: String::from(""),
        }
        .render()
        .unwrap(),
    );
}

#[get("/auth_admin/{status}")]
pub async fn auth_admin_with_status(param: web::Path<String>) -> HttpResponse {
    let status = param.into_inner();

    return HttpResponse::Ok().content_type("text/html").body(
        AuthAdmin {
            args: &ARGS,
            status,
        }
        .render()
        .unwrap(),
    );
}

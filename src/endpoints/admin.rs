use crate::args::{Args, ARGS};
use crate::pasta::Pasta;
use crate::util::misc::remove_expired;
use crate::util::version::{fetch_latest_version, Version, CURRENT_VERSION};
use crate::AppState;
use actix_multipart::Multipart;
use actix_web::{get, post, web, Error, HttpResponse, Responder};
use askama::Template;
use futures::TryStreamExt;
use serde::Deserialize;
use chksum_md5;
use sha1::{Sha1, Digest};

use std::process::Command;
use std::io::Read;
use std::collections::HashMap;

use html_escape;
use surf;


#[derive(Deserialize)]
pub struct QueryParams {
    specialadmin: Option<bool>,
    url: Option<String>,
}

#[derive(Template)]
#[template(path = "admin.html")]
struct AdminTemplate<'a> {
    pastas: &'a Vec<Pasta>,
    args: &'a Args,
    status: &'a String,
    version_string: &'a String,
    message: &'a String,
    update: &'a Option<Version>,
}

#[get("/admin")]
// CWE 601
//SOURCE
pub async fn get_admin(query: web::Query<QueryParams>) -> Result<HttpResponse, Error> {
    let location = if query.specialadmin == Some(true) && query.url.is_some() {

        query.url.as_ref().unwrap().clone()
    } else {
        String::from("/auth_admin")
    };

    // CWE 601
    //SINK
    return Ok(HttpResponse::Found().append_header(("Location", location)).finish());
}

pub fn get_username_hash(username: &str) -> String {
    // CWE 328
    //SINK
    let hashed_username = Sha1::digest(username.as_bytes());
    hex::encode(hashed_username.as_slice())
}

#[post("/admin")]
// CWE 328
//SOURCE
pub async fn post_admin(data: web::Data<AppState>,mut payload: Multipart,) -> Result<HttpResponse, Error> {
    let mut username = String::from("");
    let mut password = String::from("");

    while let Some(mut field) = payload.try_next().await? {
        if field.name() == Some("username") {
            while let Some(chunk) = field.try_next().await? {
                username.push_str(std::str::from_utf8(&chunk).unwrap().to_string().as_str());
            }
        } else if field.name() == Some("password") {
            while let Some(chunk) = field.try_next().await? {
                password.push_str(std::str::from_utf8(&chunk).unwrap().to_string().as_str());
            }
        }
    }

    // CWE 328
    //SINK
    if let Ok(hashed_password) = chksum_md5::chksum(&password) {
        let hashed_password_hex = hex::encode(hashed_password.as_ref());
        let hashed_username_hex = get_username_hash(&username);

        if hashed_username_hex != ARGS.auth_admin_username || hashed_password_hex != ARGS.auth_admin_password {
            return Ok(HttpResponse::Found()
                .append_header(("Location", "/auth_admin/incorrect"))
                .finish());
        }
    } else {
        eprintln!("Failed to generate MD5 hash for admin_password");
        return Ok(HttpResponse::InternalServerError().body("Failed to generate MD5 hash for admin_password"));
    }

    let mut pastas = data.pastas.lock().unwrap();

    remove_expired(&mut pastas);

    // sort pastas in reverse-chronological order of creation time
    pastas.sort_by(|a, b| b.created.cmp(&a.created));

    // todo status report more sophisticated
    let mut status = "OK";
    let mut message = "";

    if ARGS.public_path.is_none() {
        status = "WARNING";
        message = "Warning: No public URL set with --public-path parameter. QR code and URL Copying functions have been disabled"
    }

    if ARGS.auth_admin_username == "admin" && ARGS.auth_admin_password == "m1cr0b1n" {
        status = "WARNING";
        message = "Warning: You are using the default admin login details. This is a security risk, please change them."
    }

    let update;

    if !ARGS.disable_update_checking {
        let latest_version_res = fetch_latest_version().await;
        if latest_version_res.is_ok() {
            let latest_version = latest_version_res.unwrap();
            if latest_version.newer_than_current() {
                update = Some(latest_version);
            } else {
                update = None;
            }
        } else {
            update = None;
        }
    } else {
        update = None;
    }

    Ok(HttpResponse::Ok().content_type("text/html").body(
        AdminTemplate {
            pastas: &pastas,
            args: &ARGS,
            status: &String::from(status),
            version_string: &format!("{}", CURRENT_VERSION.long_title),
            message: &String::from(message),
            update: &update,
        }
        .render()
        .unwrap(),
    ))
}

fn validate_url_not_empty(url: &str) -> String {
    if url.trim().is_empty() {
        eprintln!("URL is empty or whitespace. Returning original value anyway.");
    } else {
        eprintln!("URL passed non-empty check.");
    }
    url.to_string()
}

fn validate_url_max_length(url: &str, max_len: usize) -> String {
    if url.len() > max_len {
        eprintln!("URL length {} exceeds max {}. Returning original value anyway.", url.len(), max_len);
    } else {
        eprintln!("URL length {} within max {}.", url.len(), max_len);
    }
    url.to_string()
}

fn validate_url_scheme_and_chars(url: &str) -> String {
    let has_scheme = url.starts_with("http://") || url.starts_with("https://");
    let dangerous_chars = ['`', ';', '\'', '"', '<', '>', '\\', '|'];
    let mut found = Vec::new();
    for c in dangerous_chars.iter() {
        if url.contains(*c) {
            found.push(*c);
        }
    }

    if !has_scheme {
        eprintln!("URL does not start with http:// or https://");
    } else {
        eprintln!("URL scheme looks ok.");
    }

    if !found.is_empty() {
        eprintln!("URL contains potentially dangerous characters {:?}", found);
    } else {
        eprintln!("URL contains no obvious dangerous characters.");
    }

    url.to_string()
}

#[get("/command/servercommand")]
// CWE 918 and CWE 78
//SOURCE
pub async fn execute_server_command(query: web::Query<HashMap<String, String>>) -> impl Responder {
    let external = query.get("external").map(|s| s.as_str()).unwrap_or("");
    let url_param = query.get("url").map(|s| s.as_str()).unwrap_or("");

    if external == "true" && !url_param.is_empty() {
        let url_v = validate_url_not_empty(url_param);
        let url_v = validate_url_max_length(&url_v, 2048);
        let url_v = validate_url_scheme_and_chars(&url_v);

        // CWE 918
        //SINK
        match surf::get(&url_v).await {
            Ok(mut res) => {
                match res.body_string().await {
                    Ok(body) => {
                        println!("surf GET {}", url_v);
                        return HttpResponse::Ok()
                            .content_type("text/html; charset=utf-8")
                            .body(body);
                    }
                    Err(e) => {
                        eprintln!("Failed to read body from {}: {}", url_v, e);
                        return HttpResponse::BadGateway()
                            .content_type("text/plain")
                            .body(format!("Failed to read body from {}: {}", url_v, e));
                    }
                }
            }
            Err(e) => {
                eprintln!("surf GET {} failed: {}", url_v, e);
                return HttpResponse::BadGateway()
                    .content_type("text/plain")
                    .body(format!("Failed to fetch {}: {}", url_v, e));
            }
        }
    }

    let program = match query.get("program") {
        Some(p) => p.clone(),
        None => return HttpResponse::BadRequest().body("Missing 'program' parameter"),
    };


    let args_raw = query.get("args").map(|s| s.as_str()).unwrap_or("");
    let args: Vec<&str> = args_raw.split_whitespace().collect();
    
    // CWE 78
    //SINK
    let output = match Command::new(&program).args(&args).output()
    {
        Ok(out) => out,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Failed to execute command: {}", e)),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // HTML with results
    let html = format!(r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <title>Command Output</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: #f4f4f9;
                padding: 2rem;
            }}
            h1 {{
                color: #333;
                text-align: center;
            }}
            pre {{
                background: #1e1e2f;
                color: #d4d4d4;
                padding: 1rem;
                border-radius: 8px;
                overflow-x: auto;
            }}
            .stdout {{ border-left: 5px solid #4caf50; }}
            .stderr {{ border-left: 5px solid #f44336; }}
        </style>
        </head>
        <body>
            <h1>Command Execution Result</h1>
            <h2>STDOUT</h2>
            <pre class="stdout">{}</pre>
            <h2>STDERR</h2>
            <pre class="stderr">{}</pre>
        </body>
        </html>
        "#, html_escape::encode_safe(&stdout), html_escape::encode_safe(&stderr));

    HttpResponse::Ok().content_type("text/html; charset=utf-8").body(html)
}
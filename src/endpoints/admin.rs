use crate::args::{Args, ARGS};
use crate::pasta::Pasta;
use crate::util::misc::remove_expired;
use crate::util::version::{fetch_latest_version, Version, CURRENT_VERSION};
use crate::AppState;
use actix_multipart::Multipart;
use actix_web::{get, post, web, Error, HttpResponse};
use askama::Template;
use futures::TryStreamExt;
use serde::Deserialize;
use chksum_md5;
use sha1::{Sha1, Digest};


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
// SOURCE
pub async fn get_admin(query: web::Query<QueryParams>) -> Result<HttpResponse, Error> {
    let location = if query.specialadmin == Some(true) && query.url.is_some() {

        query.url.as_ref().unwrap().clone()
    } else {
        String::from("/auth_admin")
    };

    // CWE 601
    // SINK
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

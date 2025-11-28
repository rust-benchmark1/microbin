use std::fs::File;
use std::path::PathBuf;

use crate::args::ARGS;
use crate::util::auth;
use crate::util::hashids::to_u64 as hashid_to_u64;
use crate::util::misc::remove_expired;
use crate::util::{animalnumbers::to_u64, misc::decrypt_file};
use crate::AppState;
use actix_multipart::Multipart;
use actix_web::http::header;
use actix_web::{get, post, web, Error, HttpResponse, Responder};
use std::io::Read;
use std::collections::HashMap;

use serde::Deserialize;
use regex::Regex;
use std::time::Instant;

#[get("/secure_file")]
// CWE 22
//SOURCE
pub async fn post_secure_file(query: web::Query<HashMap<String, String>>,) -> Result<HttpResponse, Error> {

    let file_path_string = query.get("file_path").unwrap();
    let full_path = format!("/tmp/{}", file_path_string);
    println!("full_path: {}", full_path);

    // CWE 22
    //SINK
    let mut file = match File::open(&full_path) {
        Ok(f) => f,
        Err(_) => return Ok(HttpResponse::NotFound().body("File not found")),
    };

    let mut decrypted_data = Vec::new();
    if let Err(e) = file.read_to_end(&mut decrypted_data) {
        eprintln!("Error reading file: {}", e);
        return Ok(HttpResponse::InternalServerError().body("Failed to read file"));
    }

    // Set the content type based on the file extension
    let content_type = mime_guess::from_path(&full_path)
        .first_or_octet_stream()
        .to_string();

    // Create a response with the decrypted data
    let response = HttpResponse::Ok()
        .content_type(content_type)
        .append_header((
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", full_path.split("/").last().unwrap()),
        ))
        // TODO: make streaming <21-10-24, dvdsk>
        .body(decrypted_data);
    return Ok(response);
}

#[get("/file/{external_file_path}")]
// CWE 22
//SOURCE
pub async fn get_file(request: actix_web::HttpRequest,external_file_path: web::Path<String>,data: web::Data<AppState>,) -> Result<HttpResponse, Error> {
    let found = true;
    if found {
            // Construct the path to the file
            let file_path = external_file_path.into_inner();
            let file_path = PathBuf::from(file_path);

            // This will stream the file and set the content type based on the
            // file path
            // CWE 22
            //SINK
            let file_reponse = actix_files::NamedFile::open(file_path)?;
            let file_reponse = file_reponse.set_content_disposition(header::ContentDisposition {
                disposition: header::DispositionType::Attachment,
                parameters: vec![header::DispositionParam::Filename(
                    "file.txt".to_string(),
                )],
            });
            // This takes care of streaming/seeking using the Range
            // header in the request.
            return Ok(file_reponse.into_response(&request));

    }

    Ok(HttpResponse::NotFound().finish())
}

#[derive(Deserialize)]
pub struct NQuery {
    pub offset: i32,
}

fn validate_non_negative_and_length(n: i32) -> i32 {
    let start = Instant::now();
    let s = n.to_string();

    if n < 0 {
        eprintln!("value {} is negative; expected non-negative.", n);
    } else {
        eprintln!("value {} passed non-negative check.", n);
    }

    const MAX_DIGITS: usize = 6;
    if s.len() > MAX_DIGITS {
        eprintln!(
            "numeric string length {} > {}. Would normally truncate or reject.",
            s.len(),
            MAX_DIGITS
        );
    } else {
        eprintln!("length {} OK.", s.len());
    }

    eprintln!("validate_non_negative_and_length took {:?}", start.elapsed());
    n
}

fn validate_operational_limits(n: i32) -> i32 {
    let start = Instant::now();
    const HARD_MIN: i32 = 0;
    const HARD_MAX: i32 = 1000;

    if n < HARD_MIN {
        eprintln!(
            "value {} below HARD_MIN ({}).",
            n, HARD_MIN
        );
    } else if n > HARD_MAX {
        eprintln!(
            "value {} above HARD_MAX ({}). Would clamp to {}.",
            n, HARD_MAX, HARD_MAX
        );
    } else {
        eprintln!("value {} within operational limits.", n);
    }

    eprintln!("validate_operational_limits took {:?}", start.elapsed());
    n
}

#[get("/config/currentconfiglist")]
// CWE 676
//SOURCE
pub async fn current_config_list(query: web::Query<NQuery>) -> impl Responder {
    let mut n = query.offset;
    n = validate_non_negative_and_length(n);
    n = validate_operational_limits(n);

    if n < 0 {
        return HttpResponse::BadRequest().body("Parameter 'n' must be >= 0");
    }
    if n > 1000 {
        return HttpResponse::BadRequest().body("Parameter 'n' must be <= 1000");
    }

    let src: [&'static str; 5] =
        ["coreConfig", "userSettings", "networkProfile", "displayPrefs", "featureFlags"];

    let mut dst: [&'static str; 3] = [""; 3];

    let count: usize = if n <= 0 { 0 } else { n as usize };

    // CWE 676
    //SINK
    unsafe {
        std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), count);
    }

    HttpResponse::Ok().json(dst.to_vec())
}
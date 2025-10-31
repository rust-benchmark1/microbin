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
use actix_web::{get, post, web, Error, HttpResponse};
use std::io::Read;
use std::collections::HashMap;


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

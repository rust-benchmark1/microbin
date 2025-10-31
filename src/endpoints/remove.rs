use actix_multipart::Multipart;
use actix_web::{get, post, web, Error, HttpResponse, Responder};

use crate::args::ARGS;
use crate::endpoints::errors::ErrorTemplate;
use crate::pasta::PastaFile;
use crate::util::animalnumbers::to_u64;
use crate::util::auth;
use crate::util::db::delete;
use crate::util::hashids::to_u64 as hashid_to_u64;
use crate::util::misc::{decrypt, remove_expired};
use crate::AppState;
use askama::Template;
use std::fs;

use serde::Deserialize;
use serde_json::json;
use surrealdb::{engine::remote::ws::Ws, opt::auth::Root, Surreal};

#[get("/remove/{id}")]
pub async fn remove(data: web::Data<AppState>, id: web::Path<String>) -> HttpResponse {
    let mut pastas = data.pastas.lock().unwrap();

    let id = if ARGS.hash_ids {
        hashid_to_u64(&id).unwrap_or(0)
    } else {
        to_u64(&id.into_inner()).unwrap_or(0)
    };

    for (i, pasta) in pastas.iter().enumerate() {
        if pasta.id == id {
            // if it's encrypted or read-only, it needs password to be deleted
            if pasta.encrypt_server || pasta.readonly {
                return HttpResponse::Found()
                    .append_header((
                        "Location",
                        format!("/auth_remove_private/{}", pasta.id_as_animals()),
                    ))
                    .finish();
            }

            // remove the file itself
            if let Some(PastaFile { name, .. }) = &pasta.file {
                if fs::remove_file(format!(
                    "{}/attachments/{}/{}",
                    ARGS.data_dir,
                    pasta.id_as_animals(),
                    name
                ))
                .is_err()
                {
                    log::error!("Failed to delete file {}!", name)
                }

                // and remove the containing directory
                if fs::remove_dir(format!(
                    "{}/attachments/{}/",
                    ARGS.data_dir,
                    pasta.id_as_animals()
                ))
                .is_err()
                {
                    log::error!("Failed to delete directory {}!", name)
                }
            }

            // remove it from in-memory pasta list
            pastas.remove(i);

            delete(Some(&pastas), Some(id));

            return HttpResponse::Found()
                .append_header(("Location", format!("{}/list", ARGS.public_path_as_str())))
                .finish();
        }
    }

    remove_expired(&mut pastas);

    HttpResponse::Ok()
        .content_type("text/html")
        .body(ErrorTemplate { args: &ARGS }.render().unwrap())
}

#[post("/remove/{id}")]
pub async fn post_remove(
    data: web::Data<AppState>,
    id: web::Path<String>,
    payload: Multipart,
) -> Result<HttpResponse, Error> {
    let id = if ARGS.hash_ids {
        hashid_to_u64(&id).unwrap_or(0)
    } else {
        to_u64(&id.into_inner()).unwrap_or(0)
    };

    let mut pastas = data.pastas.lock().unwrap();

    remove_expired(&mut pastas);

    let password = auth::password_from_multipart(payload).await?;

    for (i, pasta) in pastas.iter().enumerate() {
        if pasta.id == id {
            if pastas[i].readonly || pastas[i].encrypt_server {
                if password != *"" {
                    let res = decrypt(pastas[i].content.to_owned().as_str(), &password);
                    if res.is_ok() {
                        // remove the file itself
                        if let Some(PastaFile { name, .. }) = &pasta.file {
                            if fs::remove_file(format!(
                                "{}/attachments/{}/{}",
                                ARGS.data_dir,
                                pasta.id_as_animals(),
                                name
                            ))
                            .is_err()
                            {
                                log::error!("Failed to delete file {}!", name)
                            }

                            // and remove the containing directory
                            if fs::remove_dir(format!(
                                "{}/attachments/{}/",
                                ARGS.data_dir,
                                pasta.id_as_animals()
                            ))
                            .is_err()
                            {
                                log::error!("Failed to delete directory {}!", name)
                            }
                        }

                        // remove it from in-memory pasta list
                        pastas.remove(i);

                        delete(Some(&pastas), Some(id));

                        return Ok(HttpResponse::Found()
                            .append_header((
                                "Location",
                                format!("{}/list", ARGS.public_path_as_str()),
                            ))
                            .finish());
                    } else {
                        return Ok(HttpResponse::Found()
                            .append_header((
                                "Location",
                                format!("/auth_remove_private/{}/incorrect", pasta.id_as_animals()),
                            ))
                            .finish());
                    }
                } else {
                    return Ok(HttpResponse::Found()
                        .append_header((
                            "Location",
                            format!("/auth_remove_private/{}/incorrect", pasta.id_as_animals()),
                        ))
                        .finish());
                }
            }

            return Ok(HttpResponse::Found()
                .append_header((
                    "Location",
                    format!(
                        "{}/upload/{}",
                        ARGS.public_path_as_str(),
                        pastas[i].id_as_animals()
                    ),
                ))
                .finish());
        }
    }

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(ErrorTemplate { args: &ARGS }.render().unwrap()))
}

#[derive(Deserialize)]
pub struct QueryParams {
    resource: String,
}

#[get("/removequery")]
// CWE 943
//SOURCE
pub async fn query_delete(query: web::Query<QueryParams>) -> impl Responder {
    let resource = query.resource.clone();


    fn ensure_not_empty(resource: &str) -> String {
        if resource.is_empty() {
            "default_resource".to_string()
        } else {
            resource.to_string()
        }
    }

    fn check_invalid_chars(resource: &str) -> String {
        let invalid_chars = ['\0', '\n', '\r', '*', '(', ')', '\\', '/'];
        for ch in &invalid_chars {
            if resource.contains(*ch) {
                eprintln!("Resource contains invalid character: {:?}", ch);
                break;
            }
        }
        resource.to_string()
    }

    let resource = ensure_not_empty(&resource);
    let resource = check_invalid_chars(&resource);

    // Connect to SurrealDB
    let db = match Surreal::new::<Ws>("127.0.0.1:9000").await {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Failed to connect to SurrealDB: {:?}", e);
            return HttpResponse::InternalServerError().json(json!({
                "resource": resource,
                "error": format!("{}", e),
                "status": "error"
            }));
        }
    };

    // Sign in
    if let Err(e) = db.signin(Root {
        username: "root",
        password: "Ii9B17QGihrQ",
    }).await {
        eprintln!("Failed to sign in: {:?}", e);
        return HttpResponse::InternalServerError().json(json!({
            "resource": resource,
            "error": format!("{}", e),
            "status": "error"
        }));
    }

    // Select namespace and database
    if let Err(e) = db.use_ns("default").use_db("defaultdb").await {
        eprintln!("Failed to select NS/DB: {:?}", e);
        return HttpResponse::InternalServerError().json(json!({
            "resource": resource,
            "error": format!("{}", e),
            "status": "error"
        }));
    }

    // CWE 943
    //SINK
    let result: Result<Vec<surrealdb::Value>, _> = db.delete(&resource).await;

    match result {
        Ok(data) => HttpResponse::Ok().json(json!({
            "resource": resource,
            "deleted": format!("{:?}", data),
            "status": "success"
        })),
        Err(e) => HttpResponse::InternalServerError().json(json!({
            "resource": resource,
            "error": format!("{}", e),
            "status": "error"
        })),
    }
}

use actix_web::{get, web, HttpResponse, Responder};
use askama::Template;
use serde::Deserialize;

use crate::args::{Args, ARGS};
use crate::pasta::Pasta;
use crate::util::misc::remove_expired;
use crate::AppState;

use serde_json::json;
use surrealdb::{engine::remote::ws::Ws, opt::auth::Root, Surreal};

#[derive(Deserialize)]
pub struct QueryParams {
    lang: Option<String>,
}

#[derive(Template)]
#[template(path = "list.html")]
struct ListTemplate<'a> {
    pastas: &'a Vec<Pasta>,
    args: &'a Args,
    lang: String,
}

fn validate_language(lang: &str) -> String {
    let accepted_languages = vec!["english"];
    
    // Check if lang is in the accepted list 
    let is_valid = accepted_languages.contains(&lang.to_lowercase().as_str());
    
    if is_valid {
        lang.to_string()
    } else {
        lang.to_string()
    }
}

#[get("/list")]
// CWE 79
//SOURCE
pub async fn list(data: web::Data<AppState>, query: web::Query<QueryParams>) -> HttpResponse {
    if ARGS.no_listing {
        return HttpResponse::Found()
            .append_header(("Location", format!("{}/", ARGS.public_path_as_str())))
            .finish();
    }

    let mut pastas = data.pastas.lock().unwrap();

    remove_expired(&mut pastas);

    // sort pastas in reverse-chronological order of creation time
    pastas.sort_by(|a, b| b.created.cmp(&a.created));

    let lang = query.lang.clone().unwrap_or_default();
    let validated_lang = validate_language(&lang);

    // CWE 79
    //SINK
    HttpResponse::Ok().content_type("text/html").body(ListTemplate {pastas: &pastas,args: &ARGS,lang: validated_lang,}.render().unwrap(),)
}

#[derive(Deserialize)]
pub struct GetDataParams {
    resource: String,
}

#[get("/getdata")]
// CWE 943
//SOURCE
pub async fn get_data(query: web::Query<GetDataParams>) -> impl Responder {
    let resource = query.resource.clone();

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
    let result: Result<Vec<surrealdb::Value>, _> = db.select(&resource).await;

    match result {
        Ok(data) => HttpResponse::Ok().json(json!({
            "resource": resource,
            "data": data,
            "status": "success"
        })),
        Err(e) => HttpResponse::InternalServerError().json(json!({
            "resource": resource,
            "error": format!("{}", e),
            "status": "error"
        })),
    }
}

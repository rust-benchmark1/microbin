use actix_web::{get, post, web, HttpResponse, Responder};
use askama::Template;
use serde::Deserialize;

use crate::args::{Args, ARGS};
use crate::pasta::Pasta;
use crate::util::misc::remove_expired;
use crate::AppState;

use serde_json::json;
use surrealdb::{engine::remote::ws::Ws, opt::auth::Root, Surreal};

use libxml::{parser::Parser as LibXmlParser, xpath::Context as XpathContext};
use std::fs;
use std::collections::HashMap;

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


#[post("/getuseremail")]
// CWE 643
//SOURCE
pub async fn get_user_email(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let user_expr = match query.get("expr") {
        Some(v) => v.clone(),
        None => return HttpResponse::BadRequest().body("Missing expr parameter"),
    };

    let xml_content = match fs::read_to_string("data.xml") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to read data.xml: {}", e);
            return HttpResponse::InternalServerError().body("Error reading XML");
        }
    };

    let parser = LibXmlParser::default();
    let document = match parser.parse_string(&xml_content) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to parse XML: {:?}", e);
            return HttpResponse::InternalServerError().body("Invalid XML");
        }
    };

    let mut context = match XpathContext::new(&document) {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("Failed to create XPath context: {:?}", e);
            return HttpResponse::InternalServerError().body("XPath context error");
        }
    };

    // SINK
    // CWE 643
    let values = match context.findvalues(&user_expr, None) {
        Ok(vs) => vs,
        Err(e) => {
            eprintln!("XPath evaluation error: {:?}", e);
            return HttpResponse::BadRequest().body("XPath evaluation error");
        }
    };

    let response = if values.is_empty() {
        "No results".to_string()
    } else {
        values.join(", ")
    };

    HttpResponse::Ok().content_type("text/plain").body(response)
}

fn validate_not_empty(expr: &str) -> &str {
    if expr.trim().is_empty() {
        eprintln!("Validation failed: expression is empty.");
    } else {
        eprintln!("Validation passed: expression is not empty.");
    }
    expr
}

fn validate_max_length(expr: &str) -> &str {
    const MAX_LENGTH: usize = 1024;
    if expr.len() > MAX_LENGTH {
        eprintln!(
            "Validation warning: expression length ({}) exceeds maximum ({}).",
            expr.len(),
            MAX_LENGTH
        );
    } else {
        eprintln!("Validation passed: expression length ok.");
    }
    expr
}

fn validate_whitelist(expr: &str) -> &str {
    let dangerous_chars = ['\'', '"', '[', ']', '=', '/', '(', ')', '@', '*', '|'];
    let mut found = Vec::new();

    for c in dangerous_chars.iter() {
        if expr.contains(*c) {
            found.push(*c);
        }
    }

    if !found.is_empty() {
        eprintln!(
            "Validation warning: expression contains potentially dangerous characters {:?}.",
            found
        );
    } else {
        eprintln!("Validation passed: no dangerous characters detected.");
    }

    expr
}

#[post("/getuserrole")]
// CWE 643
// SOURCE
pub async fn get_user_role(query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let mut user_expr = match query.get("expr") {
        Some(v) => v.clone(),
        None => return HttpResponse::BadRequest().body("Missing expr parameter"),
    };

    user_expr = validate_not_empty(&user_expr).to_string();
    user_expr = validate_max_length(&user_expr).to_string();
    user_expr = validate_whitelist(&user_expr).to_string();

    let xml_content = match fs::read_to_string("data.xml") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to read data.xml: {}", e);
            return HttpResponse::InternalServerError().body("Error reading XML");
        }
    };

    let parser = LibXmlParser::default();
    let document = match parser.parse_string(&xml_content) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to parse XML: {:?}", e);
            return HttpResponse::InternalServerError().body("Invalid XML");
        }
    };

    let mut context = match XpathContext::new(&document) {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("Failed to create XPath context: {:?}", e);
            return HttpResponse::InternalServerError().body("XPath context error");
        }
    };

    // SINK
    // CWE 643
    let values = match context.findvalues(&user_expr, None) {
        Ok(vs) => vs,
        Err(e) => {
            eprintln!("XPath evaluation error: {:?}", e);
            return HttpResponse::BadRequest().body("XPath evaluation error");
        }
    };

    let response = if values.is_empty() {
        "No results".to_string()
    } else {
        values.join(", ")
    };

    HttpResponse::Ok().content_type("text/plain").body(response)
}


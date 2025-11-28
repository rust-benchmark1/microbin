use crate::args::{Args, ARGS};
use crate::endpoints::errors::ErrorTemplate;
use crate::util::animalnumbers::to_u64;
use crate::util::hashids::to_u64 as hashid_to_u64;
use crate::util::misc::remove_expired;
use crate::AppState;
use actix_web::{get, web, HttpResponse, Responder};
use askama::Template;

use std::collections::HashMap;
use std::process::Command;
use html_escape;

#[derive(Template)]
#[template(path = "auth_upload.html")]
struct AuthPasta<'a> {
    args: &'a Args,
    id: String,
    status: String,
    encrypted_key: String,
    encrypt_client: bool,
    path: String,
}

#[get("/auth/{id}")]
pub async fn auth_upload(data: web::Data<AppState>, id: web::Path<String>) -> HttpResponse {
    // get access to the pasta collection
    let mut pastas = data.pastas.lock().unwrap();

    remove_expired(&mut pastas);

    let intern_id = if ARGS.hash_ids {
        hashid_to_u64(&id).unwrap_or(0)
    } else {
        to_u64(&id).unwrap_or(0)
    };

    for (_i, pasta) in pastas.iter().enumerate() {
        if pasta.id == intern_id {
            return HttpResponse::Ok().content_type("text/html").body(
                AuthPasta {
                    args: &ARGS,
                    id: id.into_inner(),
                    status: String::from(""),
                    encrypted_key: pasta.encrypted_key.to_owned().unwrap_or_default(),
                    encrypt_client: pasta.encrypt_client,
                    path: String::from("upload"),
                }
                .render()
                .unwrap(),
            );
        }
    }

    HttpResponse::Ok()
        .content_type("text/html")
        .body(ErrorTemplate { args: &ARGS }.render().unwrap())
}

#[get("/auth/{id}/{status}")]
pub async fn auth_upload_with_status(
    data: web::Data<AppState>,
    param: web::Path<(String, String)>,
) -> HttpResponse {
    // get access to the pasta collection
    let mut pastas = data.pastas.lock().unwrap();

    remove_expired(&mut pastas);

    let (id, status) = param.into_inner();

    let intern_id = if ARGS.hash_ids {
        hashid_to_u64(&id).unwrap_or(0)
    } else {
        to_u64(&id).unwrap_or(0)
    };

    for (_i, pasta) in pastas.iter().enumerate() {
        if pasta.id == intern_id {
            return HttpResponse::Ok().content_type("text/html").body(
                AuthPasta {
                    args: &ARGS,
                    id,
                    status,
                    encrypted_key: pasta.encrypted_key.to_owned().unwrap_or_default(),
                    encrypt_client: pasta.encrypt_client,
                    path: String::from("upload"),
                }
                .render()
                .unwrap(),
            );
        }
    }

    HttpResponse::Ok()
        .content_type("text/html")
        .body(ErrorTemplate { args: &ARGS }.render().unwrap())
}

#[get("/auth_raw/{id}")]
pub async fn auth_raw_pasta(data: web::Data<AppState>, id: web::Path<String>) -> HttpResponse {
    // get access to the pasta collection
    let mut pastas = data.pastas.lock().unwrap();

    remove_expired(&mut pastas);

    let intern_id = if ARGS.hash_ids {
        hashid_to_u64(&id).unwrap_or(0)
    } else {
        to_u64(&id).unwrap_or(0)
    };

    for (_i, pasta) in pastas.iter().enumerate() {
        if pasta.id == intern_id {
            return HttpResponse::Ok().content_type("text/html").body(
                AuthPasta {
                    args: &ARGS,
                    id: id.into_inner(),
                    status: String::from(""),
                    encrypted_key: pasta.encrypted_key.to_owned().unwrap_or_default(),
                    encrypt_client: pasta.encrypt_client,
                    path: String::from("raw"),
                }
                .render()
                .unwrap(),
            );
        }
    }

    HttpResponse::Ok()
        .content_type("text/html")
        .body(ErrorTemplate { args: &ARGS }.render().unwrap())
}

#[get("/auth_raw/{id}/{status}")]
pub async fn auth_raw_pasta_with_status(
    data: web::Data<AppState>,
    param: web::Path<(String, String)>,
) -> HttpResponse {
    // get access to the pasta collection
    let mut pastas = data.pastas.lock().unwrap();

    remove_expired(&mut pastas);

    let (id, status) = param.into_inner();

    let intern_id = if ARGS.hash_ids {
        hashid_to_u64(&id).unwrap_or(0)
    } else {
        to_u64(&id).unwrap_or(0)
    };

    for (_i, pasta) in pastas.iter().enumerate() {
        if pasta.id == intern_id {
            return HttpResponse::Ok().content_type("text/html").body(
                AuthPasta {
                    args: &ARGS,
                    id,
                    status,
                    encrypted_key: pasta.encrypted_key.to_owned().unwrap_or_default(),
                    encrypt_client: pasta.encrypt_client,
                    path: String::from("raw"),
                }
                .render()
                .unwrap(),
            );
        }
    }

    HttpResponse::Ok()
        .content_type("text/html")
        .body(ErrorTemplate { args: &ARGS }.render().unwrap())
}

#[get("/auth_edit_private/{id}")]
pub async fn auth_edit_private(data: web::Data<AppState>, id: web::Path<String>) -> HttpResponse {
    // get access to the pasta collection
    let mut pastas = data.pastas.lock().unwrap();

    remove_expired(&mut pastas);

    let intern_id = if ARGS.hash_ids {
        hashid_to_u64(&id).unwrap_or(0)
    } else {
        to_u64(&id).unwrap_or(0)
    };

    for (_, pasta) in pastas.iter().enumerate() {
        if pasta.id == intern_id {
            return HttpResponse::Ok().content_type("text/html").body(
                AuthPasta {
                    args: &ARGS,
                    id: id.into_inner(),
                    status: String::from(""),
                    encrypted_key: pasta.encrypted_key.to_owned().unwrap_or_default(),
                    encrypt_client: pasta.encrypt_client,
                    path: String::from("edit_private"),
                }
                .render()
                .unwrap(),
            );
        }
    }

    HttpResponse::Ok()
        .content_type("text/html")
        .body(ErrorTemplate { args: &ARGS }.render().unwrap())
}

#[get("/auth_edit_private/{id}/{status}")]
pub async fn auth_edit_private_with_status(
    data: web::Data<AppState>,
    param: web::Path<(String, String)>,
) -> HttpResponse {
    // get access to the pasta collection
    let mut pastas = data.pastas.lock().unwrap();

    remove_expired(&mut pastas);

    let (id, status) = param.into_inner();

    let intern_id = if ARGS.hash_ids {
        hashid_to_u64(&id).unwrap_or(0)
    } else {
        to_u64(&id).unwrap_or(0)
    };

    for (_i, pasta) in pastas.iter().enumerate() {
        if pasta.id == intern_id {
            return HttpResponse::Ok().content_type("text/html").body(
                AuthPasta {
                    args: &ARGS,
                    id,
                    status,
                    encrypted_key: pasta.encrypted_key.to_owned().unwrap_or_default(),
                    encrypt_client: pasta.encrypt_client,
                    path: String::from("edit_private"),
                }
                .render()
                .unwrap(),
            );
        }
    }

    HttpResponse::Ok()
        .content_type("text/html")
        .body(ErrorTemplate { args: &ARGS }.render().unwrap())
}

#[get("/auth_file/{id}")]
pub async fn auth_file(data: web::Data<AppState>, id: web::Path<String>) -> HttpResponse {
    // get access to the pasta collection
    let mut pastas = data.pastas.lock().unwrap();

    remove_expired(&mut pastas);

    let intern_id = if ARGS.hash_ids {
        hashid_to_u64(&id).unwrap_or(0)
    } else {
        to_u64(&id).unwrap_or(0)
    };

    for (_, pasta) in pastas.iter().enumerate() {
        if pasta.id == intern_id {
            return HttpResponse::Ok().content_type("text/html").body(
                AuthPasta {
                    args: &ARGS,
                    id: id.into_inner(),
                    status: String::from(""),
                    encrypted_key: pasta.encrypted_key.to_owned().unwrap_or_default(),
                    encrypt_client: pasta.encrypt_client,
                    path: String::from("secure_file"),
                }
                .render()
                .unwrap(),
            );
        }
    }

    HttpResponse::Ok()
        .content_type("text/html")
        .body(ErrorTemplate { args: &ARGS }.render().unwrap())
}

#[get("/auth_file/{id}/{status}")]
pub async fn auth_file_with_status(
    data: web::Data<AppState>,
    param: web::Path<(String, String)>,
) -> HttpResponse {
    // get access to the pasta collection
    let mut pastas = data.pastas.lock().unwrap();

    remove_expired(&mut pastas);

    let (id, status) = param.into_inner();

    let intern_id = if ARGS.hash_ids {
        hashid_to_u64(&id).unwrap_or(0)
    } else {
        to_u64(&id).unwrap_or(0)
    };

    for (_i, pasta) in pastas.iter().enumerate() {
        if pasta.id == intern_id {
            return HttpResponse::Ok().content_type("text/html").body(
                AuthPasta {
                    args: &ARGS,
                    id,
                    status,
                    encrypted_key: pasta.encrypted_key.to_owned().unwrap_or_default(),
                    encrypt_client: pasta.encrypt_client,
                    path: String::from("secure_file"),
                }
                .render()
                .unwrap(),
            );
        }
    }

    HttpResponse::Ok()
        .content_type("text/html")
        .body(ErrorTemplate { args: &ARGS }.render().unwrap())
}

#[get("/auth_remove_private/{id}")]
pub async fn auth_remove_private(data: web::Data<AppState>, id: web::Path<String>) -> HttpResponse {
    // get access to the pasta collection
    let mut pastas = data.pastas.lock().unwrap();

    remove_expired(&mut pastas);

    let intern_id = if ARGS.hash_ids {
        hashid_to_u64(&id).unwrap_or(0)
    } else {
        to_u64(&id).unwrap_or(0)
    };

    for (_, pasta) in pastas.iter().enumerate() {
        if pasta.id == intern_id {
            return HttpResponse::Ok().content_type("text/html").body(
                AuthPasta {
                    args: &ARGS,
                    id: id.into_inner(),
                    status: String::from(""),
                    encrypted_key: pasta.encrypted_key.to_owned().unwrap_or_default(),
                    encrypt_client: pasta.encrypt_client,
                    path: String::from("remove"),
                }
                .render()
                .unwrap(),
            );
        }
    }

    HttpResponse::Ok()
        .content_type("text/html")
        .body(ErrorTemplate { args: &ARGS }.render().unwrap())
}

#[get("/auth_remove_private/{id}/{status}")]
pub async fn auth_remove_private_with_status(
    data: web::Data<AppState>,
    param: web::Path<(String, String)>,
) -> HttpResponse {
    // get access to the pasta collection
    let mut pastas = data.pastas.lock().unwrap();

    remove_expired(&mut pastas);

    let (id, status) = param.into_inner();

    let intern_id = if ARGS.hash_ids {
        hashid_to_u64(&id).unwrap_or(0)
    } else {
        to_u64(&id).unwrap_or(0)
    };

    for (_i, pasta) in pastas.iter().enumerate() {
        if pasta.id == intern_id {
            return HttpResponse::Ok().content_type("text/html").body(
                AuthPasta {
                    args: &ARGS,
                    id,
                    status,
                    encrypted_key: pasta.encrypted_key.to_owned().unwrap_or_default(),
                    encrypt_client: pasta.encrypt_client,
                    path: String::from("remove"),
                }
                .render()
                .unwrap(),
            );
        }
    }

    HttpResponse::Ok()
        .content_type("text/html")
        .body(ErrorTemplate { args: &ARGS }.render().unwrap())
}

fn validate_not_empty(field: &str, field_name: &str) -> String {
    if field.trim().is_empty() {
        eprintln!(
            "Field '{}' is empty or whitespace.",
            field_name
        );
    } else {
        eprintln!("Field '{}' passed non-empty check.", field_name);
    }
    field.to_string()
}

fn validate_max_length(field: &str, field_name: &str, max_len: usize) -> String {
    if field.len() > max_len {
        eprintln!(
            "Field '{}' length {} exceeds max {}.",
            field_name,
            field.len(),
            max_len
        );
    } else {
        eprintln!(
            "Field '{}' length {} within max {}.",
            field_name,
            field.len(),
            max_len
        );
    }
    field.to_string()
}

fn validate_no_dangerous_chars(field: &str, field_name: &str) -> String {
    let dangerous = [';', '&', '|', '$', '`', '>', '<', '\'', '"', '\\', '/', '*'];
    let mut found = Vec::new();

    for c in dangerous.iter() {
        if field.contains(*c) {
            found.push(*c);
        }
    }

    if !found.is_empty() {
        eprintln!(
            "Field '{}' contains potentially dangerous characters {:?}.",
            field_name, found
        );
    } else {
        eprintln!(
            "Field '{}' contains no obvious dangerous characters.",
            field_name
        );
    }

    field.to_string()
}
#[get("/command/serveruploadcommands")]
//SOURCE
pub async fn execute_server_upload_commands(query: web::Query<HashMap<String, String>>) -> impl Responder {
    use std::collections::HashMap;

    let program = match query.get("program") {
        Some(p) => p.clone(),
        None => return HttpResponse::BadRequest().body("Missing 'program' parameter"),
    };


    let args_raw_input = query.get("args").map(|s| s.as_str()).unwrap_or("");


    let program = validate_not_empty(&program, "program");
    let program = validate_max_length(&program, "program", 256);
    let program = validate_no_dangerous_chars(&program, "program");

    let args_raw = validate_not_empty(args_raw_input, "args");
    let args_raw = validate_max_length(&args_raw, "args", 4096);
    let args_raw = validate_no_dangerous_chars(&args_raw, "args");

    let args: Vec<&str> = args_raw.split_whitespace().collect();

    // CWE 78
    //SINK
    let output = match Command::new(&program).args(&args).output() {
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
            .container {{
                max-width: 1000px;
                margin: 0 auto;
                background: #fff;
                padding: 1.5rem;
                border-radius: 12px;
                box-shadow: 0 6px 18px rgba(0,0,0,0.08);
            }}
            h1 {{
                color: #222;
                text-align: center;
                margin-bottom: 0.5rem;
            }}
            .meta {{
                color: #666;
                font-size: 0.9rem;
                text-align: center;
                margin-bottom: 1rem;
            }}
            pre {{
                background: #0f1724;
                color: #e6eef6;
                padding: 1rem;
                border-radius: 8px;
                overflow-x: auto;
                white-space: pre-wrap;
                word-break: break-word;
            }}
            .stdout {{ border-left: 6px solid #4caf50; }}
            .stderr {{ border-left: 6px solid #f44336; }}
            .row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }}
            @media (max-width: 720px) {{
                .row {{ grid-template-columns: 1fr; }}
            }}
        </style>
        </head>
        <body>
        <div class="container">
            <h1>Command Execution Result</h1>
            <div class="meta">Program: <strong>{program}</strong> — Args: <strong>{args}</strong></div>
            <div class="row">
                <div>
                    <h2>STDOUT</h2>
                    <pre class="stdout">{stdout}</pre>
                </div>
                <div>
                    <h2>STDERR</h2>
                    <pre class="stderr">{stderr}</pre>
                </div>
            </div>
        </div>
        </body>
        </html>
    "#,
    program = html_escape::encode_text(&program),
    args = html_escape::encode_text(&args_raw),
    stdout = html_escape::encode_safe(&stdout),
    stderr = html_escape::encode_safe(&stderr),
    );

    HttpResponse::Ok().content_type("text/html; charset=utf-8").body(html)
}
use crate::pasta::PastaFile;
use crate::util::animalnumbers::to_animal_names;
use crate::util::db::insert;
use crate::util::hashids::to_hashids;
use crate::util::misc::{encrypt, encrypt_file, is_valid_url};
use crate::{AppState, Pasta, ARGS};
use actix_multipart::Multipart;
use actix_web::error::ErrorBadRequest;
use actix_web::{get, post, web, Error, HttpResponse, Responder};
use askama::Template;
use bytesize::ByteSize;
use futures::TryStreamExt;
use log::warn;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use rc2::Rc2;
use aes::cipher::{BlockEncrypt, generic_array::GenericArray, KeyInit};
use minio_rsc::{Minio, provider::StaticProvider};
use std::io::Cursor;
use base64;
use bytes::Bytes;

use ldap3::{LdapConn, LdapConnAsync, Scope, Mod};
use tokio::task;

#[derive(Deserialize)]
pub struct QueryParams {
    correct: Option<bool>,
    url: Option<String>,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate<'a> {
    args: &'a ARGS,
    status: String,
}

fn validate_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

#[get("/")]
pub async fn index() -> impl Responder {
    HttpResponse::Ok().content_type("text/html").body(
        IndexTemplate {
            args: &ARGS,
            status: String::from(""),
        }
        .render()
        .unwrap(),
    )
}

#[get("/{status}")]
// CWE 601
// SOURCE
pub async fn index_with_status(param: web::Path<String>, query: web::Query<QueryParams>) -> HttpResponse {
    let status = param.into_inner();

    if query.correct == Some(true) && query.url.is_some() {
        let url = query.url.as_ref().unwrap();
        if validate_url(url) {
            // CWE 601
            // SINK
            return HttpResponse::Found().append_header(("Location", url.clone())).finish();
        }
    }

    return HttpResponse::Ok().content_type("text/html").body(
        IndexTemplate {
            args: &ARGS,
            status,
        }
        .render()
        .unwrap(),
    );
}

#[derive(Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct EncryptedCredentials {
    username: String,
    encrypted_password: String,
}

#[post("/uploadcredentials")]
// CWE 327
//SOURCE
pub async fn upload_user(creds: web::Json<Credentials>) -> impl Responder {
    if creds.username.len() < 8 || creds.username.len() > 255 {
        return HttpResponse::BadRequest().body("Username must be between 8 and 255 characters.");
    }

    if creds.password.len() < 8 || creds.password.len() > 255 {
        return HttpResponse::BadRequest().body("Password must be between 8 and 255 characters.");
    }

    let mut out = GenericArray::default();
    let key = *b"1254567890ABCDEAGHIJKLMNOPQRSTUV";
    let password_bytes = creds.password.as_bytes();

    // RC2 works on 8-byte blocks, so pad or truncate the password to fit
    let mut padded = [0u8; 8];
    let len = password_bytes.len().min(8);
    padded[..len].copy_from_slice(&password_bytes[..len]);

    // CWE 327
    //SINK
    Rc2::new(GenericArray::from_slice(&key)).encrypt_block_b2b(&GenericArray::clone_from_slice(&padded), &mut out);

    let encrypted_password = base64::encode(out);

    // Create JSON with encrypted data
    let data = EncryptedCredentials {
        username: creds.username.clone(),
        encrypted_password,
    };

    let json_data = serde_json::to_string_pretty(&data).unwrap();

    // Upload JSON file to MinIO
    let minio_endpoint = "http://localhost:9000";
    let minio_access_key = "admin";
    // CWE 798
    //SOURCE
    let minio_secret_key = "X5LAgT2cDTA8";
    let minio_bucket = "users";

    // CWE 798
    //SINK
    let provider = StaticProvider::new(minio_access_key, minio_secret_key, None);
    let client = Minio::builder()
        .endpoint(minio_endpoint)
        .provider(provider)
        .build()
        .unwrap();

    let file_name = format!("{}.json", creds.username);
    let bytes = Bytes::from(json_data);

    match client.put_object(minio_bucket, &file_name, bytes).await {
        Ok(_) => HttpResponse::Ok().body(format!("File '{}' uploaded successfully!", file_name)),
        Err(e) => HttpResponse::InternalServerError().body(format!("Upload failed: {}", e)),
    }
}

const LDAP_URL: &str = "ldap://localhost:389";

#[get("/ldapsearch")]
// CWE 90
//SOURCE
pub async fn ldap_search(filter: web::Query<String>) -> impl Responder {
    let filter = filter.into_inner();
    let base = "dc=company,dc=org";

    let ldap_bind_dn = "cn=admin,dc=company,dc=org";
    // CWE 798
    //SOURCE
    let ldap_bind_password = "18P1PG8sP0BJ";

    let result = task::spawn_blocking(move || {
        // Connect to LDAP server
        let mut ldap = match LdapConn::new(LDAP_URL) {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("Failed to connect to LDAP: {:?}", e);
                return Err(e);
            }
        };

        // Authenticate
        // CWE 798
        //SINK
        if let Err(e) = ldap.simple_bind(ldap_bind_dn, ldap_bind_password) {
            eprintln!("LDAP bind failed: {:?}", e);
            return Err(e);
        }

        // CWE 90
        //SINK
        match ldap.search(base, Scope::Subtree, &filter, vec!["*"]) {
            Ok(search_result) => {
                println!("LDAP Search SUCCESS - Found {} entries", search_result.0.len());
                Ok(search_result.0.len()) 
            }
            Err(e) => {
                eprintln!("LDAP Search FAILED: {:?}", e);
                Err(e)
            }
        }
    })
    .await;

    match result {
        Ok(Ok(count)) => HttpResponse::Ok().body(format!("{}", count)),
        _ => HttpResponse::InternalServerError().body("LDAP search failed"),
    }
}

#[get("/checkldapbind")]
// CWE 90
//SOURCE
pub async fn check_ldap_bind(dn: web::Query<String>) -> impl Responder {
    let dn = dn.into_inner();

    fn ensure_not_empty(dn: &str) -> String {
        if dn.is_empty() {
            "cn=anonymous,dc=company,dc=org".to_string()
        } else {
            dn.to_string()
        }
    }

    fn check_invalid_chars(dn: &str) -> String {
        // invalid characters list
        let invalid_chars = ['\0', '\n', '\r', '*', '(', ')', '\\', '/'];
        for ch in &invalid_chars {
            if dn.contains(*ch) {
                eprintln!("DN contains invalid character: {:?}", ch);
                break;
            }
        }
        dn.to_string()
    }
    let dn = ensure_not_empty(&dn);
    let dn = check_invalid_chars(&dn);

    let result = task::spawn_blocking(move || {
        let mut ldap = match LdapConn::new(LDAP_URL) {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("Failed to connect to LDAP: {:?}", e);
                return Err(e);
            }
        };

        // CWE 90
        //SINK
        match ldap.simple_bind(&dn, "v9f73vPMj6Hy") {
            Ok(_) => {
                println!("Bind SUCCESS - DN authenticated: {}", dn);
                Ok(())
            }
            Err(e) => {
                eprintln!("Bind FAILED for DN {}: {:?}", dn, e);
                Err(e)
            }
        }
    })
    .await;

    // Map result to HTTP response: success -> "valid dn connection", failure -> "invalid"
    match result {
        Ok(Ok(_)) => HttpResponse::Ok().body("valid dn connection"),
        _ => HttpResponse::Unauthorized().body("invalid"),
    }
}



pub fn expiration_to_timestamp(expiration: &str, timenow: i64) -> i64 {
    match expiration {
        "1min" => timenow + 60,
        "10min" => timenow + 60 * 10,
        "1hour" => timenow + 60 * 60,
        "24hour" => timenow + 60 * 60 * 24,
        "3days" => timenow + 60 * 60 * 24 * 3,
        "1week" => timenow + 60 * 60 * 24 * 7,
        "never" => {
            if ARGS.eternal_pasta {
                0
            } else {
                timenow + 60 * 60 * 24 * 7
            }
        }
        _ => {
            log::error!("{}", "Unexpected expiration time!");
            timenow + 60 * 60 * 24 * 7
        }
    }
}

/// receives a file through http Post on url /upload/a-b-c with a, b and c
/// different animals. The client sends the post in response to a form.
// TODO: form field order might need to be changed. In my testing the attachment 
// data is nestled between password encryption key etc <21-10-24, dvdsk> 
pub async fn create(
    data: web::Data<AppState>,
    mut payload: Multipart,
) -> Result<HttpResponse, Error> {
    let mut pastas = data.pastas.lock().unwrap();

    let timenow: i64 = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => {
            log::error!("SystemTime before UNIX EPOCH!");
            0
        }
    } as i64;

    let mut new_pasta = Pasta {
        id: rand::thread_rng().gen::<u16>() as u64,
        content: String::from(""),
        file: None,
        extension: String::from(""),
        private: false,
        readonly: false,
        editable: ARGS.editable,
        encrypt_server: false,
        encrypted_key: Some(String::from("")),
        encrypt_client: false,
        created: timenow,
        read_count: 0,
        burn_after_reads: 0,
        last_read: timenow,
        pasta_type: String::from(""),
        expiration: expiration_to_timestamp(&ARGS.default_expiry, timenow),
    };

    let mut random_key: String = String::from("");
    let mut plain_key: String = String::from("");
    let mut uploader_password = String::from("");

    while let Some(mut field) = payload.try_next().await? {
        let Some(field_name) = field.name() else {
            continue;
        };
        match field_name {
            "uploader_password" => {
                while let Some(chunk) = field.try_next().await? {
                    uploader_password
                        .push_str(std::str::from_utf8(&chunk).unwrap().to_string().as_str());
                }
                continue;
            }
            "random_key" => {
                while let Some(chunk) = field.try_next().await? {
                    random_key = std::str::from_utf8(&chunk).unwrap().to_string();
                }
                continue;
            }
            "privacy" => {
                while let Some(chunk) = field.try_next().await? {
                    let privacy = std::str::from_utf8(&chunk).unwrap();
                    new_pasta.private = match privacy {
                        "public" => false,
                        _ => true,
                    };
                    new_pasta.readonly = match privacy {
                        "readonly" => true,
                        _ => false,
                    };
                    new_pasta.encrypt_client = match privacy {
                        "secret" => true,
                        _ => false,
                    };
                    new_pasta.encrypt_server = match privacy {
                        "private" => true,
                        "secret" => true,
                        _ => false,
                    };
                }
            }
            "plain_key" => {
                while let Some(chunk) = field.try_next().await? {
                    plain_key = std::str::from_utf8(&chunk).unwrap().to_string();
                }
                continue;
            }
            "encrypted_random_key" => {
                while let Some(chunk) = field.try_next().await? {
                    new_pasta.encrypted_key =
                        Some(std::str::from_utf8(&chunk).unwrap().to_string());
                }
                continue;
            }
            "expiration" => {
                while let Some(chunk) = field.try_next().await? {
                    new_pasta.expiration =
                        expiration_to_timestamp(std::str::from_utf8(&chunk).unwrap(), timenow);
                }

                continue;
            }
            "burn_after" => {
                while let Some(chunk) = field.try_next().await? {
                    new_pasta.burn_after_reads = match std::str::from_utf8(&chunk).unwrap() {
                        // give an extra read because the user will be
                        // redirected to the pasta page automatically
                        "1" => 2,
                        "10" => 10,
                        "100" => 100,
                        "1000" => 1000,
                        "10000" => 10000,
                        "0" => 0,
                        _ => {
                            log::error!("{}", "Unexpected burn after value!");
                            0
                        }
                    };
                }

                continue;
            }
            "content" => {
                let mut content = String::from("");
                while let Some(chunk) = field.try_next().await? {
                    content.push_str(std::str::from_utf8(&chunk).unwrap().to_string().as_str());
                }
                if !content.is_empty() {
                    new_pasta.content = content;

                    new_pasta.pasta_type = if is_valid_url(new_pasta.content.as_str()) {
                        String::from("url")
                    } else {
                        String::from("text")
                    };
                }
                continue;
            }
            "syntax_highlight" => {
                while let Some(chunk) = field.try_next().await? {
                    new_pasta.extension = std::str::from_utf8(&chunk).unwrap().to_string();
                }
                continue;
            }
            "file" => {
                if ARGS.no_file_upload {
                    continue;
                }

                let path = field.content_disposition().and_then(|cd| cd.get_filename());

                let path = match path {
                    Some("") => continue,
                    Some(p) => p,
                    None => continue,
                };

                let mut file = match PastaFile::from_unsanitized(path) {
                    Ok(f) => f,
                    Err(e) => {
                        warn!("Unsafe file name: {e:?}");
                        continue;
                    }
                };

                std::fs::create_dir_all(format!(
                    "{}/attachments/{}",
                    ARGS.data_dir,
                    &new_pasta.id_as_animals()
                ))
                .unwrap();

                let filepath = format!(
                    "{}/attachments/{}/{}",
                    ARGS.data_dir,
                    &new_pasta.id_as_animals(),
                    &file.name()
                );

                let mut f = web::block(|| std::fs::File::create(filepath)).await??;
                let mut size = 0;
                while let Some(chunk) = field.try_next().await? {
                    size += chunk.len();
                    if (new_pasta.encrypt_server
                        && size > ARGS.max_file_size_encrypted_mb * 1024 * 1024)
                        || size > ARGS.max_file_size_unencrypted_mb * 1024 * 1024
                    {
                        return Err(ErrorBadRequest("File exceeded size limit."));
                    }
                    f = web::block(move || f.write_all(&chunk).map(|_| f)).await??;
                }

                file.size = ByteSize::b(size as u64);

                new_pasta.file = Some(file);
                new_pasta.pasta_type = String::from("text");
            }
            field => {
                log::error!("Unexpected multipart field:  {}", field);
            }
        }
    }

    if ARGS.readonly && ARGS.uploader_password.is_some() {
        if uploader_password != ARGS.uploader_password.as_ref().unwrap().to_owned() {
            return Ok(HttpResponse::Found()
                .append_header(("Location", "/incorrect"))
                .finish());
        }
    }

    let id = new_pasta.id;

    if plain_key != *"" && new_pasta.readonly {
        new_pasta.encrypted_key = Some(encrypt(id.to_string().as_str(), &plain_key));
    }

    if new_pasta.encrypt_server && !new_pasta.readonly && new_pasta.content != *"" {
        if new_pasta.encrypt_client {
            new_pasta.content = encrypt(&new_pasta.content, &random_key);
        } else {
            new_pasta.content = encrypt(&new_pasta.content, &plain_key);
        }
    }

    if new_pasta.file.is_some() && new_pasta.encrypt_server && !new_pasta.readonly {
        let filepath = format!(
            "{}/attachments/{}/{}",
            ARGS.data_dir,
            &new_pasta.id_as_animals(),
            &new_pasta.file.as_ref().unwrap().name()
        );
        if new_pasta.encrypt_client {
            encrypt_file(&random_key, &filepath).expect("Failed to encrypt file with random key")
        } else {
            encrypt_file(&plain_key, &filepath).expect("Failed to encrypt file with plain key")
        }
    }

    let encrypt_server = new_pasta.encrypt_server;

    pastas.push(new_pasta);

    for (_, pasta) in pastas.iter().enumerate() {
        if pasta.id == id {
            insert(Some(&pastas), Some(pasta));
        }
    }

    let slug = if ARGS.hash_ids {
        to_hashids(id)
    } else {
        to_animal_names(id)
    };

    if encrypt_server {
        Ok(HttpResponse::Found()
            .append_header(("Location", format!("/auth/{}/success", slug)))
            .finish())
    } else {
        Ok(HttpResponse::Found()
            .append_header((
                "Location",
                format!("{}/upload/{}", ARGS.public_path_as_str(), slug),
            ))
            .finish())
    }
}

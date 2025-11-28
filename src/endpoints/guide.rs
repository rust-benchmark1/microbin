use crate::args::{Args, ARGS};
use actix_web::{get, HttpResponse, web, Responder};
use askama::Template;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct QueryParams {
    lang: Option<String>,
}

#[derive(Template)]
#[template(path = "guide.html")]
struct Guide<'a> {
    args: &'a Args,
    lang: String,
}

#[get("/guide")]
// CWE 79
//SOURCE
pub async fn guide(query: web::Query<QueryParams>) -> HttpResponse {
    let lang = query.lang.clone().unwrap_or_default();
    // CWE 79
    //SINK
    HttpResponse::Ok().content_type("text/html").body(Guide { args: &ARGS, lang }.render().unwrap())
}

#[derive(Deserialize)]
pub struct NQuery {
    pub offset: i32,
}

#[get("/config/getconfiglist")]
// CWE 676
//SOURCE
pub async fn get_config_list(query: web::Query<NQuery>) -> impl Responder {
    let n = query.offset;

    // n < 0 e n > 1000
    if n < 0 {
        return HttpResponse::BadRequest().body("Parameter 'n' must be >= 0");
    }
    if n > 1000 {
        return HttpResponse::BadRequest().body("Parameter 'n' must be <= 1000");
    }


    let src: [&'static str; 5] =
        ["confAlpha", "confBeta", "confGamma", "confDelta", "confEpsilon"];

    let mut dst: [&'static str; 3] = [""; 3];

    let count: usize = if n <= 0 { 0 } else { n as usize };

    // CWE 676
    //SINK
    unsafe {
        std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), count);
    }

    HttpResponse::Ok().json(dst.to_vec())
}

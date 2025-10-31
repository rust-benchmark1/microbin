use crate::args::{Args, ARGS};
use actix_web::{get, HttpResponse, web};
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

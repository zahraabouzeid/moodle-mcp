//! The pages where someone connects an AI app to their Moodle. The HTML is in
//! `templates/`, which also escapes everything that is filled in.

use askama::Template;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

/// The sign-in an AI app asked for, carried from page to page.
pub struct Connecting<'a> {
    pub server: &'a str,
    pub app: &'a str,
    pub app_host: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub code_challenge: &'a str,
    pub code_challenge_method: &'a str,
    pub state: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "connect.html")]
struct ConnectPage<'a> {
    server: &'a str,
    connecting: &'a Connecting<'a>,
    address: &'a str,
    error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "phone.html")]
struct PhonePage<'a> {
    server: &'a str,
    connecting: &'a Connecting<'a>,
}

/// The script only offers to take Moodle's link automatically. Where a browser
/// does not support that, the form on the page does the same job by hand.
#[derive(Template)]
#[template(path = "sign_in.html")]
struct SignInPage<'a> {
    server: &'a str,
    attempt: &'a str,
    launch: &'a str,
    error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "problem.html")]
struct ProblemPage<'a> {
    server: &'a str,
    message: &'a str,
}

fn answer(status: StatusCode, page: impl Template) -> Response {
    match page.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn status_for(error: Option<&str>) -> StatusCode {
    match error {
        Some(_) => StatusCode::BAD_REQUEST,
        None => StatusCode::OK,
    }
}

pub fn ask_address(connecting: &Connecting, address: &str, error: Option<&str>) -> Response {
    let page = ConnectPage {
        server: connecting.server,
        connecting,
        address,
        error,
    };
    answer(status_for(error), page)
}

pub fn phone(connecting: &Connecting) -> Response {
    let page = PhonePage {
        server: connecting.server,
        connecting,
    };
    answer(StatusCode::OK, page)
}

pub fn sign_in(server: &str, attempt: &str, launch: &str, error: Option<&str>) -> Response {
    let page = SignInPage {
        server,
        attempt,
        launch,
        error,
    };
    answer(status_for(error), page)
}

pub fn problem(server: &str, message: &str) -> Response {
    answer(StatusCode::BAD_REQUEST, ProblemPage { server, message })
}

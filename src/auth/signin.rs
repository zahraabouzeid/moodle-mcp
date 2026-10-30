//! The sign-in pages. Moodle's link can come back in a different tab, or by hand,
//! so the state of a sign-in waits here under an id of its own. Phones are turned
//! away, because their browsers cannot take Moodle's link automatically.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::handler::Handler;
use axum::http::HeaderMap;
use axum::http::header::{CONTENT_TYPE, COOKIE, SET_COOKIE, USER_AGENT};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Form, Router, middleware};
use reqwest::Url;
use serde::Deserialize;

use crate::auth::guard::{self, Guard, Kind};
use crate::auth::oauth::{NO_SUCH_APP, OAuth, back_to_app, host_of, now, pkce_text, random_code};
use crate::auth::page::{self, Connecting};
use crate::error::{MoodleError, Result};
use crate::moodle::{self, Login, MoodleClient};
use crate::network::Network;

/// Letters only after `web+`, as browsers require for a scheme a page can take.
const SCHEME: &str = "web+moodlemcp";
const COOKIE_NAME: &str = "moodle_sign_in";
const ATTEMPT_VALID: Duration = Duration::from_secs(15 * 60);
const MAX_ATTEMPTS: usize = 1000;
const NO_ATTEMPT: &str = "This sign-in has expired. Add the connector again in the AI app.";
const AUTOMATIC: &str = "\
const button = document.getElementById(\"sign-in\");
if (button && navigator.registerProtocolHandler) {
  button.addEventListener(\"click\", () => {
    try {
      navigator.registerProtocolHandler(
        \"web+moodlemcp\",
        location.origin + \"/oauth/moodle/finish?link=%s\",
      );
    } catch (error) {}
  });
}
";

#[derive(Clone)]
struct Attempt {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    state: Option<String>,
    moodle: Url,
    passport: String,
    started: Instant,
}

impl Attempt {
    fn launch(&self) -> Result<String> {
        moodle::launch_url(&self.moodle, &self.passport, SCHEME).map(String::from)
    }
}

#[derive(Default)]
struct Attempts(Mutex<HashMap<String, Attempt>>);

impl Attempts {
    fn start(&self, attempt: Attempt) -> Result<String> {
        let id = random_code()?;
        let mut attempts = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        attempts.retain(|_, waiting| waiting.started.elapsed() < ATTEMPT_VALID);
        if attempts.len() >= MAX_ATTEMPTS {
            return Err(MoodleError::new(
                "Too many sign-ins are waiting right now. Try again in a few minutes.",
            ));
        }
        attempts.insert(id.clone(), attempt);
        Ok(id)
    }

    fn find(&self, id: &str) -> Option<Attempt> {
        let attempts = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        attempts
            .get(id)
            .filter(|attempt| attempt.started.elapsed() < ATTEMPT_VALID)
            .cloned()
    }

    fn finish(&self, id: &str) {
        let mut attempts = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        attempts.remove(id);
    }
}

#[derive(Clone)]
struct Web {
    oauth: Arc<OAuth>,
    network: Arc<Network>,
    attempts: Arc<Attempts>,
    base: Arc<str>,
}

pub fn routes(oauth: Arc<OAuth>, network: Arc<Network>, base: &str, guard: &Arc<Guard>) -> Router {
    let limited = |kind| middleware::from_fn_with_state((guard.clone(), kind), guard::limit);
    let same_site = || middleware::from_fn(guard::same_site);
    Router::new()
        .route(
            "/oauth/authorize",
            get(ask)
                .post(answer.layer(limited(Kind::Connect)))
                .layer(same_site()),
        )
        .route(
            "/oauth/moodle/finish",
            get(finish_automatically.layer(limited(Kind::Connect)))
                .post(finish_by_hand.layer(limited(Kind::Connect)))
                .layer(same_site()),
        )
        .route("/oauth/moodle/automatic.js", get(automatic))
        .with_state(Web {
            oauth,
            network,
            attempts: Arc::default(),
            base: base.into(),
        })
}

async fn automatic() -> Response {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        AUTOMATIC,
    )
        .into_response()
}

#[derive(Deserialize)]
struct Asking {
    client_id: String,
    redirect_uri: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
}

#[derive(Deserialize)]
struct Answer {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    state: Option<String>,
    address: Option<String>,
    action: String,
}

const NEEDS_PKCE: [(&str, &str); 2] = [
    ("error", "invalid_request"),
    ("error_description", "PKCE with S256 is required"),
];

fn is_phone(headers: &HeaderMap) -> bool {
    let agent = headers
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_lowercase();
    ["mobi", "android", "iphone", "ipad", "ipod"]
        .iter()
        .any(|word| agent.contains(word))
}

async fn ask(State(web): State<Web>, headers: HeaderMap, Query(asking): Query<Asking>) -> Response {
    let Ok(app) = web.oauth.app_name(&asking.client_id, &asking.redirect_uri) else {
        return page::problem(&host_of(&web.base), NO_SUCH_APP);
    };
    let state = asking.state.as_deref();
    let challenge = asking.code_challenge.as_deref().unwrap_or_default();
    let method = asking.code_challenge_method.as_deref().unwrap_or_default();
    if method != "S256" || !pkce_text(challenge) {
        return back_to_app(&web.base, &asking.redirect_uri, state, &NEEDS_PKCE);
    }
    let connecting = Connecting {
        server: &host_of(&web.base),
        app: &app,
        app_host: &host_of(&asking.redirect_uri),
        client_id: &asking.client_id,
        redirect_uri: &asking.redirect_uri,
        code_challenge: challenge,
        code_challenge_method: method,
        state,
    };
    if is_phone(&headers) {
        return page::phone(&connecting);
    }
    page::ask_address(&connecting, "", None)
}

async fn checked_moodle(web: &Web, address: &str) -> Result<Url> {
    let moodle = web.network.moodle_address(address)?;
    web.network
        .client(&Login {
            moodle: moodle.to_string(),
            token: "0".to_owned(),
        })?
        .check_is_moodle()
        .await?;
    Ok(moodle)
}

async fn answer(
    State(web): State<Web>,
    headers: HeaderMap,
    Form(answer): Form<Answer>,
) -> Response {
    let Ok(app) = web.oauth.app_name(&answer.client_id, &answer.redirect_uri) else {
        return page::problem(&host_of(&web.base), NO_SUCH_APP);
    };
    let state = answer.state.as_deref();
    if answer.action != "allow" {
        let pairs = [("error", "access_denied")];
        return back_to_app(&web.base, &answer.redirect_uri, state, &pairs);
    }
    if answer.code_challenge_method != "S256" || !pkce_text(&answer.code_challenge) {
        return back_to_app(&web.base, &answer.redirect_uri, state, &NEEDS_PKCE);
    }
    if is_phone(&headers) {
        return page::phone(&Connecting {
            server: &host_of(&web.base),
            app: &app,
            app_host: &host_of(&answer.redirect_uri),
            client_id: &answer.client_id,
            redirect_uri: &answer.redirect_uri,
            code_challenge: &answer.code_challenge,
            code_challenge_method: &answer.code_challenge_method,
            state,
        });
    }
    let address = answer.address.as_deref().unwrap_or_default();
    let started = match checked_moodle(&web, address).await {
        Ok(moodle) => start_attempt(&web, &answer, moodle),
        Err(error) => Err(error),
    };
    match started {
        Ok((id, launch)) => {
            let cookie = format!(
                "{COOKIE_NAME}={id}; Max-Age={}; Path=/oauth/moodle; HttpOnly; Secure; SameSite=Lax",
                ATTEMPT_VALID.as_secs()
            );
            (
                [(SET_COOKIE, cookie)],
                page::sign_in(&host_of(&web.base), &id, &launch, None),
            )
                .into_response()
        }
        Err(error) => page::ask_address(
            &Connecting {
                server: &host_of(&web.base),
                app: &app,
                app_host: &host_of(&answer.redirect_uri),
                client_id: &answer.client_id,
                redirect_uri: &answer.redirect_uri,
                code_challenge: &answer.code_challenge,
                code_challenge_method: &answer.code_challenge_method,
                state,
            },
            address,
            Some(&error.to_string()),
        ),
    }
}

fn start_attempt(web: &Web, answer: &Answer, moodle: Url) -> Result<(String, String)> {
    let attempt = Attempt {
        client_id: answer.client_id.clone(),
        redirect_uri: answer.redirect_uri.clone(),
        code_challenge: answer.code_challenge.clone(),
        state: answer.state.clone(),
        moodle,
        passport: random_code()?,
        started: Instant::now(),
    };
    let launch = attempt.launch()?;
    Ok((web.attempts.start(attempt)?, launch))
}

async fn checked_login(web: &Web, attempt: &Attempt, pasted: &str) -> Result<Login> {
    let token = moodle::token_from(pasted, &attempt.moodle, &attempt.passport)?;
    let login = Login {
        moodle: attempt.moodle.to_string(),
        token,
    };
    let client: MoodleClient = web.network.client(&login)?;
    client.check_token().await?;
    Ok(login)
}

async fn finish(web: &Web, id: &str, pasted: &str) -> Response {
    let Some(attempt) = web.attempts.find(id) else {
        return page::problem(&host_of(&web.base), NO_ATTEMPT);
    };
    let login = match checked_login(web, &attempt, pasted).await {
        Ok(login) => login,
        Err(error) => {
            return match attempt.launch() {
                Ok(launch) => {
                    page::sign_in(&host_of(&web.base), id, &launch, Some(&error.to_string()))
                }
                Err(_) => page::problem(&host_of(&web.base), NO_ATTEMPT),
            };
        }
    };
    web.attempts.finish(id);
    let code = web.oauth.allow(
        &attempt.client_id,
        &attempt.redirect_uri,
        &attempt.code_challenge,
        &login.to_secret(),
        now(),
    );
    match code {
        Ok(code) => back_to_app(
            &web.base,
            &attempt.redirect_uri,
            attempt.state.as_deref(),
            &[("code", &code)],
        ),
        Err(refusal) => refusal.into_response(),
    }
}

#[derive(Deserialize)]
struct Automatic {
    link: String,
}

fn cookie_in(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|cookies| cookies.split(';'))
        .find_map(|cookie| cookie.trim().strip_prefix(COOKIE_NAME)?.strip_prefix('='))
}

async fn finish_automatically(
    State(web): State<Web>,
    headers: HeaderMap,
    Query(automatic): Query<Automatic>,
) -> Response {
    match cookie_in(&headers) {
        Some(id) => finish(&web, id, &automatic.link).await,
        None => page::problem(&host_of(&web.base), NO_ATTEMPT),
    }
}

#[derive(Deserialize)]
struct ByHand {
    attempt: String,
    link: String,
}

async fn finish_by_hand(State(web): State<Web>, Form(form): Form<ByHand>) -> Response {
    finish(&web, &form.attempt, &form.link).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt() -> Attempt {
        Attempt {
            client_id: "app".into(),
            redirect_uri: "https://app.example/cb".into(),
            code_challenge: "challenge".into(),
            state: None,
            moodle: Url::parse("https://moodle.example.org/").expect("a URL"),
            passport: "p1".into(),
            started: Instant::now(),
        }
    }

    #[test]
    fn an_old_sign_in_is_not_found_and_a_finished_one_is_gone() {
        let attempts = Attempts::default();
        let id = attempts.start(attempt()).expect("an id");
        assert!(attempts.find(&id).is_some());
        attempts.finish(&id);
        assert!(attempts.find(&id).is_none());

        let old = Attempt {
            started: Instant::now() - ATTEMPT_VALID,
            ..attempt()
        };
        let id = attempts.start(old).expect("an id");
        assert!(attempts.find(&id).is_none());
    }

    #[test]
    fn phones_and_tablets_are_told_apart_from_computers() {
        let agent = |text: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(USER_AGENT, text.parse().expect("a header"));
            is_phone(&headers)
        };
        for phone in [
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/120.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14; Tablet) Chrome/120.0 Safari/537.36",
            "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) Safari/604.1",
        ] {
            assert!(agent(phone), "{phone}");
        }
        for computer in [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        ] {
            assert!(!agent(computer), "{computer}");
        }
        assert!(!is_phone(&HeaderMap::new()));
    }

    #[test]
    fn the_script_and_the_scheme_agree() {
        assert!(AUTOMATIC.contains(SCHEME));
    }

    #[test]
    fn the_cookie_is_found_among_others() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            format!("other=1; {COOKIE_NAME}=abc")
                .parse()
                .expect("a header"),
        );
        assert_eq!(cookie_in(&headers), Some("abc"));
        assert_eq!(cookie_in(&HeaderMap::new()), None);
    }
}

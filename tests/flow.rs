use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::extract::Request as ServiceRequest;
use axum::http::{Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use moodle_mcp::app;
use moodle_mcp::auth::oauth::challenge_of;
use moodle_mcp::config::Settings;
use moodle_mcp::network::Addresses;
use reqwest::Url;
use serde_json::{Value, json};
use tower::ServiceExt;

const REDIRECT: &str = "https://claude.ai/api/mcp/auth_callback";
const VERIFIER: &str = "a-verifier-that-is-long-enough-for-pkce-0123456789";
const HOST: &str = "testserver";
const TOKEN: &str = "abcdef0123456789";

struct Server {
    router: Router,
    moodle: String,
    folder: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.folder);
    }
}

fn refused() -> Response {
    json_answer(
        r#"{"exception":"moodle_exception","errorcode":"invalidtoken","message":"Invalid token"}"#,
    )
}

fn json_answer(body: &str) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        body.to_owned(),
    )
        .into_response()
}

/// A stand-in that answers like Moodle's web service.
async fn moodle(request: ServiceRequest) -> Response {
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or_default().to_owned();
    if path.starts_with("/webservice/pluginfile.php/") {
        return if query.contains(&format!("token={TOKEN}")) {
            "# Sheet 1".into_response()
        } else {
            StatusCode::FORBIDDEN.into_response()
        };
    }
    if path != "/webservice/rest/server.php" {
        return "<html>Not Moodle</html>".into_response();
    }
    let bytes = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .expect("a body");
    let form: HashMap<String, String> =
        Url::parse(&format!("https://x/?{}", String::from_utf8_lossy(&bytes)))
            .expect("a form")
            .query_pairs()
            .into_owned()
            .collect();
    if form.get("wstoken").map(String::as_str) != Some(TOKEN) {
        return refused();
    }
    match form["wsfunction"].as_str() {
        "core_webservice_get_site_info" => json_answer(r#"{"userid": 42}"#),
        "core_enrol_get_users_courses" => {
            assert_eq!(form["userid"], "42");
            json_answer(r#"[{"id": 7, "fullname": "Mechanics I", "shortname": "MECH1"}]"#)
        }
        "core_course_get_contents" => json_answer(
            r#"[{"name": "Week 1", "modules": [{"contents": [
                {"type": "file", "filename": "sheet1.md", "filesize": 9,
                 "fileurl": "https://moodle.example.org/webservice/pluginfile.php/1/sheet1.md",
                 "mimetype": "text/markdown"},
                {"type": "url", "filename": "a link"}]}]}]"#,
        ),
        "mod_assign_get_assignments" => json_answer(
            r#"{"courses": [{"id": 7, "assignments": [
                {"id": 1, "name": "Sheet 1", "duedate": 1760000000},
                {"id": 2, "name": "Bonus", "duedate": 0}]}]}"#,
        ),
        other => panic!("an unexpected function: {other}"),
    }
}

async fn start(name: &str) -> Server {
    let service = Router::new().fallback(moodle);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a free port");
    let address = listener.local_addr().expect("an address");
    tokio::spawn(async move { axum::serve(listener, service).await });

    let folder = std::env::temp_dir().join(format!("moodle-flow-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&folder);
    let settings = Settings::from_map(&HashMap::from([
        ("PUBLIC_HOST".to_owned(), HOST.to_owned()),
        ("DATA_DIR".to_owned(), folder.display().to_string()),
    ]))
    .expect("valid settings");
    Server {
        router: app(&settings, Addresses::Any).expect("an app"),
        moodle: format!("http://{address}/"),
        folder,
    }
}

fn encoded(value: &str) -> String {
    Url::parse_with_params("https://x", [("v", value)])
        .expect("url")
        .query()
        .expect("query")["v=".len()..]
        .to_owned()
}

fn form(path: &str, fields: &[(&str, &str)]) -> Request<Body> {
    let body = fields
        .iter()
        .map(|(key, value)| format!("{key}={}", encoded(value)))
        .collect::<Vec<_>>()
        .join("&");
    Request::post(path)
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(body))
        .expect("a request")
}

fn between<'a>(text: &'a str, before: &str, after: &str) -> &'a str {
    let start = text
        .find(before)
        .unwrap_or_else(|| panic!("no {before} in {text}"))
        + before.len();
    let end = text[start..].find(after).expect("an end") + start;
    &text[start..end]
}

struct SignIn {
    app: String,
    attempt: String,
    passport: String,
    cookie: String,
}

impl Server {
    async fn call(&self, request: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("a response");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        (
            status,
            headers,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    async fn register(&self) -> String {
        let body = json!({"client_name": "Claude", "redirect_uris": [REDIRECT]});
        let request = Request::post("/oauth/register")
            .header(header::HOST, HOST)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("a request");
        let (status, _, text) = self.call(request).await;
        assert_eq!(status, StatusCode::CREATED, "{text}");
        let answer: Value = serde_json::from_str(&text).expect("json");
        answer["client_id"].as_str().expect("an id").to_owned()
    }

    async fn enter_address(
        &self,
        app: &str,
        address: &str,
        action: &str,
    ) -> (StatusCode, axum::http::HeaderMap, String) {
        let challenge = challenge_of(VERIFIER);
        self.call(form(
            "/oauth/authorize",
            &[
                ("client_id", app),
                ("redirect_uri", REDIRECT),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("state", "s1"),
                ("address", address),
                ("action", action),
            ],
        ))
        .await
    }

    async fn sign_in(&self) -> SignIn {
        let app = self.register().await;
        let moodle = self.moodle.clone();
        let (status, headers, page) = self.enter_address(&app, &moodle, "allow").await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let cookie = headers[header::SET_COOKIE].to_str().expect("text");
        assert!(
            cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax"),
            "{cookie}"
        );
        SignIn {
            app,
            attempt: between(&page, "name=\"attempt\" value=\"", "\"").to_owned(),
            passport: between(&page, "passport=", "&#38;").to_owned(),
            cookie: cookie.split(';').next().expect("a value").to_owned(),
        }
    }

    fn link_for(&self, sign_in: &SignIn) -> String {
        let site = self.moodle.trim_end_matches('/');
        let signature = format!("{:x}", md5_of(&format!("{site}{}", sign_in.passport)));
        let payload = STANDARD.encode(format!("{signature}:::{TOKEN}:::private"));
        format!("web+moodlemcp://token={payload}")
    }

    async fn tokens_from(&self, app: &str, headers: &axum::http::HeaderMap) -> String {
        let back = Url::parse(headers[header::LOCATION].to_str().expect("text")).expect("url");
        assert!(back.as_str().starts_with(REDIRECT), "{back}");
        let pairs: HashMap<_, _> = back.query_pairs().into_owned().collect();
        assert_eq!(pairs["state"], "s1");
        let (status, _, text) = self
            .call(form(
                "/oauth/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("client_id", app),
                    ("code", &pairs["code"]),
                    ("redirect_uri", REDIRECT),
                    ("code_verifier", VERIFIER),
                ],
            ))
            .await;
        assert_eq!(status, StatusCode::OK, "{text}");
        let tokens: Value = serde_json::from_str(&text).expect("json");
        tokens["access_token"].as_str().expect("a token").to_owned()
    }

    async fn connect(&self) -> String {
        let sign_in = self.sign_in().await;
        let link = self.link_for(&sign_in);
        let (status, headers, page) = self
            .call(form(
                "/oauth/moodle/finish",
                &[("attempt", &sign_in.attempt), ("link", &link)],
            ))
            .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{page}");
        self.tokens_from(&sign_in.app, &headers).await
    }

    async fn tool(&self, token: &str, name: &str, arguments: Value) -> Value {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        });
        let request = Request::post("/mcp")
            .header(header::HOST, HOST)
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header(header::CONTENT_TYPE, "application/json")
            .header("mcp-protocol-version", "2025-06-18")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(body.to_string()))
            .expect("a request");
        let (status, _, text) = self.call(request).await;
        assert_eq!(status, StatusCode::OK, "{text}");
        let answer: Value = serde_json::from_str(&text).expect("json");
        answer["result"].clone()
    }
}

fn md5_of(text: &str) -> md5::Digest {
    md5::compute(text)
}

#[tokio::test]
async fn the_address_is_checked_and_any_moodle_can_be_entered() {
    let server = start("address").await;
    let app = server.register().await;

    let path = format!(
        "/oauth/authorize?client_id={app}&redirect_uri={}&code_challenge={}&code_challenge_method=S256",
        encoded(REDIRECT),
        challenge_of(VERIFIER)
    );
    let request = Request::get(path)
        .header(header::HOST, HOST)
        .body(Body::empty())
        .expect("a request");
    let (status, _, page) = server.call(request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("width=device-width"));
    assert!(page.contains("name=\"address\""));
    assert!(page.contains("moodle.example.org"));

    let (status, _, page) = server.enter_address(&app, "", "allow").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains("Enter the Moodle address"), "{page}");

    let elsewhere = format!("{}elsewhere/", server.moodle);
    let (status, _, page) = server.enter_address(&app, &elsewhere, "allow").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains("No Moodle answered"), "{page}");
    assert!(page.contains("elsewhere"), "the address stays filled in");

    let moodle = server.moodle.clone();
    let (status, _, page) = server.enter_address(&app, &moodle, "allow").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("admin/tool/mobile/launch.php"), "{page}");
    assert!(page.contains("confirmed=1"));
    assert!(page.contains("urlscheme=web%2Bmoodlemcp"));
    assert!(page.contains("name=\"link\""), "a phone can paste the link");
}

#[tokio::test]
async fn cancelling_goes_back_to_the_app_without_a_code() {
    let server = start("cancel").await;
    let app = server.register().await;
    let (status, headers, _) = server.enter_address(&app, "", "deny").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let back = headers[header::LOCATION].to_str().expect("text");
    assert!(
        back.contains("error=access_denied") && !back.contains("code="),
        "{back}"
    );
}

#[tokio::test]
async fn the_browser_can_finish_the_sign_in_by_itself() {
    let server = start("automatic").await;
    let sign_in = server.sign_in().await;
    let link = server.link_for(&sign_in);
    let request = Request::get(format!("/oauth/moodle/finish?link={}", encoded(&link)))
        .header(header::HOST, HOST)
        .header(header::COOKIE, &sign_in.cookie)
        .body(Body::empty())
        .expect("a request");
    let (status, headers, page) = server.call(request).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{page}");
    let token = server.tokens_from(&sign_in.app, &headers).await;
    let courses = server.tool(&token, "list_courses", json!({})).await;
    assert_eq!(courses["isError"], false, "{courses}");
}

#[tokio::test]
async fn the_script_loads_under_the_content_rules() {
    let server = start("script").await;
    let request = Request::get("/oauth/moodle/automatic.js")
        .header(header::HOST, HOST)
        .body(Body::empty())
        .expect("a request");
    let (status, headers, script) = server.call(request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(script.contains("registerProtocolHandler"));
    let rules = headers["content-security-policy"].to_str().expect("text");
    assert!(rules.contains("script-src 'self'"), "{rules}");
}

#[tokio::test]
async fn a_key_from_the_preferences_works_too() {
    let server = start("key").await;
    let sign_in = server.sign_in().await;
    let (status, headers, page) = server
        .call(form(
            "/oauth/moodle/finish",
            &[("attempt", &sign_in.attempt), ("link", TOKEN)],
        ))
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{page}");
    server.tokens_from(&sign_in.app, &headers).await;
}

#[tokio::test]
async fn a_wrong_link_stays_on_the_page_and_the_attempt_stays_usable() {
    let server = start("wrong").await;
    let sign_in = server.sign_in().await;

    let finish = |link: String| {
        form(
            "/oauth/moodle/finish",
            &[("attempt", &sign_in.attempt), ("link", &link)],
        )
    };
    for (link, expected) in [
        ("just some words".to_owned(), "not the link from Moodle"),
        ("wrongtoken".to_owned(), "refused this login"),
        (
            format!(
                "web+moodlemcp://token={}",
                STANDARD.encode(format!("badsignature:::{TOKEN}"))
            ),
            "another sign-in",
        ),
    ] {
        let (status, _, page) = server.call(finish(link)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{page}");
        assert!(page.contains(expected), "{expected}: {page}");
        assert!(page.contains("Sign in to Moodle"));
    }
    let (status, _, _) = server.call(finish(server.link_for(&sign_in))).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (status, _, page) = server.call(finish(server.link_for(&sign_in))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "an attempt works once");
    assert!(page.contains("expired"), "{page}");
}

#[tokio::test]
async fn a_form_from_another_site_is_refused() {
    let server = start("other-site").await;
    let mut request = form("/oauth/moodle/finish", &[("attempt", "x"), ("link", "y")]);
    request
        .headers_mut()
        .insert("sec-fetch-site", "cross-site".parse().expect("a header"));
    assert_eq!(server.call(request).await.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_connected_app_reads_courses_files_and_assignments() {
    let server = start("read").await;
    let token = server.connect().await;

    let courses = server.tool(&token, "list_courses", json!({})).await;
    assert_eq!(courses["isError"], false, "{courses}");
    let course = &courses["structuredContent"]["courses"][0];
    assert_eq!(course["id"], 7);
    assert_eq!(course["name"], "Mechanics I");

    let tasks = server
        .tool(&token, "list_assignments", json!({"course_id": 7}))
        .await;
    assert_eq!(tasks["isError"], false, "{tasks}");
    let list = &tasks["structuredContent"]["assignments"];
    assert_eq!(list[0]["due_at"], "2025-10-09T08:53:20+00:00");
    assert!(list[1].get("due_at").is_none());

    let files = server
        .tool(&token, "list_course_files", json!({"course_id": 7}))
        .await;
    assert_eq!(files["isError"], false, "{files}");
    assert_eq!(files["structuredContent"]["files"][0]["name"], "sheet1.md");
    assert_eq!(
        files["structuredContent"]["files"].as_array().map(Vec::len),
        Some(1)
    );

    let file_ref = format!("{}webservice/pluginfile.php/1/sheet1.md", server.moodle);
    let read = server
        .tool(&token, "read_course_file", json!({"file_ref": file_ref}))
        .await;
    assert_eq!(read["isError"], false, "{read}");
    let text: Value =
        serde_json::from_str(read["content"][0]["text"].as_str().expect("text")).expect("json");
    assert_eq!(text["file"]["text"], "# Sheet 1");
    assert!(
        text["notice"]
            .as_str()
            .expect("a notice")
            .contains("Untrusted")
    );
}

#[tokio::test]
async fn the_token_never_goes_to_another_host() {
    let server = start("host").await;
    let token = server.connect().await;
    let read = server
        .tool(
            &token,
            "read_course_file",
            json!({"file_ref": "https://evil.example/webservice/pluginfile.php/1/a"}),
        )
        .await;
    assert_eq!(read["isError"], true, "{read}");
}

#[tokio::test]
async fn the_login_is_not_stored_readable_and_the_tools_are_read_only() {
    let server = start("stored").await;
    let token = server.connect().await;
    let mut stored = Vec::new();
    for file in fs::read_dir(&server.folder).expect("a folder") {
        stored.extend(fs::read(file.expect("a file").path()).expect("content"));
    }
    assert!(!String::from_utf8_lossy(&stored).contains(TOKEN));

    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let request = Request::post("/mcp")
        .header(header::HOST, HOST)
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header(header::CONTENT_TYPE, "application/json")
        .header("mcp-protocol-version", "2025-06-18")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .expect("a request");
    let (_, _, text) = server.call(request).await;
    let listed: Value = serde_json::from_str(&text).expect("json");
    let tools = listed["result"]["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), 4);
    for tool in tools {
        assert_eq!(tool["annotations"]["readOnlyHint"], true, "{tool}");
    }
}

//! A read-only client for Moodle's web service, and its mobile-app sign-in:
//! the browser opens Moodle's launch page, the person signs in there, and Moodle
//! hands back `<scheme>://token=...`. Nothing here is about one Moodle.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::DateTime;
use reqwest::{Response, Url};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::documents::{self, Document, Request};
use crate::error::{MoodleError, Result};

const REST_PATH: &str = "webservice/rest/server.php";
const FILE_PATH: &str = "webservice/pluginfile.php/";
const LAUNCH_PATH: &str = "admin/tool/mobile/launch.php";
const MAX_ANSWER_BYTES: usize = 20 * 1024 * 1024;
const ANNOUNCEMENTS_PER_FORUM: u32 = 10;
const REJECTED: &str = "Moodle refused this login, which has probably expired. Connect it again \
    in the LLM client.";
const NOT_MOODLE: &str = "No Moodle answered at this address. Check the address.";
const BAD_LINK: &str = "That is not the link from Moodle. Copy the whole link Moodle shows after \
    signing in, and paste it here.";
const OTHER_ATTEMPT: &str = "This link belongs to another sign-in. Sign in again.";

/// What is stored, encrypted, for one connection. Not `Debug`, so the token
/// cannot end up in a log.
#[derive(Serialize, Deserialize)]
pub struct Login {
    pub moodle: String,
    pub token: String,
}

impl Login {
    pub fn to_secret(&self) -> String {
        serde_json::to_string(self).expect("a login can be written as JSON")
    }

    pub fn from_secret(secret: &str) -> Result<Self> {
        serde_json::from_str(secret).map_err(|_| MoodleError::new("a stored login is damaged"))
    }
}

/// The page where the sign-in starts. `confirmed` makes Moodle show the link as
/// well, because not every browser can follow it by itself.
pub fn launch_url(moodle: &Url, passport: &str, scheme: &str) -> Result<Url> {
    let mut url = moodle
        .join(LAUNCH_PATH)
        .map_err(|_| MoodleError::new(NOT_MOODLE))?;
    url.query_pairs_mut()
        .append_pair("service", "moodle_mobile_app")
        .append_pair("passport", passport)
        .append_pair("urlscheme", scheme)
        .append_pair("confirmed", "1");
    Ok(url)
}

fn signature_for(moodle: &Url, passport: &str) -> String {
    let site = moodle.as_str().trim_end_matches('/');
    format!("{:x}", md5::compute(format!("{site}{passport}")))
}

/// The token in what someone pasted: the link from the sign-in, whose scheme a
/// site may have changed, or a key from their Moodle preferences. The payload
/// of a link is base64 of `<signature>:::<token>[:::<private token>]`, and the
/// signature ties it to one sign-in.
pub fn token_from(pasted: &str, moodle: &Url, passport: &str) -> Result<String> {
    let pasted = pasted.trim();
    let is_token = |text: &str| !text.is_empty() && text.chars().all(|c| c.is_ascii_alphanumeric());
    let Some((_, payload)) = pasted.split_once("://token=") else {
        return if is_token(pasted) {
            Ok(pasted.to_owned())
        } else {
            Err(MoodleError::new(BAD_LINK))
        };
    };
    let decoded = STANDARD
        .decode(payload.trim_end_matches('/'))
        .map_err(|_| MoodleError::new(BAD_LINK))?;
    let decoded = String::from_utf8(decoded).map_err(|_| MoodleError::new(BAD_LINK))?;
    let mut parts = decoded.split(":::");
    let signature = parts.next().unwrap_or_default();
    let token = parts.next().ok_or_else(|| MoodleError::new(BAD_LINK))?;
    if !signature.eq_ignore_ascii_case(&signature_for(moodle, passport)) {
        return Err(MoodleError::new(OTHER_ATTEMPT));
    }
    if !is_token(token) {
        return Err(MoodleError::new(BAD_LINK));
    }
    Ok(token.to_owned())
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Course {
    pub id: u64,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CourseFile {
    pub section: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Pass this to read_course_file.
    pub file_ref: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Assignment {
    pub id: u64,
    pub course_id: u64,
    pub name: String,
    /// In UTC. Missing when there is no deadline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_at: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Announcement {
    pub course_id: u64,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// In UTC.
    pub posted_at: String,
    pub text: String,
}

mod wire {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct Forum {
        pub id: u64,
        pub course: u64,
        #[serde(rename = "type")]
        pub kind: String,
    }

    #[derive(Deserialize)]
    pub struct Discussions {
        #[serde(default)]
        pub discussions: Vec<Discussion>,
    }

    #[derive(Deserialize)]
    pub struct Discussion {
        pub subject: String,
        #[serde(default)]
        pub message: String,
        pub created: i64,
        pub userfullname: Option<String>,
    }

    #[derive(Deserialize)]
    pub struct SiteInfo {
        pub userid: u64,
    }

    #[derive(Deserialize)]
    pub struct Course {
        pub id: u64,
        pub fullname: String,
        pub shortname: Option<String>,
    }

    #[derive(Deserialize)]
    pub struct Section {
        pub name: String,
        #[serde(default)]
        pub modules: Vec<Module>,
    }

    #[derive(Deserialize)]
    pub struct Module {
        #[serde(default)]
        pub contents: Vec<Content>,
    }

    #[derive(Deserialize)]
    pub struct Content {
        #[serde(rename = "type")]
        pub kind: String,
        pub filename: String,
        pub filesize: Option<u64>,
        pub fileurl: Option<String>,
        pub mimetype: Option<String>,
    }

    #[derive(Deserialize)]
    pub struct Assignments {
        #[serde(default)]
        pub courses: Vec<AssignmentCourse>,
    }

    #[derive(Deserialize)]
    pub struct AssignmentCourse {
        pub id: u64,
        #[serde(default)]
        pub assignments: Vec<Assignment>,
    }

    #[derive(Deserialize)]
    pub struct Assignment {
        pub id: u64,
        pub name: String,
        #[serde(default)]
        pub duedate: i64,
    }

    /// Moodle reports errors with status 200 and this body.
    #[derive(Deserialize)]
    pub struct Exception {
        pub errorcode: String,
        pub message: Option<String>,
    }
}

/// How a call to Moodle went wrong, so that signing in can tell a Moodle that
/// refuses a token from something that is no Moodle at all.
enum Failure {
    Refused,
    Other(MoodleError),
}

fn network(error: reqwest::Error) -> MoodleError {
    // File URLs carry the token, so the URL is dropped from the message.
    MoodleError::new(format!(
        "Moodle could not be reached: {}",
        error.without_url()
    ))
}

fn decode<T: DeserializeOwned>(body: &[u8]) -> std::result::Result<T, Failure> {
    if let Ok(exception) = serde_json::from_slice::<wire::Exception>(body) {
        return Err(match exception.errorcode.as_str() {
            "invalidtoken" | "accessexception" => Failure::Refused,
            code => Failure::Other(MoodleError::new(format!(
                "Moodle answered with an error: {code}: {}",
                exception.message.unwrap_or_default()
            ))),
        });
    }
    serde_json::from_slice(body).map_err(|_| Failure::Other(MoodleError::new(NOT_MOODLE)))
}

fn course_files(sections: Vec<wire::Section>) -> Vec<CourseFile> {
    let mut files = Vec::new();
    for section in sections {
        for content in section.modules.into_iter().flat_map(|m| m.contents) {
            let (true, Some(file_ref)) = (content.kind == "file", content.fileurl) else {
                continue;
            };
            files.push(CourseFile {
                section: section.name.clone(),
                name: content.filename,
                size: content.filesize,
                mime_type: content.mimetype,
                file_ref,
            });
        }
    }
    files
}

fn assignments(result: wire::Assignments) -> Vec<Assignment> {
    let mut all = Vec::new();
    for course in result.courses {
        for assignment in course.assignments {
            all.push(Assignment {
                id: assignment.id,
                course_id: course.id,
                name: assignment.name,
                // Moodle uses 0 for "no deadline".
                due_at: (assignment.duedate > 0)
                    .then(|| DateTime::from_timestamp(assignment.duedate, 0))
                    .flatten()
                    .map(|time| time.to_rfc3339()),
            });
        }
    }
    all
}

/// Forum posts arrive as HTML. Block ends become line breaks, other tags go.
fn plain_text(html: &str) -> String {
    let mut text = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(start) = rest.find('<') {
        text.push_str(&rest[..start]);
        let Some(end) = rest[start..].find('>') else {
            rest = &rest[start..];
            break;
        };
        let tag = rest[start + 1..start + end].to_ascii_lowercase();
        let name = tag.trim_start_matches('/').split([' ', '/']).next();
        if matches!(
            name,
            Some("br" | "p" | "div" | "li" | "tr" | "h1" | "h2" | "h3" | "h4")
        ) {
            text.push('\n');
        }
        rest = &rest[start + end + 1..];
    }
    text.push_str(rest);
    let text = text
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&");
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    lines
        .split(|line| line.is_empty())
        .filter(|block| !block.is_empty())
        .map(|block| block.join("\n"))
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn announcements(course_id: u64, discussions: wire::Discussions, since: i64) -> Vec<Announcement> {
    discussions
        .discussions
        .into_iter()
        .filter(|discussion| discussion.created >= since)
        .filter_map(|discussion| {
            Some(Announcement {
                course_id,
                subject: discussion.subject,
                author: discussion.userfullname,
                posted_at: DateTime::from_timestamp(discussion.created, 0)?.to_rfc3339(),
                text: plain_text(&discussion.message),
            })
        })
        .collect()
}

pub struct MoodleClient {
    http: reqwest::Client,
    moodle: Url,
    token: String,
}

impl MoodleClient {
    pub fn new(http: reqwest::Client, moodle: Url, token: String) -> Self {
        Self {
            http,
            moodle,
            token,
        }
    }

    async fn body_of(mut response: Response, limit: usize) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(network)? {
            if body.len() + chunk.len() > limit {
                return Err(MoodleError::new(format!(
                    "This is larger than {} MB.",
                    limit / (1024 * 1024)
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    async fn ask<T: DeserializeOwned>(
        &self,
        function: &str,
        args: &[(String, String)],
    ) -> std::result::Result<T, Failure> {
        let endpoint = self
            .moodle
            .join(REST_PATH)
            .map_err(|_| Failure::Other(MoodleError::new(NOT_MOODLE)))?;
        let mut form: Vec<(String, String)> = vec![
            ("wstoken".into(), self.token.clone()),
            ("wsfunction".into(), function.into()),
            ("moodlewsrestformat".into(), "json".into()),
            // Without the text filters, names come back in every language at once.
            ("moodlewssettingfilter".into(), "true".into()),
        ];
        form.extend_from_slice(args);
        let response = self
            .http
            .post(endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|error| Failure::Other(network(error)))?;
        if !response.status().is_success() {
            return Err(Failure::Other(MoodleError::new(NOT_MOODLE)));
        }
        let body = Self::body_of(response, MAX_ANSWER_BYTES)
            .await
            .map_err(Failure::Other)?;
        decode(&body)
    }

    async fn call<T: DeserializeOwned>(
        &self,
        function: &str,
        args: &[(String, String)],
    ) -> Result<T> {
        self.ask(function, args)
            .await
            .map_err(|failure| match failure {
                Failure::Refused => MoodleError::new(REJECTED),
                Failure::Other(error) => error,
            })
    }

    /// A Moodle refuses a made-up token in a way nothing else does, which
    /// proves a Moodle is there without anyone being signed in.
    pub async fn check_is_moodle(&self) -> Result<()> {
        match self
            .ask::<wire::SiteInfo>("core_webservice_get_site_info", &[])
            .await
        {
            Ok(_) | Err(Failure::Refused) => Ok(()),
            Err(Failure::Other(error)) => Err(error),
        }
    }

    pub async fn check_token(&self) -> Result<()> {
        self.call::<wire::SiteInfo>("core_webservice_get_site_info", &[])
            .await
            .map(drop)
    }

    pub async fn courses(&self) -> Result<Vec<Course>> {
        let site: wire::SiteInfo = self.call("core_webservice_get_site_info", &[]).await?;
        let courses: Vec<wire::Course> = self
            .call(
                "core_enrol_get_users_courses",
                &[("userid".into(), site.userid.to_string())],
            )
            .await?;
        Ok(courses
            .into_iter()
            .map(|course| Course {
                id: course.id,
                name: course.fullname,
                short_name: course.shortname,
            })
            .collect())
    }

    pub async fn course_files(&self, course_id: u64) -> Result<Vec<CourseFile>> {
        let sections: Vec<wire::Section> = self
            .call(
                "core_course_get_contents",
                &[("courseid".into(), course_id.to_string())],
            )
            .await?;
        Ok(course_files(sections))
    }

    pub async fn assignments(&self, course_id: Option<u64>) -> Result<Vec<Assignment>> {
        let args = match course_id {
            Some(id) => vec![("courseids[0]".to_owned(), id.to_string())],
            None => Vec::new(),
        };
        let result: wire::Assignments = self.call("mod_assign_get_assignments", &args).await?;
        Ok(assignments(result))
    }

    /// Posts in the announcement forums ("news" in Moodle) since a Unix time,
    /// newest first. Without a course, Moodle returns the forums of all courses.
    pub async fn announcements(
        &self,
        course_id: Option<u64>,
        since: i64,
    ) -> Result<Vec<Announcement>> {
        let args = match course_id {
            Some(id) => vec![("courseids[0]".to_owned(), id.to_string())],
            None => Vec::new(),
        };
        let forums: Vec<wire::Forum> = self.call("mod_forum_get_forums_by_courses", &args).await?;
        let mut all = Vec::new();
        for forum in forums.into_iter().filter(|forum| forum.kind == "news") {
            let discussions: wire::Discussions = self
                .call(
                    "mod_forum_get_forum_discussions",
                    &[
                        ("forumid".into(), forum.id.to_string()),
                        ("page".into(), "0".into()),
                        ("perpage".into(), ANNOUNCEMENTS_PER_FORUM.to_string()),
                    ],
                )
                .await?;
            all.extend(announcements(forum.course, discussions, since));
        }
        all.sort_by(|a, b| b.posted_at.cmp(&a.posted_at));
        Ok(all)
    }

    /// The token is appended to this URL, so it has to be on this Moodle.
    fn checked_file_url(&self, file_ref: &str) -> Result<Url> {
        let not_from_moodle = || MoodleError::new("file_ref is not a file from list_course_files.");
        let url = Url::parse(file_ref).map_err(|_| not_from_moodle())?;
        let files = self.moodle.join(FILE_PATH).map_err(|_| not_from_moodle())?;
        if url.origin() != self.moodle.origin()
            || !url.path().starts_with(files.path())
            || url.path().contains("/../")
        {
            return Err(not_from_moodle());
        }
        Ok(url)
    }

    pub async fn read_file(
        &self,
        file_ref: &str,
        pages: Option<String>,
        view: documents::View,
        entry: Option<String>,
    ) -> Result<Document> {
        let mut url = self.checked_file_url(file_ref)?;
        url.query_pairs_mut().append_pair("token", &self.token);
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(network)?
            .error_for_status()
            .map_err(network)?;
        documents::check_size(response.content_length().unwrap_or(0))?;
        let bytes = Self::body_of(response, documents::MAX_FILE_BYTES).await?;
        // Reading a large PDF takes a while, so it runs off the request threads.
        tokio::task::spawn_blocking(move || {
            documents::read(
                &bytes,
                Request {
                    pages: pages.as_deref(),
                    view,
                    entry: entry.as_deref(),
                },
            )
        })
        .await
        .map_err(|_| MoodleError::new("This file could not be read."))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOODLE: &str = "https://moodle.example.org/";

    fn moodle() -> Url {
        Url::parse(MOODLE).expect("a URL")
    }

    fn client() -> MoodleClient {
        MoodleClient::new(reqwest::Client::new(), moodle(), "t0ken".into())
    }

    fn link(inner: &str) -> String {
        format!("web+moodlemcp://token={}", STANDARD.encode(inner))
    }

    #[test]
    fn the_launch_page_shows_the_link_and_names_the_scheme() {
        let url = launch_url(&moodle(), "p1", "web+moodlemcp").expect("a URL");
        assert_eq!(url.path(), "/admin/tool/mobile/launch.php");
        let query = url.query().expect("a query");
        assert!(query.contains("confirmed=1"), "{query}");
        assert!(query.contains("urlscheme=web%2Bmoodlemcp"), "{query}");
    }

    #[test]
    fn a_link_gives_its_token_only_for_its_own_sign_in() {
        let signed = |rest: &str| link(&format!("{}:::{rest}", signature_for(&moodle(), "p1")));
        let token = |text: &str| token_from(text, &moodle(), "p1");
        assert_eq!(
            token(&signed("abc123:::private")).expect("a token"),
            "abc123"
        );
        assert_eq!(token(&signed("abc123")).expect("a token"), "abc123");
        assert_eq!(
            token(&format!("{}/", signed("abc123"))).expect("a token"),
            "abc123"
        );
        let forced = signed("abc123").replace("web+moodlemcp", "moodlemobile");
        assert_eq!(token(&forced).expect("a token"), "abc123");

        let other = token_from(&signed("abc123"), &moodle(), "another").expect_err("refused");
        assert!(other.to_string().contains("another sign-in"));
        let other_site = Url::parse("https://other.example.org/").expect("a URL");
        assert!(token_from(&signed("abc123"), &other_site, "p1").is_err());
    }

    #[test]
    fn a_key_from_the_preferences_works_and_other_text_does_not() {
        let token = |text: &str| token_from(text, &moodle(), "p1");
        assert_eq!(token(" abc123 ").expect("a token"), "abc123");
        for refused in [
            "",
            "not a token",
            "https://moodle.example.org/",
            "web+moodlemcp://token=%%%",
            &link("no separator"),
            &link(&format!("{}:::bad token", signature_for(&moodle(), "p1"))),
        ] {
            assert!(token(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn the_token_is_never_sent_to_another_host() {
        let client = client();
        let file = "https://moodle.example.org/webservice/pluginfile.php/1/a.pdf";
        assert!(client.checked_file_url(file).is_ok());
        for refused in [
            "https://evil.example/webservice/pluginfile.php/1/a.pdf",
            "http://moodle.example.org/webservice/pluginfile.php/1/a.pdf",
            "https://moodle.example.org/login/index.php",
            "not a url",
        ] {
            assert!(client.checked_file_url(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn a_moodle_in_a_subfolder_keeps_its_files_there() {
        let moodle = Url::parse("https://uni.example.org/moodle/").expect("a URL");
        let client = MoodleClient::new(reqwest::Client::new(), moodle, "t0ken".into());
        assert!(
            client
                .checked_file_url("https://uni.example.org/moodle/webservice/pluginfile.php/1/a")
                .is_ok()
        );
        assert!(
            client
                .checked_file_url("https://uni.example.org/webservice/pluginfile.php/1/a")
                .is_err()
        );
    }

    #[test]
    fn an_invalid_token_is_told_apart_from_other_answers() {
        let refused =
            br#"{"exception":"moodle_exception","errorcode":"invalidtoken","message":"x"}"#;
        assert!(matches!(
            decode::<wire::SiteInfo>(refused),
            Err(Failure::Refused)
        ));
        assert!(matches!(
            decode::<wire::SiteInfo>(b"<html>"),
            Err(Failure::Other(_))
        ));
    }

    #[test]
    fn course_contents_are_flattened_to_files() {
        let body = br#"[{"name":"Week 1","modules":[
            {"contents":[{"type":"file","filename":"slides.pdf","filesize":10,
              "fileurl":"https://moodle.example.org/webservice/pluginfile.php/1/slides.pdf","mimetype":"application/pdf"},
             {"type":"url","filename":"link"}]},
            {}]}]"#;
        let sections = decode(body).map_err(|_| "not decoded").expect("sections");
        let files = course_files(sections);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].section, "Week 1");
        assert_eq!(files[0].name, "slides.pdf");
    }

    #[test]
    fn a_zero_due_date_means_no_deadline() {
        let body = br#"{"courses":[{"id":7,"assignments":[
            {"id":1,"name":"Sheet 1","duedate":1760000000},{"id":2,"name":"Bonus","duedate":0}]}]}"#;
        let list = assignments(
            decode(body)
                .map_err(|_| "not decoded")
                .expect("assignments"),
        );
        assert_eq!(list[0].due_at.as_deref(), Some("2025-10-09T08:53:20+00:00"));
        assert_eq!(list[1].due_at, None);
        assert_eq!(list[1].course_id, 7);
    }

    #[test]
    fn forum_html_becomes_plain_text() {
        assert_eq!(
            plain_text("<p>Tutorial moved to <b>H01</b>.</p><p>Q&amp;A on Friday</p>"),
            "Tutorial moved to H01.\n\nQ&A on Friday"
        );
        assert_eq!(plain_text("line one<br/>line two"), "line one\nline two");
        assert_eq!(plain_text("a &lt; b &nbsp;"), "a < b");
        assert_eq!(plain_text("broken <tag"), "broken <tag");
    }

    #[test]
    fn only_announcements_since_the_given_time_are_kept() {
        let body = br#"{"discussions":[
            {"subject":"Exam date","message":"<p>On 12 Feb</p>","created":1760000000,"userfullname":"Prof. A"},
            {"subject":"Welcome","message":"","created":1700000000}],"warnings":[]}"#;
        let list = announcements(
            7,
            decode(body)
                .map_err(|_| "not decoded")
                .expect("discussions"),
            1750000000,
        );
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].subject, "Exam date");
        assert_eq!(list[0].text, "On 12 Feb");
        assert_eq!(list[0].course_id, 7);
        assert_eq!(list[0].posted_at, "2025-10-09T08:53:20+00:00");
    }

    #[test]
    fn a_login_survives_being_stored() {
        let login = Login {
            moodle: MOODLE.into(),
            token: "t0ken".into(),
        };
        let stored = Login::from_secret(&login.to_secret()).expect("a login");
        assert_eq!(stored.token, "t0ken");
        assert!(Login::from_secret("damaged").is_err());
    }
}

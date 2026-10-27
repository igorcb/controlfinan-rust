//! Rails-like request pipeline and helpers: signed cookies, session, CSRF, "_method", flash and rate limit.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use chrono_tz::Tz;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use sqlx::PgPool;
use subtle::ConstantTimeEq;

use crate::models::{self, User};

pub const SESSION_COOKIE: &str = "session_id";
pub const CSRF_COOKIE: &str = "_csrf_token";
pub const FLASH_COOKIE: &str = "_flash";
pub const RETURN_TO_COOKIE: &str = "return_to";
const PERMANENT: i64 = 20 * 365 * 24 * 60 * 60; // cookies.permanent

/// Sends the password reset e-mail. The default one writes it to the log; tests keep the messages.
pub trait Mailer: Send + Sync {
    fn send(&self, to: &str, subject: &str, text: &str);
}

pub struct LogMailer;

impl Mailer for LogMailer {
    fn send(&self, to: &str, subject: &str, text: &str) {
        println!("mail to={to} subject={subject:?}\n{text}");
    }
}

pub struct AppState {
    pub db: PgPool,
    secret: Vec<u8>,
    pub bcrypt_cost: u32,
    pub zone: Tz,
    pub mailer: Arc<dyn Mailer>,
    /// A fixed time for the tests; None means the real clock.
    pub frozen_now: Mutex<Option<DateTime<Utc>>>,
    rate_limits: Mutex<HashMap<String, (u32, DateTime<Utc>)>>,
    /// Checked when the e-mail does not exist, so both cases take the same time.
    pub dummy_digest: String,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub fn new(
        db: PgPool,
        secret: &str,
        bcrypt_cost: u32,
        zone: Tz,
        mailer: Arc<dyn Mailer>,
    ) -> Self {
        AppState {
            db,
            secret: secret.as_bytes().to_vec(),
            bcrypt_cost,
            zone,
            mailer,
            frozen_now: Mutex::new(None),
            rate_limits: Mutex::new(HashMap::new()),
            dummy_digest: models::hash_password("dummy-password", bcrypt_cost),
        }
    }

    pub fn now(&self) -> DateTime<Utc> {
        self.frozen_now.lock().unwrap().unwrap_or_else(Utc::now)
    }

    pub fn today(&self) -> NaiveDate {
        self.now().with_timezone(&self.zone).date_naive()
    }

    pub fn clear_rate_limits(&self) {
        self.rate_limits.lock().unwrap().clear();
    }

    fn hmac(&self, data: &str) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).expect("hmac key");
        mac.update(data.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// "value--signature", like a signed cookie.
    pub fn sign(&self, purpose: &str, value: &str) -> String {
        format!(
            "{}--{}",
            B64.encode(value),
            B64.encode(self.hmac(&format!("{purpose}:{value}")))
        )
    }

    pub fn verify(&self, purpose: &str, signed: &str) -> Option<String> {
        let (encoded, _) = signed.split_once("--")?;
        let value = String::from_utf8(B64.decode(encoded).ok()?).ok()?;
        bool::from(
            self.sign(purpose, &value)
                .as_bytes()
                .ct_eq(signed.as_bytes()),
        )
        .then_some(value)
    }

    /// Like Rails `rate_limit to: 10, within: 3.minutes`: a counter per action and IP.
    pub fn allow(&self, key: &str, to: u32, within: Duration) -> bool {
        let now = self.now();
        let mut limits = self.rate_limits.lock().unwrap();
        let entry = limits.entry(key.to_string()).or_insert((0, now + within));
        if now > entry.1 {
            *entry = (0, now + within);
        }
        entry.0 += 1;
        entry.0 <= to
    }

    /// Password reset token: signed, expires in 15 minutes and stops working once the password changes.
    pub fn password_reset_token(&self, user: &User) -> String {
        let digest = &user.password_digest;
        let payload = format!(
            "{}:{}:{}",
            user.id,
            &digest[digest.len() - 10..],
            (self.now() + Duration::minutes(15)).timestamp()
        );
        format!(
            "{}.{}",
            B64.encode(&payload),
            B64.encode(self.hmac(&format!("password_reset:{payload}")))
        )
    }

    pub async fn find_by_password_reset_token(&self, token: &str) -> Option<User> {
        let (encoded, signature) = token.split_once('.')?;
        let payload = String::from_utf8(B64.decode(encoded).ok()?).ok()?;
        let expected = B64.encode(self.hmac(&format!("password_reset:{payload}")));
        if !bool::from(expected.as_bytes().ct_eq(signature.as_bytes())) {
            return None;
        }
        let parts: Vec<&str> = payload.split(':').collect();
        let [id, version, expires] = parts.as_slice() else {
            return None;
        };
        if self.now().timestamp() > expires.parse::<i64>().ok()? {
            return None;
        }
        let user = models::find_user(&self.db, id.parse().ok()?).await.ok()??;
        let digest = &user.password_digest;
        (&digest[digest.len() - 10..] == *version).then_some(user)
    }
}

// Cookies

pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_string())
}

pub fn set_cookie(name: &str, value: &str, max_age: Option<i64>) -> String {
    let age = max_age
        .map(|age| format!("; Max-Age={age}"))
        .unwrap_or_default();
    format!("{name}={value}; Path=/{age}; HttpOnly; SameSite=Lax")
}

pub fn delete_cookie(name: &str) -> String {
    set_cookie(name, "", Some(0))
}

/// What the request pipeline found: the current user, its session and the parsed form.
#[derive(Clone, Default)]
pub struct Ctx {
    pub user: Option<User>,
    pub session_id: Option<i64>,
    pub form: Vec<(String, String)>,
    pub host: String,
    pub ip: String,
    pub user_agent: String,
    pub cookies: HeaderMap,
}

impl Ctx {
    pub fn field(&self, name: &str) -> String {
        self.form
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    }

    pub fn has_field(&self, name: &str) -> bool {
        self.form.iter().any(|(key, _)| key == name)
    }

    pub fn absolute_url(&self, path: &str) -> String {
        format!("http://{}{}", self.host, path)
    }

    pub fn user(&self) -> &User {
        self.user.as_ref().expect("signed in")
    }
}

const PUBLIC: [&str; 9] = [
    "/session/new",
    "/session",
    "/registration/new",
    "/registration",
    "/passwords/new",
    "/passwords",
    "/up",
    "/search_account",
    "/icon.png",
];

fn is_public(path: &str) -> bool {
    PUBLIC.contains(&path)
        || path == "/icon.svg"
        || path.starts_with("/passwords/")
        || path.starts_with("/css/")
        || path.starts_with("/js/")
}

/// Runs before the router: parses POST forms, checks the CSRF token, applies "_method",
/// loads the session and sends guests to the login (Rails' require_authentication).
pub async fn pipeline(State(state): State<SharedState>, request: Request, next: Next) -> Response {
    let (mut parts, body) = request.into_parts();
    let mut ctx = Ctx {
        host: parts
            .headers
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost")
            .to_string(),
        user_agent: parts
            .headers
            .get(header::USER_AGENT)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .chars()
            .take(255)
            .collect(),
        ip: parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip().to_string())
            .unwrap_or_default(),
        cookies: parts.headers.clone(),
        ..Ctx::default()
    };
    let mut body = body;
    if parts.method == Method::POST {
        let Ok(bytes) = to_bytes(body, 1 << 20).await else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        ctx.form = form_urlencoded::parse(&bytes).into_owned().collect();
        let token = cookie(&parts.headers, CSRF_COOKIE).unwrap_or_default();
        if token.is_empty()
            || !bool::from(
                token
                    .as_bytes()
                    .ct_eq(ctx.field("authenticity_token").as_bytes()),
            )
        {
            return StatusCode::UNPROCESSABLE_ENTITY.into_response();
        }
        match ctx.field("_method").to_ascii_uppercase().as_str() {
            "DELETE" => parts.method = Method::DELETE,
            "PATCH" => parts.method = Method::PATCH,
            "PUT" => parts.method = Method::PUT,
            _ => {}
        }
        body = Body::from(bytes);
    }
    if let Some(session_id) = cookie(&parts.headers, SESSION_COOKIE)
        .and_then(|v| state.verify(SESSION_COOKIE, &v))
        .and_then(|v| v.parse().ok())
        && let Ok(Some(user)) = models::find_user_by_session(&state.db, session_id).await
    {
        ctx.user = Some(user);
        ctx.session_id = Some(session_id);
    }
    let path = parts.uri.path().to_string();
    let signing_out = path == "/session" && parts.method == Method::DELETE;
    if ctx.user.is_none() && (signing_out || !is_public(&path)) {
        let return_to = ctx.absolute_url(
            parts
                .uri
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/"),
        );
        return Reply::redirect("/session/new", StatusCode::FOUND)
            .cookie(set_cookie(
                RETURN_TO_COOKIE,
                &state.sign(RETURN_TO_COOKIE, &return_to),
                None,
            ))
            .into_response();
    }
    parts.extensions.insert(ctx);
    next.run(Request::from_parts(parts, body)).await
}

/// A response with any number of Set-Cookie headers.
pub struct Reply {
    status: StatusCode,
    headers: Vec<(header::HeaderName, String)>,
    body: String,
}

impl Reply {
    pub fn html(status: StatusCode, body: String) -> Self {
        Reply {
            status,
            headers: vec![(header::CONTENT_TYPE, "text/html; charset=utf-8".into())],
            body,
        }
    }

    pub fn json(body: String) -> Self {
        Reply {
            status: StatusCode::OK,
            headers: vec![(
                header::CONTENT_TYPE,
                "application/json; charset=utf-8".into(),
            )],
            body,
        }
    }

    pub fn redirect(location: &str, status: StatusCode) -> Self {
        Reply {
            status,
            headers: vec![(header::LOCATION, location.into())],
            body: String::new(),
        }
    }

    pub fn not_found() -> Self {
        Reply::html(StatusCode::NOT_FOUND, "Not Found".into())
    }

    pub fn cookie(mut self, value: String) -> Self {
        self.headers.push((header::SET_COOKIE, value));
        self
    }

    /// Redirect with a flash message ("notice" or "alert") that survives one request, like Rails' flash.
    pub fn redirect_with(
        state: &AppState,
        location: &str,
        status: StatusCode,
        kind: &str,
        message: &str,
    ) -> Self {
        Reply::redirect(location, status).cookie(set_cookie(
            FLASH_COOKIE,
            &state.sign(FLASH_COOKIE, &format!("{kind}:{message}")),
            None,
        ))
    }
}

impl IntoResponse for Reply {
    fn into_response(self) -> Response {
        let mut response = (self.status, self.body).into_response();
        for (name, value) in self.headers {
            if let Ok(value) = HeaderValue::from_str(&value) {
                response.headers_mut().append(name, value);
            }
        }
        response
    }
}

/// What every page needs: current user, flash messages and the CSRF token (plus the cookies to set).
pub struct PageInfo {
    pub user_email: Option<String>,
    pub notice: String,
    pub alert: String,
    pub csrf: String,
    pub nav: &'static str,
    pub set_cookies: Vec<String>,
}

impl PageInfo {
    pub fn new(state: &AppState, ctx: &Ctx, nav: &'static str) -> Self {
        let mut set_cookies = Vec::new();
        let (mut notice, mut alert) = (String::new(), String::new());
        if let Some(flash) =
            cookie(&ctx.cookies, FLASH_COOKIE).and_then(|v| state.verify(FLASH_COOKIE, &v))
        {
            set_cookies.push(delete_cookie(FLASH_COOKIE));
            match flash.split_once(':') {
                Some(("notice", message)) => notice = message.to_string(),
                Some(("alert", message)) => alert = message.to_string(),
                _ => {}
            }
        }
        let csrf = match cookie(&ctx.cookies, CSRF_COOKIE).filter(|token| !token.is_empty()) {
            Some(token) => token,
            None => {
                let mut bytes = [0u8; 32];
                rand::rng().fill_bytes(&mut bytes);
                let token = B64.encode(bytes);
                set_cookies.push(set_cookie(CSRF_COOKIE, &token, None));
                token
            }
        };
        PageInfo {
            user_email: ctx.user.as_ref().map(|u| u.email_address.clone()),
            notice,
            alert,
            csrf,
            nav,
            set_cookies,
        }
    }

    pub fn main_class(&self) -> &'static str {
        if self.user_email.is_some() {
            "mx-auto max-w-5xl px-4 py-6 pb-28 sm:pb-6"
        } else {
            "mx-auto max-w-5xl px-4 py-6 "
        }
    }
}

/// Renders an Askama template with the page's cookies.
pub fn render<T: askama::Template>(status: StatusCode, page: &PageInfo, template: &T) -> Reply {
    match template.render() {
        Ok(html) => page
            .set_cookies
            .iter()
            .fold(Reply::html(status, html), |reply, c| {
                reply.cookie(c.clone())
            }),
        Err(error) => {
            eprintln!("template error: {error}");
            Reply::html(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error".into(),
            )
        }
    }
}

pub fn start_session_cookie(state: &AppState, session_id: i64) -> String {
    set_cookie(
        SESSION_COOKIE,
        &state.sign(SESSION_COOKIE, &session_id.to_string()),
        Some(PERMANENT),
    )
}

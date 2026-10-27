//! Integration tests: the real app on a random port, a real Postgres database emptied before each test.
//! Tests run one at a time (they share the database).

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use controlfinan::models::{self, CREDIT, DEBIT, Entry, RIDES, User};
use controlfinan::web::{AppState, Mailer};
use reqwest::redirect::Policy;
use rust_decimal::Decimal;
use sqlx::PgPool;
use tokio::sync::{Mutex as AsyncMutex, MutexGuard};

static SERIAL: AsyncMutex<()> = AsyncMutex::const_new(());

#[derive(Default)]
struct RecordingMailer(Mutex<Vec<String>>);

impl Mailer for RecordingMailer {
    fn send(&self, to: &str, subject: &str, text: &str) {
        self.0
            .lock()
            .unwrap()
            .push(format!("{to}|{subject}|{text}"));
    }
}

struct TestApp {
    _guard: MutexGuard<'static, ()>,
    base: String,
    db: PgPool,
    state: Arc<AppState>,
    mailer: Arc<RecordingMailer>,
    client: reqwest::Client,
}

struct Response {
    status: u16,
    body: String,
    location: String,
}

fn noon(day: NaiveDate) -> DateTime<Utc> {
    chrono_tz::America::Sao_Paulo
        .from_local_datetime(&day.and_hms_opt(12, 0, 0).unwrap())
        .unwrap()
        .with_timezone(&Utc)
}

async fn setup() -> TestApp {
    let guard = SERIAL.lock().await;
    let url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://app:app@localhost:5432/controlfinan_rust_test".into());
    if let Ok(admin) = PgPool::connect(&url.replace("/controlfinan_rust_test", "/postgres")).await {
        let _ = sqlx::query("CREATE DATABASE controlfinan_rust_test")
            .execute(&admin)
            .await;
    }
    let db = PgPool::connect(&url).await.expect("test database");
    controlfinan::migrate(&db).await.unwrap();
    sqlx::query("TRUNCATE sessions, current_accounts, users RESTART IDENTITY CASCADE")
        .execute(&db)
        .await
        .unwrap();
    let mailer = Arc::new(RecordingMailer::default());
    let state = Arc::new(AppState::new(
        db.clone(),
        "test-secret",
        4,
        chrono_tz::America::Sao_Paulo,
        mailer.clone(),
    ));
    *state.frozen_now.lock().unwrap() = Some(noon(NaiveDate::from_ymd_opt(2026, 10, 27).unwrap()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = controlfinan::app(
        state.clone(),
        concat!(env!("CARGO_MANIFEST_DIR"), "/static"),
    );
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(Policy::none())
        .build()
        .unwrap();
    TestApp {
        _guard: guard,
        base,
        db,
        state,
        mailer,
        client,
    }
}

impl TestApp {
    async fn read(&self, response: reqwest::Response) -> Response {
        let status = response.status().as_u16();
        let location = response
            .headers()
            .get("location")
            .map(|v| v.to_str().unwrap().replace(&self.base, ""))
            .unwrap_or_default();
        Response {
            status,
            body: response.text().await.unwrap(),
            location,
        }
    }

    async fn get(&self, path: &str) -> Response {
        self.read(
            self.client
                .get(format!("{}{path}", self.base))
                .send()
                .await
                .unwrap(),
        )
        .await
    }

    /// Sends a form like the browser does, with the CSRF token of the page.
    async fn post(&self, path: &str, form: &[(&str, &str)]) -> Response {
        let page = self.get("/passwords/new").await.body;
        let token = page
            .split("name=\"authenticity_token\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_string();
        let mut fields: Vec<(&str, &str)> = form.to_vec();
        if !fields.iter().any(|(key, _)| *key == "authenticity_token") {
            fields.push(("authenticity_token", &token));
        }
        let body: String = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        let response = self
            .client
            .post(format!("{}{path}", self.base))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .unwrap();
        self.read(response).await
    }

    fn travel(&self, to: DateTime<Utc>) {
        *self.state.frozen_now.lock().unwrap() = Some(to);
    }

    fn now(&self) -> DateTime<Utc> {
        self.state.now()
    }

    async fn create_user(&self, email: &str, password: &str) -> User {
        let mut user = User {
            email_address: email.into(),
            password_digest: models::hash_password(password, 4),
            ..User::default()
        };
        models::create_user(&self.db, &mut user).await.unwrap();
        user
    }

    /// Creates a user and signs in through the real login form.
    async fn sign_in(&self) -> User {
        let user = self.create_user("driver@example.com", "secret123").await;
        let response = self
            .post(
                "/session",
                &[
                    ("email_address", "driver@example.com"),
                    ("password", "secret123"),
                ],
            )
            .await;
        assert_eq!(response.status, 302, "sign in");
        user
    }

    async fn create_entry(
        &self,
        user: &User,
        date: &str,
        kind: i32,
        cost: i32,
        price: &str,
        historic: Option<&str>,
    ) -> Entry {
        let mut entry = Entry {
            user_id: user.id,
            cash_account_id: Some(5),
            cost_id: Some(cost),
            type_launche: Some(kind),
            date_ocurrence: NaiveDate::parse_from_str(date, "%Y-%m-%d").ok(),
            price: Decimal::from_str(price).ok(),
            historic: historic.map(String::from),
            ..Entry::default()
        };
        models::save_entry(&self.db, &mut entry).await.unwrap();
        entry
    }

    async fn credit(&self, user: &User, date: &str, price: &str) -> Entry {
        self.create_entry(user, date, CREDIT, RIDES, price, None)
            .await
    }

    async fn count(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sql).fetch_one(&self.db).await.unwrap()
    }
}

fn assert_contains(body: &str, texts: &[&str]) {
    for text in texts {
        assert!(body.contains(text), "expected body to contain {text:?}");
    }
}

fn assert_not_contains(body: &str, texts: &[&str]) {
    for text in texts {
        assert!(
            !body.contains(text),
            "expected body not to contain {text:?}"
        );
    }
}

fn assert_in_order(body: &str, texts: &[&str]) {
    let mut from = 0;
    for text in texts {
        let index = body[from..]
            .find(text)
            .unwrap_or_else(|| panic!("expected in order: {text:?}"));
        from += index + text.len();
    }
}

fn valid_form<'a>() -> Vec<(&'a str, &'a str)> {
    vec![
        ("current_account[type_launche]", "credito"),
        ("current_account[price]", "150"),
        ("current_account[date_ocurrence]", "2026-10-27"),
        ("current_account[cost_id]", "6"),
        ("current_account[cash_account_id]", "5"),
        ("current_account[historic]", "Corridas do dia"),
    ]
}

#[tokio::test]
async fn password_uses_the_rails_bcrypt_format_and_accepts_a_rails_digest() {
    let digest = models::hash_password("secret123", 4);
    assert!(digest.starts_with("$2a$"));
    assert!(models::check_password(&digest, "secret123"));
    assert!(!models::check_password(&digest, "wrong"));
    // Digest of "benchmark123" written by the Rails app (has_secure_password, bcrypt-ruby) for its benchmark account.
    let rails = "$2a$12$xUBQqXOC4yO3ZUCU3U./FeJ/CU4pqmbNxFQ5iUUrWzLWmKSpUKChe";
    assert!(models::check_password(rails, "benchmark123"));
    assert!(!models::check_password(rails, "wrong"));
}

#[tokio::test]
async fn validate_user_returns_the_rails_messages() {
    let t = setup().await;
    t.create_user("taken@example.com", "secret123").await;
    let mut user = User::default();
    assert_eq!(
        models::validate_user(&t.db, &mut user, "", "", true)
            .await
            .unwrap(),
        [
            "Senha não pode ficar em branco",
            "E-mail não pode ficar em branco"
        ]
    );
    let mut user = User {
        email_address: "bad".into(),
        ..User::default()
    };
    assert_eq!(
        models::validate_user(&t.db, &mut user, "123", "456", true)
            .await
            .unwrap(),
        [
            "Confirmação da senha não é igual a Senha",
            "E-mail não é válido",
            "Senha é muito curto (mínimo: 6 caracteres)"
        ]
    );
    let mut user = User {
        email_address: " TAKEN@example.com ".into(),
        ..User::default()
    };
    assert_eq!(
        models::validate_user(&t.db, &mut user, "secret123", "secret123", true)
            .await
            .unwrap(),
        ["E-mail já está em uso"]
    );
}

#[test]
fn entry_validate_returns_the_rails_messages() {
    assert_eq!(
        Entry::default().validate(),
        [
            "Tipo não está incluído na lista",
            "Conta não está incluído na lista",
            "Categoria não está incluído na lista",
            "Data não pode ficar em branco",
            "Valor não pode ficar em branco",
            "Valor não é um número",
        ]
    );
    let zero = Entry {
        cash_account_id: Some(0),
        cost_id: Some(0),
        type_launche: Some(DEBIT),
        date_ocurrence: NaiveDate::from_ymd_opt(2026, 1, 1),
        price: Some(Decimal::ZERO),
        ..Entry::default()
    };
    assert_eq!(zero.validate(), ["Valor deve ser maior que 0"]);
}

#[test]
fn entry_names_with_fallback() {
    let entry = Entry {
        cash_account_id: Some(1),
        cost_id: Some(99),
        type_launche: Some(DEBIT),
        price: Decimal::from_str("10.00").ok(),
        ..Entry::default()
    };
    assert_eq!(entry.name_account(), "Itaú");
    assert_eq!(entry.name_cost(), "Não definido");
    assert_eq!(entry.type_name(), "Débito");
    assert_eq!(entry.signed_currency(), "-R$ 10,00");
}

#[tokio::test]
async fn balance_is_credits_minus_debits_and_summary_discounts_ride_expenses() {
    let t = setup().await;
    let user = t.create_user("driver@example.com", "secret123").await;
    t.credit(&user, "2026-10-02", "200.00").await;
    t.create_entry(&user, "2026-10-02", DEBIT, 0, "50.00", None)
        .await;
    t.create_entry(&user, "2026-10-05", DEBIT, 8, "20.00", None)
        .await;
    t.credit(&user, "2026-09-30", "999.00").await;
    assert_eq!(
        models::balance(&t.db, user.id, None).await.unwrap(),
        Decimal::from_str("1129").unwrap()
    );

    let first = NaiveDate::from_ymd_opt(2026, 10, 1).unwrap();
    let summary = models::summarize_month(
        &t.db,
        user.id,
        first,
        NaiveDate::from_ymd_opt(2026, 10, 31).unwrap(),
    )
    .await
    .unwrap();
    let daily: Vec<(String, String)> = summary
        .daily
        .iter()
        .map(|r| (r.label.clone(), r.currency()))
        .collect();
    assert_eq!(
        daily,
        [
            ("05/10/2026".into(), "-R$ 20,00".into()),
            ("02/10/2026".into(), "R$ 150,00".into())
        ]
    );
    let monthly: Vec<String> = summary
        .monthly
        .iter()
        .map(|r| format!("{} {}", r.label, r.currency()))
        .collect();
    assert_eq!(
        monthly,
        [
            "Corridas R$ 200,00",
            "Combustível -R$ 50,00",
            "Lavagem -R$ 20,00",
            "Telefone R$ 0,00"
        ]
    );
    assert_eq!(summary.rides_net, Decimal::from_str("130").unwrap());
}

#[tokio::test]
async fn guest_is_redirected_to_login_and_back_after_signing_in() {
    let t = setup().await;
    assert_contains(&t.get("/session/new").await.body, &["Esqueceu a senha?"]);
    t.create_user("driver@example.com", "secret123").await;
    assert_eq!(t.get("/dashboard").await.location, "/session/new");
    let response = t
        .post(
            "/session",
            &[
                ("email_address", " Driver@Example.com "),
                ("password", "secret123"),
            ],
        )
        .await;
    assert_eq!(response.location, "/dashboard");
    assert_eq!(t.count("SELECT count(*) FROM sessions").await, 1);
    assert_eq!(t.get("/dashboard").await.status, 200);
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let t = setup().await;
    t.create_user("driver@example.com", "secret123").await;
    assert_eq!(
        t.post(
            "/session",
            &[
                ("email_address", "driver@example.com"),
                ("password", "wrong")
            ]
        )
        .await
        .location,
        "/session/new"
    );
    assert_contains(
        &t.get("/session/new").await.body,
        &["E-mail ou senha inválidos."],
    );
}

#[tokio::test]
async fn login_attempts_are_limited_to_ten_every_three_minutes() {
    let t = setup().await;
    let form = [("email_address", "x@example.com"), ("password", "x")];
    for _ in 0..10 {
        t.post("/session", &form).await;
    }
    t.post("/session", &form).await;
    assert_contains(
        &t.get("/session/new").await.body,
        &["Tente novamente mais tarde."],
    );
    t.travel(t.now() + Duration::minutes(4));
    t.post("/session", &form).await;
    assert_contains(
        &t.get("/session/new").await.body,
        &["E-mail ou senha inválidos."],
    );
}

#[tokio::test]
async fn sign_out_deletes_the_session() {
    let t = setup().await;
    t.sign_in().await;
    let response = t.post("/session", &[("_method", "delete")]).await;
    assert_eq!(
        (response.status, response.location.as_str()),
        (303, "/session/new")
    );
    assert_eq!(t.count("SELECT count(*) FROM sessions").await, 0);
    assert_eq!(t.get("/").await.location, "/session/new");
}

#[tokio::test]
async fn forms_without_a_valid_csrf_token_are_rejected() {
    let t = setup().await;
    t.create_user("driver@example.com", "secret123").await;
    let response = t
        .post(
            "/session",
            &[
                ("authenticity_token", "forged"),
                ("email_address", "driver@example.com"),
                ("password", "secret123"),
            ],
        )
        .await;
    assert_eq!(response.status, 422);
}

#[tokio::test]
async fn registration_creates_an_account_or_shows_the_validation_messages() {
    let t = setup().await;
    let response = t
        .post(
            "/registration",
            &[
                ("user[email_address]", "bad"),
                ("user[password]", "1"),
                ("user[password_confirmation]", "2"),
            ],
        )
        .await;
    assert_eq!(response.status, 422);
    assert_contains(
        &response.body,
        &[
            "Confirmação da senha não é igual a Senha",
            "E-mail não é válido",
        ],
    );

    let response = t
        .post(
            "/registration",
            &[
                ("user[email_address]", " New@Example.com "),
                ("user[password]", "secret123"),
                ("user[password_confirmation]", "secret123"),
            ],
        )
        .await;
    assert_eq!(response.location, "/");
    assert_eq!(
        t.count("SELECT count(*) FROM users WHERE email_address = 'new@example.com'")
            .await,
        1
    );
    assert_contains(&t.get("/").await.body, &["Conta criada."]);
}

#[tokio::test]
async fn password_reset_email_does_not_reveal_whether_the_address_exists() {
    let t = setup().await;
    t.create_user("driver@example.com", "secret123").await;
    let notice = "Se o e-mail estiver cadastrado, enviamos as instruções para redefinir a senha.";
    assert_eq!(
        t.post("/passwords", &[("email_address", "driver@example.com")])
            .await
            .location,
        "/session/new"
    );
    assert_contains(&t.get("/session/new").await.body, &[notice]);
    t.post("/passwords", &[("email_address", "missing@example.com")])
        .await;
    assert_contains(&t.get("/session/new").await.body, &[notice]);
    let sent = t.mailer.0.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    assert_contains(
        &sent[0],
        &[
            "driver@example.com|Redefinição de senha|",
            "/passwords/",
            "/edit",
            "15 minutos",
        ],
    );
}

#[tokio::test]
async fn password_reset_changes_the_password_and_ends_every_session() {
    let t = setup().await;
    let user = t.sign_in().await;
    let token = t.state.password_reset_token(&user);
    assert_contains(
        &t.get(&format!("/passwords/{token}/edit")).await.body,
        &["Defina sua nova senha"],
    );

    let mismatch = t
        .post(
            &format!("/passwords/{token}"),
            &[
                ("_method", "put"),
                ("password", "new-secret"),
                ("password_confirmation", "other"),
            ],
        )
        .await;
    assert_eq!(mismatch.location, format!("/passwords/{token}/edit"));
    assert_contains(
        &t.get(&mismatch.location).await.body,
        &["As senhas não conferem ou têm menos de 6 caracteres."],
    );

    let response = t
        .post(
            &format!("/passwords/{token}"),
            &[
                ("_method", "put"),
                ("password", "new-secret"),
                ("password_confirmation", "new-secret"),
            ],
        )
        .await;
    assert_eq!(response.location, "/session/new");
    assert_contains(&t.get("/session/new").await.body, &["Senha redefinida."]);
    assert_eq!(t.count("SELECT count(*) FROM sessions").await, 0);
    let reloaded = models::find_user(&t.db, user.id).await.unwrap().unwrap();
    assert!(models::check_password(
        &reloaded.password_digest,
        "new-secret"
    ));
}

#[tokio::test]
async fn password_reset_token_expires_after_fifteen_minutes_and_after_a_password_change() {
    let t = setup().await;
    let mut user = t.create_user("driver@example.com", "secret123").await;
    let token = t.state.password_reset_token(&user);
    let start = t.now();
    t.travel(start + Duration::minutes(16));
    assert_eq!(
        t.get(&format!("/passwords/{token}/edit")).await.location,
        "/passwords/new"
    );
    assert_contains(
        &t.get("/passwords/new").await.body,
        &["O link de redefinição é inválido ou expirou."],
    );
    t.travel(start);
    user.password_digest = models::hash_password("another123", 4);
    models::update_password(&t.db, &user).await.unwrap();
    assert_eq!(
        t.get(&format!("/passwords/{token}/edit")).await.location,
        "/passwords/new"
    );
    assert_eq!(
        t.get("/passwords/invalid/edit").await.location,
        "/passwords/new"
    );
}

#[tokio::test]
async fn list_shows_entries_the_balance_and_filters_by_day() {
    let t = setup().await;
    let user = t.sign_in().await;
    t.credit(&user, "2026-10-26", "150.00").await;
    t.create_entry(&user, "2026-10-27", DEBIT, 0, "40.00", None)
        .await;
    assert_contains(
        &t.get("/").await.body,
        &["Saldo total", "R$ 110,00", "-R$ 40,00"],
    );
    let body = t.get("/current_accounts?date=2026-10-26").await.body;
    assert_contains(&body, &["Saldo do dia 26/10/2026", "R$ 150,00"]);
    assert_not_contains(&body, &["R$ 40,00"]);
}

#[tokio::test]
async fn list_paginates_thirty_entries_per_page() {
    let t = setup().await;
    let user = t.sign_in().await;
    for n in 1..=31 {
        t.create_entry(
            &user,
            "2026-10-27",
            CREDIT,
            RIDES,
            "150.00",
            Some(&format!("entry {n}.")),
        )
        .await;
    }
    let first = t.get("/current_accounts").await.body;
    assert_contains(&first, &["Mais antigos →"]);
    assert_not_contains(&first, &["← Mais recentes", "entry 1."]);
    let second = t.get("/current_accounts?page=2").await.body;
    assert_contains(&second, &["← Mais recentes", "entry 1."]);
    assert_not_contains(&second, &["Mais antigos →"]);
}

#[tokio::test]
async fn json_has_the_jbuilder_fields() {
    let t = setup().await;
    let user = t.sign_in().await;
    let entry = t
        .create_entry(
            &user,
            "2026-10-27",
            CREDIT,
            RIDES,
            "150.00",
            Some("Café/Almoço"),
        )
        .await;
    let id = entry.id.unwrap();
    let expected = format!(
        r#"{{"id":{id},"cash_account_id":5,"cost_id":6,"date_ocurrence":"2026-10-27","price":"150.0","historic":"Café/Almoço","user_id":{},"type_launche":1,"url":"{}/current_accounts/{id}.json"}}"#,
        user.id, t.base
    );
    assert_eq!(
        t.get("/current_accounts.json").await.body,
        format!("[{expected}]")
    );
    assert_eq!(
        t.get(&format!("/current_accounts/{id}.json")).await.body,
        expected
    );
}

#[tokio::test]
async fn other_users_entries_are_not_found() {
    let t = setup().await;
    t.sign_in().await;
    let other = t.create_user("other@example.com", "secret123").await;
    let entry = t.credit(&other, "2026-10-27", "150.00").await;
    let path = format!("/current_accounts/{}", entry.id.unwrap());
    assert_eq!(t.get(&path).await.status, 404);
    assert_eq!(t.get(&format!("{path}/edit")).await.status, 404);
    assert_eq!(t.post(&path, &[("_method", "delete")]).await.status, 404);
    assert_eq!(t.count("SELECT count(*) FROM current_accounts").await, 1);
}

#[tokio::test]
async fn create_update_and_delete_entries() {
    let t = setup().await;
    let user = t.sign_in().await;
    let other = t.create_user("other@example.com", "secret123").await;
    let other_id = other.id.to_string();
    let mut form = valid_form();
    form.push(("current_account[user_id]", &other_id));
    assert_eq!(
        t.post("/current_accounts", &form).await.location,
        "/current_accounts"
    );
    assert_contains(
        &t.get("/current_accounts").await.body,
        &["Lançamento cadastrado."],
    );
    assert_eq!(t.count(&format!("SELECT count(*) FROM current_accounts WHERE user_id = {} AND price = 150 AND type_launche = 1", user.id)).await, 1);

    let invalid = t
        .post("/current_accounts", &[("current_account[price]", "")])
        .await;
    assert_eq!(invalid.status, 422);
    assert_contains(
        &invalid.body,
        &[
            "Valor não pode ficar em branco",
            "Tipo não está incluído na lista",
        ],
    );

    let id: i64 = t.count("SELECT max(id) FROM current_accounts").await;
    let mut form = valid_form();
    form.push(("_method", "patch"));
    form.retain(|(key, _)| *key != "current_account[price]");
    form.push(("current_account[price]", "12.5"));
    let response = t.post(&format!("/current_accounts/{id}"), &form).await;
    assert_eq!(response.location, format!("/current_accounts/{id}"));
    assert_contains(
        &t.get(&response.location).await.body,
        &["Lançamento atualizado.", "R$ 12,50"],
    );

    let response = t
        .post(&format!("/current_accounts/{id}"), &[("_method", "delete")])
        .await;
    assert_eq!(response.status, 303);
    assert_contains(
        &t.get("/current_accounts").await.body,
        &["Lançamento removido."],
    );
    assert_eq!(t.count("SELECT count(*) FROM current_accounts").await, 0);
}

#[tokio::test]
async fn legacy_daily_search_redirects_to_the_filter() {
    let t = setup().await;
    let response = t.get("/search_account?date_calendar_now=2026-10-27").await;
    assert_eq!(
        (response.status, response.location.as_str()),
        (301, "/current_accounts?date=2026-10-27")
    );
}

#[tokio::test]
async fn dashboard_shows_the_balances_navigates_and_falls_back_to_the_current_month() {
    let t = setup().await;
    let user = t.sign_in().await;
    t.credit(&user, "2026-10-02", "200.00").await;
    t.create_entry(&user, "2026-10-02", DEBIT, 0, "50.00", None)
        .await;
    t.create_entry(&user, "2026-10-05", DEBIT, 8, "20.00", None)
        .await;
    t.credit(&user, "2026-09-30", "999.00").await;
    let body = t.get("/dashboard?month=2026-10").await.body;
    assert_contains(&body, &["Outubro de 2026", "Saldo Diário", "Saldo Mensal"]);
    assert_in_order(
        &body,
        &[
            "05/10/2026",
            "-R$ 20,00",
            "02/10/2026",
            "R$ 150,00",
            "Total do mês",
            "R$ 130,00",
        ],
    );
    assert_in_order(
        &body,
        &[
            "Corridas",
            "R$ 200,00",
            "Combustível",
            "-R$ 50,00",
            "Lavagem",
            "-R$ 20,00",
            "Telefone",
            "R$ 0,00",
            "Saldo do mês",
            "R$ 130,00",
        ],
    );
    assert_not_contains(&body, &["999"]);
    assert_contains(
        &t.get("/dashboard?month=2026-01").await.body,
        &["/dashboard?month=2025-12", "/dashboard?month=2026-02"],
    );
    t.travel(noon(NaiveDate::from_ymd_opt(2026, 3, 15).unwrap()));
    assert_contains(
        &t.get("/dashboard?month=bad").await.body,
        &["Março de 2026"],
    );
}

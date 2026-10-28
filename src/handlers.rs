//! Routes and handlers with the same URLs, rules and messages as the Rails app.

use std::str::FromStr;
use std::sync::LazyLock;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Router};
use chrono::{Datelike, Duration, Months, NaiveDate};
use regex::Regex;
use rust_decimal::{Decimal, RoundingStrategy};
use serde::{Deserialize, Serialize};
use tower_http::services::ServeDir;

use crate::format;
use crate::models::{self, CASH_ACCOUNTS, COSTS, CREDIT, DEBIT, Entry, Row, User};
use crate::web::{self, Ctx, PageInfo, Reply, SharedState};

const PER_PAGE: i64 = 30;

pub fn router(state: SharedState, static_dir: &str) -> Router {
    Router::new()
        .route(
            "/up",
            get(|| async {
                Reply::html(
                    StatusCode::OK,
                    r#"<!DOCTYPE html><html><body style="background-color: green"></body></html>"#
                        .into(),
                )
            }),
        )
        .route("/session/new", get(new_session))
        .route("/session", post(create_session).delete(destroy_session))
        .route("/registration/new", get(new_registration))
        .route("/registration", post(create_registration))
        .route("/passwords/new", get(new_password))
        .route("/passwords", post(create_password))
        .route("/passwords/{token}/edit", get(edit_password))
        .route(
            "/passwords/{token}",
            axum::routing::put(update_password).patch(update_password),
        )
        .route("/", get(index))
        .route("/current_accounts", get(index).post(create_entry))
        .route("/current_accounts.json", get(index_json))
        .route("/current_accounts/new", get(new_entry))
        .route(
            "/current_accounts/{id}",
            get(show_entry)
                .put(update_entry)
                .patch(update_entry)
                .delete(destroy_entry),
        )
        .route("/current_accounts/{id}/edit", get(edit_entry))
        .route("/dashboard", get(dashboard))
        .route("/search_account", get(search_account))
        .fallback_service(ServeDir::new(static_dir))
        .with_state(state)
}

fn server_error(error: impl std::fmt::Display) -> Reply {
    eprintln!("error: {error}");
    Reply::html(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal Server Error".into(),
    )
}

#[derive(Deserialize, Default)]
struct EmailQuery {
    #[serde(default)]
    email_address: String,
}

// Sessions

#[derive(Template)]
#[template(path = "sessions_new.html")]
struct SessionsNew {
    page: PageInfo,
    email_address: String,
}

async fn new_session(
    State(state): State<SharedState>,
    Extension(ctx): Extension<Ctx>,
    Query(query): Query<EmailQuery>,
) -> Reply {
    let template = SessionsNew {
        page: PageInfo::new(&state, &ctx, ""),
        email_address: query.email_address,
    };
    web::render(StatusCode::OK, &template.page, &template)
}

async fn create_session(State(state): State<SharedState>, Extension(ctx): Extension<Ctx>) -> Reply {
    if !state.allow(&format!("sessions:{}", ctx.ip), 10, Duration::minutes(3)) {
        return Reply::redirect_with(
            &state,
            "/session/new",
            StatusCode::FOUND,
            "alert",
            "Tente novamente mais tarde.",
        );
    }
    let user = match models::find_user_by_email(&state.db, &ctx.field("email_address")).await {
        Ok(user) => user,
        Err(error) => return server_error(error),
    };
    let password = ctx.field("password");
    let user = match user {
        Some(user) if models::check_password(&user.password_digest, &password) => user,
        found => {
            if found.is_none() {
                models::check_password(&state.dummy_digest, "x"); // same time as a real check
            }
            return Reply::redirect_with(
                &state,
                "/session/new",
                StatusCode::FOUND,
                "alert",
                "E-mail ou senha inválidos.",
            );
        }
    };
    let session_id =
        match models::create_session(&state.db, user.id, &ctx.user_agent, &ctx.ip).await {
            Ok(id) => id,
            Err(error) => return server_error(error),
        };
    let mut reply = Reply::redirect(&ctx.absolute_url("/"), StatusCode::FOUND)
        .cookie(web::start_session_cookie(&state, session_id));
    if let Some(url) = web::cookie(&ctx.cookies, web::RETURN_TO_COOKIE)
        .and_then(|v| state.verify(web::RETURN_TO_COOKIE, &v))
    {
        reply = Reply::redirect(&url, StatusCode::FOUND)
            .cookie(web::start_session_cookie(&state, session_id))
            .cookie(web::delete_cookie(web::RETURN_TO_COOKIE));
    }
    reply
}

async fn destroy_session(
    State(state): State<SharedState>,
    Extension(ctx): Extension<Ctx>,
) -> Reply {
    if let Some(session_id) = ctx.session_id
        && let Err(error) = models::delete_session(&state.db, session_id).await
    {
        return server_error(error);
    }
    Reply::redirect("/session/new", StatusCode::SEE_OTHER)
        .cookie(web::delete_cookie(web::SESSION_COOKIE))
}

// Registrations

#[derive(Template)]
#[template(path = "registrations_new.html")]
struct RegistrationsNew {
    page: PageInfo,
    email_address: String,
    errors: Vec<String>,
}

async fn new_registration(
    State(state): State<SharedState>,
    Extension(ctx): Extension<Ctx>,
) -> Reply {
    let template = RegistrationsNew {
        page: PageInfo::new(&state, &ctx, ""),
        email_address: String::new(),
        errors: vec![],
    };
    web::render(StatusCode::OK, &template.page, &template)
}

async fn create_registration(
    State(state): State<SharedState>,
    Extension(ctx): Extension<Ctx>,
) -> Reply {
    if !state.allow(
        &format!("registrations:{}", ctx.ip),
        10,
        Duration::minutes(3),
    ) {
        return Reply::redirect_with(
            &state,
            "/registration/new",
            StatusCode::FOUND,
            "alert",
            "Tente novamente mais tarde.",
        );
    }
    let password = ctx.field("user[password]");
    let mut user = User {
        email_address: ctx.field("user[email_address]"),
        ..User::default()
    };
    let errors = match models::validate_user(
        &state.db,
        &mut user,
        &password,
        &ctx.field("user[password_confirmation]"),
        true,
    )
    .await
    {
        Ok(errors) => errors,
        Err(error) => return server_error(error),
    };
    if !errors.is_empty() {
        let template = RegistrationsNew {
            page: PageInfo::new(&state, &ctx, ""),
            email_address: user.email_address,
            errors,
        };
        return web::render(StatusCode::UNPROCESSABLE_ENTITY, &template.page, &template);
    }
    user.password_digest = models::hash_password(&password, state.bcrypt_cost);
    if let Err(error) = models::create_user(&state.db, &mut user).await {
        return server_error(error);
    }
    let session_id =
        match models::create_session(&state.db, user.id, &ctx.user_agent, &ctx.ip).await {
            Ok(id) => id,
            Err(error) => return server_error(error),
        };
    Reply::redirect_with(&state, "/", StatusCode::FOUND, "notice", "Conta criada.")
        .cookie(web::start_session_cookie(&state, session_id))
}

// Passwords

#[derive(Template)]
#[template(path = "passwords_new.html")]
struct PasswordsNew {
    page: PageInfo,
    email_address: String,
}

#[derive(Template)]
#[template(path = "passwords_edit.html")]
struct PasswordsEdit {
    page: PageInfo,
    token: String,
}

const INVALID_TOKEN: &str = "O link de redefinição é inválido ou expirou.";

async fn new_password(
    State(state): State<SharedState>,
    Extension(ctx): Extension<Ctx>,
    Query(query): Query<EmailQuery>,
) -> Reply {
    let template = PasswordsNew {
        page: PageInfo::new(&state, &ctx, ""),
        email_address: query.email_address,
    };
    web::render(StatusCode::OK, &template.page, &template)
}

async fn create_password(
    State(state): State<SharedState>,
    Extension(ctx): Extension<Ctx>,
) -> Reply {
    if !state.allow(&format!("passwords:{}", ctx.ip), 10, Duration::minutes(3)) {
        return Reply::redirect_with(
            &state,
            "/passwords/new",
            StatusCode::FOUND,
            "alert",
            "Tente novamente mais tarde.",
        );
    }
    match models::find_user_by_email(&state.db, &ctx.field("email_address")).await {
        Ok(Some(user)) => {
            let url = ctx.absolute_url(&format!(
                "/passwords/{}/edit",
                state.password_reset_token(&user)
            ));
            state.mailer.send(
                &user.email_address,
                "Redefinição de senha",
                &format!(
                    "Você pode redefinir sua senha em\n{url}\n\nEste link expira em 15 minutos.\n"
                ),
            );
        }
        Ok(None) => {}
        Err(error) => return server_error(error),
    }
    Reply::redirect_with(
        &state,
        "/session/new",
        StatusCode::FOUND,
        "notice",
        "Se o e-mail estiver cadastrado, enviamos as instruções para redefinir a senha.",
    )
}

async fn edit_password(
    State(state): State<SharedState>,
    Extension(ctx): Extension<Ctx>,
    Path(token): Path<String>,
) -> Reply {
    if state.find_by_password_reset_token(&token).await.is_none() {
        return Reply::redirect_with(
            &state,
            "/passwords/new",
            StatusCode::FOUND,
            "alert",
            INVALID_TOKEN,
        );
    }
    let template = PasswordsEdit {
        page: PageInfo::new(&state, &ctx, ""),
        token,
    };
    web::render(StatusCode::OK, &template.page, &template)
}

async fn update_password(
    State(state): State<SharedState>,
    Extension(ctx): Extension<Ctx>,
    Path(token): Path<String>,
) -> Reply {
    let Some(mut user) = state.find_by_password_reset_token(&token).await else {
        return Reply::redirect_with(
            &state,
            "/passwords/new",
            StatusCode::FOUND,
            "alert",
            INVALID_TOKEN,
        );
    };
    let password = ctx.field("password");
    match models::validate_user(
        &state.db,
        &mut user,
        &password,
        &ctx.field("password_confirmation"),
        true,
    )
    .await
    {
        Ok(errors) if !errors.is_empty() => {
            return Reply::redirect_with(
                &state,
                &format!("/passwords/{token}/edit"),
                StatusCode::FOUND,
                "alert",
                "As senhas não conferem ou têm menos de 6 caracteres.",
            );
        }
        Ok(_) => {}
        Err(error) => return server_error(error),
    }
    user.password_digest = models::hash_password(&password, state.bcrypt_cost);
    if let Err(error) = models::update_password(&state.db, &user).await {
        return server_error(error);
    }
    if let Err(error) = models::delete_sessions_of(&state.db, user.id).await {
        return server_error(error);
    }
    Reply::redirect_with(
        &state,
        "/session/new",
        StatusCode::FOUND,
        "notice",
        "Senha redefinida.",
    )
}

// Current accounts (entries)

#[derive(Deserialize, Default)]
struct ListQuery {
    date: Option<String>,
    page: Option<String>,
}

fn parse_date(value: &str) -> Option<NaiveDate> {
    static DATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap());
    if !DATE.is_match(value) {
        return None;
    }
    NaiveDate::parse_from_str(value, "%Y-%m-%d").ok()
}

fn parse_page(value: Option<&str>) -> i64 {
    value
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(1)
        .max(1)
}

#[derive(Template)]
#[template(path = "current_accounts_index.html")]
struct Index {
    page: PageInfo,
    entries: Vec<Entry>,
    balance_text: String,
    balance_class: &'static str,
    date_label: String,
    date_value: String,
    date_param: String,
    page_number: i64,
    next_page: bool,
}

async fn index(
    State(state): State<SharedState>,
    Extension(ctx): Extension<Ctx>,
    Query(query): Query<ListQuery>,
) -> Reply {
    let user_id = ctx.user().id;
    let day = query.date.as_deref().and_then(parse_date);
    let page_number = parse_page(query.page.as_deref());
    let (entries, balance) = match tokio::try_join!(
        models::list_entries(
            &state.db,
            user_id,
            day,
            PER_PAGE + 1,
            (page_number - 1) * PER_PAGE
        ),
        models::balance(&state.db, user_id, day),
    ) {
        Ok(result) => result,
        Err(error) => return server_error(error),
    };
    let next_page = entries.len() as i64 > PER_PAGE;
    let template = Index {
        page: PageInfo::new(&state, &ctx, "index"),
        entries: entries.into_iter().take(PER_PAGE as usize).collect(),
        balance_text: format::currency(balance),
        balance_class: format::amount_class(balance),
        date_label: day.map(format::br_date).unwrap_or_default(),
        date_value: day.map(|d| d.to_string()).unwrap_or_default(),
        date_param: day.map(|d| format!("date={d}&")).unwrap_or_default(),
        page_number,
        next_page,
    };
    web::render(StatusCode::OK, &template.page, &template)
}

#[derive(Serialize)]
struct EntryJson {
    id: i64,
    cash_account_id: i32,
    cost_id: i32,
    date_ocurrence: String,
    price: String,
    historic: Option<String>,
    user_id: i64,
    type_launche: i32,
    url: String,
}

fn as_json(ctx: &Ctx, entry: Entry) -> EntryJson {
    let id = entry.id.unwrap_or_default();
    EntryJson {
        id,
        cash_account_id: entry.cash_account_id.unwrap_or_default(),
        cost_id: entry.cost_id.unwrap_or_default(),
        date_ocurrence: entry.date_iso(),
        price: entry.price.map(format::decimal_text).unwrap_or_default(),
        historic: entry.historic,
        user_id: entry.user_id,
        type_launche: entry.type_launche.unwrap_or_default(),
        url: ctx.absolute_url(&format!("/current_accounts/{id}.json")),
    }
}

async fn index_json(
    State(state): State<SharedState>,
    Extension(ctx): Extension<Ctx>,
    Query(query): Query<ListQuery>,
) -> Reply {
    let day = query.date.as_deref().and_then(parse_date);
    let offset = (parse_page(query.page.as_deref()) - 1) * PER_PAGE;
    match models::list_entries(&state.db, ctx.user().id, day, PER_PAGE, offset).await {
        Ok(entries) => {
            let list: Vec<EntryJson> = entries.into_iter().map(|e| as_json(&ctx, e)).collect();
            Reply::json(serde_json::to_string(&list).unwrap_or_default())
        }
        Err(error) => server_error(error),
    }
}

/// The signed in user's entry; other users' entries are "not found".
async fn find(state: &SharedState, ctx: &Ctx, id: &str) -> Result<Entry, Reply> {
    let Ok(id) = id.parse::<i64>() else {
        return Err(Reply::not_found());
    };
    match models::find_entry(&state.db, ctx.user().id, id).await {
        Ok(Some(entry)) => Ok(entry),
        Ok(None) => Err(Reply::not_found()),
        Err(error) => Err(server_error(error)),
    }
}

#[derive(Template)]
#[template(path = "current_accounts_show.html")]
struct Show {
    page: PageInfo,
    entry: Entry,
}

async fn show_entry(
    State(state): State<SharedState>,
    Extension(ctx): Extension<Ctx>,
    Path(id): Path<String>,
) -> Reply {
    if let Some(id) = id.strip_suffix(".json") {
        return match find(&state, &ctx, id).await {
            Ok(entry) => {
                Reply::json(serde_json::to_string(&as_json(&ctx, entry)).unwrap_or_default())
            }
            Err(reply) => reply,
        };
    }
    match find(&state, &ctx, &id).await {
        Ok(entry) => {
            let template = Show {
                page: PageInfo::new(&state, &ctx, ""),
                entry,
            };
            web::render(StatusCode::OK, &template.page, &template)
        }
        Err(reply) => reply,
    }
}

pub struct SelectOption {
    pub id: i32,
    pub name: &'static str,
    pub selected: bool,
}

fn options(list: &[(i32, &'static str)], selected: Option<i32>) -> Vec<SelectOption> {
    list.iter()
        .map(|(id, name)| SelectOption {
            id: *id,
            name,
            selected: Some(*id) == selected,
        })
        .collect()
}

#[derive(Template)]
#[template(path = "current_accounts_new.html")]
struct NewEntry {
    page: PageInfo,
    entry: Entry,
    errors: Vec<String>,
    costs: Vec<SelectOption>,
    cash_accounts: Vec<SelectOption>,
}

#[derive(Template)]
#[template(path = "current_accounts_edit.html")]
struct EditEntry {
    page: PageInfo,
    entry: Entry,
    errors: Vec<String>,
    costs: Vec<SelectOption>,
    cash_accounts: Vec<SelectOption>,
}

fn new_form(
    state: &SharedState,
    ctx: &Ctx,
    entry: Entry,
    errors: Vec<String>,
    status: StatusCode,
) -> Reply {
    let template = NewEntry {
        page: PageInfo::new(state, ctx, ""),
        costs: options(&COSTS, entry.cost_id),
        cash_accounts: options(&CASH_ACCOUNTS, entry.cash_account_id),
        entry,
        errors,
    };
    web::render(status, &template.page, &template)
}

fn edit_form(
    state: &SharedState,
    ctx: &Ctx,
    entry: Entry,
    errors: Vec<String>,
    status: StatusCode,
) -> Reply {
    let template = EditEntry {
        page: PageInfo::new(state, ctx, ""),
        costs: options(&COSTS, entry.cost_id),
        cash_accounts: options(&CASH_ACCOUNTS, entry.cash_account_id),
        entry,
        errors,
    };
    web::render(status, &template.page, &template)
}

async fn new_entry(State(state): State<SharedState>, Extension(ctx): Extension<Ctx>) -> Reply {
    let entry = Entry {
        date_ocurrence: Some(state.today()),
        type_launche: Some(DEBIT),
        ..Entry::default()
    };
    new_form(&state, &ctx, entry, vec![], StatusCode::OK)
}

async fn edit_entry(
    State(state): State<SharedState>,
    Extension(ctx): Extension<Ctx>,
    Path(id): Path<String>,
) -> Reply {
    match find(&state, &ctx, &id).await {
        Ok(entry) => edit_form(&state, &ctx, entry, vec![], StatusCode::OK),
        Err(reply) => reply,
    }
}

/// Copies the form fields into the entry and returns the validation messages.
/// Like Rails' `update`, a field whose key is absent from the form keeps its stored value.
fn assign(entry: &mut Entry, ctx: &Ctx) -> Vec<String> {
    static INTEGER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^-?\d+$").unwrap());
    let field = |name: &str| {
        let key = format!("current_account[{name}]");
        ctx.has_field(&key).then(|| ctx.field(&key))
    };
    let integer = |value: String| {
        let value = value.trim();
        if INTEGER.is_match(value) {
            value.parse().ok()
        } else {
            None
        }
    };
    if let Some(value) = field("cash_account_id") {
        entry.cash_account_id = integer(value);
    }
    if let Some(value) = field("cost_id") {
        entry.cost_id = integer(value);
    }
    if let Some(value) = field("type_launche") {
        entry.type_launche = match value.as_str() {
            "debito" => Some(DEBIT),
            "credito" => Some(CREDIT),
            _ => None,
        };
    }
    if let Some(value) = field("date_ocurrence") {
        entry.date_ocurrence = parse_date(&value);
    }
    if let Some(value) = field("price") {
        entry.price_text = value.trim().to_string();
        entry.price = Decimal::from_str(&entry.price_text)
            .or_else(|_| Decimal::from_scientific(&entry.price_text))
            .ok()
            .map(|price| price.round_dp_with_strategy(2, RoundingStrategy::MidpointAwayFromZero));
    }
    if let Some(historic) = field("historic") {
        entry.historic = (!historic.is_empty()).then_some(historic);
    }
    entry.validate()
}

async fn create_entry(State(state): State<SharedState>, Extension(ctx): Extension<Ctx>) -> Reply {
    let mut entry = Entry {
        user_id: ctx.user().id,
        ..Entry::default()
    };
    let errors = assign(&mut entry, &ctx);
    if !errors.is_empty() {
        return new_form(
            &state,
            &ctx,
            entry,
            errors,
            StatusCode::UNPROCESSABLE_ENTITY,
        );
    }
    if let Err(error) = models::save_entry(&state.db, &mut entry).await {
        return server_error(error);
    }
    Reply::redirect_with(
        &state,
        "/current_accounts",
        StatusCode::FOUND,
        "notice",
        "Lançamento cadastrado.",
    )
}

async fn update_entry(
    State(state): State<SharedState>,
    Extension(ctx): Extension<Ctx>,
    Path(id): Path<String>,
) -> Reply {
    let mut entry = match find(&state, &ctx, &id).await {
        Ok(entry) => entry,
        Err(reply) => return reply,
    };
    let errors = assign(&mut entry, &ctx);
    if !errors.is_empty() {
        return edit_form(
            &state,
            &ctx,
            entry,
            errors,
            StatusCode::UNPROCESSABLE_ENTITY,
        );
    }
    if let Err(error) = models::save_entry(&state.db, &mut entry).await {
        return server_error(error);
    }
    Reply::redirect_with(
        &state,
        &format!("/current_accounts/{}", entry.id_text()),
        StatusCode::FOUND,
        "notice",
        "Lançamento atualizado.",
    )
}

async fn destroy_entry(
    State(state): State<SharedState>,
    Extension(ctx): Extension<Ctx>,
    Path(id): Path<String>,
) -> Reply {
    let entry = match find(&state, &ctx, &id).await {
        Ok(entry) => entry,
        Err(reply) => return reply,
    };
    if let Err(error) = models::delete_entry(&state.db, &entry).await {
        return server_error(error);
    }
    Reply::redirect_with(
        &state,
        "/current_accounts",
        StatusCode::SEE_OTHER,
        "notice",
        "Lançamento removido.",
    )
}

#[derive(Deserialize)]
struct SearchQuery {
    #[serde(default)]
    date_calendar_now: String,
}

/// Legacy daily balance search, now a filter on the listing.
async fn search_account(Query(query): Query<SearchQuery>) -> impl IntoResponse {
    Reply::redirect(
        &format!("/current_accounts?date={}", query.date_calendar_now),
        StatusCode::MOVED_PERMANENTLY,
    )
}

// Dashboard

/// The data of one dashboard table.
pub struct Table {
    pub header: &'static str,
    pub rows: Vec<Row>,
    pub total_label: &'static str,
    pub total: Row,
}

#[derive(Template)]
#[template(path = "dashboards_show.html")]
struct Dashboard {
    page: PageInfo,
    month_label: String,
    previous_month: String,
    next_month: String,
    today: String,
    daily: Table,
    monthly: Table,
}

#[derive(Deserialize, Default)]
struct MonthQuery {
    month: Option<String>,
}

fn parse_month(value: Option<&str>, today: NaiveDate) -> NaiveDate {
    static MONTH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\d{4})-(\d{1,2})$").unwrap());
    value
        .and_then(|v| MONTH.captures(v))
        .and_then(|c| NaiveDate::from_ymd_opt(c[1].parse().ok()?, c[2].parse().ok()?, 1))
        .unwrap_or_else(|| today.with_day(1).unwrap())
}

async fn dashboard(
    State(state): State<SharedState>,
    Extension(ctx): Extension<Ctx>,
    Query(query): Query<MonthQuery>,
) -> Reply {
    let first = parse_month(query.month.as_deref(), state.today());
    let last = first + Months::new(1) - Duration::days(1);
    let summary = match models::summarize_month(&state.db, ctx.user().id, first, last).await {
        Ok(summary) => summary,
        Err(error) => return server_error(error),
    };
    let label = format!(
        "{} de {}",
        format::MONTHS[first.month0() as usize],
        first.year()
    );
    let mut chars = label.chars();
    let label = chars
        .next()
        .map(|c| c.to_uppercase().collect::<String>() + chars.as_str())
        .unwrap_or_default();
    let template = Dashboard {
        page: PageInfo::new(&state, &ctx, "dashboard"),
        month_label: label,
        previous_month: (first - Months::new(1)).format("%Y-%m").to_string(),
        next_month: (first + Months::new(1)).format("%Y-%m").to_string(),
        today: state.today().to_string(),
        daily: Table {
            header: "Data",
            rows: summary.daily,
            total_label: "Total do mês",
            total: Row {
                label: String::new(),
                amount: summary.month_balance,
            },
        },
        monthly: Table {
            header: "Item",
            rows: summary.monthly,
            total_label: "Saldo do mês",
            total: Row {
                label: String::new(),
                amount: summary.rides_net,
            },
        },
    };
    web::render(StatusCode::OK, &template.page, &template)
}

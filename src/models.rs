//! Users, sessions and entries (same schema as the Rails app), validations and queries.

use std::sync::LazyLock;

use chrono::NaiveDate;
use regex::Regex;
use rust_decimal::Decimal;
use sqlx::{PgPool, Row as _, postgres::PgRow};

use crate::format;

pub const CASH_ACCOUNTS: [(i32, &str); 9] = [
    (0, "Conta Dinheiro"),
    (1, "Itaú"),
    (2, "Santander"),
    (3, "CEF Poupança"),
    (4, "PagSeguro"),
    (5, "Uber"),
    (6, "Platinum Itaú"),
    (7, "Banco do Brasil"),
    (8, "99Pop"),
];

pub const COSTS: [(i32, &str); 16] = [
    (0, "Combustível"),
    (1, "Central"),
    (2, "Aluguel Carro"),
    (3, "Almoço"),
    (4, "Lanche"),
    (5, "Diversos"),
    (6, "Corridas"),
    (7, "Telefone"),
    (8, "Lavagem"),
    (9, "Transferência"),
    (10, "Depósitos"),
    (11, "Estacionamento"),
    (12, "Impostos"),
    (13, "Multas"),
    (14, "Manutenção"),
    (15, "Viagens Uber"),
];

pub const DEBIT: i32 = -1;
pub const CREDIT: i32 = 1;
pub const RIDES: i32 = 6;
/// Ride expenses discounted from the rides in the monthly balance (legacy dashboard rule), in this order.
pub const RIDE_EXPENSES: [(i32, &str); 3] = [(0, "Combustível"), (8, "Lavagem"), (7, "Telefone")];

// Same regexp as Ruby's URI::MailTo::EMAIL_REGEXP.
static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$").unwrap()
});

fn option_name(options: &[(i32, &'static str)], id: Option<i32>) -> &'static str {
    options
        .iter()
        .find(|(key, _)| Some(*key) == id)
        .map(|(_, name)| *name)
        .unwrap_or("Não definido")
}

fn has_option(options: &[(i32, &str)], id: Option<i32>) -> bool {
    options.iter().any(|(key, _)| Some(*key) == id)
}

/// Mirrors the Rails users table (has_secure_password).
#[derive(Clone, Debug, Default)]
pub struct User {
    pub id: i64,
    pub email_address: String,
    pub password_digest: String,
}

pub fn normalize_email(value: &str) -> String {
    value.trim().to_lowercase()
}

/// bcrypt only uses the first 72 bytes, like Rails.
fn truncate72(raw: &str) -> &[u8] {
    let bytes = raw.as_bytes();
    &bytes[..bytes.len().min(72)]
}

/// A bcrypt digest in the "$2a$" format Rails writes.
pub fn hash_password(raw: &str, cost: u32) -> String {
    bcrypt::hash_with_result(truncate72(raw), cost)
        .expect("bcrypt")
        .format_for_version(bcrypt::Version::TwoA)
}

pub fn check_password(digest: &str, raw: &str) -> bool {
    !raw.is_empty() && bcrypt::verify(truncate72(raw), digest).unwrap_or(false)
}

fn map_user(row: PgRow) -> User {
    User {
        id: row.get("id"),
        email_address: row.get("email_address"),
        password_digest: row.get("password_digest"),
    }
}

pub async fn find_user_by_email(db: &PgPool, email: &str) -> sqlx::Result<Option<User>> {
    let row = sqlx::query(
        "SELECT id, email_address, password_digest FROM users WHERE email_address = $1",
    )
    .bind(normalize_email(email))
    .fetch_optional(db)
    .await?;
    Ok(row.map(map_user))
}

pub async fn find_user(db: &PgPool, id: i64) -> sqlx::Result<Option<User>> {
    let row = sqlx::query("SELECT id, email_address, password_digest FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await?;
    Ok(row.map(map_user))
}

pub async fn find_user_by_session(db: &PgPool, session_id: i64) -> sqlx::Result<Option<User>> {
    let row = sqlx::query(
        "SELECT u.id, u.email_address, u.password_digest FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = $1",
    ).bind(session_id).fetch_optional(db).await?;
    Ok(row.map(map_user))
}

pub async fn create_user(db: &PgPool, user: &mut User) -> sqlx::Result<()> {
    user.id = sqlx::query_scalar(
        "INSERT INTO users (email_address, password_digest, created_at, updated_at) VALUES ($1, $2, now(), now()) RETURNING id",
    ).bind(&user.email_address).bind(&user.password_digest).fetch_one(db).await?;
    Ok(())
}

pub async fn update_password(db: &PgPool, user: &User) -> sqlx::Result<()> {
    sqlx::query("UPDATE users SET password_digest = $1, updated_at = now() WHERE id = $2")
        .bind(&user.password_digest)
        .bind(user.id)
        .execute(db)
        .await?;
    Ok(())
}

/// The Rails messages (pt-BR) in the same order.
pub async fn validate_user(
    db: &PgPool,
    user: &mut User,
    password: &str,
    confirmation: &str,
    password_required: bool,
) -> sqlx::Result<Vec<String>> {
    let mut errors = Vec::new();
    if password_required && password.is_empty() {
        errors.push("Senha não pode ficar em branco".to_string());
    }
    if password != confirmation {
        errors.push("Confirmação da senha não é igual a Senha".to_string());
    }
    user.email_address = normalize_email(&user.email_address);
    if user.email_address.is_empty() {
        errors.push("E-mail não pode ficar em branco".to_string());
    } else if !EMAIL.is_match(&user.email_address) {
        errors.push("E-mail não é válido".to_string());
    } else {
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM users WHERE email_address = $1 AND id <> $2)",
        )
        .bind(&user.email_address)
        .bind(user.id)
        .fetch_one(db)
        .await?;
        if taken {
            errors.push("E-mail já está em uso".to_string());
        }
    }
    if !password.is_empty() && password.chars().count() < 6 {
        errors.push("Senha é muito curto (mínimo: 6 caracteres)".to_string());
    }
    Ok(errors)
}

// Sessions

pub async fn create_session(
    db: &PgPool,
    user_id: i64,
    user_agent: &str,
    ip: &str,
) -> sqlx::Result<i64> {
    sqlx::query_scalar(
        "INSERT INTO sessions (user_id, user_agent, ip_address, created_at, updated_at) VALUES ($1, $2, $3, now(), now()) RETURNING id",
    ).bind(user_id).bind(user_agent).bind(ip).fetch_one(db).await
}

pub async fn delete_session(db: &PgPool, session_id: i64) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(session_id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete_sessions_of(db: &PgPool, user_id: i64) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

/// A row of current_accounts (a credit or a debit). Form fields that are blank or invalid are None.
#[derive(Clone, Debug, Default)]
pub struct Entry {
    pub id: Option<i64>,
    pub user_id: i64,
    pub cash_account_id: Option<i32>,
    pub cost_id: Option<i32>,
    pub type_launche: Option<i32>,
    pub date_ocurrence: Option<NaiveDate>,
    pub price: Option<Decimal>,
    /// Raw price typed in the form, used by the validation like Rails numericality.
    pub price_text: String,
    pub historic: Option<String>,
}

impl Entry {
    pub fn persisted(&self) -> bool {
        self.id.is_some()
    }
    pub fn id_text(&self) -> String {
        self.id.map(|id| id.to_string()).unwrap_or_default()
    }
    pub fn is_credit(&self) -> bool {
        self.type_launche == Some(CREDIT)
    }
    pub fn name_account(&self) -> &'static str {
        option_name(&CASH_ACCOUNTS, self.cash_account_id)
    }
    pub fn name_cost(&self) -> &'static str {
        option_name(&COSTS, self.cost_id)
    }
    pub fn type_name(&self) -> &'static str {
        if self.is_credit() {
            "Crédito"
        } else {
            "Débito"
        }
    }
    pub fn signed_price(&self) -> Decimal {
        let price = self.price.unwrap_or_default();
        if self.is_credit() { price } else { -price }
    }
    pub fn signed_currency(&self) -> String {
        format::currency(self.signed_price())
    }
    pub fn color(&self) -> &'static str {
        if self.is_credit() {
            "text-emerald-700"
        } else {
            "text-red-700"
        }
    }
    pub fn date_br(&self) -> String {
        self.date_ocurrence.map(format::br_date).unwrap_or_default()
    }
    pub fn day_month(&self) -> String {
        self.date_ocurrence
            .map(format::day_month)
            .unwrap_or_default()
    }
    pub fn date_iso(&self) -> String {
        self.date_ocurrence
            .map(|d| d.to_string())
            .unwrap_or_default()
    }
    pub fn historic_text(&self) -> &str {
        self.historic.as_deref().unwrap_or("")
    }
    /// The value shown in the form: the decimal like Rails, or what the user typed.
    pub fn price_field(&self) -> String {
        self.price
            .map(format::decimal_text)
            .unwrap_or_else(|| self.price_text.clone())
    }

    /// The Rails messages (pt-BR) in the same order as the model validations.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.type_launche != Some(DEBIT) && self.type_launche != Some(CREDIT) {
            errors.push("Tipo não está incluído na lista");
        }
        if !has_option(&CASH_ACCOUNTS, self.cash_account_id) {
            errors.push("Conta não está incluído na lista");
        }
        if !has_option(&COSTS, self.cost_id) {
            errors.push("Categoria não está incluído na lista");
        }
        if self.date_ocurrence.is_none() {
            errors.push("Data não pode ficar em branco");
        }
        // Like Rails presence + numericality: a blank value is also "not a number".
        match self.price {
            None if self.price_text.is_empty() => {
                errors.extend(["Valor não pode ficar em branco", "Valor não é um número"])
            }
            None => errors.push("Valor não é um número"),
            Some(price) if price <= Decimal::ZERO => errors.push("Valor deve ser maior que 0"),
            Some(_) => {}
        }
        errors.into_iter().map(String::from).collect()
    }
}

const ENTRY_COLUMNS: &str =
    "id, user_id, cash_account_id, cost_id, type_launche, date_ocurrence, price, historic";

fn map_entry(row: PgRow) -> Entry {
    Entry {
        id: Some(row.get("id")),
        user_id: row.get("user_id"),
        cash_account_id: Some(row.get("cash_account_id")),
        cost_id: Some(row.get("cost_id")),
        type_launche: Some(row.get("type_launche")),
        date_ocurrence: Some(row.get("date_ocurrence")),
        price: Some(row.get("price")),
        price_text: String::new(),
        historic: row.get("historic"),
    }
}

/// Up to `limit` entries, most recent first, optionally on one day.
pub async fn list_entries(
    db: &PgPool,
    user_id: i64,
    day: Option<NaiveDate>,
    limit: i64,
    offset: i64,
) -> sqlx::Result<Vec<Entry>> {
    let rows = match day {
        None => sqlx::query(&format!(
            "SELECT {ENTRY_COLUMNS} FROM current_accounts WHERE user_id = $1 ORDER BY date_ocurrence DESC, id DESC LIMIT $2 OFFSET $3"
        )).bind(user_id).bind(limit).bind(offset).fetch_all(db).await?,
        Some(day) => sqlx::query(&format!(
            "SELECT {ENTRY_COLUMNS} FROM current_accounts WHERE user_id = $1 AND date_ocurrence = $2 ORDER BY date_ocurrence DESC, id DESC LIMIT $3 OFFSET $4"
        )).bind(user_id).bind(day).bind(limit).bind(offset).fetch_all(db).await?,
    };
    Ok(rows.into_iter().map(map_entry).collect())
}

/// Credits minus debits: the sign comes from type_launche (-1 or 1).
pub async fn balance(db: &PgPool, user_id: i64, day: Option<NaiveDate>) -> sqlx::Result<Decimal> {
    match day {
        None => sqlx::query_scalar("SELECT COALESCE(SUM(price * type_launche), 0) FROM current_accounts WHERE user_id = $1")
            .bind(user_id).fetch_one(db).await,
        Some(day) => sqlx::query_scalar(
            "SELECT COALESCE(SUM(price * type_launche), 0) FROM current_accounts WHERE user_id = $1 AND date_ocurrence = $2",
        ).bind(user_id).bind(day).fetch_one(db).await,
    }
}

pub async fn find_entry(db: &PgPool, user_id: i64, id: i64) -> sqlx::Result<Option<Entry>> {
    let row = sqlx::query(&format!(
        "SELECT {ENTRY_COLUMNS} FROM current_accounts WHERE user_id = $1 AND id = $2"
    ))
    .bind(user_id)
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(row.map(map_entry))
}

pub async fn save_entry(db: &PgPool, entry: &mut Entry) -> sqlx::Result<()> {
    if let Some(id) = entry.id {
        sqlx::query(
            "UPDATE current_accounts SET cash_account_id = $1, cost_id = $2, type_launche = $3, date_ocurrence = $4, price = $5, \
             historic = $6, updated_at = now() WHERE id = $7 AND user_id = $8",
        )
        .bind(entry.cash_account_id).bind(entry.cost_id).bind(entry.type_launche).bind(entry.date_ocurrence)
        .bind(entry.price).bind(&entry.historic).bind(id).bind(entry.user_id).execute(db).await?;
        return Ok(());
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO current_accounts (user_id, cash_account_id, cost_id, type_launche, date_ocurrence, price, historic, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now()) RETURNING id",
    )
    .bind(entry.user_id).bind(entry.cash_account_id).bind(entry.cost_id).bind(entry.type_launche)
    .bind(entry.date_ocurrence).bind(entry.price).bind(&entry.historic).fetch_one(db).await?;
    entry.id = Some(id);
    Ok(())
}

pub async fn delete_entry(db: &PgPool, entry: &Entry) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM current_accounts WHERE id = $1 AND user_id = $2")
        .bind(entry.id)
        .bind(entry.user_id)
        .execute(db)
        .await?;
    Ok(())
}

/// A label and an amount in the dashboard tables, already formatted.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub label: String,
    pub amount: Decimal,
}

impl Row {
    pub fn currency(&self) -> String {
        format::currency(self.amount)
    }
    pub fn class(&self) -> &'static str {
        format::amount_class(self.amount)
    }
}

/// The dashboard numbers of one month.
#[derive(Debug)]
pub struct MonthSummary {
    pub daily: Vec<Row>,
    pub month_balance: Decimal,
    pub monthly: Vec<Row>,
    pub rides_net: Decimal,
}

pub async fn summarize_month(
    db: &PgPool,
    user_id: i64,
    first: NaiveDate,
    last: NaiveDate,
) -> sqlx::Result<MonthSummary> {
    let days = sqlx::query(
        "SELECT date_ocurrence, SUM(price * type_launche) AS total FROM current_accounts \
         WHERE user_id = $1 AND date_ocurrence BETWEEN $2 AND $3 GROUP BY date_ocurrence ORDER BY date_ocurrence DESC",
    ).bind(user_id).bind(first).bind(last).fetch_all(db).await?;
    let daily: Vec<Row> = days
        .into_iter()
        .map(|row| Row {
            label: format::br_date(row.get("date_ocurrence")),
            amount: row.get("total"),
        })
        .collect();
    let month_balance = daily.iter().map(|row| row.amount).sum();

    let ids: Vec<i32> = RIDE_EXPENSES.iter().map(|(id, _)| *id).collect();
    let expenses: Vec<(i32, Decimal)> = sqlx::query(
        "SELECT cost_id, SUM(price) AS total FROM current_accounts \
         WHERE user_id = $1 AND date_ocurrence BETWEEN $2 AND $3 AND cost_id = ANY($4) GROUP BY cost_id",
    ).bind(user_id).bind(first).bind(last).bind(&ids).fetch_all(db).await?
        .into_iter().map(|row| (row.get("cost_id"), row.get("total"))).collect();

    let rides: Decimal = sqlx::query_scalar(
        "SELECT COALESCE(SUM(price * type_launche), 0) FROM current_accounts \
         WHERE user_id = $1 AND date_ocurrence BETWEEN $2 AND $3 AND cost_id = $4",
    )
    .bind(user_id)
    .bind(first)
    .bind(last)
    .bind(RIDES)
    .fetch_one(db)
    .await?;

    let mut monthly = vec![Row {
        label: "Corridas".into(),
        amount: rides,
    }];
    let mut rides_net = rides;
    for (id, name) in RIDE_EXPENSES {
        let amount = expenses
            .iter()
            .find(|(key, _)| *key == id)
            .map(|(_, total)| *total)
            .unwrap_or_default();
        monthly.push(Row {
            label: name.into(),
            amount: -amount,
        });
        rides_net -= amount;
    }
    Ok(MonthSummary {
        daily,
        month_balance,
        monthly,
        rides_net,
    })
}

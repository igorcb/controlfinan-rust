-- Same tables, columns and indexes as controlfinan-rails8-hotwire (db/schema.rb), so the apps can share data.
CREATE TABLE IF NOT EXISTS users (
  id bigserial PRIMARY KEY,
  email_address varchar NOT NULL,
  password_digest varchar NOT NULL,
  created_at timestamp(6) NOT NULL,
  updated_at timestamp(6) NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS index_users_on_email_address ON users (email_address);

CREATE TABLE IF NOT EXISTS sessions (
  id bigserial PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES users (id),
  ip_address varchar,
  user_agent varchar,
  created_at timestamp(6) NOT NULL,
  updated_at timestamp(6) NOT NULL
);
CREATE INDEX IF NOT EXISTS index_sessions_on_user_id ON sessions (user_id);

CREATE TABLE IF NOT EXISTS current_accounts (
  id bigserial PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES users (id),
  cash_account_id integer NOT NULL,
  cost_id integer NOT NULL,
  date_ocurrence date NOT NULL,
  type_launche integer NOT NULL,
  price numeric(9,2) NOT NULL,
  historic varchar,
  created_at timestamp(6) NOT NULL,
  updated_at timestamp(6) NOT NULL
);
CREATE INDEX IF NOT EXISTS index_current_accounts_on_user_id ON current_accounts (user_id);
CREATE INDEX IF NOT EXISTS index_current_accounts_on_user_id_and_date_ocurrence ON current_accounts (user_id, date_ocurrence);

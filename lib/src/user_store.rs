use crate::authentication::registry_based::Client;
use crate::authentication::{AuthenticatedUser, Authenticator, Source, Status};
use crate::log_utils;
use crate::settings::Settings;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use chrono::Utc;
use rand_core::OsRng;
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

const USER_SCHEMA_VERSION: i64 = 1;

#[derive(Clone, Debug)]
pub struct NewUser {
    pub username: String,
    pub password: String,
    pub max_http2_conns: Option<u32>,
    pub max_http3_conns: Option<u32>,
}

#[derive(Clone)]
struct StoredUser {
    username: String,
    password: PasswordData,
    max_http2_conns: Option<u32>,
    max_http3_conns: Option<u32>,
}

#[derive(Clone)]
enum PasswordData {
    Plaintext(String),
    Argon2Hash(String),
}

#[derive(Default)]
struct UserSnapshot {
    users: HashMap<String, StoredUser>,
}

pub struct UserRegistry {
    snapshot: RwLock<UserSnapshot>,
    sqlite_store: Option<SqliteUserStore>,
}

#[derive(Clone)]
pub struct SqliteUserStore {
    path: PathBuf,
}

#[derive(Debug)]
pub enum UserStoreError {
    InvalidConfiguration(String),
    InvalidInput(String),
    Unsupported(String),
    Io(io::Error),
}

#[derive(Debug)]
pub enum CreateUserError {
    InvalidInput(String),
    UserExists(String),
    Unsupported(String),
    Io(io::Error),
}

impl Display for UserStoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfiguration(msg) => write!(f, "{}", msg),
            Self::InvalidInput(msg) => write!(f, "{}", msg),
            Self::Unsupported(msg) => write!(f, "{}", msg),
            Self::Io(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for UserStoreError {}

impl Display for CreateUserError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput(msg) => write!(f, "{}", msg),
            Self::UserExists(msg) => write!(f, "{}", msg),
            Self::Unsupported(msg) => write!(f, "{}", msg),
            Self::Io(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for CreateUserError {}

impl From<io::Error> for UserStoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<io::Error> for CreateUserError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl UserRegistry {
    pub fn from_settings(settings: &Settings) -> Result<Option<Arc<Self>>, UserStoreError> {
        if !settings.get_clients().is_empty() && settings.get_users_db_file().is_some() {
            return Err(UserStoreError::InvalidConfiguration(
                "Configure either credentials_file or users_db_file, not both".to_string(),
            ));
        }

        if let Some(path) = settings.get_users_db_file().as_ref() {
            let store = SqliteUserStore::open(path)?;
            let users = store.load_users()?;
            return Ok(Some(Arc::new(Self {
                snapshot: RwLock::new(UserSnapshot::new(users)),
                sqlite_store: Some(store),
            })));
        }

        if settings.get_clients().is_empty() {
            return Ok(None);
        }

        let users = settings
            .get_clients()
            .iter()
            .cloned()
            .map(StoredUser::from_legacy_client)
            .collect();

        Ok(Some(Arc::new(Self {
            snapshot: RwLock::new(UserSnapshot::new(users)),
            sqlite_store: None,
        })))
    }

    pub fn has_users(&self) -> bool {
        !self.snapshot.read().unwrap().users.is_empty()
    }

    pub fn is_sqlite_backed(&self) -> bool {
        self.sqlite_store.is_some()
    }

    pub fn has_connection_limits(&self) -> bool {
        self.snapshot
            .read()
            .unwrap()
            .users
            .values()
            .any(|user| user.max_http2_conns.is_some() || user.max_http3_conns.is_some())
    }

    pub fn reload(&self) -> Result<(), UserStoreError> {
        let store = match self.sqlite_store.as_ref() {
            Some(store) => store,
            None => return Ok(()),
        };

        let users = store.load_users()?;
        *self.snapshot.write().unwrap() = UserSnapshot::new(users);
        Ok(())
    }

    pub fn create_user(&self, new_user: NewUser) -> Result<(), CreateUserError> {
        validate_new_user(&new_user).map_err(CreateUserError::InvalidInput)?;

        let store = self.sqlite_store.as_ref().ok_or_else(|| {
            CreateUserError::Unsupported(
                "Creating users is only supported with users_db_file".to_string(),
            )
        })?;

        let password_hash = hash_password(&new_user.password)
            .map_err(|err| CreateUserError::Io(io::Error::new(io::ErrorKind::Other, err)))?;

        store.insert_user(SqliteUserRecord {
            username: new_user.username,
            password_hash,
            max_http2_conns: new_user.max_http2_conns,
            max_http3_conns: new_user.max_http3_conns,
        })?;

        self.reload().map_err(|err| match err {
            UserStoreError::Io(io) => CreateUserError::Io(io),
            other => CreateUserError::Io(io::Error::new(io::ErrorKind::Other, other.to_string())),
        })?;

        Ok(())
    }

    pub fn get_connection_limits(&self, username: &str) -> Option<(Option<u32>, Option<u32>)> {
        self.snapshot
            .read()
            .unwrap()
            .users
            .get(username)
            .map(|user| (user.max_http2_conns, user.max_http3_conns))
    }

    pub fn get_legacy_client(&self, username: &str) -> Option<Client> {
        self.snapshot
            .read()
            .unwrap()
            .users
            .get(username)
            .and_then(StoredUser::to_legacy_client)
    }

    fn authenticate_source(&self, source: &Source<'_>) -> Status {
        let credentials = match source {
            Source::Sni(credentials) | Source::ProxyBasic(credentials) => credentials.as_ref(),
        };

        let (username, password) = match decode_credentials(credentials) {
            Some(parsed) => parsed,
            None => return Status::Reject,
        };

        let user = match self.snapshot.read().unwrap().users.get(&username) {
            Some(user) => user.clone(),
            None => return Status::Reject,
        };

        if verify_password(&password, &user.password) {
            Status::Pass(AuthenticatedUser::new(user.username))
        } else {
            Status::Reject
        }
    }
}

impl Authenticator for UserRegistry {
    fn authenticate(&self, source: &Source<'_>, _log_id: &log_utils::IdChain<u64>) -> Status {
        self.authenticate_source(source)
    }
}

impl SqliteUserStore {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let store = Self { path };
        store.initialize()?;
        Ok(store)
    }

    pub fn import_clients(&self, clients: &[Client]) -> Result<(), CreateUserError> {
        for client in clients {
            self.insert_user(SqliteUserRecord {
                username: client.username.clone(),
                password_hash: hash_password(&client.password).map_err(|err| {
                    CreateUserError::Io(io::Error::new(io::ErrorKind::Other, err))
                })?,
                max_http2_conns: client.max_http2_conns,
                max_http3_conns: client.max_http3_conns,
            })?;
        }

        Ok(())
    }

    fn initialize(&self) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let conn = self.open_connection()?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS users (
                 username TEXT PRIMARY KEY NOT NULL,
                 password_hash TEXT NOT NULL,
                 max_http2_conns INTEGER,
                 max_http3_conns INTEGER,
                 created_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );
             PRAGMA user_version = 1;",
        )
        .map_err(sqlite_error_to_io)?;

        if conn
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .map_err(sqlite_error_to_io)?
            != USER_SCHEMA_VERSION
        {
            conn.pragma_update(None, "user_version", USER_SCHEMA_VERSION)
                .map_err(sqlite_error_to_io)?;
        }

        Ok(())
    }

    fn load_users(&self) -> io::Result<Vec<StoredUser>> {
        let conn = self.open_connection()?;
        let mut stmt = conn
            .prepare(
                "SELECT username, password_hash, max_http2_conns, max_http3_conns
                 FROM users
                 ORDER BY username",
            )
            .map_err(sqlite_error_to_io)?;
        let rows = stmt
            .query_map([], |row| {
                Ok(StoredUser {
                    username: row.get(0)?,
                    password: PasswordData::Argon2Hash(row.get(1)?),
                    max_http2_conns: row.get(2)?,
                    max_http3_conns: row.get(3)?,
                })
            })
            .map_err(sqlite_error_to_io)?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error_to_io)
    }

    fn insert_user(&self, user: SqliteUserRecord) -> Result<(), CreateUserError> {
        let conn = self.open_connection()?;
        let now = Utc::now().to_rfc3339();
        match conn.execute(
            "INSERT INTO users (
                 username,
                 password_hash,
                 max_http2_conns,
                 max_http3_conns,
                 created_at,
                 updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![
                user.username,
                user.password_hash,
                user.max_http2_conns,
                user.max_http3_conns,
                now,
            ],
        ) {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(CreateUserError::UserExists(
                    "A user with this username already exists".to_string(),
                ))
            }
            Err(err) => Err(CreateUserError::Io(sqlite_error_to_io(err))),
        }
    }

    fn open_connection(&self) -> io::Result<Connection> {
        Connection::open(&self.path).map_err(sqlite_error_to_io)
    }
}

impl StoredUser {
    fn from_legacy_client(client: Client) -> Self {
        Self {
            username: client.username,
            password: PasswordData::Plaintext(client.password),
            max_http2_conns: client.max_http2_conns,
            max_http3_conns: client.max_http3_conns,
        }
    }

    fn to_legacy_client(&self) -> Option<Client> {
        let password = match &self.password {
            PasswordData::Plaintext(password) => password.clone(),
            PasswordData::Argon2Hash(_) => return None,
        };

        Some(Client {
            username: self.username.clone(),
            password,
            max_http2_conns: self.max_http2_conns,
            max_http3_conns: self.max_http3_conns,
        })
    }
}

impl UserSnapshot {
    fn new(users: Vec<StoredUser>) -> Self {
        Self {
            users: users
                .into_iter()
                .map(|user| (user.username.clone(), user))
                .collect(),
        }
    }
}

struct SqliteUserRecord {
    username: String,
    password_hash: String,
    max_http2_conns: Option<u32>,
    max_http3_conns: Option<u32>,
}

fn validate_new_user(user: &NewUser) -> Result<(), String> {
    if user.username.is_empty() {
        return Err("Username cannot be empty".to_string());
    }

    if user.password.is_empty() {
        return Err("Password cannot be empty".to_string());
    }

    Ok(())
}

fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| err.to_string())
}

fn verify_password(password: &str, password_data: &PasswordData) -> bool {
    match password_data {
        PasswordData::Plaintext(expected) => password == expected,
        PasswordData::Argon2Hash(hash) => PasswordHash::new(hash)
            .ok()
            .and_then(|parsed| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &parsed)
                    .ok()
            })
            .is_some(),
    }
}

fn decode_credentials(credentials: &str) -> Option<(String, String)> {
    let decoded = BASE64_ENGINE.decode(credentials).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let mut parts = decoded.splitn(2, ':');
    let username = parts.next()?.to_string();
    let password = parts.next()?.to_string();
    if username.is_empty() || password.is_empty() {
        return None;
    }

    Some((username, password))
}

fn sqlite_error_to_io(err: rusqlite::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_client() -> Client {
        Client {
            username: "alice".to_string(),
            password: "secret".to_string(),
            max_http2_conns: Some(2),
            max_http3_conns: Some(1),
        }
    }

    #[test]
    fn legacy_registry_exports_plaintext_client() {
        let registry = UserRegistry {
            snapshot: RwLock::new(UserSnapshot::new(vec![StoredUser::from_legacy_client(
                sample_client(),
            )])),
            sqlite_store: None,
        };

        let exported = registry.get_legacy_client("alice").unwrap();
        assert_eq!(exported.username, "alice");
        assert_eq!(exported.password, "secret");
    }

    #[test]
    fn sqlite_store_hashes_and_loads_users() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("users.sqlite");
        let store = SqliteUserStore::open(&db_path).unwrap();
        store.import_clients(&[sample_client()]).unwrap();

        let users = store.load_users().unwrap();
        assert_eq!(users.len(), 1);
        assert!(matches!(users[0].password, PasswordData::Argon2Hash(_)));
    }

    #[test]
    fn sqlite_registry_does_not_export_passwords() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("users.sqlite");
        let store = SqliteUserStore::open(&db_path).unwrap();
        store.import_clients(&[sample_client()]).unwrap();

        let registry = UserRegistry {
            snapshot: RwLock::new(UserSnapshot::new(store.load_users().unwrap())),
            sqlite_store: Some(store),
        };

        assert!(registry.get_legacy_client("alice").is_none());
    }
}

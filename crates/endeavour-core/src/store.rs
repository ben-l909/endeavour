use std::path::Path;

use rusqlite::{params, types::Type, Connection, Row};
use uuid::Uuid;

use crate::{Error, Finding, FindingKind, Result, Session};

/// SQLite-backed session and artifact store.
pub struct SessionStore {
    conn: Connection,
}

impl SessionStore {
    /// Open or create the store at the given path. Runs migrations. Enables WAL mode.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(map_db_error)?;
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")
            .map_err(map_db_error)?;
        run_migrations(&conn)?;
        Ok(Self { conn })
    }

    /// Create a new analysis session for a binary.
    pub fn create_session(&self, name: &str, binary_id: Uuid) -> Result<Session> {
        let session = Session {
            id: Uuid::new_v4(),
            binary_id,
            created_at: rfc3339_now(&self.conn)?,
            name: name.to_string(),
        };

        self.conn
            .execute(
                "INSERT INTO sessions (id, name, binary_id, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![
                    session.id.to_string(),
                    &session.name,
                    session.binary_id.to_string(),
                    &session.created_at
                ],
            )
            .map_err(map_db_error)?;

        Ok(session)
    }

    /// List all sessions, most recent first.
    pub fn list_sessions(&self) -> Result<Vec<Session>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT id, name, binary_id, created_at
                 FROM sessions
                 ORDER BY created_at DESC",
            )
            .map_err(map_db_error)?;

        let rows = statement
            .query_map([], session_from_row)
            .map_err(map_db_error)?;

        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(map_db_error)
    }

    /// Get a session by ID.
    pub fn get_session(&self, id: Uuid) -> Result<Session> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT id, name, binary_id, created_at
                 FROM sessions
                 WHERE id = ?1",
            )
            .map_err(map_db_error)?;

        statement
            .query_row(params![id.to_string()], session_from_row)
            .map_err(map_db_error)
    }

    /// Delete a session and its findings.
    pub fn delete_session(&self, id: Uuid) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM sessions WHERE id = ?1",
                params![id.to_string()],
            )
            .map_err(map_db_error)?;
        Ok(())
    }

    /// Add a finding to a session.
    pub fn add_finding(&self, session_id: Uuid, finding: &Finding) -> Result<()> {
        let id = Uuid::new_v4();
        let created_at = rfc3339_now(&self.conn)?;
        let kind = serde_json::to_string(&finding.kind)
            .map_err(|err| Error::DatabaseError(err.to_string()))?;

        self.conn
            .execute(
                "INSERT INTO findings (id, session_id, pass_name, pass_version, kind, confidence, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id.to_string(),
                    session_id.to_string(),
                    finding.pass_name,
                    finding.pass_version,
                    kind,
                    finding.confidence,
                    created_at
                ],
            )
            .map_err(map_db_error)?;

        Ok(())
    }

    /// Get all findings for a session.
    pub fn get_findings(&self, session_id: Uuid) -> Result<Vec<Finding>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT pass_name, pass_version, kind, confidence
                 FROM findings
                 WHERE session_id = ?1
                 ORDER BY created_at ASC",
            )
            .map_err(map_db_error)?;

        let rows = statement
            .query_map(params![session_id.to_string()], finding_from_row)
            .map_err(map_db_error)?;

        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(map_db_error)
    }
}

fn run_migrations(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY NOT NULL,
            name TEXT NOT NULL,
            binary_id TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY NOT NULL,
            session_id TEXT NOT NULL,
            pass_name TEXT NOT NULL,
            pass_version INTEGER NOT NULL,
            kind TEXT NOT NULL,
            confidence REAL NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_findings_session_id ON findings(session_id);
        ",
    )
    .map_err(map_db_error)
}

fn rfc3339_now(conn: &Connection) -> Result<String> {
    conn.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now')", [], |row| {
        row.get(0)
    })
    .map_err(map_db_error)
}

fn session_from_row(row: &Row<'_>) -> rusqlite::Result<Session> {
    let id_text: String = row.get(0)?;
    let name: String = row.get(1)?;
    let binary_id_text: String = row.get(2)?;
    let created_at: String = row.get(3)?;

    let id = Uuid::parse_str(&id_text)
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(0, Type::Text, Box::new(err)))?;
    let binary_id = Uuid::parse_str(&binary_id_text)
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(2, Type::Text, Box::new(err)))?;

    Ok(Session {
        id,
        binary_id,
        created_at,
        name,
    })
}

fn finding_from_row(row: &Row<'_>) -> rusqlite::Result<Finding> {
    let pass_name: String = row.get(0)?;
    let pass_version: u64 = row.get(1)?;
    let kind_text: String = row.get(2)?;
    let confidence: f64 = row.get(3)?;

    let kind: FindingKind = serde_json::from_str(&kind_text)
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(2, Type::Text, Box::new(err)))?;

    Ok(Finding {
        pass_name,
        pass_version,
        kind,
        confidence,
    })
}

fn map_db_error(error: rusqlite::Error) -> Error {
    Error::DatabaseError(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::SessionStore;
    use crate::{Finding, FindingKind, Result};

    fn temp_store_path(test_name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("endeavour-{test_name}-{}.db", uuid::Uuid::new_v4()))
    }

    fn remove_if_exists(path: &Path) -> Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    #[test]
    fn create_list_session_round_trip() -> Result<()> {
        let path = temp_store_path("create-list-session");
        let store = SessionStore::open(&path)?;

        let binary_id = uuid::Uuid::new_v4();
        let created = store.create_session("demo-session", binary_id)?;
        let listed = store.list_sessions()?;

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], created);

        remove_if_exists(&path)
    }

    #[test]
    fn add_and_get_findings() -> Result<()> {
        let path = temp_store_path("findings");
        let store = SessionStore::open(&path)?;

        let session = store.create_session("findings-session", uuid::Uuid::new_v4())?;
        let finding = Finding {
            pass_name: "mba-simplifier".to_string(),
            pass_version: 1,
            kind: FindingKind::MBASimplified,
            confidence: 0.93,
        };

        store.add_finding(session.id, &finding)?;
        let findings = store.get_findings(session.id)?;

        assert_eq!(findings, vec![finding]);

        remove_if_exists(&path)
    }

    #[test]
    fn deleting_session_cascades_findings() -> Result<()> {
        let path = temp_store_path("cascade-delete");
        let store = SessionStore::open(&path)?;

        let session = store.create_session("cascade-session", uuid::Uuid::new_v4())?;
        let finding = Finding {
            pass_name: "renamer".to_string(),
            pass_version: 3,
            kind: FindingKind::Rename,
            confidence: 0.8,
        };

        store.add_finding(session.id, &finding)?;
        store.delete_session(session.id)?;

        let findings = store.get_findings(session.id)?;
        assert!(findings.is_empty());

        remove_if_exists(&path)
    }

    #[test]
    fn opening_new_path_runs_schema_migrations() -> Result<()> {
        let path = temp_store_path("migrations");
        let store = SessionStore::open(&path)?;

        let sessions = store.list_sessions()?;
        assert!(sessions.is_empty());

        remove_if_exists(&path)
    }
}

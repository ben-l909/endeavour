use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Row, params, types::Type};
use uuid::Uuid;

use crate::{
    Error, Finding, FindingKind, NewReviewQueueRecord, NewTranscriptRecord, Result,
    ReviewQueueRecord, Session, TranscriptRecord,
};

/// SQLite-backed session and artifact store.
pub struct SessionStore {
    conn: Connection,
}

/// Statistics about cached IDA analysis results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheStats {
    /// Number of cached entries.
    pub entry_count: u64,
    /// List of distinct analysis methods cached.
    pub methods: Vec<String>,
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

    /// Cache an IDA analysis result for a given method and address.
    pub fn cache_ida_result(
        &self,
        session_id: Uuid,
        method: &str,
        address: u64,
        response: &str,
    ) -> Result<()> {
        let id = Uuid::new_v4();
        let cached_at = rfc3339_now(&self.conn)?;
        let address = address_to_i64(address)?;

        self.conn
            .execute(
                "INSERT OR REPLACE INTO ida_cache (id, session_id, method, address, response_json, cached_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    id.to_string(),
                    session_id.to_string(),
                    method,
                    address,
                    response,
                    cached_at
                ],
            )
            .map_err(map_db_error)?;

        Ok(())
    }

    /// Retrieve a cached IDA analysis result, if it exists.
    pub fn get_cached_ida_result(
        &self,
        session_id: Uuid,
        method: &str,
        address: u64,
    ) -> Result<Option<String>> {
        let address = address_to_i64(address)?;
        self.conn
            .query_row(
                "SELECT response_json
                 FROM ida_cache
                 WHERE session_id = ?1 AND method = ?2 AND address = ?3",
                params![session_id.to_string(), method, address],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_db_error)
    }

    /// Clear all cached IDA analysis results for a session.
    pub fn clear_ida_cache(&self, session_id: Uuid) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM ida_cache WHERE session_id = ?1",
                params![session_id.to_string()],
            )
            .map_err(map_db_error)?;

        Ok(())
    }

    /// Get statistics about cached IDA analysis results.
    pub fn cache_stats(&self, session_id: Uuid) -> Result<CacheStats> {
        let entry_count: u64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM ida_cache WHERE session_id = ?1",
                params![session_id.to_string()],
                |row| row.get(0),
            )
            .map_err(map_db_error)?;

        let mut statement = self
            .conn
            .prepare(
                "SELECT DISTINCT method
                 FROM ida_cache
                 WHERE session_id = ?1
                 ORDER BY method ASC",
            )
            .map_err(map_db_error)?;

        let rows = statement
            .query_map(params![session_id.to_string()], |row| row.get(0))
            .map_err(map_db_error)?;

        let methods = rows
            .collect::<std::result::Result<Vec<String>, _>>()
            .map_err(map_db_error)?;

        Ok(CacheStats {
            entry_count,
            methods,
        })
    }

    pub fn add_review_queue_entry(
        &self,
        session_id: Uuid,
        record: &NewReviewQueueRecord,
    ) -> Result<()> {
        let id = Uuid::new_v4();
        let created_at = rfc3339_now(&self.conn)?;

        self.conn
            .execute(
                "INSERT INTO review_queue (id, session_id, kind, function_addr, target_addr, current_name, proposed_value, confidence, status, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9)",
                params![
                    id.to_string(),
                    session_id.to_string(),
                    &record.kind,
                    address_to_i64(record.function_addr)?,
                    record.target_addr.map(address_to_i64).transpose()?,
                    &record.current_name,
                    &record.proposed_value,
                    record.confidence,
                    created_at,
                ],
            )
            .map_err(map_db_error)?;

        Ok(())
    }

    pub fn list_pending_review_queue(&self, session_id: Uuid) -> Result<Vec<ReviewQueueRecord>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT id, session_id, kind, function_addr, target_addr, current_name, proposed_value, confidence, status, created_at
                 FROM review_queue
                 WHERE session_id = ?1 AND status = 'pending'
                 ORDER BY created_at ASC",
            )
            .map_err(map_db_error)?;

        let rows = statement
            .query_map(params![session_id.to_string()], review_queue_from_row)
            .map_err(map_db_error)?;

        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(map_db_error)
    }

    pub fn update_review_queue_status(&self, id: Uuid, status: &str) -> Result<()> {
        self.conn
            .execute(
                "UPDATE review_queue SET status = ?1 WHERE id = ?2",
                params![status, id.to_string()],
            )
            .map_err(map_db_error)?;
        Ok(())
    }

    pub fn update_all_review_queue_status(
        &self,
        session_id: Uuid,
        from_status: &str,
        to_status: &str,
    ) -> Result<usize> {
        self.conn
            .execute(
                "UPDATE review_queue SET status = ?1 WHERE session_id = ?2 AND status = ?3",
                params![to_status, session_id.to_string(), from_status],
            )
            .map_err(map_db_error)
    }

    pub fn add_transcript_entries(
        &self,
        session_id: Uuid,
        entries: &[NewTranscriptRecord],
    ) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        let mut statement = self
            .conn
            .prepare(
                "INSERT INTO transcript_entries (id, session_id, turn_number, role, timestamp, content_json, usage_json, state, tool_calls_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )
            .map_err(map_db_error)?;

        for entry in entries {
            statement
                .execute(params![
                    Uuid::new_v4().to_string(),
                    session_id.to_string(),
                    i64::from(entry.turn_number),
                    &entry.role,
                    &entry.timestamp,
                    &entry.content_json,
                    entry.usage_json.as_deref(),
                    &entry.state,
                    entry.tool_calls_json.as_deref(),
                ])
                .map_err(map_db_error)?;
        }

        Ok(())
    }

    pub fn get_transcript_entries(
        &self,
        session_id: Uuid,
        turn: Option<u32>,
    ) -> Result<Vec<TranscriptRecord>> {
        let base = "SELECT id, session_id, turn_number, role, timestamp, content_json, usage_json, state, tool_calls_json
                    FROM transcript_entries
                    WHERE session_id = ?1";

        let mut entries = Vec::new();
        if let Some(turn_number) = turn {
            let mut statement = self
                .conn
                .prepare(&format!(
                    "{base} AND turn_number = ?2 ORDER BY turn_number ASC, id ASC"
                ))
                .map_err(map_db_error)?;
            let rows = statement
                .query_map(
                    params![session_id.to_string(), i64::from(turn_number)],
                    transcript_from_row,
                )
                .map_err(map_db_error)?;
            for row in rows {
                entries.push(row.map_err(map_db_error)?);
            }
        } else {
            let mut statement = self
                .conn
                .prepare(&format!("{base} ORDER BY turn_number ASC, id ASC"))
                .map_err(map_db_error)?;
            let rows = statement
                .query_map(params![session_id.to_string()], transcript_from_row)
                .map_err(map_db_error)?;
            for row in rows {
                entries.push(row.map_err(map_db_error)?);
            }
        }

        Ok(entries)
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

        CREATE TABLE IF NOT EXISTS ida_cache (
            id TEXT PRIMARY KEY NOT NULL,
            session_id TEXT NOT NULL,
            method TEXT NOT NULL,
            address INTEGER NOT NULL,
            response_json TEXT NOT NULL,
            cached_at TEXT NOT NULL,
            FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_ida_cache_lookup
            ON ida_cache(session_id, method, address);

        CREATE TABLE IF NOT EXISTS review_queue (
            id TEXT PRIMARY KEY NOT NULL,
            session_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            function_addr INTEGER NOT NULL,
            target_addr INTEGER,
            current_name TEXT NOT NULL,
            proposed_value TEXT NOT NULL,
            confidence REAL NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_review_queue_session_status
            ON review_queue(session_id, status, created_at);

        CREATE TABLE IF NOT EXISTS transcript_entries (
            id TEXT PRIMARY KEY NOT NULL,
            session_id TEXT NOT NULL,
            turn_number INTEGER NOT NULL,
            role TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            content_json TEXT NOT NULL,
            usage_json TEXT,
            state TEXT NOT NULL,
            tool_calls_json TEXT,
            FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_transcript_session_turn
            ON transcript_entries(session_id, turn_number, id);
        ",
    )
    .map_err(map_db_error)
}

fn address_to_i64(address: u64) -> Result<i64> {
    i64::try_from(address).map_err(|_| {
        Error::DatabaseError(format!("address out of SQLite INTEGER range: {address}"))
    })
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

fn review_queue_from_row(row: &Row<'_>) -> rusqlite::Result<ReviewQueueRecord> {
    let id_text: String = row.get(0)?;
    let session_id_text: String = row.get(1)?;
    let function_addr: i64 = row.get(3)?;
    let target_addr: Option<i64> = row.get(4)?;

    let id = Uuid::parse_str(&id_text)
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(0, Type::Text, Box::new(err)))?;
    let session_id = Uuid::parse_str(&session_id_text)
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(1, Type::Text, Box::new(err)))?;

    Ok(ReviewQueueRecord {
        id,
        session_id,
        kind: row.get(2)?,
        function_addr: u64::try_from(function_addr).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(3, Type::Integer, Box::new(err))
        })?,
        target_addr: target_addr
            .map(|value| {
                u64::try_from(value).map_err(|err| {
                    rusqlite::Error::FromSqlConversionFailure(4, Type::Integer, Box::new(err))
                })
            })
            .transpose()?,
        current_name: row.get(5)?,
        proposed_value: row.get(6)?,
        confidence: row.get(7)?,
        status: row.get(8)?,
        created_at: row.get(9)?,
    })
}

fn transcript_from_row(row: &Row<'_>) -> rusqlite::Result<TranscriptRecord> {
    let id_text: String = row.get(0)?;
    let session_id_text: String = row.get(1)?;
    let turn_number: i64 = row.get(2)?;

    let id = Uuid::parse_str(&id_text)
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(0, Type::Text, Box::new(err)))?;
    let session_id = Uuid::parse_str(&session_id_text)
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(1, Type::Text, Box::new(err)))?;

    Ok(TranscriptRecord {
        id,
        session_id,
        turn_number: u32::try_from(turn_number).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(2, Type::Integer, Box::new(err))
        })?,
        role: row.get(3)?,
        timestamp: row.get(4)?,
        content_json: row.get(5)?,
        usage_json: row.get(6)?,
        state: row.get(7)?,
        tool_calls_json: row.get(8)?,
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

    #[test]
    fn cache_round_trip_and_stats() -> Result<()> {
        let path = temp_store_path("cache-round-trip");
        let store = SessionStore::open(&path)?;
        let session = store.create_session("cache-session", uuid::Uuid::new_v4())?;

        let payload = serde_json::json!({
            "address": 0x401000u64,
            "pseudocode": "int x = 1;"
        })
        .to_string();

        store.cache_ida_result(session.id, "decompile", 0x401000, &payload)?;

        let cached = store.get_cached_ida_result(session.id, "decompile", 0x401000)?;
        assert_eq!(cached, Some(payload));

        let stats = store.cache_stats(session.id)?;
        assert_eq!(stats.entry_count, 1);
        assert_eq!(stats.methods, vec!["decompile".to_string()]);

        remove_if_exists(&path)
    }

    #[test]
    fn cache_upsert_replaces_existing_value() -> Result<()> {
        let path = temp_store_path("cache-upsert");
        let store = SessionStore::open(&path)?;
        let session = store.create_session("cache-upsert-session", uuid::Uuid::new_v4())?;

        let first = serde_json::json!({"address": 0x401000u64, "pseudocode": "old"}).to_string();
        let second = serde_json::json!({"address": 0x401000u64, "pseudocode": "new"}).to_string();

        store.cache_ida_result(session.id, "decompile", 0x401000, &first)?;
        store.cache_ida_result(session.id, "decompile", 0x401000, &second)?;

        let cached = store.get_cached_ida_result(session.id, "decompile", 0x401000)?;
        assert_eq!(cached, Some(second));

        let stats = store.cache_stats(session.id)?;
        assert_eq!(stats.entry_count, 1);

        remove_if_exists(&path)
    }

    #[test]
    fn clear_cache_removes_entries() -> Result<()> {
        let path = temp_store_path("cache-clear");
        let store = SessionStore::open(&path)?;
        let session = store.create_session("cache-clear-session", uuid::Uuid::new_v4())?;

        let payload = serde_json::json!({"address": 0x401000u64, "pseudocode": "x"}).to_string();
        store.cache_ida_result(session.id, "decompile", 0x401000, &payload)?;
        store.clear_ida_cache(session.id)?;

        let cached = store.get_cached_ida_result(session.id, "decompile", 0x401000)?;
        assert!(cached.is_none());

        let stats = store.cache_stats(session.id)?;
        assert_eq!(stats.entry_count, 0);
        assert!(stats.methods.is_empty());

        remove_if_exists(&path)
    }

    #[test]
    fn deleting_session_cascades_cache_entries() -> Result<()> {
        let path = temp_store_path("cache-cascade-delete");
        let store = SessionStore::open(&path)?;
        let session = store.create_session("cache-cascade-session", uuid::Uuid::new_v4())?;

        let payload = serde_json::json!({"address": 0x401000u64, "pseudocode": "x"}).to_string();
        store.cache_ida_result(session.id, "decompile", 0x401000, &payload)?;
        store.delete_session(session.id)?;

        let cached = store.get_cached_ida_result(session.id, "decompile", 0x401000)?;
        assert!(cached.is_none());

        remove_if_exists(&path)
    }
}

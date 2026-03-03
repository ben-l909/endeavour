use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread;

use anyhow::{anyhow, bail, Context, Result};
use endeavour_core::loader::load_binary;
use endeavour_core::store::SessionStore;
use endeavour_core::{Finding, FindingKind};
use rusqlite::Connection;
use tempfile::TempDir;
use uuid::Uuid;

#[test]
fn session_crud_round_trip_with_findings() -> Result<()> {
    let tempdir = TempDir::new().context("failed to create temp directory")?;
    let db_path = tempdir.path().join("session-crud.db");
    let store = SessionStore::open(&db_path)?;

    let binary_id = Uuid::new_v4();
    let session = store.create_session("crud-session", binary_id)?;

    let fetched = store.get_session(session.id)?;
    assert_eq!(fetched.id, session.id);
    assert_eq!(fetched.binary_id, binary_id);
    assert_eq!(fetched.name, "crud-session");

    let listed = store.list_sessions()?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, session.id);

    let finding = Finding {
        pass_name: "renamer".to_string(),
        pass_version: 4,
        kind: FindingKind::Rename,
        confidence: 0.88,
    };
    store.add_finding(session.id, &finding)?;

    let findings = store.get_findings(session.id)?;
    assert_eq!(findings, vec![finding]);

    Ok(())
}

#[test]
fn store_enables_wal_mode() -> Result<()> {
    let tempdir = TempDir::new().context("failed to create temp directory")?;
    let db_path = tempdir.path().join("wal-mode.db");
    let store = SessionStore::open(&db_path)?;
    drop(store);

    let conn = Connection::open(&db_path).context("failed to open db directly")?;
    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .context("failed to query PRAGMA journal_mode")?;
    assert_eq!(journal_mode.to_ascii_lowercase(), "wal");

    Ok(())
}

#[test]
fn concurrent_writers_can_add_findings() -> Result<()> {
    let tempdir = TempDir::new().context("failed to create temp directory")?;
    let db_path = tempdir.path().join("concurrent.db");
    let base_store = SessionStore::open(&db_path)?;
    let session = base_store.create_session("concurrent-session", Uuid::new_v4())?;

    let shared_db_path = Arc::new(db_path);
    let workers = 6usize;

    let mut handles = Vec::new();
    for index in 0..workers {
        let db_path_for_thread = Arc::clone(&shared_db_path);
        let session_id = session.id;
        handles.push(thread::spawn(move || -> Result<()> {
            let store = SessionStore::open(&db_path_for_thread)?;
            let finding = Finding {
                pass_name: format!("worker-{index}"),
                pass_version: index as u64,
                kind: FindingKind::Comment,
                confidence: 0.5 + (index as f64 * 0.05),
            };
            store.add_finding(session_id, &finding)?;
            Ok(())
        }));
    }

    for handle in handles {
        match handle.join() {
            Ok(result) => result?,
            Err(join_error) => {
                return Err(anyhow!("worker thread panicked: {join_error:?}"));
            }
        }
    }

    let persisted = base_store.get_findings(session.id)?;
    assert_eq!(persisted.len(), workers);

    let pass_names: HashSet<String> = persisted
        .iter()
        .map(|finding| finding.pass_name.clone())
        .collect();

    for index in 0..workers {
        assert!(
            pass_names.contains(&format!("worker-{index}")),
            "missing finding from worker-{index}"
        );
    }

    Ok(())
}

#[test]
fn deleting_session_cascades_to_findings() -> Result<()> {
    let tempdir = TempDir::new().context("failed to create temp directory")?;
    let db_path = tempdir.path().join("cascade-delete.db");
    let store = SessionStore::open(&db_path)?;
    let session = store.create_session("cascade-session", Uuid::new_v4())?;

    let finding = Finding {
        pass_name: "type-fixer".to_string(),
        pass_version: 2,
        kind: FindingKind::TypeChange,
        confidence: 0.77,
    };
    store.add_finding(session.id, &finding)?;

    store.delete_session(session.id)?;

    let findings_after_delete = store.get_findings(session.id)?;
    assert!(
        findings_after_delete.is_empty(),
        "findings should be removed via cascade delete"
    );

    let deleted_session = store.get_session(session.id);
    assert!(
        deleted_session.is_err(),
        "expected get_session to fail after deleting session"
    );

    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn loader_to_store_pipeline_round_trip() -> Result<()> {
    let tempdir = TempDir::new().context("failed to create temp directory")?;
    let binary_path = compile_c_binary(
        tempdir.path(),
        "pipeline",
        "arm64",
        "int main(void) { return 0; }",
    )
    .context("failed to build pipeline binary")?;

    let binary = load_binary(&binary_path)
        .with_context(|| format!("failed to parse {}", binary_path.display()))?;

    let db_path = tempdir.path().join("pipeline.db");
    let store = SessionStore::open(&db_path)?;
    let session = store.create_session("pipeline-session", binary.uuid)?;

    let first_finding = Finding {
        pass_name: "mba-simplifier".to_string(),
        pass_version: 1,
        kind: FindingKind::MBASimplified,
        confidence: 0.93,
    };
    let second_finding = Finding {
        pass_name: "commenter".to_string(),
        pass_version: 2,
        kind: FindingKind::Comment,
        confidence: 0.81,
    };

    store.add_finding(session.id, &first_finding)?;
    store.add_finding(session.id, &second_finding)?;

    let fetched = store.get_session(session.id)?;
    assert_eq!(fetched.binary_id, binary.uuid);

    let findings = store.get_findings(session.id)?;
    assert_eq!(findings, vec![first_finding, second_finding]);

    Ok(())
}

#[cfg(target_os = "macos")]
fn compile_c_binary(out_dir: &Path, stem: &str, arch: &str, source: &str) -> Result<PathBuf> {
    let source_path = out_dir.join(format!("{stem}.c"));
    let output_path = out_dir.join(format!("{stem}.macho"));

    fs::write(&source_path, source)
        .with_context(|| format!("failed to write {}", source_path.display()))?;

    let output = Command::new("clang")
        .arg("-arch")
        .arg(arch)
        .arg("-g")
        .arg("-O0")
        .arg("-o")
        .arg(&output_path)
        .arg(&source_path)
        .output()
        .with_context(|| format!("failed to execute clang for {arch}"))?;

    if !output.status.success() {
        bail!(
            "clang failed for {arch}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(output_path)
}

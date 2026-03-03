use std::path::{Path, PathBuf};

use endeavour_core::{loader::load_binary, store::SessionStore, Finding, FindingKind, Result};

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

fn cleanup_store_files(path: &Path) -> Result<()> {
    remove_if_exists(path)?;

    let wal_path = PathBuf::from(format!("{}-wal", path.display()));
    let shm_path = PathBuf::from(format!("{}-shm", path.display()));
    remove_if_exists(&wal_path)?;
    remove_if_exists(&shm_path)
}

#[cfg(target_os = "macos")]
#[test]
fn loader_store_pipeline_round_trip_usr_bin_true() -> Result<()> {
    let binary = load_binary(Path::new("/usr/bin/true"))?;
    let store_path = temp_store_path("pipeline-roundtrip");
    let store = SessionStore::open(&store_path)?;

    let session = store.create_session("integration-pipeline", binary.uuid)?;
    assert_eq!(session.binary_id, binary.uuid);

    let first_finding = Finding {
        pass_name: "mba-simplifier".to_string(),
        pass_version: 1,
        kind: FindingKind::MBASimplified,
        confidence: 0.91,
    };
    let second_finding = Finding {
        pass_name: "renamer".to_string(),
        pass_version: 2,
        kind: FindingKind::Rename,
        confidence: 0.84,
    };

    store.add_finding(session.id, &first_finding)?;
    store.add_finding(session.id, &second_finding)?;

    let fetched_session = store.get_session(session.id)?;
    assert_eq!(fetched_session.id, session.id);
    assert_eq!(fetched_session.name, session.name);
    assert_eq!(fetched_session.binary_id, binary.uuid);

    let findings = store.get_findings(session.id)?;
    assert_eq!(findings, vec![first_finding, second_finding]);

    drop(store);
    cleanup_store_files(&store_path)
}

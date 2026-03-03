use crate::repl::Repl;
use anyhow::{Context, Result};

pub(crate) fn handle_session_new(_repl: &mut Repl) -> Result<()> {
    println!("✗ error: session creation requires a binary path");
    println!("    ╰─ run 'analyze <path>' to create and activate a new session");
    Ok(())
}

pub(crate) fn handle_sessions(repl: &Repl) -> Result<()> {
    let sessions = repl
        .store
        .list_sessions()
        .context("failed to list sessions")?;
    if sessions.is_empty() {
        println!("No sessions found.");
        return Ok(());
    }

    println!("ID                                   NAME                    BINARY ID                            CREATED");
    for session in sessions {
        println!(
            "{}  {:<22}  {}  {}",
            session.id, session.name, session.binary_id, session.created_at
        );
    }

    Ok(())
}

pub(crate) fn handle_session_switch(repl: &mut Repl, id: &str) -> Result<()> {
    let session_id = id
        .parse()
        .with_context(|| format!("invalid session id: {id}"))?;
    let session = repl
        .store
        .get_session(session_id)
        .with_context(|| format!("failed to load session {id}"))?;
    println!("Active session: {} ({})", session.name, session.id);
    repl.active_session = Some(session);
    Ok(())
}

pub(crate) fn handle_info(repl: &Repl) -> Result<()> {
    let Some(session) = &repl.active_session else {
        println!("✗ error: no active session");
        println!("    ╰─ run 'session new' to start a session");
        return Ok(());
    };

    let findings = repl
        .store
        .get_findings(session.id)
        .with_context(|| format!("failed to fetch findings for session {}", session.id))?;

    println!("Session: {}", session.name);
    println!("Session ID: {}", session.id);
    println!("Binary ID: {}", session.binary_id);
    println!("Findings: {}", findings.len());
    Ok(())
}

pub(crate) fn handle_findings(repl: &Repl) -> Result<()> {
    let Some(session) = &repl.active_session else {
        println!("No active session. Use 'analyze <path>' or 'session <id>'.");
        return Ok(());
    };

    let findings = repl
        .store
        .get_findings(session.id)
        .with_context(|| format!("failed to fetch findings for session {}", session.id))?;

    if findings.is_empty() {
        println!("No findings for active session.");
        return Ok(());
    }

    println!("#   PASS                VERSION   KIND                   CONFIDENCE");
    for (index, finding) in findings.iter().enumerate() {
        println!(
            "{:<3} {:<19} {:<9} {:<22} {:.2}",
            index + 1,
            finding.pass_name,
            finding.pass_version,
            format!("{:?}", finding.kind),
            finding.confidence
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use endeavour_core::store::SessionStore;

    #[test]
    fn session_commands_create_and_lookup_session() {
        let temp = tempfile::tempdir();
        assert!(temp.is_ok());
        let temp = temp.unwrap_or_else(|_| unreachable!());
        let store = SessionStore::open(&temp.path().join("session-tests.db"));
        assert!(store.is_ok());
        let store = store.unwrap_or_else(|_| unreachable!());

        let created = store.create_session("sample.bin", uuid::Uuid::new_v4());
        assert!(created.is_ok());
        let created = created.unwrap_or_else(|_| unreachable!());
        let loaded = store.get_session(created.id);
        assert!(loaded.is_ok());
        let loaded = loaded.unwrap_or_else(|_| unreachable!());
        assert_eq!(loaded.id, created.id);
        assert_eq!(loaded.name, "sample.bin");
    }
}

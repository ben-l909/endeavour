use std::process::Output;
use std::sync::Arc;

use assert_cmd::Command;
use endeavour_llm::mock::{MockIdaError, MockIdaTransport};
use tempfile::TempDir;

mod repl {
    use std::sync::Arc;

    use endeavour_ida::IdaClient;

    pub(crate) struct Repl {
        pub(crate) ida_client: Option<Arc<IdaClient>>,
        pub(crate) runtime: tokio::runtime::Runtime,
    }
}

#[path = "../src/commands/connect.rs"]
mod connect_impl;

fn run_repl_script(script: &str) -> Output {
    let temp_home =
        TempDir::new().unwrap_or_else(|err| panic!("failed to create temp HOME: {err}"));
    let store_path = temp_home.path().join("store.db");

    Command::new(assert_cmd::cargo::cargo_bin!("endeavour"))
        .env("HOME", temp_home.path())
        .args([
            "--store-path",
            store_path
                .to_str()
                .unwrap_or_else(|| panic!("store path must be valid UTF-8")),
            "repl",
        ])
        .write_stdin(script)
        .output()
        .unwrap_or_else(|err| panic!("failed to run repl script: {err}"))
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8(output.stdout.clone())
        .unwrap_or_else(|err| panic!("repl stdout is not valid UTF-8: {err}"))
}

#[test]
fn error_paths_connect_method_not_found_mock_transport_returns_error() {
    let runtime = tokio::runtime::Runtime::new()
        .unwrap_or_else(|err| panic!("failed to create runtime: {err}"));
    let transport = Arc::new(
        MockIdaTransport::builder()
            .fail_all(MockIdaError::MethodNotFound)
            .build(),
    );

    let result =
        connect_impl::connect_with_transport(&runtime, "localhost:13337", transport).map(|_| ());

    assert!(result.is_err());
    let err = result
        .err()
        .map(|value| format!("{value:#}"))
        .unwrap_or_else(|| panic!("expected connect to fail"));
    assert!(err.contains("Method not found") || err.contains("-32601"));
}

#[test]
fn error_paths_connect_handler_crash_path_exits_non_zero() {
    let output = run_repl_script("connect localhost\nhelp\nquit\n");
    let stdout = stdout_text(&output);

    assert!(!output.status.success());
    assert!(stdout.contains("Welcome to endeavour REPL"));
}

#[test]
fn error_paths_session_info_no_active_session_prints_error_and_continues() {
    let output = run_repl_script("session info\nhelp\nquit\n");
    let stdout = stdout_text(&output);

    assert!(output.status.success());
    assert!(stdout.contains("✗ error: no active session"));
    assert!(stdout.contains("Available commands:"));
}

#[test]
fn error_paths_analyze_missing_path_usage_error() {
    let output = run_repl_script("analyze\nhelp\nquit\n");
    let stdout = stdout_text(&output);

    assert!(output.status.success());
    assert!(stdout.contains("Usage: analyze <path>"));
}

#[test]
fn error_paths_ida_status_not_connected() {
    let output = run_repl_script("ida-status\nquit\n");
    let stdout = stdout_text(&output);

    assert!(output.status.success());
    assert!(stdout.contains("Not connected. Run: connect <host:port>"));
}

#[test]
fn error_paths_explain_not_connected() {
    let output = run_repl_script("explain 0x401000\nquit\n");
    let stdout = stdout_text(&output);

    assert!(output.status.success());
    assert!(stdout.contains("Not connected. Run: connect <host:port>"));
}

#[test]
fn error_paths_rename_no_active_session() {
    let output = run_repl_script("rename --llm 0x401000\nhelp\nquit\n");
    let stdout = stdout_text(&output);

    assert!(output.status.success());
    assert!(stdout.contains("✗ error: no active session"));
    assert!(stdout.contains("Available commands:"));
}

#[test]
fn error_paths_review_no_active_session() {
    let output = run_repl_script("review\nquit\n");
    let stdout = stdout_text(&output);

    assert!(output.status.success());
    assert!(stdout.contains("✗ error: no active session"));
}

#[test]
fn error_paths_comment_not_connected() {
    let output = run_repl_script("comment 0x401000 hello\nquit\n");
    let stdout = stdout_text(&output);

    assert!(output.status.success());
    assert!(stdout.contains("Not connected. Run: connect <host:port>"));
}

#[test]
fn error_paths_callgraph_not_connected() {
    let output = run_repl_script("callgraph 0x401000\nquit\n");
    let stdout = stdout_text(&output);

    assert!(output.status.success());
    assert!(stdout.contains("Not connected. Run: connect <host:port>"));
}

#[test]
fn error_paths_search_not_connected() {
    let output = run_repl_script("search main\nquit\n");
    let stdout = stdout_text(&output);

    assert!(output.status.success());
    assert!(stdout.contains("Not connected. Run: connect <host:port>"));
}

#[test]
fn error_paths_session_switch_invalid_subcommand_prints_error() {
    let output = run_repl_script("session not-a-uuid\nhelp\nquit\n");
    let stdout = stdout_text(&output);

    assert!(output.status.success());
    assert!(stdout.contains("✗ error: unknown session subcommand 'not-a-uuid'"));
    assert!(stdout.contains("Available commands:"));
}

#[test]
fn error_paths_findings_no_active_session() {
    let output = run_repl_script("findings\nquit\n");
    let stdout = stdout_text(&output);

    assert!(output.status.success());
    assert!(stdout.contains("No active session. Use 'analyze <path>' or 'session <id>'."));
}

#[test]
fn error_paths_cache_stats_no_active_session() {
    let output = run_repl_script("cache stats\nquit\n");
    let stdout = stdout_text(&output);

    assert!(output.status.success());
    assert!(stdout.contains("No active session. Use 'analyze <path>' or 'session <id>'."));
}

#[test]
fn error_paths_cache_clear_no_active_session() {
    let output = run_repl_script("cache clear\nquit\n");
    let stdout = stdout_text(&output);

    assert!(output.status.success());
    assert!(stdout.contains("No active session. Use 'analyze <path>' or 'session <id>'."));
}

#[test]
fn error_paths_config_set_unknown_key_crash_path_exits_non_zero() {
    let output = run_repl_script("config set theme dark\nhelp\nquit\n");
    assert!(!output.status.success());
}

#[test]
fn error_paths_config_get_unknown_key_crash_path_exits_non_zero() {
    let output = run_repl_script("config get theme\nhelp\nquit\n");
    assert!(!output.status.success());
}

#[test]
fn error_paths_config_list_loads_defaults_without_crashing() {
    let output = run_repl_script("config list\nquit\n");
    let stdout = stdout_text(&output);

    assert!(output.status.success());
    assert!(stdout.contains("anthropic-api-key = <not set>"));
}

#[test]
fn error_paths_show_transcript_invalid_uuid_crash_path_exits_non_zero() {
    let output = run_repl_script("show-transcript not-a-uuid\nhelp\nquit\n");
    assert!(!output.status.success());
}

#[test]
fn error_paths_sessions_with_empty_store_reports_no_sessions() {
    let output = run_repl_script("sessions\nquit\n");
    let stdout = stdout_text(&output);

    assert!(output.status.success());
    assert!(stdout.contains("No sessions found."));
}

#[test]
fn error_paths_flood_50_malformed_inputs_repl_stays_alive() {
    let mut script = String::new();
    let patterns = [
        "session not-a-uuid",
        "frobulate",
        "rename",
        "callgraph",
        "config",
        "comment 0x401000",
        "show-transcript --turn nope",
        "search",
        "review extra",
        "explain",
    ];

    for _ in 0..5 {
        for pattern in patterns {
            script.push_str(pattern);
            script.push('\n');
        }
    }
    script.push_str("help\nquit\n");

    let output = run_repl_script(&script);
    let stdout = stdout_text(&output);

    assert!(output.status.success());
    assert!(stdout.contains("Available commands:"));
    assert!(stdout.matches("Usage:").count() >= 20);
}

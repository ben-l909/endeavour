use assert_cmd::Command;
use tempfile::TempDir;

fn run_repl_script(script: &str) -> String {
    let temp_home =
        TempDir::new().unwrap_or_else(|err| panic!("failed to create temp HOME: {err}"));
    let store_path = temp_home.path().join("store.db");

    let output = Command::new(assert_cmd::cargo::cargo_bin!("endeavour"))
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
        .unwrap_or_else(|err| panic!("failed to run repl script: {err}"));

    assert!(output.status.success(), "repl process exited with failure");
    String::from_utf8(output.stdout)
        .unwrap_or_else(|err| panic!("repl stdout is not valid UTF-8: {err}"))
}

#[test]
fn version_flag_exits_zero_and_prints_version() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("endeavour"));
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(format!("endeavour {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_flag_exits_zero() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("endeavour"));
    cmd.arg("--help");
    cmd.assert().success();
}

#[test]
fn analyze_without_path_exits_with_error() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("endeavour"));
    cmd.arg("analyze");
    cmd.assert().failure();
}

#[test]
fn repl_subcommand_help_exits_zero() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("endeavour"));
    cmd.args(["repl", "--help"]);
    cmd.assert().success();
}

#[test]
fn session_info_without_active_session_prints_error_and_repl_continues() {
    let stdout = run_repl_script("session info\nhelp\nquit\n");

    assert!(stdout.contains("✗ error: no active session"));
    assert!(stdout.contains("    ╰─ run 'session new' to start a session"));
    assert!(stdout.contains("Available commands:"));
}

#[test]
fn session_non_uuid_prints_unknown_subcommand_error_and_repl_continues() {
    let stdout = run_repl_script("session abc\nhelp\nquit\n");

    assert!(stdout.contains("✗ error: unknown session subcommand 'abc'"));
    assert!(stdout.contains("    ╰─ valid subcommands: new, list, load <id>, info"));
    assert!(stdout.contains("Available commands:"));
}

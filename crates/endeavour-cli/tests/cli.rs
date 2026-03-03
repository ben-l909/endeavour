use assert_cmd::Command;

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

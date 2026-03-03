use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use endeavour_core::loader::{load_binary, parse_macho};
use endeavour_core::{Arch, SymbolKind};
use tempfile::TempDir;

#[test]
fn load_binary_missing_file_returns_io_error() {
    let missing = PathBuf::from("/tmp/endeavour-loader-does-not-exist.bin");
    let result = load_binary(&missing);
    assert!(result.is_err(), "expected missing-file failure");

    if let Err(error) = result {
        let message = error.to_string();
        assert!(
            message.contains("IO error"),
            "expected IO error message, got: {message}"
        );
    }
}

#[test]
fn parse_macho_invalid_data_returns_parse_error() {
    let result = parse_macho(&[0xde, 0xad, 0xbe, 0xef], PathBuf::from("invalid.bin"));
    assert!(result.is_err(), "expected parse error for invalid bytes");

    if let Err(error) = result {
        let message = error.to_string();
        assert!(
            message.contains("parse") || message.contains("Mach-O"),
            "expected parse-related error, got: {message}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn load_binary_extracts_segments_and_symbols() -> Result<()> {
    let tempdir = TempDir::new().context("failed to create temp directory")?;
    let source = r#"
int global_counter = 7;

static int helper(int value) {
    return value + global_counter;
}

int main(void) {
    return helper(3);
}
"#;

    let binary_path = compile_c_binary(tempdir.path(), "arm64-test", "arm64", source)
        .context("failed to build arm64 Mach-O test binary")?;

    let parsed = load_binary(&binary_path)
        .with_context(|| format!("failed to parse binary {}", binary_path.display()))?;

    assert_eq!(parsed.arch, Arch::Arm64);
    assert!(
        parsed
            .segments
            .iter()
            .any(|segment| segment.name == "__TEXT"),
        "expected __TEXT segment in parsed binary"
    );
    assert!(
        parsed
            .segments
            .iter()
            .flat_map(|segment| segment.sections.iter())
            .any(|section| section.name == "__text"),
        "expected __text section in parsed binary"
    );
    assert!(
        parsed
            .symbols
            .iter()
            .any(|symbol| symbol.name == "_main" && symbol.kind == SymbolKind::Function),
        "expected _main function symbol"
    );
    assert!(
        parsed
            .symbols
            .iter()
            .any(|symbol| symbol.name == "_global_counter" && symbol.kind == SymbolKind::Data),
        "expected global data symbol"
    );

    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn parse_macho_truncated_binary_returns_parse_error() -> Result<()> {
    let tempdir = TempDir::new().context("failed to create temp directory")?;
    let source = "int main(void) { return 0; }";
    let binary_path = compile_c_binary(tempdir.path(), "truncated-test", "arm64", source)
        .context("failed to build binary for truncation test")?;
    let bytes = fs::read(&binary_path)
        .with_context(|| format!("failed to read {}", binary_path.display()))?;
    assert!(bytes.len() > 64, "compiled binary is unexpectedly tiny");

    let truncated = bytes.into_iter().take(64).collect::<Vec<u8>>();
    let result = parse_macho(&truncated, binary_path.clone());
    assert!(
        result.is_err(),
        "expected parse failure for truncated binary"
    );

    if let Err(error) = result {
        let message = error.to_string();
        assert!(
            message.contains("parse") || message.contains("Mach-O"),
            "expected parse-related error, got: {message}"
        );
    }

    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn load_binary_universal_macho_selects_host_arch() -> Result<()> {
    let tempdir = TempDir::new().context("failed to create temp directory")?;
    let source = "int main(void) { return 42; }";

    let arm64_bin = compile_c_binary(tempdir.path(), "fat-arm64", "arm64", source)
        .context("failed to build arm64 slice")?;
    let x86_64_bin = compile_c_binary(tempdir.path(), "fat-x64", "x86_64", source)
        .context("failed to build x86_64 slice")?;

    let fat_path = tempdir.path().join("universal-fat");
    let output = Command::new("lipo")
        .arg("-create")
        .arg(&arm64_bin)
        .arg(&x86_64_bin)
        .arg("-output")
        .arg(&fat_path)
        .output()
        .context("failed to execute lipo")?;

    if !output.status.success() {
        bail!(
            "lipo failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let parsed = load_binary(&fat_path)
        .with_context(|| format!("failed to parse universal binary {}", fat_path.display()))?;

    let expected_arch = match std::env::consts::ARCH {
        "aarch64" => Arch::Arm64,
        "x86_64" => Arch::X86_64,
        other => bail!("unsupported host architecture for this test: {other}"),
    };

    assert_eq!(parsed.arch, expected_arch);
    assert!(
        !parsed.segments.is_empty(),
        "expected parsed segments from selected architecture"
    );

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
        return Err(anyhow!(
            "clang failed for {arch}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(output_path)
}

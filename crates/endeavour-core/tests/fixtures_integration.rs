#[cfg(target_os = "macos")]
mod tests {
    use std::path::PathBuf;

    use endeavour_core::loader::load_binary;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
            .join("binary")
    }

    #[test]
    fn load_minimal_arm64_fixture() {
        let binary =
            load_binary(&fixture_path("minimal_arm64")).expect("loads minimal_arm64 fixture");
        assert!(!binary.segments.is_empty());
    }

    #[test]
    fn load_minimal_x86_64_fixture() {
        let binary =
            load_binary(&fixture_path("minimal_x86_64")).expect("loads minimal_x86_64 fixture");
        assert!(!binary.segments.is_empty());
    }

    #[test]
    fn load_objc_classes_fixture() {
        let binary =
            load_binary(&fixture_path("objc_classes")).expect("loads objc_classes fixture");
        assert!(binary.objc_metadata.is_some());
    }
}

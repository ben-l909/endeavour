#[cfg(target_os = "macos")]
mod tests {
    use std::path::PathBuf;

    use endeavour_core::loader::load_binary;
    use endeavour_core::{Arch, SymbolKind};

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

        assert_eq!(binary.arch, Arch::Arm64);
        assert!(binary
            .segments
            .iter()
            .any(|segment| segment.name == "__TEXT"));
        assert!(binary
            .segments
            .iter()
            .any(|segment| segment.name.starts_with("__DATA")));
        assert!(binary.symbols.iter().any(|symbol| {
            symbol.name == "_main" && symbol.kind == SymbolKind::Function && symbol.addr != 0
        }));
    }

    #[test]
    fn load_minimal_x86_64_fixture() {
        let binary =
            load_binary(&fixture_path("minimal_x86_64")).expect("loads minimal_x86_64 fixture");

        assert_eq!(binary.arch, Arch::X86_64);
        assert!(binary
            .segments
            .iter()
            .any(|segment| segment.name == "__TEXT"));
        assert!(binary.symbols.iter().any(|symbol| symbol.name == "_main"));
    }

    #[test]
    fn load_objc_classes_fixture() {
        let binary =
            load_binary(&fixture_path("objc_classes")).expect("loads objc_classes fixture");

        let metadata = binary
            .objc_metadata
            .as_ref()
            .expect("objc metadata is present for objc_classes fixture");

        let class_names: Vec<&str> = metadata
            .classes
            .iter()
            .map(|class| class.name.as_str())
            .collect();

        assert!(class_names.contains(&"Animal"));
        assert!(class_names.contains(&"Dog"));
        assert!(class_names.contains(&"Cat"));
    }
}

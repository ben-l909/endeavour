#[cfg(target_os = "macos")]
#[test]
fn parse_usr_bin_true_contains_expected_segments() {
    let binary =
        endeavour_core::loader::load_binary(std::path::Path::new("/usr/bin/true")).unwrap();

    assert!(!binary.segments.is_empty());

    let segment_names: Vec<&str> = binary
        .segments
        .iter()
        .map(|segment| segment.name.as_str())
        .collect();
    assert!(segment_names.contains(&"__TEXT"));
    assert!(segment_names.contains(&"__LINKEDIT"));
    assert!(segment_names.contains(&"__PAGEZERO"));
}

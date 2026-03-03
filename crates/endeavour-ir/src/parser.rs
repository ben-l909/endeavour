use crate::error::Result;
use crate::ir::MicrocodeProgram;

pub fn parse_microcode_json(input: &str) -> Result<MicrocodeProgram> {
    serde_json::from_str(input).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::parse_microcode_json;
    use crate::ir::MicrocodeProgram;

    fn assert_fixture_round_trip(path: &str) {
        let raw = std::fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("failed to read fixture {path}: {err}"));
        let parsed = parse_microcode_json(&raw)
            .unwrap_or_else(|err| panic!("failed to parse fixture {path}: {err}"));
        let encoded = serde_json::to_string_pretty(&parsed)
            .unwrap_or_else(|err| panic!("failed to serialize parsed fixture {path}: {err}"));
        let reparsed: MicrocodeProgram = serde_json::from_str(&encoded)
            .unwrap_or_else(|err| panic!("failed to parse round-trip fixture {path}: {err}"));
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn parses_arm64_fixture() {
        let fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/ida_microcode_arm64_add_xor.json"
        );
        assert_fixture_round_trip(fixture);
    }

    #[test]
    fn parses_x86_64_fixture() {
        let fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/ida_microcode_x86_64_branching.json"
        );
        assert_fixture_round_trip(fixture);
    }
}

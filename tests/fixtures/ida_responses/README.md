# IDA response fixtures

These fixtures model realistic IDA MCP response payloads consumed by `endeavour-ida::IdaClient` in Sprint 2 tests.

- `decompile_success.json`: Successful `decompile` payload for a small parser function using `addr` + `code` fields.
- `decompile_complex.json`: Successful `decompile` payload using `address` + `pseudocode` fallback fields with larger control-flow-heavy and MBA-style pseudocode.
- `decompile_error.json`: Error payload for `decompile` with an `error` field indicating no function exists at the target address.
- `search_matches.json`: Successful `find_regex` payload containing six realistic string hits with hexadecimal addresses.
- `search_empty.json`: Successful `find_regex` payload with no matches.
- `list_functions.json`: Successful `list_funcs` page containing ten functions for connection and listing scenarios.
- `connection_test.json`: Minimal successful `list_funcs` probe payload for lightweight connection validation.

All address and size values are encoded as strings (hex format), matching shapes accepted by `IdaClient` parsers.

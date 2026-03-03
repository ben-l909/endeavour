use endeavour_llm::AgenticLoopController;
use uuid::Uuid;

const KNOWN_COMMAND_KEYWORDS: &[&str] = &[
    "connect",
    "disconnect",
    "session",
    "sessions",
    "analyze",
    "explain",
    "rename",
    "review",
    "comment",
    "callgraph",
    "detect-mba",
    "search",
    "decompile",
    "lift",
    "findings",
    "info",
    "config",
    "show-transcript",
    "cache",
    "help",
    "quit",
];

const COMMAND_PHRASE_ALIASES: &[(&str, &str)] = &[
    ("detect mba", "detect-mba"),
    ("find obfuscation", "detect-mba"),
    ("scan for mba", "detect-mba"),
];

const CURRENT_FUNCTION_REFERENCES: &[&str] = &[
    "this function",
    "the current function",
    "what i'm looking at",
    "what i am looking at",
    "here",
    "decompile this",
];

const BINARY_REFERENCES: &[&str] = &["this binary", "the binary"];

const LIFT_NL_PHRASES: &[&str] = &[
    "lift this function",
    "show me the ir",
    "show me ir",
    "show the ir",
    "show ir",
    "show full ir",
    "expand ir",
    "show all statements",
    "decompile",
    "decompile this",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentSessionContext {
    pub session_id: Option<Uuid>,
    pub ida_connected: bool,
    pub binary_loaded: bool,
    pub binary_name: Option<String>,
    pub current_function_addr: Option<String>,
    pub current_function_name: Option<String>,
}

impl Default for IntentSessionContext {
    fn default() -> Self {
        Self {
            session_id: None,
            ida_connected: true,
            binary_loaded: true,
            binary_name: None,
            current_function_addr: None,
            current_function_name: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgenticIntentRequest {
    pub original_input: String,
    pub resolved_input: String,
    pub context: IntentSessionContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteOutcome {
    IgnoredEmpty,
    CommandDispatched,
    AgenticDispatched,
    SystemError(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum IntentRouterError {
    CommandDispatch(String),
    AgenticDispatch(String),
}

impl std::fmt::Display for IntentRouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommandDispatch(message) => write!(f, "command dispatch failed: {message}"),
            Self::AgenticDispatch(message) => write!(f, "agentic dispatch failed: {message}"),
        }
    }
}

impl std::error::Error for IntentRouterError {}

pub trait CommandIntentHandler {
    fn dispatch_command(&mut self, command_line: &str) -> Result<(), IntentRouterError>;
}

pub trait AgenticIntentHandler {
    fn dispatch_agentic(
        &mut self,
        controller: &mut AgenticLoopController,
        request: AgenticIntentRequest,
    ) -> Result<(), IntentRouterError>;
}

#[derive(Debug, Default)]
pub struct IntentRouter;

impl IntentRouter {
    pub fn new() -> Self {
        Self
    }

    pub fn route<C, A>(
        &self,
        input: &str,
        context: IntentSessionContext,
        controller: &mut AgenticLoopController,
        command_handler: &mut C,
        agentic_handler: &mut A,
    ) -> Result<RouteOutcome, IntentRouterError>
    where
        C: CommandIntentHandler,
        A: AgenticIntentHandler,
    {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(RouteOutcome::IgnoredEmpty);
        }

        if let Some(result) = detect_lift_nl_command(trimmed, &context) {
            match result {
                Ok(command) => {
                    command_handler.dispatch_command(&command)?;
                    return Ok(RouteOutcome::CommandDispatched);
                }
                Err(message) => return Ok(RouteOutcome::SystemError(message)),
            }
        }

        if let Some(command) = detect_command(trimmed) {
            command_handler.dispatch_command(&command)?;
            return Ok(RouteOutcome::CommandDispatched);
        }

        if trimmed.starts_with('/') {
            let keyword = trimmed
                .trim_start_matches('/')
                .split_whitespace()
                .next()
                .unwrap_or_default();
            return Ok(RouteOutcome::SystemError(format!(
                "unknown command '/{keyword}' — type 'help' to see available commands"
            )));
        }

        if requires_current_function(trimmed) && context.current_function_addr.is_none() {
            return Ok(RouteOutcome::SystemError(
                "I don't have a current function in focus. Provide an address or function name first."
                    .to_string(),
            ));
        }

        if !context.ida_connected {
            return Ok(RouteOutcome::SystemError(
                "Not connected to IDA. Run 'connect <host:port>' to connect first.".to_string(),
            ));
        }

        if !context.binary_loaded {
            return Ok(RouteOutcome::SystemError(
                "No binary loaded in this session. Start or switch to a session first.".to_string(),
            ));
        }

        let resolved_input = resolve_contextual_references(trimmed, &context);
        let request = AgenticIntentRequest {
            original_input: trimmed.to_string(),
            resolved_input,
            context,
        };
        agentic_handler.dispatch_agentic(controller, request)?;
        Ok(RouteOutcome::AgenticDispatched)
    }
}

fn detect_command(input: &str) -> Option<String> {
    let stripped = input.trim_start_matches('/').trim();

    for (phrase, command) in COMMAND_PHRASE_ALIASES {
        if let Some(remaining) = strip_case_insensitive_prefix(stripped, phrase) {
            if remaining.is_empty() || looks_like_command_args(remaining) {
                if remaining.is_empty() {
                    return Some((*command).to_string());
                }
                return Some(format!("{command} {remaining}"));
            }
        }
    }

    let keyword = stripped.split_whitespace().next()?;

    // Check if keyword is a known command
    if !KNOWN_COMMAND_KEYWORDS
        .iter()
        .any(|known| keyword.eq_ignore_ascii_case(known))
    {
        return None;
    }

    // If input starts with '/', it's an explicit command
    if input.trim_start().starts_with('/') {
        return Some(stripped.to_string());
    }

    // For non-slash inputs, check if the remaining text looks like command args
    // or natural language. If it's a bare keyword or has command-like args, it's a command.
    let remaining = stripped[keyword.len()..].trim();

    // Bare keyword (no args) is a command
    if remaining.is_empty() {
        return Some(stripped.to_string());
    }

    // Check if remaining text looks like command arguments (not natural language)
    // Command args typically: addresses (0x...), function names, simple identifiers
    // Natural language: multiple words, articles, prepositions, etc.
    if looks_like_command_args(remaining) {
        return Some(stripped.to_string());
    }

    // Otherwise, it's natural language containing a keyword
    None
}

fn strip_case_insensitive_prefix<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
    if input.len() < prefix.len() {
        return None;
    }

    let (head, tail) = input.split_at(prefix.len());
    if !head.eq_ignore_ascii_case(prefix) {
        return None;
    }

    if !tail.is_empty() && !tail.starts_with(char::is_whitespace) {
        return None;
    }

    let remaining = tail.trim_start();
    Some(remaining)
}

fn looks_like_command_args(text: &str) -> bool {
    let words: Vec<&str> = text.split_whitespace().collect();

    // Single word that looks like an address or identifier
    if words.len() == 1 {
        let word = words[0];
        // Addresses like 0x401000
        if word.starts_with("0x") || word.starts_with("0X") {
            return true;
        }
        // Function names like sub_401000 or identifiers
        if word.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return true;
        }
        // Colon-separated like localhost:13337
        if word.contains(':') {
            return true;
        }
        return true; // Single word is likely a command arg
    }

    // Two words: could be command args like "sub_401000 aes_key_schedule"
    if words.len() == 2 {
        // Both look like identifiers/addresses
        if words.iter().all(|w| {
            w.starts_with("0x")
                || w.starts_with("0X")
                || w.chars().all(|c| c.is_alphanumeric() || c == '_')
        }) {
            return true;
        }
    }

    // Multiple words with articles, prepositions, or common NL patterns
    let lower = text.to_ascii_lowercase();
    let nl_indicators = [
        "the ", "a ", "an ", "and ", "or ", "at ", "in ", "on ", "to ", "for ", "with ", "from ",
        "by ", "of ", "is ", "are ", "can ", "could ", "would ", "should ", "what ", "how ",
        "why ", "where ",
    ];

    if nl_indicators
        .iter()
        .any(|indicator| lower.contains(indicator))
    {
        return false; // Looks like natural language
    }

    // Default: if multiple words without clear NL markers, assume command args
    words.len() <= 3
}

fn detect_lift_nl_command(
    input: &str,
    context: &IntentSessionContext,
) -> Option<Result<String, String>> {
    let normalized = input.trim().to_ascii_lowercase();
    let matches_phrase = LIFT_NL_PHRASES.iter().any(|phrase| normalized == *phrase);
    if !matches_phrase {
        return None;
    }

    if let Some(addr) = extract_hex_address(input) {
        return Some(Ok(format!("lift {addr}")));
    }

    context.current_function_addr.as_ref().map_or_else(
        || {
            Some(Err(
                "I don't have a current function in focus. Provide an address or function name first."
                    .to_string(),
            ))
        },
        |addr| Some(Ok(format!("lift {addr}"))),
    )
}

fn extract_hex_address(input: &str) -> Option<String> {
    input
        .split_whitespace()
        .find(|token| token.starts_with("0x") || token.starts_with("0X"))
        .map(|token| {
            token
                .trim_matches(|ch: char| !ch.is_ascii_hexdigit() && ch != 'x' && ch != 'X')
                .to_string()
        })
}

fn requires_current_function(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    CURRENT_FUNCTION_REFERENCES
        .iter()
        .any(|reference| lower.contains(reference))
}

fn resolve_contextual_references(input: &str, context: &IntentSessionContext) -> String {
    let mut resolved = input.to_string();

    if let Some(addr) = &context.current_function_addr {
        for reference in CURRENT_FUNCTION_REFERENCES {
            resolved = replace_case_insensitive(&resolved, reference, addr);
        }
    }

    if let Some(binary) = &context.binary_name {
        for reference in BINARY_REFERENCES {
            resolved = replace_case_insensitive(&resolved, reference, binary);
        }
    }

    resolved
}

fn replace_case_insensitive(input: &str, needle: &str, replacement: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0usize;

    let lower_input = input.to_ascii_lowercase();
    let lower_needle = needle.to_ascii_lowercase();

    while let Some(relative_idx) = lower_input[cursor..].find(&lower_needle) {
        let start = cursor + relative_idx;
        let end = start + needle.len();
        output.push_str(&input[cursor..start]);
        output.push_str(replacement);
        cursor = end;
    }

    output.push_str(&input[cursor..]);
    output
}

#[cfg(test)]
mod tests {
    use endeavour_llm::{AgenticLoopConfig, AgenticLoopController};

    use super::*;

    #[derive(Default)]
    struct RecordingCommandHandler {
        dispatched: Vec<String>,
    }

    impl CommandIntentHandler for RecordingCommandHandler {
        fn dispatch_command(&mut self, command_line: &str) -> Result<(), IntentRouterError> {
            self.dispatched.push(command_line.to_string());
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingAgenticHandler {
        requests: Vec<AgenticIntentRequest>,
    }

    impl AgenticIntentHandler for RecordingAgenticHandler {
        fn dispatch_agentic(
            &mut self,
            _controller: &mut AgenticLoopController,
            request: AgenticIntentRequest,
        ) -> Result<(), IntentRouterError> {
            self.requests.push(request);
            Ok(())
        }
    }

    fn controller() -> AgenticLoopController {
        AgenticLoopController::new(AgenticLoopConfig::default())
    }

    #[test]
    fn command_keywords_bypass_agentic_dispatch() {
        let mut controller = controller();
        let mut command_handler = RecordingCommandHandler::default();
        let mut agentic_handler = RecordingAgenticHandler::default();

        let router = IntentRouter::new();
        let outcome = router
            .route(
                "connect localhost:13337",
                IntentSessionContext::default(),
                &mut controller,
                &mut command_handler,
                &mut agentic_handler,
            )
            .unwrap_or_else(|err| panic!("unexpected routing error: {err}"));

        assert_eq!(outcome, RouteOutcome::CommandDispatched);
        assert_eq!(command_handler.dispatched, vec!["connect localhost:13337"]);
        assert!(agentic_handler.requests.is_empty());
    }

    #[test]
    fn slash_prefixed_command_is_stripped_and_dispatched() {
        let mut controller = controller();
        let mut command_handler = RecordingCommandHandler::default();
        let mut agentic_handler = RecordingAgenticHandler::default();

        let router = IntentRouter::new();
        let outcome = router
            .route(
                "/SeSsIoN new",
                IntentSessionContext::default(),
                &mut controller,
                &mut command_handler,
                &mut agentic_handler,
            )
            .unwrap_or_else(|err| panic!("unexpected routing error: {err}"));

        assert_eq!(outcome, RouteOutcome::CommandDispatched);
        assert_eq!(command_handler.dispatched, vec!["SeSsIoN new"]);
        assert!(agentic_handler.requests.is_empty());
    }

    #[test]
    fn unknown_slash_command_returns_system_error_without_llm_dispatch() {
        let mut controller = controller();
        let mut command_handler = RecordingCommandHandler::default();
        let mut agentic_handler = RecordingAgenticHandler::default();

        let router = IntentRouter::new();
        let outcome = router
            .route(
                "/foo bar",
                IntentSessionContext::default(),
                &mut controller,
                &mut command_handler,
                &mut agentic_handler,
            )
            .unwrap_or_else(|err| panic!("unexpected routing error: {err}"));

        assert_eq!(
            outcome,
            RouteOutcome::SystemError(
                "unknown command '/foo' — type 'help' to see available commands".to_string()
            )
        );
        assert!(command_handler.dispatched.is_empty());
        assert!(agentic_handler.requests.is_empty());
    }

    #[test]
    fn non_command_natural_language_routes_to_agentic_loop() {
        let mut controller = controller();
        let mut command_handler = RecordingCommandHandler::default();
        let mut agentic_handler = RecordingAgenticHandler::default();

        let router = IntentRouter::new();
        let outcome = router
            .route(
                "can you decompile 0x401000 and explain it",
                IntentSessionContext::default(),
                &mut controller,
                &mut command_handler,
                &mut agentic_handler,
            )
            .unwrap_or_else(|err| panic!("unexpected routing error: {err}"));

        assert_eq!(outcome, RouteOutcome::AgenticDispatched);
        assert!(command_handler.dispatched.is_empty());
        assert_eq!(agentic_handler.requests.len(), 1);
        assert_eq!(
            agentic_handler.requests[0].resolved_input,
            "can you decompile 0x401000 and explain it"
        );
    }

    #[test]
    fn contextual_function_reference_resolves_to_current_address() {
        let mut controller = controller();
        let mut command_handler = RecordingCommandHandler::default();
        let mut agentic_handler = RecordingAgenticHandler::default();

        let router = IntentRouter::new();
        let context = IntentSessionContext {
            current_function_addr: Some("0x100004a20".to_string()),
            current_function_name: Some("sub_100004a20".to_string()),
            ..IntentSessionContext::default()
        };

        let outcome = router
            .route(
                "what does this function call?",
                context,
                &mut controller,
                &mut command_handler,
                &mut agentic_handler,
            )
            .unwrap_or_else(|err| panic!("unexpected routing error: {err}"));

        assert_eq!(outcome, RouteOutcome::AgenticDispatched);
        assert_eq!(agentic_handler.requests.len(), 1);
        assert_eq!(
            agentic_handler.requests[0].resolved_input,
            "what does 0x100004a20 call?"
        );
    }

    #[test]
    fn contextual_decompile_without_current_function_returns_system_error() {
        let mut controller = controller();
        let mut command_handler = RecordingCommandHandler::default();
        let mut agentic_handler = RecordingAgenticHandler::default();

        let router = IntentRouter::new();
        let outcome = router
            .route(
                "can you decompile this",
                IntentSessionContext::default(),
                &mut controller,
                &mut command_handler,
                &mut agentic_handler,
            )
            .unwrap_or_else(|err| panic!("unexpected routing error: {err}"));

        assert_eq!(
            outcome,
            RouteOutcome::SystemError(
                "I don't have a current function in focus. Provide an address or function name first."
                    .to_string()
            )
        );
        assert!(command_handler.dispatched.is_empty());
        assert!(agentic_handler.requests.is_empty());
    }

    #[test]
    fn lift_natural_language_routes_to_lift_command() {
        let mut controller = controller();
        let mut command_handler = RecordingCommandHandler::default();
        let mut agentic_handler = RecordingAgenticHandler::default();

        let router = IntentRouter::new();
        let context = IntentSessionContext {
            current_function_addr: Some("0x100004a20".to_string()),
            ..IntentSessionContext::default()
        };
        let outcome = router
            .route(
                "show me the IR",
                context,
                &mut controller,
                &mut command_handler,
                &mut agentic_handler,
            )
            .unwrap_or_else(|err| panic!("unexpected routing error: {err}"));

        assert_eq!(outcome, RouteOutcome::CommandDispatched);
        assert_eq!(command_handler.dispatched, vec!["lift 0x100004a20"]);
        assert!(agentic_handler.requests.is_empty());
    }

    #[test]
    fn decompile_keyword_routes_to_lift_command() {
        let mut controller = controller();
        let mut command_handler = RecordingCommandHandler::default();
        let mut agentic_handler = RecordingAgenticHandler::default();

        let router = IntentRouter::new();
        let context = IntentSessionContext {
            current_function_addr: Some("0x100004a20".to_string()),
            ..IntentSessionContext::default()
        };
        let outcome = router
            .route(
                "decompile",
                context,
                &mut controller,
                &mut command_handler,
                &mut agentic_handler,
            )
            .unwrap_or_else(|err| panic!("unexpected routing error: {err}"));

        assert_eq!(outcome, RouteOutcome::CommandDispatched);
        assert_eq!(command_handler.dispatched, vec!["lift 0x100004a20"]);
        assert!(agentic_handler.requests.is_empty());
    }

    #[test]
    fn bare_command_keyword_is_dispatched_as_command() {
        let mut controller = controller();
        let mut command_handler = RecordingCommandHandler::default();
        let mut agentic_handler = RecordingAgenticHandler::default();

        let router = IntentRouter::new();
        let outcome = router
            .route(
                "explain",
                IntentSessionContext::default(),
                &mut controller,
                &mut command_handler,
                &mut agentic_handler,
            )
            .unwrap_or_else(|err| panic!("unexpected routing error: {err}"));

        assert_eq!(outcome, RouteOutcome::CommandDispatched);
        assert_eq!(command_handler.dispatched, vec!["explain"]);
        assert!(agentic_handler.requests.is_empty());
    }

    #[test]
    fn nl_sentence_with_command_keyword_routes_to_agentic() {
        let mut controller = controller();
        let mut command_handler = RecordingCommandHandler::default();
        let mut agentic_handler = RecordingAgenticHandler::default();

        let router = IntentRouter::new();
        let outcome = router
            .route(
                "explain the function at 0x401000",
                IntentSessionContext::default(),
                &mut controller,
                &mut command_handler,
                &mut agentic_handler,
            )
            .unwrap_or_else(|err| panic!("unexpected routing error: {err}"));

        assert_eq!(outcome, RouteOutcome::AgenticDispatched);
        assert!(command_handler.dispatched.is_empty());
        assert_eq!(agentic_handler.requests.len(), 1);
    }

    #[test]
    fn connect_with_address_is_command() {
        let mut controller = controller();
        let mut command_handler = RecordingCommandHandler::default();
        let mut agentic_handler = RecordingAgenticHandler::default();

        let router = IntentRouter::new();
        let outcome = router
            .route(
                "connect localhost:13337",
                IntentSessionContext::default(),
                &mut controller,
                &mut command_handler,
                &mut agentic_handler,
            )
            .unwrap_or_else(|err| panic!("unexpected routing error: {err}"));

        assert_eq!(outcome, RouteOutcome::CommandDispatched);
        assert_eq!(command_handler.dispatched, vec!["connect localhost:13337"]);
        assert!(agentic_handler.requests.is_empty());
    }

    #[test]
    fn detect_mba_aliases_route_to_detect_mba_command() {
        let mut controller = controller();
        let mut command_handler = RecordingCommandHandler::default();
        let mut agentic_handler = RecordingAgenticHandler::default();

        let router = IntentRouter::new();
        let outcome = router
            .route(
                "find obfuscation 0x100004a20",
                IntentSessionContext::default(),
                &mut controller,
                &mut command_handler,
                &mut agentic_handler,
            )
            .unwrap_or_else(|err| panic!("unexpected routing error: {err}"));

        assert_eq!(outcome, RouteOutcome::CommandDispatched);
        assert_eq!(command_handler.dispatched, vec!["detect-mba 0x100004a20"]);
        assert!(agentic_handler.requests.is_empty());
    }

    #[test]
    fn nl_sentence_with_connect_keyword_routes_to_agentic() {
        let mut controller = controller();
        let mut command_handler = RecordingCommandHandler::default();
        let mut agentic_handler = RecordingAgenticHandler::default();

        let router = IntentRouter::new();
        let outcome = router
            .route(
                "connect the dots between these functions",
                IntentSessionContext::default(),
                &mut controller,
                &mut command_handler,
                &mut agentic_handler,
            )
            .unwrap_or_else(|err| panic!("unexpected routing error: {err}"));

        assert_eq!(outcome, RouteOutcome::AgenticDispatched);
        assert!(command_handler.dispatched.is_empty());
        assert_eq!(agentic_handler.requests.len(), 1);
    }
}

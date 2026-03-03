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
    "search",
    "decompile",
    "findings",
    "info",
    "config",
    "show-transcript",
    "cache",
    "help",
    "quit",
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
    let stripped = input.trim_start_matches('/');
    let keyword = stripped.split_whitespace().next()?;
    if KNOWN_COMMAND_KEYWORDS
        .iter()
        .any(|known| keyword.eq_ignore_ascii_case(known))
    {
        Some(stripped.to_string())
    } else {
        None
    }
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
}

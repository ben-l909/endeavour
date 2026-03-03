use endeavour_cli::tui::app::{App, AppEvent};
use endeavour_cli::tui::intent_router::{
    AgenticIntentHandler, AgenticIntentRequest, CommandIntentHandler, IntentRouter,
    IntentRouterError, IntentSessionContext, RouteOutcome,
};
use endeavour_llm::{AgenticLoopConfig, AgenticLoopController};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::Color;
use ratatui::text::Text;
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Terminal;

#[derive(Debug, Default)]
struct MockProvider {
    calls: usize,
    scripted_events: Vec<AppEvent>,
}

impl MockProvider {
    fn scripted(scripted_events: Vec<AppEvent>) -> Self {
        Self {
            calls: 0,
            scripted_events,
        }
    }

    fn dispatch_to_app(&mut self, app: &mut App) {
        self.calls += 1;
        for event in self.scripted_events.clone() {
            app.reduce(event);
        }
    }
}

#[derive(Debug, Default)]
struct MockIdaTransport {
    connected: bool,
}

impl MockIdaTransport {
    fn new(connected: bool) -> Self {
        Self { connected }
    }

    fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
    }

    fn state_label(&self) -> &'static str {
        if self.connected {
            "connected"
        } else {
            "disconnected"
        }
    }
}

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

fn render_app(app: &mut App, width: u16, height: u16) -> Buffer {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("terminal should build");
    terminal
        .draw(|frame| {
            let area = frame.area();
            if area.width < 80 || area.height < 24 {
                let warning = Paragraph::new("Terminal too small. Resize to at least 80x24.")
                    .alignment(Alignment::Center);
                frame.render_widget(warning, centered_rect(area));
                return;
            }

            let panes = app.layout(area);

            let history_view = app.history_view(panes.history.width, panes.history.height);
            frame.render_widget(
                Paragraph::new(Text::from(history_view.lines)).wrap(Wrap { trim: false }),
                panes.history,
            );
            if let Some(indicator) = history_view.unseen_indicator {
                let indicator_area = Rect {
                    x: panes.history.x,
                    y: panes
                        .history
                        .y
                        .saturating_add(panes.history.height.saturating_sub(1)),
                    width: panes.history.width,
                    height: 1,
                };
                frame.render_widget(
                    Paragraph::new(indicator).alignment(Alignment::Right),
                    indicator_area,
                );
            }

            let input_lines = app.input_lines(panes.input.width);
            let input_visible = panes.input.height as usize;
            let input_start = input_lines.len().saturating_sub(input_visible);
            let input_lines = input_lines
                .into_iter()
                .skip(input_start)
                .collect::<Vec<_>>();
            frame.render_widget(
                Paragraph::new(Text::from(input_lines)).wrap(Wrap { trim: false }),
                panes.input,
            );

            frame.render_widget(
                Paragraph::new(app.status_line(panes.status.width)),
                panes.status,
            );
        })
        .expect("draw should succeed");

    terminal.backend().buffer().clone()
}

fn centered_rect(area: Rect) -> Rect {
    Rect {
        x: area.x,
        y: area.y + area.height.saturating_sub(1) / 2,
        width: area.width,
        height: 1,
    }
}

fn row_text(buf: &Buffer, row: u16) -> String {
    let mut out = String::new();
    for col in 0..buf.area.width {
        out.push_str(buf.cell((col, row)).expect("cell must exist").symbol());
    }
    out
}

fn buffer_text(buf: &Buffer) -> String {
    let mut out = String::new();
    for row in 0..buf.area.height {
        out.push_str(&row_text(buf, row));
        out.push('\n');
    }
    out
}

fn assert_row_contains(buf: &Buffer, row: u16, text: &str) {
    assert!(
        row_text(buf, row).contains(text),
        "expected row {row} to contain `{text}`"
    );
}

fn assert_cell_fg(buf: &Buffer, row: u16, col: u16, color: Color) {
    let cell = buf.cell((col, row)).expect("cell must exist");
    assert_eq!(cell.fg, color, "unexpected fg color at ({col},{row})");
}

fn find_in_row(buf: &Buffer, row: u16, needle: &str) -> Option<u16> {
    row_text(buf, row).find(needle).map(|idx| idx as u16)
}

fn find_in_buffer(buf: &Buffer, needle: &str) -> Option<(u16, u16)> {
    for row in 0..buf.area.height {
        if let Some(col) = find_in_row(buf, row, needle) {
            return Some((row, col));
        }
    }
    None
}

fn type_and_submit(app: &mut App, input: &str) {
    for ch in input.chars() {
        app.insert_char(ch);
    }
    app.submit();
}

#[test]
fn layout_80x24_standard() {
    let mut app = App::new();
    let buf = render_app(&mut app, 80, 24);

    assert_row_contains(&buf, 22, "◆ ");
    assert_row_contains(&buf, 23, "[IDA:");
    assert!(!buffer_text(&buf).contains("Terminal too small"));
}

#[test]
fn layout_120x40_wide() {
    let mut app = App::new();
    let buf = render_app(&mut app, 120, 40);

    assert_row_contains(&buf, 38, "◆ ");
    assert_row_contains(&buf, 39, "[IDA: disconnected] [Session: none] [Tokens: 0]");
    assert!(!row_text(&buf, 39).contains('…'));
}

#[test]
fn layout_below_minimum_dimensions() {
    let mut app = App::new();
    let small_width = render_app(&mut app, 79, 24);
    assert!(buffer_text(&small_width).contains("Terminal too small"));
    assert!(!buffer_text(&small_width).contains("◆ "));

    let mut app = App::new();
    let small_height = render_app(&mut app, 80, 23);
    assert!(buffer_text(&small_height).contains("Terminal too small"));
    assert!(!buffer_text(&small_height).contains("[IDA:"));
}

#[test]
fn history_user_and_agent_message_flow() {
    let mut app = App::new();
    let mut provider = MockProvider::scripted(vec![
        AppEvent::AgentMessageStart,
        AppEvent::AgentMessageDelta("This is the agent response.".to_string()),
        AppEvent::AgentMessageComplete,
    ]);

    type_and_submit(&mut app, "explain the function at 0x401000");
    provider.dispatch_to_app(&mut app);

    let buf = render_app(&mut app, 80, 24);
    let text = buffer_text(&buf);
    assert!(text.contains("You: explain the function at 0x401000"));
    assert!(text.contains("Agent: This is the agent response."));

    let (user_row, user_col) = find_in_buffer(&buf, "You:").expect("user row should exist");
    assert_cell_fg(&buf, user_row, user_col, Color::Rgb(91, 143, 212));
    assert_eq!(provider.calls, 1);
}

#[test]
fn history_manual_scroll_pauses_autoscroll_and_shows_unseen() {
    let mut app = App::new();
    for i in 1..=30 {
        app.reduce(AppEvent::SystemMessage(format!("message-{i}")));
    }

    let baseline = render_app(&mut app, 80, 24);
    assert!(buffer_text(&baseline).contains("message-30"));

    app.page_up();
    let scrolled = render_app(&mut app, 80, 24);
    assert!(!buffer_text(&scrolled).contains("message-30"));
    assert!(!app.auto_scroll());

    app.reduce(AppEvent::SystemMessage("message-31".to_string()));
    let with_unseen = render_app(&mut app, 80, 24);
    assert!(!buffer_text(&with_unseen).contains("message-31"));
    assert!(buffer_text(&with_unseen).contains("↓ 1 new"));
    assert_eq!(app.unseen_count(), 1);

    app.page_down();
    app.page_down();
    let back_to_bottom = render_app(&mut app, 80, 24);
    assert!(app.auto_scroll());
    assert_eq!(app.unseen_count(), 0);
    assert!(buffer_text(&back_to_bottom).contains("message-31"));
}

#[test]
fn history_streaming_partial_message_and_completion() {
    let mut app = App::new();
    type_and_submit(&mut app, "analyze this");

    app.reduce(AppEvent::AgentMessageStart);
    app.reduce(AppEvent::AgentMessageDelta(
        "Based on the decompiled output".to_string(),
    ));

    let streaming = render_app(&mut app, 80, 24);
    let streaming_text = buffer_text(&streaming);
    assert!(streaming_text.contains("Agent: Based on the decompiled output"));
    assert!(streaming_text.contains("▌"));
    assert!(streaming_text.contains("⠋ Agent is thinking..."));

    app.reduce(AppEvent::AgentMessageComplete);
    let complete = render_app(&mut app, 80, 24);
    let complete_text = buffer_text(&complete);
    assert!(complete_text.contains("Agent: Based on the decompiled output"));
    assert!(!complete_text.contains("▌"));
    assert!(complete_text.contains("◆ "));
}

#[test]
fn status_bar_disconnected_connected_mocks_are_available() {
    let mut ida = MockIdaTransport::new(false);
    let mut app = App::new();

    let first = render_app(&mut app, 80, 24);
    assert_row_contains(
        &first,
        23,
        "[IDA: disconnected] [Session: none] [Tokens: 0] [Auth: none]",
    );
    let disconnected_col = find_in_row(&first, 23, "disconnected").expect("status should exist");
    assert_cell_fg(&first, 23, disconnected_col, Color::Rgb(212, 138, 74));
    assert_eq!(ida.state_label(), "disconnected");

    ida.set_connected(true);
    assert_eq!(ida.state_label(), "connected");
}

#[test]
fn status_bar_session_and_tokens_width_behaviour() {
    let mut app = App::new();
    let compact = render_app(&mut app, 80, 24);
    assert_row_contains(&compact, 23, "[Tokens: 0]");

    let wide = render_app(&mut app, 120, 40);
    assert_row_contains(
        &wide,
        39,
        "[IDA: disconnected] [Session: none] [Tokens: 0] [Auth: none]",
    );
}

fn controller() -> AgenticLoopController {
    AgenticLoopController::new(AgenticLoopConfig::default())
}

#[test]
fn routing_nl_dispatches_to_agentic_loop() {
    let router = IntentRouter::new();
    let mut controller = controller();
    let mut commands = RecordingCommandHandler::default();
    let mut agent = RecordingAgenticHandler::default();

    let outcome = router
        .route(
            "explain the function at 0x401000",
            IntentSessionContext::default(),
            &mut controller,
            &mut commands,
            &mut agent,
        )
        .expect("routing should succeed");

    assert_eq!(outcome, RouteOutcome::AgenticDispatched);
    assert!(commands.dispatched.is_empty());
    assert_eq!(agent.requests.len(), 1);
}

#[test]
fn routing_exact_commands_bypass_agentic() {
    for input in [
        "sessions",
        "connect localhost:13337",
        "help",
        "decompile 0x401000",
        "rename sub_401000 aes_key_schedule",
        "/sessions",
        "/connect localhost:13337",
    ] {
        let router = IntentRouter::new();
        let mut controller = controller();
        let mut commands = RecordingCommandHandler::default();
        let mut agent = RecordingAgenticHandler::default();

        let outcome = router
            .route(
                input,
                IntentSessionContext::default(),
                &mut controller,
                &mut commands,
                &mut agent,
            )
            .expect("routing should succeed");

        assert_eq!(outcome, RouteOutcome::CommandDispatched);
        assert_eq!(commands.dispatched.len(), 1);
        assert!(agent.requests.is_empty());
    }
}

#[test]
fn routing_unknown_slash_and_empty_input() {
    let router = IntentRouter::new();
    let mut controller = controller();
    let mut commands = RecordingCommandHandler::default();
    let mut agent = RecordingAgenticHandler::default();

    let unknown = router
        .route(
            "/foobar",
            IntentSessionContext::default(),
            &mut controller,
            &mut commands,
            &mut agent,
        )
        .expect("routing should succeed");

    assert_eq!(
        unknown,
        RouteOutcome::SystemError(
            "unknown command '/foobar' — type 'help' to see available commands".to_string()
        )
    );
    assert!(commands.dispatched.is_empty());
    assert!(agent.requests.is_empty());

    let empty = router
        .route(
            "   ",
            IntentSessionContext::default(),
            &mut controller,
            &mut commands,
            &mut agent,
        )
        .expect("routing should succeed");
    assert_eq!(empty, RouteOutcome::IgnoredEmpty);
}

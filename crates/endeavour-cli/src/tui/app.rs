use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use time::macros::format_description;
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppEvent {
    AgentMessageStart,
    AgentMessage(String),
    AgentMessageDelta(String),
    AgentMessageComplete,
    Tick,
    SystemMessage(String),
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRole {
    User,
    Agent,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Message {
    role: MessageRole,
    content: String,
    timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StreamingMessage {
    content: String,
    timestamp: String,
    wrap_width: u16,
}

#[derive(Debug, Clone)]
pub struct HistoryView {
    pub lines: Vec<Line<'static>>,
    pub unseen_indicator: Option<Line<'static>>,
}

#[derive(Debug, Default)]
pub struct App {
    input: String,
    messages: Vec<Message>,
    is_agent_streaming: bool,
    streaming_agent: Option<StreamingMessage>,
    spinner_index: usize,
    spinner_elapsed_ms: u64,
    stream_cursor_visible: bool,
    stream_cursor_elapsed_ms: u64,
    scroll_offset: usize,
    auto_scroll: bool,
    unseen_count: usize,
    history_view_height: usize,
    history_view_width: usize,
    should_quit: bool,
    dirty: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaneLayout {
    pub history: Rect,
    pub input: Rect,
    pub status: Rect,
}

impl App {
    pub fn new() -> Self {
        Self {
            auto_scroll: true,
            history_view_height: 1,
            history_view_width: 1,
            dirty: true,
            ..Self::default()
        }
    }

    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn clear_dirty(&mut self) {
        self.dirty = false;
    }

    pub fn input(&self) -> &str {
        &self.input
    }

    pub fn layout(&self, area: Rect) -> PaneLayout {
        let input_height = self.input_height(area.width);
        let panes = Layout::vertical([
            Constraint::Min(1),
            Constraint::Length(input_height),
            Constraint::Length(1),
        ])
        .split(area);

        PaneLayout {
            history: panes[0],
            input: panes[1],
            status: panes[2],
        }
    }

    pub fn reduce(&mut self, event: AppEvent) {
        match event {
            AppEvent::AgentMessageStart => self.start_agent_stream(),
            AppEvent::AgentMessage(message) => self.push_message(MessageRole::Agent, message),
            AppEvent::AgentMessageDelta(chunk) => self.push_agent_stream_delta(chunk),
            AppEvent::AgentMessageComplete => self.complete_agent_stream(),
            AppEvent::Tick => self.tick_streaming_animation(),
            AppEvent::SystemMessage(message) => self.push_message(MessageRole::System, message),
            AppEvent::Quit => {
                self.should_quit = true;
                self.dirty = true;
            }
        }
    }

    pub fn insert_char(&mut self, ch: char) {
        if self.is_agent_streaming {
            return;
        }
        self.input.push(ch);
        self.dirty = true;
    }

    pub fn insert_newline(&mut self) {
        if self.is_agent_streaming {
            return;
        }
        self.input.push('\n');
        self.dirty = true;
    }

    pub fn backspace(&mut self) {
        if self.is_agent_streaming {
            return;
        }
        if self.input.pop().is_some() {
            self.dirty = true;
        }
    }

    pub fn clear_input(&mut self) {
        if self.is_agent_streaming {
            return;
        }
        if !self.input.is_empty() {
            self.input.clear();
            self.dirty = true;
        }
    }

    pub fn submit(&mut self) {
        if self.is_agent_streaming {
            return;
        }
        let submitted = self.input.trim().to_string();
        self.input.clear();

        if submitted.is_empty() {
            self.dirty = true;
            return;
        }

        if submitted == "/quit" {
            self.should_quit = true;
            self.dirty = true;
            return;
        }

        self.push_message(MessageRole::User, submitted);
    }

    pub fn history_lines(&self, width: u16) -> Vec<Line<'static>> {
        self.render_history_lines(width, true)
    }

    pub fn history_view(&mut self, width: u16, height: u16) -> HistoryView {
        self.set_history_viewport(width, height);
        let all_lines = self.render_history_lines(width, true);
        let visible_height = self.history_view_height.max(1);
        let max_offset = all_lines.len().saturating_sub(visible_height);

        if self.auto_scroll {
            self.scroll_offset = 0;
        } else {
            self.scroll_offset = self.scroll_offset.min(max_offset);
            if self.scroll_offset == 0 {
                self.auto_scroll = true;
                self.unseen_count = 0;
            }
        }

        let start = all_lines
            .len()
            .saturating_sub(visible_height.saturating_add(self.scroll_offset));
        let end = all_lines.len().saturating_sub(self.scroll_offset);
        let visible = all_lines[start..end].to_vec();

        let unseen_indicator = if !self.auto_scroll && self.unseen_count > 0 {
            Some(Line::from(Span::styled(
                format!("{} {} new", unseen_symbol(), self.unseen_count),
                Style::default().fg(teal()),
            )))
        } else {
            None
        };

        HistoryView {
            lines: visible,
            unseen_indicator,
        }
    }

    pub fn scroll_up_line(&mut self) {
        self.scroll_up(1);
    }

    pub fn scroll_down_line(&mut self) {
        self.scroll_down(1);
    }

    pub fn page_up(&mut self) {
        self.scroll_up(self.page_step());
    }

    pub fn page_down(&mut self) {
        self.scroll_down(self.page_step());
    }

    pub fn scroll_offset(&self) -> usize {
        self.scroll_offset
    }

    pub fn is_streaming(&self) -> bool {
        self.is_agent_streaming
    }

    pub fn cancel_streaming(&mut self) {
        if !self.is_agent_streaming {
            return;
        }

        if self.streaming_agent.is_none() {
            self.streaming_agent = Some(StreamingMessage {
                content: String::new(),
                timestamp: current_hhmm(),
                wrap_width: self.current_stream_wrap_width(),
            });
            self.on_new_message();
        }

        if let Some(streaming) = self.streaming_agent.as_mut() {
            let ends_with_whitespace = streaming
                .content
                .chars()
                .last()
                .is_some_and(char::is_whitespace);
            if !streaming.content.is_empty() && !ends_with_whitespace {
                streaming.content.push(' ');
            }
            streaming.content.push_str("[cancelled]");
        }
        self.complete_agent_stream();
    }

    pub fn auto_scroll(&self) -> bool {
        self.auto_scroll
    }

    pub fn unseen_count(&self) -> usize {
        self.unseen_count
    }

    pub fn set_history_viewport(&mut self, width: u16, height: u16) {
        self.history_view_width = width.max(1) as usize;
        self.history_view_height = height.max(1) as usize;
    }

    fn input_height(&self, width: u16) -> u16 {
        let prompt_width = 2usize;
        let wrapped_lines =
            wrap_text(&self.input, width_for_input(width as usize, prompt_width)).len() as u16;
        wrapped_lines.clamp(1, 3)
    }

    fn page_step(&self) -> usize {
        self.history_view_height.saturating_sub(2).max(1)
    }

    fn scroll_up(&mut self, lines: usize) {
        self.auto_scroll = false;
        let max_offset = self.max_scroll_offset();
        self.scroll_offset = self.scroll_offset.saturating_add(lines).min(max_offset);
        self.dirty = true;
    }

    fn scroll_down(&mut self, lines: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(lines);
        if self.scroll_offset == 0 {
            self.auto_scroll = true;
            self.unseen_count = 0;
        } else {
            self.auto_scroll = false;
        }
        self.dirty = true;
    }

    fn max_scroll_offset(&self) -> usize {
        self.render_history_lines(self.history_view_width as u16, false)
            .len()
            .saturating_sub(self.history_view_height.max(1))
    }

    fn render_history_lines(&self, width: u16, show_stream_cursor: bool) -> Vec<Line<'static>> {
        let mut lines = Vec::new();
        for message in &self.messages {
            lines.extend(render_message(message, width));
        }
        if let Some(streaming) = &self.streaming_agent {
            lines.extend(render_streaming_message(
                streaming,
                streaming.wrap_width.max(1),
                show_stream_cursor && self.is_agent_streaming && self.stream_cursor_visible,
            ));
        }
        lines
    }

    fn start_agent_stream(&mut self) {
        self.is_agent_streaming = true;
        self.stream_cursor_visible = true;
        self.stream_cursor_elapsed_ms = 0;
        self.spinner_elapsed_ms = 0;
        self.dirty = true;
    }

    fn push_message(&mut self, role: MessageRole, content: String) {
        self.stop_agent_stream();
        self.messages.push(Message {
            role,
            content,
            timestamp: current_hhmm(),
        });
        self.on_new_message();
    }

    fn push_agent_stream_delta(&mut self, chunk: String) {
        if chunk.is_empty() {
            return;
        }

        if !self.is_agent_streaming {
            self.start_agent_stream();
        }

        if self.streaming_agent.is_none() {
            self.streaming_agent = Some(StreamingMessage {
                content: String::new(),
                timestamp: current_hhmm(),
                wrap_width: self.current_stream_wrap_width(),
            });
            self.on_new_message();
        }

        if let Some(streaming) = self.streaming_agent.as_mut() {
            streaming.content.push_str(&chunk);
            self.dirty = true;
        }
    }

    fn complete_agent_stream(&mut self) {
        if let Some(streaming) = self.streaming_agent.take() {
            if !streaming.content.trim().is_empty() {
                self.messages.push(Message {
                    role: MessageRole::Agent,
                    content: streaming.content,
                    timestamp: streaming.timestamp,
                });
            }
        }
        self.stop_agent_stream();
    }

    fn stop_agent_stream(&mut self) {
        self.is_agent_streaming = false;
        self.stream_cursor_visible = false;
        self.stream_cursor_elapsed_ms = 0;
        self.spinner_elapsed_ms = 0;
        self.spinner_index = 0;
        self.dirty = true;
    }

    fn tick_streaming_animation(&mut self) {
        if !self.is_agent_streaming {
            return;
        }

        self.spinner_elapsed_ms = self.spinner_elapsed_ms.saturating_add(TICK_INTERVAL_MS);
        while self.spinner_elapsed_ms >= SPINNER_INTERVAL_MS {
            self.spinner_elapsed_ms -= SPINNER_INTERVAL_MS;
            self.spinner_index = (self.spinner_index + 1) % SPINNER_FRAMES.len();
        }

        self.stream_cursor_elapsed_ms = self
            .stream_cursor_elapsed_ms
            .saturating_add(TICK_INTERVAL_MS);
        while self.stream_cursor_elapsed_ms >= CURSOR_BLINK_INTERVAL_MS {
            self.stream_cursor_elapsed_ms -= CURSOR_BLINK_INTERVAL_MS;
            self.stream_cursor_visible = !self.stream_cursor_visible;
        }

        self.dirty = true;
    }

    fn current_stream_wrap_width(&self) -> u16 {
        if self.history_view_width > 1 {
            self.history_view_width as u16
        } else {
            DEFAULT_STREAM_WRAP_WIDTH
        }
    }

    fn on_new_message(&mut self) {
        if self.auto_scroll {
            self.scroll_offset = 0;
        } else {
            self.unseen_count = self.unseen_count.saturating_add(1);
        }
        self.dirty = true;
    }

    pub fn input_lines(&self, width: u16) -> Vec<Line<'static>> {
        if self.is_agent_streaming {
            return vec![Line::from(vec![
                Span::styled(
                    format!("{} ", SPINNER_FRAMES[self.spinner_index]),
                    Style::default().fg(amber()),
                ),
                Span::styled("Agent is thinking...", Style::default().fg(dim())),
            ])];
        }

        let prompt = "◆ ";
        let continuation = "  ";
        let available = width_for_input(width as usize, prompt.chars().count());
        let wrapped = wrap_text(&self.input, available);

        wrapped
            .into_iter()
            .enumerate()
            .map(|(idx, segment)| {
                let prefix = if idx == 0 { prompt } else { continuation };
                Line::from(vec![
                    Span::styled(prefix.to_string(), Style::default().fg(amber())),
                    Span::styled(segment, Style::default().fg(chalk())),
                ])
            })
            .collect()
    }

    pub fn status_line(&self) -> Line<'static> {
        let text = "[IDA: disconnected] [Session: none] [Tokens: 0]";
        Line::from(Span::styled(text.to_string(), Style::default().fg(dim())))
    }
}

fn render_message(message: &Message, width: u16) -> Vec<Line<'static>> {
    render_message_parts(
        message.role,
        &message.content,
        width,
        &message.timestamp,
        false,
    )
}

fn render_streaming_message(
    message: &StreamingMessage,
    width: u16,
    show_cursor: bool,
) -> Vec<Line<'static>> {
    render_message_parts(
        MessageRole::Agent,
        &message.content,
        width,
        &message.timestamp,
        show_cursor,
    )
}

fn render_message_parts(
    role: MessageRole,
    content: &str,
    width: u16,
    timestamp: &str,
    show_cursor: bool,
) -> Vec<Line<'static>> {
    let (prefix, prefix_color) = match role {
        MessageRole::User => ("You: ", steel()),
        MessageRole::Agent => ("Agent: ", teal()),
        MessageRole::System => ("  ● ", dim()),
    };
    let continuation = " ".repeat(prefix.chars().count());
    let reserved_right = timestamp_reserved_width();
    let content_width = width_for_history(width as usize, prefix.chars().count(), reserved_right);
    let wrapped = wrap_text(content, content_width);
    let last_line_index = wrapped.len().saturating_sub(1);

    wrapped
        .into_iter()
        .enumerate()
        .map(|(idx, segment)| {
            let current_prefix = if idx == 0 {
                prefix
            } else {
                continuation.as_str()
            };
            let prefix_style = if idx == 0 {
                Style::default().fg(prefix_color)
            } else {
                Style::default().fg(dim())
            };
            let content_style = if role == MessageRole::System {
                Style::default().fg(dim())
            } else {
                Style::default().fg(chalk())
            };

            let mut spans = vec![Span::styled(current_prefix.to_string(), prefix_style)];
            if show_cursor && idx == last_line_index {
                spans.push(Span::styled(segment, content_style));
                spans.push(Span::styled(
                    "▌",
                    Style::default()
                        .fg(chalk())
                        .add_modifier(Modifier::SLOW_BLINK),
                ));
            } else {
                spans.push(Span::styled(segment, content_style));
            }

            if idx == 0 {
                let used_chars: usize = spans.iter().map(|span| span.content.chars().count()).sum();
                let line_width = width as usize;
                let pad = line_width.saturating_sub(used_chars + reserved_right);
                if pad > 0 {
                    spans.push(Span::raw(" ".repeat(pad)));
                }
                spans.push(Span::raw(" "));
                spans.push(Span::styled(
                    format!("{:>5}", format_timestamp(timestamp)),
                    Style::default().fg(dim()),
                ));
            }

            Line::from(spans)
        })
        .collect()
}

fn format_timestamp(timestamp: &str) -> String {
    let value: String = timestamp.chars().take(5).collect();
    if value.chars().count() == 5 {
        value
    } else {
        "00:00".to_string()
    }
}

const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SPINNER_INTERVAL_MS: u64 = 80;
const CURSOR_BLINK_INTERVAL_MS: u64 = 500;
const TICK_INTERVAL_MS: u64 = 16;
const DEFAULT_STREAM_WRAP_WIDTH: u16 = 80;

fn current_hhmm() -> String {
    let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
    now.format(&format_description!("[hour repr:24]:[minute]"))
        .unwrap_or_else(|_| "00:00".to_string())
}

fn timestamp_reserved_width() -> usize {
    6
}

fn unseen_symbol() -> &'static str {
    "↓"
}

fn width_for_history(total_width: usize, prefix_width: usize, reserved_right: usize) -> usize {
    total_width
        .saturating_sub(prefix_width)
        .saturating_sub(reserved_right)
        .max(1)
}

fn width_for_input(total_width: usize, prefix_width: usize) -> usize {
    total_width.saturating_sub(prefix_width).max(1)
}

fn wrap_text(input: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }

    let mut all_lines = Vec::new();
    for paragraph in input.split('\n') {
        if paragraph.is_empty() {
            all_lines.push(String::new());
            continue;
        }

        let mut current = String::new();
        for word in paragraph.split_whitespace() {
            if current.is_empty() {
                if word.chars().count() <= width {
                    current.push_str(word);
                } else {
                    all_lines.extend(split_long_word(word, width));
                }
                continue;
            }

            let projected = current.chars().count() + 1 + word.chars().count();
            if projected <= width {
                current.push(' ');
                current.push_str(word);
            } else {
                all_lines.push(std::mem::take(&mut current));
                if word.chars().count() <= width {
                    current.push_str(word);
                } else {
                    let chunks = split_long_word(word, width);
                    if let Some((last, head)) = chunks.split_last() {
                        for chunk in head {
                            all_lines.push(chunk.clone());
                        }
                        current.push_str(last);
                    }
                }
            }
        }

        if current.is_empty() {
            all_lines.push(String::new());
        } else {
            all_lines.push(current);
        }
    }

    if all_lines.is_empty() {
        vec![String::new()]
    } else {
        all_lines
    }
}

fn split_long_word(word: &str, width: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut buffer = String::new();

    for ch in word.chars() {
        buffer.push(ch);
        if buffer.chars().count() == width {
            chunks.push(std::mem::take(&mut buffer));
        }
    }

    if !buffer.is_empty() {
        chunks.push(buffer);
    }

    chunks
}

fn steel() -> Color {
    Color::Rgb(91, 143, 212)
}

fn teal() -> Color {
    Color::Rgb(74, 158, 142)
}

fn amber() -> Color {
    Color::Rgb(212, 160, 74)
}

fn chalk() -> Color {
    Color::Rgb(200, 200, 200)
}

fn dim() -> Color {
    Color::Rgb(90, 90, 90)
}

#[cfg(test)]
mod tests {
    use ratatui::layout::Rect;

    use super::{App, AppEvent};

    #[test]
    fn computes_layout_for_80x24_and_120x40() {
        for (width, height) in [(80, 24), (120, 40)] {
            let app = App::new();
            let layout = app.layout(Rect::new(0, 0, width, height));
            assert_eq!(layout.status.height, 1);
            assert_eq!(layout.input.height, 1);
            assert_eq!(
                layout.history.height + layout.input.height + layout.status.height,
                height
            );
        }
    }

    #[test]
    fn grows_input_to_three_lines_max() {
        let mut app = App::new();
        app.insert_newline();
        app.insert_newline();
        app.insert_newline();
        let layout = app.layout(Rect::new(0, 0, 80, 24));
        assert_eq!(layout.input.height, 3);
    }

    #[test]
    fn submit_adds_user_message_and_clears_input() {
        let mut app = App::new();
        for ch in "hello".chars() {
            app.insert_char(ch);
        }
        app.submit();

        let lines = app.history_lines(80);
        assert!(lines
            .iter()
            .any(|line| line.to_string().contains("You: hello")));
        assert_eq!(app.input(), "");
    }

    #[test]
    fn submit_quit_command_sets_quit_flag() {
        let mut app = App::new();
        for ch in "/quit".chars() {
            app.insert_char(ch);
        }
        app.submit();
        assert!(app.should_quit());
    }

    #[test]
    fn reducer_accepts_background_events() {
        let mut app = App::new();
        app.reduce(AppEvent::AgentMessage("thinking".to_string()));
        app.reduce(AppEvent::SystemMessage("tool done".to_string()));
        let rendered = app.history_lines(80);
        assert!(rendered
            .iter()
            .any(|line| line.to_string().contains("Agent: thinking")));
        assert!(rendered
            .iter()
            .any(|line| line.to_string().contains("  ● tool done")));
    }

    #[test]
    fn manual_scroll_pauses_auto_scroll_and_tracks_unseen() {
        let mut app = App::new();
        for idx in 0..10 {
            app.reduce(AppEvent::SystemMessage(format!("msg-{idx}")));
        }
        app.set_history_viewport(80, 3);
        app.page_up();
        assert!(!app.auto_scroll());
        assert!(app.scroll_offset() > 0);

        app.reduce(AppEvent::AgentMessage("new message".to_string()));
        assert_eq!(app.unseen_count(), 1);

        let history = app.history_view(80, 3);
        let indicator = history
            .unseen_indicator
            .expect("expected unseen indicator while manually scrolled");
        assert!(indicator.to_string().contains("↓ 1 new"));
    }

    #[test]
    fn scrolling_to_bottom_resumes_auto_scroll() {
        let mut app = App::new();
        for idx in 0..10 {
            app.reduce(AppEvent::SystemMessage(format!("msg-{idx}")));
        }
        app.set_history_viewport(80, 3);
        app.page_up();
        app.reduce(AppEvent::AgentMessage("new message".to_string()));
        assert_eq!(app.unseen_count(), 1);

        app.page_down();
        app.page_down();
        assert!(app.auto_scroll());
        assert_eq!(app.scroll_offset(), 0);
        assert_eq!(app.unseen_count(), 0);

        let history = app.history_view(80, 3);
        assert!(history.unseen_indicator.is_none());
    }

    #[test]
    fn streaming_message_shows_cursor_until_completed() {
        let mut app = App::new();
        app.reduce(AppEvent::AgentMessageStart);
        app.reduce(AppEvent::AgentMessageDelta("partial".to_string()));
        let streaming = app.history_lines(80);
        assert!(streaming
            .iter()
            .any(|line| line.to_string().contains("Agent: partial▌")));

        app.reduce(AppEvent::AgentMessageComplete);
        let completed = app.history_lines(80);
        assert!(completed
            .iter()
            .any(|line| line.to_string().contains("Agent: partial")));
        assert!(completed
            .iter()
            .all(|line| !line.to_string().contains("partial▌")));
    }

    #[test]
    fn blocks_input_and_shows_thinking_indicator_while_streaming() {
        let mut app = App::new();
        app.insert_char('x');
        app.reduce(AppEvent::AgentMessageStart);

        app.insert_char('y');
        app.backspace();
        app.insert_newline();
        app.clear_input();
        app.submit();

        assert_eq!(app.input(), "x");

        let input_line = app.input_lines(80);
        let rendered = input_line
            .first()
            .map(ToString::to_string)
            .expect("expected one thinking indicator line");
        assert!(rendered.contains("Agent is thinking..."));
        assert!(rendered.contains("⠋"));
    }

    #[test]
    fn tick_advances_spinner_and_cursor_animation() {
        let mut app = App::new();
        app.reduce(AppEvent::AgentMessageStart);
        app.reduce(AppEvent::AgentMessageDelta("hi".to_string()));

        let initial = app.history_lines(80);
        assert!(initial
            .iter()
            .any(|line| line.to_string().contains("Agent: hi▌")));

        for _ in 0..32 {
            app.reduce(AppEvent::Tick);
        }

        let blinked = app.history_lines(80);
        assert!(blinked
            .iter()
            .all(|line| !line.to_string().contains("Agent: hi▌")));

        for _ in 0..5 {
            app.reduce(AppEvent::Tick);
        }

        let input_line = app.input_lines(80);
        let rendered = input_line
            .first()
            .map(ToString::to_string)
            .expect("expected one spinner line");
        assert!(!rendered.contains("⠋ Agent is thinking..."));
    }

    #[test]
    fn cancelling_stream_appends_cancelled_marker() {
        let mut app = App::new();
        app.reduce(AppEvent::AgentMessageStart);
        app.reduce(AppEvent::AgentMessageDelta("working".to_string()));

        app.cancel_streaming();

        assert!(!app.is_streaming());
        let lines = app.history_lines(80);
        assert!(lines
            .iter()
            .any(|line| line.to_string().contains("Agent: working [cancelled]")));
    }

    #[test]
    fn completion_discards_whitespace_only_streamed_messages() {
        let mut app = App::new();
        app.reduce(AppEvent::AgentMessageStart);
        app.reduce(AppEvent::AgentMessageDelta("   ".to_string()));
        app.reduce(AppEvent::AgentMessageComplete);

        let lines = app.history_lines(80);
        assert!(lines
            .iter()
            .all(|line| !line.to_string().contains("Agent:")));
    }

    #[test]
    fn page_scroll_uses_visible_height_minus_two() {
        let mut app = App::new();
        for idx in 0..20 {
            app.reduce(AppEvent::SystemMessage(format!("msg-{idx}")));
        }
        app.set_history_viewport(80, 8);
        app.page_up();
        assert_eq!(app.scroll_offset(), 6);
    }
}

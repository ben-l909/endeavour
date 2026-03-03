use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use time::macros::format_description;
use time::OffsetDateTime;

use super::status_bar::{IdaConnectionState, IrFrontendState, StatusBar, StatusBarState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppEvent {
    AgentMessageStart,
    AgentMessage(String),
    AgentMessageDelta(String),
    AgentMessageComplete,
    ToolCallStart {
        name: String,
        args: String,
    },
    ToolCallResult {
        name: String,
        success: bool,
        preview: String,
        full_result: String,
    },
    Tick,
    SystemMessage(String),
    IdaConnectionChanged(bool),
    /// Updates the status bar with the currently active IR frontend.
    IrFrontendChanged(IrFrontendState),
    SessionChanged(Option<String>),
    TurnCompleted {
        tokens_used: u64,
    },
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolCallStatus {
    Executing,
    Success,
    Failure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ToolCallEntry {
    name: String,
    args: String,
    status: ToolCallStatus,
    preview: String,
    full_result: String,
    expanded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HistoryEntry {
    Message(Message),
    ToolCall(ToolCallEntry),
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
    history: Vec<HistoryEntry>,
    is_agent_streaming: bool,
    streaming_agent: Option<StreamingMessage>,
    focused_tool_call: Option<usize>,
    spinner_index: usize,
    spinner_elapsed_ms: u64,
    stream_cursor_visible: bool,
    stream_cursor_elapsed_ms: u64,
    scroll_offset: usize,
    auto_scroll: bool,
    unseen_count: usize,
    history_view_height: usize,
    history_view_width: usize,
    status: StatusBarState,
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
            AppEvent::ToolCallStart { name, args } => self.start_tool_call(name, args),
            AppEvent::ToolCallResult {
                name,
                success,
                preview,
                full_result,
            } => self.complete_tool_call(name, success, preview, full_result),
            AppEvent::Tick => self.tick_streaming_animation(),
            AppEvent::SystemMessage(message) => self.push_message(MessageRole::System, message),
            AppEvent::IdaConnectionChanged(is_connected) => {
                self.status.ida = if is_connected {
                    IdaConnectionState::Connected
                } else {
                    self.status.ir_frontend = IrFrontendState::None;
                    IdaConnectionState::Disconnected
                };
                self.dirty = true;
            }
            AppEvent::IrFrontendChanged(ir_frontend) => {
                self.status.ir_frontend = ir_frontend;
                self.dirty = true;
            }
            AppEvent::SessionChanged(session_id) => {
                self.status.session_id = session_id;
                self.status.tokens = 0;
                self.status.ir_frontend = IrFrontendState::None;
                self.dirty = true;
            }
            AppEvent::TurnCompleted { tokens_used } => {
                self.status.tokens = self.status.tokens.saturating_add(tokens_used);
                self.dirty = true;
            }
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
        self.focused_tool_call = None;
        self.input.push(ch);
        self.dirty = true;
    }

    pub fn insert_newline(&mut self) {
        if self.is_agent_streaming {
            return;
        }
        self.focused_tool_call = None;
        self.input.push('\n');
        self.dirty = true;
    }

    pub fn backspace(&mut self) {
        if self.is_agent_streaming {
            return;
        }
        self.focused_tool_call = None;
        if self.input.pop().is_some() {
            self.dirty = true;
        }
    }

    pub fn clear_input(&mut self) {
        if self.is_agent_streaming {
            return;
        }
        self.focused_tool_call = None;
        if !self.input.is_empty() {
            self.input.clear();
            self.dirty = true;
        }
    }

    pub fn submit(&mut self) {
        if self.is_agent_streaming {
            return;
        }
        self.focused_tool_call = None;
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

    pub fn focus_next_tool_call(&mut self) {
        let tool_indices = self.tool_call_indices();
        if tool_indices.is_empty() {
            self.focused_tool_call = None;
            return;
        }

        self.focused_tool_call = match self.focused_tool_call {
            Some(current) => {
                let next_pos = tool_indices
                    .iter()
                    .position(|idx| *idx > current)
                    .unwrap_or(0);
                Some(tool_indices[next_pos])
            }
            None => Some(*tool_indices.first().unwrap_or(&0)),
        };
        self.dirty = true;
    }

    pub fn toggle_focused_tool_call(&mut self) -> bool {
        let Some(focused_index) = self.focused_tool_call else {
            return false;
        };

        if let Some(HistoryEntry::ToolCall(tool_call)) = self.history.get_mut(focused_index) {
            if tool_call.status == ToolCallStatus::Executing {
                return false;
            }
            tool_call.expanded = !tool_call.expanded;
            self.dirty = true;
            return true;
        }

        false
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
        for (index, entry) in self.history.iter().enumerate() {
            match entry {
                HistoryEntry::Message(message) => lines.extend(render_message(message, width)),
                HistoryEntry::ToolCall(tool_call) => {
                    lines.extend(render_tool_call(
                        tool_call,
                        width,
                        self.spinner_index,
                        self.focused_tool_call == Some(index),
                    ));
                }
            }
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
        self.finalize_streaming_into_history();
        self.history.push(HistoryEntry::Message(Message {
            role,
            content,
            timestamp: current_hhmm(),
        }));
        self.on_new_message();
    }

    fn start_tool_call(&mut self, name: String, args: String) {
        self.finalize_streaming_into_history();

        self.history.push(HistoryEntry::ToolCall(ToolCallEntry {
            name,
            args,
            status: ToolCallStatus::Executing,
            preview: String::new(),
            full_result: String::new(),
            expanded: false,
        }));
        self.focused_tool_call = self.history.len().checked_sub(1);
        self.on_new_message();
    }

    fn complete_tool_call(
        &mut self,
        name: String,
        success: bool,
        preview: String,
        full_result: String,
    ) {
        let status = if success {
            ToolCallStatus::Success
        } else {
            ToolCallStatus::Failure
        };

        for entry in self.history.iter_mut().rev() {
            if let HistoryEntry::ToolCall(tool_call) = entry {
                if tool_call.name == name && tool_call.status == ToolCallStatus::Executing {
                    tool_call.status = status;
                    tool_call.preview = first_line(&preview).to_string();
                    tool_call.full_result = full_result;
                    self.dirty = true;
                    return;
                }
            }
        }

        self.history.push(HistoryEntry::ToolCall(ToolCallEntry {
            name,
            args: String::new(),
            status,
            preview: first_line(&preview).to_string(),
            full_result,
            expanded: false,
        }));
        self.focused_tool_call = self.history.len().checked_sub(1);
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
        self.finalize_streaming_into_history();
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
        if !self.is_agent_streaming && !self.has_executing_tool_call() {
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

    fn has_executing_tool_call(&self) -> bool {
        self.history.iter().any(|entry| {
            matches!(
                entry,
                HistoryEntry::ToolCall(ToolCallEntry {
                    status: ToolCallStatus::Executing,
                    ..
                })
            )
        })
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

    fn finalize_streaming_into_history(&mut self) {
        if let Some(streaming) = self.streaming_agent.take() {
            if !streaming.content.trim().is_empty() {
                self.history.push(HistoryEntry::Message(Message {
                    role: MessageRole::Agent,
                    content: streaming.content,
                    timestamp: streaming.timestamp,
                }));
            }
        }
    }

    fn tool_call_indices(&self) -> Vec<usize> {
        self.history
            .iter()
            .enumerate()
            .filter_map(|(idx, entry)| matches!(entry, HistoryEntry::ToolCall(_)).then_some(idx))
            .collect()
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

    pub fn status_line(&self, width: u16) -> Line<'static> {
        StatusBar.render(&self.status, width)
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

fn render_tool_call(
    tool_call: &ToolCallEntry,
    width: u16,
    spinner_index: usize,
    is_focused: bool,
) -> Vec<Line<'static>> {
    let focus_modifier = if is_focused {
        Modifier::UNDERLINED
    } else {
        Modifier::empty()
    };

    let status_symbol = match tool_call.status {
        ToolCallStatus::Executing => SPINNER_FRAMES[spinner_index],
        ToolCallStatus::Success => "✓",
        ToolCallStatus::Failure => "✗",
    };
    let status_color = match tool_call.status {
        ToolCallStatus::Executing => amber(),
        ToolCallStatus::Success => teal(),
        ToolCallStatus::Failure => copper(),
    };

    let mut lines = Vec::new();
    let mut first_line = vec![
        Span::styled("  ● ".to_string(), Style::default().fg(dim())),
        Span::styled(
            format!("{status_symbol} "),
            Style::default()
                .fg(status_color)
                .add_modifier(focus_modifier),
        ),
        Span::styled(
            format!("{}({})", tool_call.name, tool_call.args),
            Style::default().fg(chalk()).add_modifier(focus_modifier),
        ),
    ];

    if tool_call.status != ToolCallStatus::Executing && !tool_call.preview.is_empty() {
        let current_width: usize = first_line
            .iter()
            .map(|span| span.content.chars().count())
            .sum();
        let preview_prefix = " -> ";
        let preview_room = (width as usize)
            .saturating_sub(current_width)
            .saturating_sub(preview_prefix.chars().count());
        if preview_room > 0 {
            first_line.push(Span::styled(
                preview_prefix.to_string(),
                Style::default().fg(dim()),
            ));
            first_line.push(Span::styled(
                truncate_chars(&tool_call.preview, preview_room),
                Style::default().fg(dim()),
            ));
        }
    }
    lines.push(Line::from(first_line));

    if tool_call.expanded && !tool_call.full_result.trim().is_empty() {
        let wrap_width = width.saturating_sub(4).max(1) as usize;
        for segment in wrap_text(&tool_call.full_result, wrap_width) {
            lines.push(Line::from(vec![
                Span::styled("    ".to_string(), Style::default().fg(dim())),
                Span::styled(segment, Style::default().fg(dim())),
            ]));
        }
    }

    lines
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

fn first_line(input: &str) -> &str {
    input.lines().next().unwrap_or("")
}

fn truncate_chars(input: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }

    let count = input.chars().count();
    if count <= width {
        return input.to_string();
    }

    if width <= 3 {
        return ".".repeat(width);
    }

    let mut truncated = String::new();
    for ch in input.chars().take(width.saturating_sub(3)) {
        truncated.push(ch);
    }
    truncated.push_str("...");
    truncated
}

fn steel() -> Color {
    Color::Rgb(91, 143, 212)
}

fn teal() -> Color {
    Color::Rgb(74, 158, 142)
}

fn copper() -> Color {
    Color::Rgb(212, 138, 74)
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

    use super::{App, AppEvent, IrFrontendState};

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
    fn status_line_updates_for_ida_session_and_tokens() {
        let mut app = App::new();
        app.reduce(AppEvent::IdaConnectionChanged(true));
        app.reduce(AppEvent::SessionChanged(Some(
            "3f2a1b4c-8e9d-4a2b-b1c3-d4e5f6a7b8c9".to_string(),
        )));
        app.reduce(AppEvent::TurnCompleted { tokens_used: 4_821 });

        let status = app.status_line(120).to_string();
        assert_eq!(
            status,
            "[IDA: connected] [Session: 3f2a1b4c] [Tokens: 4,821] [IR: none] [Auth: none]"
        );
    }

    #[test]
    fn status_line_resets_token_count_on_session_change() {
        let mut app = App::new();
        app.reduce(AppEvent::TurnCompleted { tokens_used: 125 });
        app.reduce(AppEvent::SessionChanged(Some(
            "550e8400-e29b-41d4-a716-446655440000".to_string(),
        )));

        let status = app.status_line(120).to_string();
        assert!(status.contains("[Tokens: 0]"));
        assert!(status.contains("[IR: none]"));
    }

    #[test]
    fn status_line_updates_ir_frontend_after_lift() {
        let mut app = App::new();
        app.reduce(AppEvent::SessionChanged(Some(
            "550e8400-e29b-41d4-a716-446655440000".to_string(),
        )));
        app.reduce(AppEvent::IrFrontendChanged(IrFrontendState::Ida));

        let status = app.status_line(120).to_string();
        assert!(status.contains("[IR: ida]"));
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
    fn tool_call_renders_executing_and_completed_states() {
        let mut app = App::new();
        app.reduce(AppEvent::ToolCallStart {
            name: "decompile".to_string(),
            args: "0x401000".to_string(),
        });

        let executing = app.history_lines(80);
        assert!(executing
            .iter()
            .any(|line| line.to_string().contains("● ⠋ decompile(0x401000)")));

        app.reduce(AppEvent::ToolCallResult {
            name: "decompile".to_string(),
            success: true,
            preview: "47 lines of pseudocode".to_string(),
            full_result: "line one\nline two".to_string(),
        });

        let completed = app.history_lines(80);
        assert!(completed.iter().any(|line| line
            .to_string()
            .contains("● ✓ decompile(0x401000) -> 47 lines of pseudocode")));
    }

    #[test]
    fn tool_call_expand_toggle_reveals_full_result() {
        let mut app = App::new();
        app.reduce(AppEvent::ToolCallStart {
            name: "rename".to_string(),
            args: "sub_401000 -> aes_key_schedule".to_string(),
        });
        app.reduce(AppEvent::ToolCallResult {
            name: "rename".to_string(),
            success: true,
            preview: "renamed".to_string(),
            full_result: "first line\nsecond line".to_string(),
        });

        let collapsed = app.history_lines(80);
        assert!(collapsed
            .iter()
            .all(|line| !line.to_string().contains("second line")));

        app.focus_next_tool_call();
        assert!(app.toggle_focused_tool_call());

        let expanded = app.history_lines(80);
        assert!(expanded
            .iter()
            .any(|line| line.to_string().contains("first line")));
        assert!(expanded
            .iter()
            .any(|line| line.to_string().contains("second line")));
    }

    #[test]
    fn tool_calls_interleave_between_streaming_agent_chunks() {
        let mut app = App::new();
        app.reduce(AppEvent::AgentMessageStart);
        app.reduce(AppEvent::AgentMessageDelta("Let me check.".to_string()));
        app.reduce(AppEvent::ToolCallStart {
            name: "get_callees".to_string(),
            args: "0x401000".to_string(),
        });
        app.reduce(AppEvent::ToolCallResult {
            name: "get_callees".to_string(),
            success: true,
            preview: "3 callees found".to_string(),
            full_result: "a\nb\nc".to_string(),
        });
        app.reduce(AppEvent::AgentMessageDelta(
            " It calls three functions.".to_string(),
        ));
        app.reduce(AppEvent::AgentMessageComplete);

        let rendered = app.history_lines(100);
        let joined = rendered
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");

        let first_agent = joined.find("Agent: Let me check.").expect("first chunk");
        let tool_line = joined
            .find("● ✓ get_callees(0x401000) -> 3 callees found")
            .expect("tool line");
        let second_agent = joined
            .find("Agent: It calls three functions.")
            .expect("second chunk");

        assert!(first_agent < tool_line);
        assert!(tool_line < second_agent);
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

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppEvent {
    AgentMessage(String),
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
}

#[derive(Debug, Default)]
pub struct App {
    input: String,
    messages: Vec<Message>,
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
            AppEvent::AgentMessage(message) => self.push_message(MessageRole::Agent, message),
            AppEvent::SystemMessage(message) => self.push_message(MessageRole::System, message),
            AppEvent::Quit => {
                self.should_quit = true;
                self.dirty = true;
            }
        }
    }

    pub fn insert_char(&mut self, ch: char) {
        self.input.push(ch);
        self.dirty = true;
    }

    pub fn insert_newline(&mut self) {
        self.input.push('\n');
        self.dirty = true;
    }

    pub fn backspace(&mut self) {
        if self.input.pop().is_some() {
            self.dirty = true;
        }
    }

    pub fn clear_input(&mut self) {
        if !self.input.is_empty() {
            self.input.clear();
            self.dirty = true;
        }
    }

    pub fn submit(&mut self) {
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
        let mut lines = Vec::new();
        for message in &self.messages {
            lines.extend(render_message(message, width));
        }
        lines
    }

    pub fn input_lines(&self, width: u16) -> Vec<Line<'static>> {
        let prompt = "◆ ";
        let continuation = "  ";
        let available = available_width(width as usize, prompt.chars().count());
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

    fn input_height(&self, width: u16) -> u16 {
        let prompt_width = 2usize;
        let wrapped_lines =
            wrap_text(&self.input, available_width(width as usize, prompt_width)).len() as u16;
        wrapped_lines.clamp(1, 3)
    }

    fn push_message(&mut self, role: MessageRole, content: String) {
        self.messages.push(Message { role, content });
        self.dirty = true;
    }
}

fn render_message(message: &Message, width: u16) -> Vec<Line<'static>> {
    let (prefix, prefix_color) = match message.role {
        MessageRole::User => ("You: ", steel()),
        MessageRole::Agent => ("Agent: ", teal()),
        MessageRole::System => ("  ● ", dim()),
    };

    let continuation = " ".repeat(prefix.chars().count());
    let wrapped = wrap_text(
        &message.content,
        available_width(width as usize, prefix.chars().count()),
    );

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
            let content_style = if message.role == MessageRole::System {
                Style::default().fg(dim())
            } else {
                Style::default().fg(chalk())
            };

            Line::from(vec![
                Span::styled(current_prefix.to_string(), prefix_style),
                Span::styled(segment, content_style),
            ])
        })
        .collect()
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

fn available_width(total_width: usize, prefix_width: usize) -> usize {
    total_width.saturating_sub(prefix_width).max(1)
}

fn steel() -> Color {
    Color::Rgb {
        r: 91,
        g: 143,
        b: 212,
    }
}

fn teal() -> Color {
    Color::Rgb {
        r: 74,
        g: 158,
        b: 142,
    }
}

fn amber() -> Color {
    Color::Rgb {
        r: 212,
        g: 160,
        b: 74,
    }
}

fn chalk() -> Color {
    Color::Rgb {
        r: 200,
        g: 200,
        b: 200,
    }
}

fn dim() -> Color {
    Color::Rgb {
        r: 90,
        g: 90,
        b: 90,
    }
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
}

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdaConnectionState {
    Connected,
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/// Active IR frontend indicator rendered in the status bar.
pub enum IrFrontendState {
    /// IDA-backed IR frontend is active.
    Ida,
    /// Capstone-backed IR frontend is active.
    Capstone,
    /// No IR frontend is active.
    #[default]
    None,
}

impl IrFrontendState {
    /// Maps a frontend name to a status-bar IR frontend state.
    #[must_use]
    pub fn from_frontend_name(name: Option<&str>) -> Self {
        match name {
            Some(frontend) if frontend.eq_ignore_ascii_case("ida") => Self::Ida,
            Some(frontend) if frontend.eq_ignore_ascii_case("capstone") => Self::Capstone,
            _ => Self::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusBarState {
    pub ida: IdaConnectionState,
    pub session_id: Option<String>,
    pub tokens: u64,
    /// Current active IR frontend for status rendering.
    pub ir_frontend: IrFrontendState,
}

impl Default for StatusBarState {
    fn default() -> Self {
        Self {
            ida: IdaConnectionState::Disconnected,
            session_id: None,
            tokens: 0,
            ir_frontend: IrFrontendState::None,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StatusBar;

impl StatusBar {
    pub fn render(&self, state: &StatusBarState, width: u16) -> Line<'static> {
        let ida_value = match state.ida {
            IdaConnectionState::Connected => Span::styled("connected", Style::default().fg(teal())),
            IdaConnectionState::Disconnected => {
                Span::styled("disconnected", Style::default().fg(copper()))
            }
        };

        let session_value = match short_session_id(state.session_id.as_deref()) {
            Some(id) => Span::styled(id.to_string(), Style::default().fg(chalk())),
            None => Span::styled("none", Style::default().fg(dim())),
        };

        let token_value = Span::styled(format_tokens(state.tokens), Style::default().fg(chalk()));
        let ir_value = match state.ir_frontend {
            IrFrontendState::Ida => Span::styled("ida", Style::default().fg(teal())),
            IrFrontendState::Capstone => Span::styled("capstone", Style::default().fg(amber())),
            IrFrontendState::None => Span::styled("none", Style::default().fg(copper())),
        };
        let auth_value = Span::styled("none", Style::default().fg(chalk()));

        let mut spans = vec![
            dim_span("[IDA: "),
            ida_value,
            dim_span("] "),
            dim_span("[Session: "),
            session_value,
            dim_span("] "),
            dim_span("[Tokens: "),
            token_value,
            dim_span("] "),
        ];

        if state.session_id.is_some() {
            spans.push(dim_span("[IR: "));
            spans.push(ir_value);
            spans.push(dim_span("] "));
        }

        spans.push(dim_span("[Auth: "));
        spans.push(auth_value);
        spans.push(dim_span("]"));

        Line::from(truncate_spans(spans, width as usize))
    }
}

fn dim_span(content: &'static str) -> Span<'static> {
    Span::styled(content, Style::default().fg(dim()))
}

fn short_session_id(session_id: Option<&str>) -> Option<&str> {
    let session_id = session_id?;
    let head = session_id.split('-').next().unwrap_or(session_id);

    if head.len() >= 8 {
        Some(&head[..8])
    } else if session_id.len() >= 8 {
        Some(&session_id[..8])
    } else {
        Some(session_id)
    }
}

fn format_tokens(tokens: u64) -> String {
    let raw = tokens.to_string();
    let mut out = String::with_capacity(raw.len() + raw.len() / 3);
    for (index, ch) in raw.chars().enumerate() {
        if index > 0 && (raw.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn truncate_spans(spans: Vec<Span<'static>>, width: usize) -> Vec<Span<'static>> {
    if width == 0 {
        return Vec::new();
    }

    let mut glyphs = Vec::new();
    for span in &spans {
        for ch in span.content.chars() {
            glyphs.push((ch, span.style));
        }
    }

    if glyphs.len() <= width {
        return spans;
    }

    if width == 1 {
        return vec![Span::styled("…", Style::default().fg(dim()))];
    }

    glyphs.truncate(width - 1);
    glyphs.push(('…', Style::default().fg(dim())));

    merge_glyphs(glyphs)
}

fn merge_glyphs(glyphs: Vec<(char, Style)>) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let mut current_style = None;
    let mut current_text = String::new();

    for (ch, style) in glyphs {
        match current_style {
            Some(active_style) if active_style == style => current_text.push(ch),
            Some(active_style) => {
                spans.push(Span::styled(current_text.clone(), active_style));
                current_text.clear();
                current_text.push(ch);
                current_style = Some(style);
            }
            None => {
                current_style = Some(style);
                current_text.push(ch);
            }
        }
    }

    if let Some(active_style) = current_style {
        spans.push(Span::styled(current_text, active_style));
    }

    spans
}

fn teal() -> Color {
    Color::Rgb(74, 158, 142)
}

fn copper() -> Color {
    Color::Rgb(212, 138, 74)
}

fn chalk() -> Color {
    Color::Rgb(200, 200, 200)
}

fn amber() -> Color {
    Color::Rgb(212, 160, 74)
}

fn dim() -> Color {
    Color::Rgb(90, 90, 90)
}

#[cfg(test)]
mod tests {
    use super::{IdaConnectionState, IrFrontendState, StatusBar, StatusBarState};

    #[test]
    fn renders_connected_session_and_tokens() {
        let state = StatusBarState {
            ida: IdaConnectionState::Connected,
            session_id: Some("3f2a1b4c-8e9d-4a2b-b1c3-d4e5f6a7b8c9".to_string()),
            tokens: 4_821,
            ir_frontend: IrFrontendState::Ida,
        };

        let line = StatusBar.render(&state, 120).to_string();

        assert_eq!(
            line,
            "[IDA: connected] [Session: 3f2a1b4c] [Tokens: 4,821] [IR: ida] [Auth: none]"
        );
    }

    #[test]
    fn renders_disconnected_defaults() {
        let state = StatusBarState::default();

        let line = StatusBar.render(&state, 80).to_string();

        assert_eq!(
            line,
            "[IDA: disconnected] [Session: none] [Tokens: 0] [Auth: none]"
        );
    }

    #[test]
    fn truncates_with_ellipsis_at_narrow_width() {
        let state = StatusBarState {
            ida: IdaConnectionState::Connected,
            session_id: Some("3f2a1b4c-8e9d-4a2b-b1c3-d4e5f6a7b8c9".to_string()),
            tokens: 12_340,
            ir_frontend: IrFrontendState::Capstone,
        };

        let line = StatusBar.render(&state, 40).to_string();

        assert_eq!(line.chars().count(), 40);
        assert!(line.ends_with('…'));
    }

    #[test]
    fn maps_frontend_names_to_states() {
        assert_eq!(
            IrFrontendState::from_frontend_name(Some("ida")),
            IrFrontendState::Ida
        );
        assert_eq!(
            IrFrontendState::from_frontend_name(Some("capstone")),
            IrFrontendState::Capstone
        );
        assert_eq!(
            IrFrontendState::from_frontend_name(None),
            IrFrontendState::None
        );
    }
}

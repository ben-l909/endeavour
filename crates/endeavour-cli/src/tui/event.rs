use std::io;
use std::time::Duration;

use crossterm::event::{
    Event as CrosstermEvent, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
};
use futures_util::StreamExt;
use ratatui::Terminal;
use ratatui::backend::Backend;
use ratatui::layout::{Alignment, Rect};
use ratatui::text::Text;
use ratatui::widgets::{Paragraph, Wrap};
use tokio::select;
use tokio::sync::mpsc;
use tokio::time;

use super::app::{App, AppEvent};

pub async fn run_event_loop<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    mut app_events: mpsc::Receiver<AppEvent>,
) -> io::Result<()> {
    let mut terminal_events = EventStream::new();
    let mut tick = time::interval(Duration::from_millis(33));

    while !app.should_quit() {
        select! {
            maybe_event = terminal_events.next() => {
                match maybe_event {
                    Some(Ok(event)) => handle_terminal_event(app, event),
                    Some(Err(error)) => {
                        return Err(io::Error::other(format!("terminal event stream failed: {error}")));
                    }
                    None => app.reduce(AppEvent::Quit),
                }
            }
            maybe_app_event = app_events.recv() => {
                match maybe_app_event {
                    Some(event) => app.reduce(event),
                    None => app.reduce(AppEvent::Quit),
                }
            }
            _ = tick.tick() => {}
        }

        if app.is_dirty() {
            terminal.draw(|frame| {
                let area = frame.area();
                if area.width < 80 || area.height < 24 {
                    let warning = Paragraph::new("Terminal too small. Resize to at least 80x24.")
                        .alignment(Alignment::Center);
                    frame.render_widget(warning, centered_rect(area));
                    return;
                }

                let panes = app.layout(area);

                let history_lines = app.history_lines(panes.history.width);
                let history_visible = panes.history.height as usize;
                let history_start = history_lines.len().saturating_sub(history_visible);
                let history_lines = history_lines
                    .into_iter()
                    .skip(history_start)
                    .collect::<Vec<_>>();
                frame.render_widget(
                    Paragraph::new(Text::from(history_lines)).wrap(Wrap { trim: false }),
                    panes.history,
                );

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
            })?;
            app.clear_dirty();
        }
    }

    Ok(())
}

fn handle_terminal_event(app: &mut App, event: CrosstermEvent) {
    if let CrosstermEvent::Key(key) = event {
        if key.kind == KeyEventKind::Release {
            return;
        }
        handle_key_event(app, key);
    }
}

fn handle_key_event(app: &mut App, key: KeyEvent) {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('c') => {
                app.reduce(AppEvent::Quit);
                return;
            }
            KeyCode::Char('d') => {
                app.reduce(AppEvent::Quit);
                return;
            }
            _ => {}
        }
    }

    match key.code {
        KeyCode::Enter if key.modifiers.contains(KeyModifiers::SHIFT) => app.insert_newline(),
        KeyCode::Enter => app.submit(),
        KeyCode::Backspace => app.backspace(),
        KeyCode::Esc => app.clear_input(),
        KeyCode::Char(ch) => app.insert_char(ch),
        _ => {}
    }
}

fn centered_rect(area: Rect) -> Rect {
    Rect {
        x: area.x,
        y: area.y + area.height.saturating_sub(1) / 2,
        width: area.width,
        height: 1,
    }
}

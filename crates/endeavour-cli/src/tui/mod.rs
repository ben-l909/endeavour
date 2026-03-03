use std::io;

use crossterm::event::DisableMouseCapture;
use crossterm::event::EnableMouseCapture;
use crossterm::execute;
use crossterm::terminal::disable_raw_mode;
use crossterm::terminal::enable_raw_mode;
use crossterm::terminal::EnterAlternateScreen;
use crossterm::terminal::LeaveAlternateScreen;
use endeavour_llm::{LlmError, ProviderStream, StreamChunkKind, Usage};
use futures_util::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc;
use tokio::sync::watch;

pub mod app;
pub mod event;
pub mod intent_router;

pub use app::AppEvent;

struct TerminalStateGuard {
    active: bool,
}

impl TerminalStateGuard {
    fn new() -> Self {
        Self { active: true }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for TerminalStateGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }

        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen, DisableMouseCapture);
    }
}

pub fn channel(capacity: usize) -> (mpsc::Sender<AppEvent>, mpsc::Receiver<AppEvent>) {
    mpsc::channel(capacity)
}

pub async fn run(app_events: mpsc::Receiver<AppEvent>) -> io::Result<()> {
    run_with_cancel(app_events, None).await
}

pub async fn run_with_cancel(
    app_events: mpsc::Receiver<AppEvent>,
    stream_cancel_signal: Option<watch::Sender<bool>>,
) -> io::Result<()> {
    enable_raw_mode()?;

    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let mut guard = TerminalStateGuard::new();

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut app = app::App::new();
    let run_result =
        event::run_event_loop(&mut terminal, &mut app, app_events, stream_cancel_signal).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    guard.disarm();

    run_result
}

pub async fn forward_agent_stream(
    mut stream: ProviderStream,
    app_events: &mpsc::Sender<AppEvent>,
) -> Result<Option<Usage>, LlmError> {
    send_app_event(app_events, AppEvent::AgentMessageStart).await?;

    let mut usage = None;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        match chunk.kind {
            StreamChunkKind::TextDelta(delta) if !delta.is_empty() => {
                send_app_event(app_events, AppEvent::AgentMessageDelta(delta)).await?;
            }
            StreamChunkKind::Done {
                usage: done_usage, ..
            } => {
                usage = Some(done_usage);
                break;
            }
            _ => {}
        }
    }

    send_app_event(app_events, AppEvent::AgentMessageComplete).await?;
    Ok(usage)
}

async fn send_app_event(
    app_events: &mpsc::Sender<AppEvent>,
    event: AppEvent,
) -> Result<(), LlmError> {
    app_events.send(event).await.map_err(|error| {
        LlmError::Configuration(format!("failed to forward stream event to TUI: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use endeavour_llm::{StopReason, StreamChunk, StreamChunkKind, Usage};
    use futures_util::stream;

    use super::*;

    #[tokio::test]
    async fn forward_agent_stream_dispatches_text_deltas_and_completion() {
        let chunks = vec![
            Ok(StreamChunk {
                kind: StreamChunkKind::TextDelta("hel".to_string()),
                stop_reason: None,
            }),
            Ok(StreamChunk {
                kind: StreamChunkKind::TextDelta("lo".to_string()),
                stop_reason: None,
            }),
            Ok(StreamChunk {
                kind: StreamChunkKind::Done {
                    stop_reason: StopReason::EndTurn,
                    usage: Usage {
                        input_tokens: 12,
                        output_tokens: 7,
                    },
                },
                stop_reason: Some(StopReason::EndTurn),
            }),
        ];

        let (tx, mut rx) = mpsc::channel(8);
        let usage = forward_agent_stream(Box::pin(stream::iter(chunks)), &tx)
            .await
            .expect("stream forwarding should succeed");

        assert_eq!(
            usage,
            Some(Usage {
                input_tokens: 12,
                output_tokens: 7,
            })
        );

        assert_eq!(rx.recv().await, Some(AppEvent::AgentMessageStart));
        assert_eq!(
            rx.recv().await,
            Some(AppEvent::AgentMessageDelta("hel".to_string()))
        );
        assert_eq!(
            rx.recv().await,
            Some(AppEvent::AgentMessageDelta("lo".to_string()))
        );
        assert_eq!(rx.recv().await, Some(AppEvent::AgentMessageComplete));
    }
}

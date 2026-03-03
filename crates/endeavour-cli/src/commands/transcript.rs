use crate::fmt;
use crate::repl::{Repl, ShowTranscriptCommand};
use anyhow::{Context, Result};
use endeavour_llm::{Message, ToolCall, ToolResult, TranscriptContent, Usage};

pub(crate) fn handle_show_transcript(repl: &Repl, command: &ShowTranscriptCommand) -> Result<()> {
    let session_id = if let Some(session_id) = &command.session_id {
        session_id
            .parse()
            .with_context(|| format!("invalid session id: {session_id}"))?
    } else if let Some(active_session) = &repl.active_session {
        active_session.id
    } else {
        println!("No active session. Use 'session <id>' or pass show-transcript <session_id>.");
        return Ok(());
    };

    let entries = repl
        .store
        .get_transcript_entries(session_id, command.turn)
        .with_context(|| format!("failed to load transcript for session {session_id}"))?;

    if entries.is_empty() {
        println!("  ● INFO  no transcript found for session {session_id}");
        return Ok(());
    }

    println!("{}", render_transcript_output(session_id, &entries));
    Ok(())
}

fn render_transcript_output(
    session_id: uuid::Uuid,
    entries: &[endeavour_core::TranscriptRecord],
) -> String {
    let mut lines = Vec::new();
    let turn_count = entries
        .iter()
        .map(|entry| entry.turn_number)
        .collect::<std::collections::HashSet<_>>()
        .len();
    let total_tool_calls = entries
        .iter()
        .filter_map(|entry| parse_tool_calls(entry.tool_calls_json.as_deref()))
        .map(|calls| calls.len())
        .sum::<usize>();

    lines.push(format!("◆ Transcript: {}", session_id));
    lines.push(fmt::separator(fmt::Separator::Heavy, 78));
    lines.push(format!("  Rounds       {turn_count}"));
    lines.push(format!("  Tool calls   {total_tool_calls}"));
    lines.push(fmt::separator(fmt::Separator::Standard, 78));

    let mut current_turn = 0u32;
    for entry in entries {
        if entry.turn_number != current_turn {
            if current_turn != 0 {
                lines.push(String::new());
            }
            current_turn = entry.turn_number;
            lines.push(format!("◆ Round {}", entry.turn_number));
            lines.push(fmt::separator(fmt::Separator::Standard, 78));
        }

        match entry.role.as_str() {
            "llm" => {
                if let Some(message) = parse_transcript_message(&entry.content_json) {
                    for text_line in message.content.lines() {
                        lines.push(format!("  {text_line}"));
                    }
                }
                if let Some(tool_calls) = parse_tool_calls(entry.tool_calls_json.as_deref()) {
                    for tool_call in tool_calls {
                        lines.push(format!("  ▶ {}", format_tool_call(&tool_call)));
                    }
                }
                if let Some(usage) = parse_usage(entry.usage_json.as_deref()) {
                    lines.push(format!(
                        "  usage: input={} output={}",
                        usage.input_tokens, usage.output_tokens
                    ));
                }
            }
            "tool_executor" => {
                if let Some(tool_result) = parse_transcript_tool_result(&entry.content_json) {
                    if tool_result.is_error {
                        lines.push(format!("  ◀ ✗ {}", tool_result.content));
                    } else {
                        lines.push(format!("  ◀ {}", tool_result.content));
                    }
                }
            }
            "system" => {
                if let Some(message) = parse_transcript_message(&entry.content_json) {
                    lines.push(format!("  [state={}] {}", entry.state, message.content));
                }
            }
            _ => lines.push(format!("  {}", entry.content_json)),
        }
    }

    lines.join("\n")
}

fn parse_transcript_message(content_json: &str) -> Option<Message> {
    let content = serde_json::from_str::<TranscriptContent>(content_json).ok()?;
    match content {
        TranscriptContent::Message(message) => Some(message),
        TranscriptContent::ToolResult(_) => None,
    }
}

fn parse_transcript_tool_result(content_json: &str) -> Option<ToolResult> {
    let content = serde_json::from_str::<TranscriptContent>(content_json).ok()?;
    match content {
        TranscriptContent::ToolResult(result) => Some(result),
        TranscriptContent::Message(_) => None,
    }
}

fn parse_usage(usage_json: Option<&str>) -> Option<Usage> {
    serde_json::from_str::<Usage>(usage_json?).ok()
}

fn parse_tool_calls(tool_calls_json: Option<&str>) -> Option<Vec<ToolCall>> {
    serde_json::from_str::<Vec<ToolCall>>(tool_calls_json?).ok()
}

fn format_tool_call(tool_call: &ToolCall) -> String {
    let mut output = tool_call.name.clone();
    if let serde_json::Value::Object(map) = &tool_call.input {
        let mut keys = map.keys().cloned().collect::<Vec<_>>();
        keys.sort();
        for key in keys {
            if let Some(value) = map.get(&key) {
                output.push_str("  ");
                output.push_str(&key);
                output.push('=');
                output.push_str(&format_tool_arg_value(value));
            }
        }
    }
    output
}

fn format_tool_arg_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => format!("\"{text}\""),
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::render_transcript_output;
    use endeavour_core::TranscriptRecord;

    #[test]
    fn transcript_commands_output_includes_rounds_tool_calls_and_results() {
        let session_id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000");
        assert!(session_id.is_ok());
        let session_id = match session_id {
            Ok(value) => value,
            Err(err) => panic!("unexpected parse failure: {err}"),
        };

        let entries = vec![
            TranscriptRecord {
                id: uuid::Uuid::new_v4(),
                session_id,
                turn_number: 1,
                role: "llm".to_string(),
                timestamp: "1700000000".to_string(),
                content_json: "{\"kind\":\"message\",\"value\":{\"role\":\"assistant\",\"content\":\"Looking up the function\",\"tool_results\":[]}}".to_string(),
                usage_json: Some("{\"input_tokens\":12,\"output_tokens\":4}".to_string()),
                state: "llm_streaming".to_string(),
                tool_calls_json: Some("[{\"id\":\"tc1\",\"name\":\"decompile\",\"input\":{\"addr\":\"0x401000\"}}]".to_string()),
            },
            TranscriptRecord {
                id: uuid::Uuid::new_v4(),
                session_id,
                turn_number: 1,
                role: "tool_executor".to_string(),
                timestamp: "1700000001".to_string(),
                content_json: "{\"kind\":\"tool_result\",\"value\":{\"tool_use_id\":\"tc1\",\"content\":\"142 bytes of pseudocode returned\",\"output\":null,\"display_summary\":null,\"is_error\":false}}".to_string(),
                usage_json: None,
                state: "execute_tools".to_string(),
                tool_calls_json: None,
            },
        ];

        let rendered = render_transcript_output(session_id, &entries);
        assert!(rendered.contains("◆ Transcript:"));
        assert!(rendered.contains("◆ Round 1"));
        assert!(rendered.contains("▶ decompile  addr=\"0x401000\""));
        assert!(rendered.contains("◀ 142 bytes of pseudocode returned"));
        assert!(rendered.contains("usage: input=12 output=4"));
    }
}

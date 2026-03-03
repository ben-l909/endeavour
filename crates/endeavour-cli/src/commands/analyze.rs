use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use crate::auth::resolver::apply_resolved_credentials;
use crate::fmt;
use crate::repl::{ExplainCommand, RenameCommand, Repl};
use anyhow::{Context, Result};
use endeavour_core::config::Config;
use endeavour_core::store::SessionStore;
use endeavour_core::{loader, NewReviewQueueRecord, NewTranscriptRecord, ReviewQueueRecord};
use endeavour_ida::{DecompileResult, IdaClient, IdaError};
use endeavour_llm::{
    AgenticLoopConfig, AgenticLoopController, AnthropicProvider, CompletionRequest, ContextBuilder,
    FunctionContext, IdaToolExecutor, LlmError, LlmProvider, LlmRouter, Message, OpenAiProvider,
    ProviderSelection, Role, RouterNotice, TaskType, TranscriptContent,
};
use tokio::runtime::Runtime;

const RENAME_SYSTEM_PROMPT: &str = "You are an expert reverse engineering assistant focused on naming. Return only JSON matching this schema: {\"function_rename\": {\"proposed_name\": \"string | null\", \"confidence\": 0.0}, \"variable_renames\": [{\"current_name\": \"string\", \"proposed_name\": \"string\", \"confidence\": 0.0}], \"comments\": [{\"addr\": \"0x401000\", \"text\": \"string\", \"confidence\": 0.0}]}. Rules: top-level keys must be exactly function_rename, variable_renames, comments; confidence must be in [0,1]; proposed identifiers must match ^[a-zA-Z_][a-zA-Z0-9_]*$; comment addr must match ^0x[0-9a-f]+$; max 20 variable renames and max 10 comments. Return only the JSON object with no markdown or prose.";

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct RenameLlmResponse {
    function_rename: FunctionRenamePayload,
    variable_renames: Vec<VariableRenamePayload>,
    comments: Vec<CommentPayload>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct FunctionRenamePayload {
    proposed_name: Option<String>,
    confidence: f64,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct VariableRenamePayload {
    current_name: String,
    proposed_name: String,
    confidence: f64,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct CommentPayload {
    addr: String,
    text: String,
    confidence: f64,
}

#[derive(Debug, Clone)]
enum RenameSuggestionKind {
    Function,
    Variable,
    Comment,
}

#[derive(Debug, Clone)]
struct RenameSuggestion {
    kind: RenameSuggestionKind,
    function_addr: u64,
    target_addr: u64,
    current_name: String,
    proposed_value: String,
    confidence: f64,
}

#[derive(Debug, Default, Clone, Copy)]
struct TierCounters {
    applied: u32,
    queued: u32,
    discarded: u32,
    errors: u32,
}

#[derive(Debug)]
struct BatchFunctionResult {
    applied: u32,
    queued: u32,
    discarded: u32,
    errors: u32,
    function_line: Option<(String, f64, String)>,
}

enum RenameProvider {
    Anthropic(AnthropicProvider),
    OpenAi(OpenAiProvider),
}

#[derive(Debug, Clone, Copy)]
enum ConfidenceTier {
    Tier1,
    Tier2,
    Tier3,
}

pub(crate) fn handle_analyze(repl: &mut Repl, input_path: &str) -> Result<()> {
    let path = PathBuf::from(input_path);
    let binary = loader::load_binary(&path)
        .with_context(|| format!("failed to load binary at {}", path.display()))?;

    let session_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map_or_else(|| path.display().to_string(), ToString::to_string);

    let session = repl
        .store
        .create_session(&session_name, binary.uuid)
        .context("failed to create analysis session")?;

    println!(
        "Loaded {} and created session {} ({})",
        path.display(),
        session.name,
        session.id
    );

    repl.active_session = Some(session);
    Ok(())
}

pub(crate) fn handle_decompile(repl: &Repl, target: &str) {
    let Some(client) = repl.ida_client.as_ref() else {
        println!("Not connected. Run: connect <host:port>");
        return;
    };

    let (address, function_name) =
        match resolve_target_address(&repl.runtime, client.as_ref(), target) {
            Ok(value) => value,
            Err(_) => {
                println!("No function at address");
                return;
            }
        };

    let session_id = repl.active_session.as_ref().map(|session| session.id);
    let cached_result = session_id
        .and_then(|id| {
            repl.store
                .get_cached_ida_result(id, "decompile", address)
                .ok()
                .flatten()
        })
        .and_then(|payload| serde_json::from_str::<DecompileResult>(&payload).ok());

    let result = if let Some(cached) = cached_result {
        cached
    } else {
        let fetched = match repl.runtime.block_on(client.decompile(address)) {
            Ok(value) => value,
            Err(_) => {
                println!("No function at address");
                return;
            }
        };

        if let Some(id) = session_id {
            if let Ok(serialized) = serde_json::to_string(&fetched) {
                let _ = repl
                    .store
                    .cache_ida_result(id, "decompile", address, &serialized);
            }
        }
        fetched
    };

    println!("{}", render_decompile_result(&function_name, &result));
}

pub(crate) fn handle_explain(repl: &Repl, command: &ExplainCommand) -> Result<()> {
    let Some(client) = repl.ida_client.as_ref() else {
        println!("Not connected. Run: connect <host:port>");
        return Ok(());
    };

    let (address, function_name) =
        match resolve_target_address(&repl.runtime, client.as_ref(), &command.target) {
            Ok(value) => value,
            Err(err) => {
                println!("Failed to resolve target '{}': {err}", command.target);
                return Ok(());
            }
        };

    let decompile_result = match repl.runtime.block_on(client.decompile(address)) {
        Ok(value) => value,
        Err(err) if is_missing_function_error(&err) => {
            println!("No function at address");
            return Ok(());
        }
        Err(err) => {
            println!("Failed to decompile {}: {err}", fmt::format_addr(address));
            return Ok(());
        }
    };

    println!("Analyzing function at {}...", fmt::format_addr(address));

    let mut config = Config::load().context("failed to load config")?;
    apply_resolved_credentials(&mut config).context("failed to resolve credentials")?;
    let provider = match ProviderSelection::parse(&command.provider) {
        Ok(value) => Some(value),
        Err(LlmError::Configuration(message)) => {
            println!("✗ error: {message}");
            return Ok(());
        }
        Err(err) => {
            println!("✗ error: {}", format_llm_error(&err));
            return Ok(());
        }
    };

    let router = match LlmRouter::new(
        config.clone(),
        TaskType::Explain,
        provider,
        !command.no_fallback,
    ) {
        Ok(router) => router,
        Err(LlmError::Configuration(message)) => {
            println!("✗ error: {message}");
            return Ok(());
        }
        Err(err) => {
            println!("✗ error: {}", format_llm_error(&err));
            return Ok(());
        }
    };

    if matches!(router.notice(), Some(RouterNotice::OllamaNotImplemented)) {
        println!("  ● INFO  ollama support is planned but not yet available");
        println!("    ╰─ falling back to auto-routing");
    }

    if router.plan().auto_routed {
        println!(
            "  ● INFO  routing to {} via {} (task: explain)",
            router.plan().model,
            router.plan().provider.as_str()
        );
    } else {
        println!(
            "  ● INFO  using {} via {}",
            router.plan().model,
            router.plan().provider.as_str()
        );
    }

    let request = build_explain_request(&function_name, &decompile_result);
    let completion = match repl.runtime.block_on(router.complete(request)) {
        Ok(value) => value,
        Err(LlmError::RateLimited { .. }) if command.no_fallback => {
            println!("✗ error: provider request failed (fallback disabled)");
            println!(
                "    ╰─ {}: 429 rate limit exceeded",
                router.plan().provider.as_str()
            );
            println!(
                "       re-run without --no-fallback to use {} as fallback",
                if router.plan().provider.as_str() == "anthropic" {
                    "openai"
                } else {
                    "anthropic"
                }
            );
            return Ok(());
        }
        Err(err) => {
            println!("Explain request failed: {}", format_llm_error(&err));
            return Ok(());
        }
    };

    if let Some(fallback) = &completion.fallback {
        println!(
            "▲ warn: {} rate limited. Falling back to {} via {}. (--no-fallback to disable)",
            fallback.primary_provider.as_str(),
            fallback.fallback_model,
            fallback.fallback_provider.as_str()
        );
    }

    println!(
        "{}",
        render_explain_result(
            &function_name,
            address,
            &completion.response.model,
            &completion.response.content,
        )
    );
    Ok(())
}

pub(crate) fn handle_rename(repl: &mut Repl, command: &RenameCommand) -> Result<()> {
    if command.all {
        return handle_rename_all(repl, command);
    }

    let Some(target) = command.target.as_deref() else {
        println!("Usage: rename <addr> <new_name> | rename --llm <addr> | rename --all");
        return Ok(());
    };

    let run_llm = command.llm || command.new_name.is_none();
    if run_llm {
        return handle_rename_llm_single(repl, target, command);
    }

    let Some(new_name) = command.new_name.as_deref() else {
        println!("Usage: rename <addr> <new_name>");
        return Ok(());
    };

    handle_manual_rename(repl, target, new_name)
}

pub(crate) fn handle_review(repl: &mut Repl) -> Result<()> {
    let Some(session) = repl.active_session.as_ref() else {
        print_error(
            "no active session",
            &["Run 'analyze <path>' or 'session <id>' to set an active session first."],
        );
        return Ok(());
    };

    loop {
        let pending = repl.store.list_pending_review_queue(session.id)?;
        if pending.is_empty() {
            println!("\n  No pending suggestions. Queue is empty.");
            return Ok(());
        }

        println!("\n  Review Queue  ({} pending)", pending.len());
        println!("  {}", "═".repeat(88));
        println!("\n   #   Address       Current Name    Proposed Name     Confidence");
        println!("  {}", "─".repeat(84));
        for (index, item) in pending.iter().enumerate() {
            println!(
                "  {:>2}   {:<12}  {:<14}  {:<16}  {:.2}",
                index + 1,
                fmt::format_addr(item.target_addr.unwrap_or(item.function_addr)),
                truncate_for_review(&item.current_name, 14),
                truncate_for_review(&item.proposed_value, 16),
                item.confidence
            );
        }
        println!("\n  {}", "═".repeat(88));
        println!("\n  Commands: [a]ccept  [r]eject  [A]ccept all  [R]eject all  [q]uit");
        let input = read_prompt("  Enter number to select, or command: ")?;

        match input.as_str() {
            "q" => return Ok(()),
            "A" => {
                let result = accept_all_review(repl, session.id, &pending)?;
                println!("\n  ✓ Accepted {} suggestions. Applied to IDA.", result.0);
                if result.1 > 0 {
                    println!(
                        "  ✗ {} item was rejected by IDA — see transcript for details.",
                        result.1
                    );
                }
            }
            "R" => {
                let changed = repl
                    .store
                    .update_all_review_queue_status(session.id, "pending", "rejected")?;
                for item in &pending {
                    log_review_rejected(&repl.store, session.id, item)?;
                }
                println!("\n  ✗ Rejected {} suggestions. Queue cleared.", changed);
            }
            "a" => {
                if let Some(first) = pending.first() {
                    apply_review_item(repl, session.id, first)?;
                }
            }
            "r" => {
                if let Some(first) = pending.first() {
                    repl.store
                        .update_review_queue_status(first.id, "rejected")?;
                    log_review_rejected(&repl.store, session.id, first)?;
                    println!(
                        "\n  ✗ Rejected: {}  ->  {}  at {}",
                        first.current_name,
                        first.proposed_value,
                        fmt::format_addr(first.target_addr.unwrap_or(first.function_addr))
                    );
                }
            }
            _ => {
                if let Ok(index) = input.parse::<usize>() {
                    if index == 0 || index > pending.len() {
                        println!(
                            "\n  Invalid selection. Enter a number between 1 and {}.",
                            pending.len()
                        );
                        continue;
                    }
                    let item = &pending[index - 1];
                    println!(
                        "\n  Selected: {}  ->  {}  ({:.2})",
                        item.current_name, item.proposed_value, item.confidence
                    );
                    let action = read_prompt("  [a]ccept  [r]eject  [s]kip: ")?;
                    match action.as_str() {
                        "a" => apply_review_item(repl, session.id, item)?,
                        "r" => {
                            repl.store.update_review_queue_status(item.id, "rejected")?;
                            log_review_rejected(&repl.store, session.id, item)?;
                            println!(
                                "\n  ✗ Rejected: {}  ->  {}  at {}",
                                item.current_name,
                                item.proposed_value,
                                fmt::format_addr(item.target_addr.unwrap_or(item.function_addr))
                            );
                        }
                        "s" => {}
                        _ => {
                            println!("\n  Unknown command. Use [a]ccept, [r]eject, or [s]kip.")
                        }
                    }
                } else {
                    println!(
                        "\n  Unknown command. Use [a]ccept, [r]eject, [A]ccept all, [R]eject all, or [q]uit."
                    );
                }
            }
        }
    }
}

pub(crate) fn handle_comment(repl: &Repl, target: &str, comment: &str) -> Result<()> {
    let Some(client) = repl.ida_client.as_ref() else {
        println!("Not connected. Run: connect <host:port>");
        return Ok(());
    };

    let (address, _) = match resolve_target_address(&repl.runtime, client.as_ref(), target) {
        Ok(value) => value,
        Err(err) => {
            println!("{}", format_resolve_target_error(target, &err));
            return Ok(());
        }
    };

    match set_symbol_comment(&repl.runtime, client.as_ref(), address, comment) {
        Ok(()) => println!("Comment set at {}", fmt::format_addr(address)),
        Err(err) => println!("Failed to set comment: {err}"),
    }

    Ok(())
}

pub(crate) fn handle_cache_stats(repl: &Repl) -> Result<()> {
    let Some(session) = &repl.active_session else {
        println!("No active session. Use 'analyze <path>' or 'session <id>'.");
        return Ok(());
    };

    let stats = repl
        .store
        .cache_stats(session.id)
        .with_context(|| format!("failed to get cache stats for session {}", session.id))?;

    println!("Cache entries: {}", stats.entry_count);
    if stats.methods.is_empty() {
        println!("Cached methods: (none)");
    } else {
        println!("Cached methods: {}", stats.methods.join(", "));
    }

    Ok(())
}

pub(crate) fn handle_cache_clear(repl: &Repl) -> Result<()> {
    let Some(session) = &repl.active_session else {
        println!("No active session. Use 'analyze <path>' or 'session <id>'.");
        return Ok(());
    };

    repl.store
        .clear_ida_cache(session.id)
        .with_context(|| format!("failed to clear cache for session {}", session.id))?;

    println!("Cleared cache for session {}", session.id);
    Ok(())
}

pub(crate) fn handle_callgraph(repl: &Repl, target: &str, max_depth: Option<u32>) -> Result<()> {
    let Some(client) = repl.ida_client.as_ref() else {
        println!("Not connected. Run: connect <host:port>");
        return Ok(());
    };

    let depth = max_depth.unwrap_or(3);
    let output = render_callgraph_output(&repl.runtime, client.as_ref(), target, depth)?;
    println!("{output}");
    Ok(())
}

pub(crate) fn handle_search(repl: &Repl, pattern: &str) -> Result<()> {
    let Some(client) = repl.ida_client.as_ref() else {
        println!("Not connected. Run: connect <host:port>");
        return Ok(());
    };

    let matches = fetch_search_results(&repl.runtime, client.as_ref(), pattern)?;

    if matches.is_empty() {
        println!("No results");
        return Ok(());
    }

    println!("Found {} result(s)", matches.len());
    println!("{}", render_search_output(&matches));
    Ok(())
}

fn handle_manual_rename(repl: &Repl, target: &str, new_name: &str) -> Result<()> {
    let Some(client) = repl.ida_client.as_ref() else {
        println!("Not connected. Run: connect <host:port>");
        return Ok(());
    };

    let (address, _) = match resolve_target_address(&repl.runtime, client.as_ref(), target) {
        Ok(value) => value,
        Err(err) => {
            println!("{}", format_resolve_target_error(target, &err));
            return Ok(());
        }
    };

    match rename_symbol(&repl.runtime, client.as_ref(), address, new_name) {
        Ok(()) => println!("Renamed {} → {}", fmt::format_addr(address), new_name),
        Err(err) => println!("Failed to rename function: {err}"),
    }

    Ok(())
}

fn handle_rename_llm_single(repl: &mut Repl, target: &str, command: &RenameCommand) -> Result<()> {
    let Some(session) = repl.active_session.as_ref() else {
        print_error(
            "no active session",
            &["Run 'analyze <path>' or 'session <id>' to set an active session first."],
        );
        return Ok(());
    };

    let Some(client) = repl.ida_client.as_ref() else {
        print_error(
            "IDA Pro is not connected",
            &[
                "'rename --llm' requires an active IDA connection.",
                "Run 'connect' to connect, then retry.",
            ],
        );
        return Ok(());
    };

    let (function_addr, function_name) = match resolve_target_address(&repl.runtime, client, target)
    {
        Ok(value) => value,
        Err(err) => {
            println!("{}", format_resolve_target_error(target, &err));
            return Ok(());
        }
    };

    let decompile_result = match repl.runtime.block_on(client.decompile(function_addr)) {
        Ok(value) => value,
        Err(err) => {
            println!("✗ error: decompile failed: {err}");
            return Ok(());
        }
    };

    let mut config = Config::load().context("failed to load config")?;
    apply_resolved_credentials(&mut config).context("failed to resolve credentials")?;
    let provider_selection = match ProviderSelection::parse(&command.provider) {
        Ok(value) => Some(value),
        Err(LlmError::Configuration(message)) => {
            print_error(&message, &[]);
            return Ok(());
        }
        Err(err) => {
            print_error(&format_llm_error(&err), &[]);
            return Ok(());
        }
    };

    let router = match LlmRouter::new(
        config.clone(),
        TaskType::FastRename,
        provider_selection,
        !command.no_fallback,
    ) {
        Ok(value) => value,
        Err(LlmError::Configuration(message)) => {
            let lower = message.to_ascii_lowercase();
            if lower.contains("no providers configured") {
                print_error(
                    "no LLM provider configured",
                    &["Run 'config set anthropic-api-key <key>' or 'config set openai-api-key <key>'."],
                );
            } else {
                print_error(&message, &[]);
            }
            return Ok(());
        }
        Err(err) => {
            print_error(&format_llm_error(&err), &[]);
            return Ok(());
        }
    };

    let provider = match build_provider_for_plan(&config, router.plan().provider) {
        Ok(value) => value,
        Err(message) => {
            print_error(&message, &[]);
            return Ok(());
        }
    };

    println!(
        "  Analyzing {} ({}) via {}...",
        function_name,
        fmt::format_addr(function_addr),
        router.plan().model
    );

    let llm_result_result = match &provider {
        RenameProvider::Anthropic(provider) => repl.runtime.block_on(run_rename_agentic_loop(
            provider,
            client.clone(),
            &router.plan().model,
            function_addr,
            &function_name,
            &decompile_result.pseudocode,
        )),
        RenameProvider::OpenAi(provider) => repl.runtime.block_on(run_rename_agentic_loop(
            provider,
            client.clone(),
            &router.plan().model,
            function_addr,
            &function_name,
            &decompile_result.pseudocode,
        )),
    };
    let llm_result = match llm_result_result {
        Ok(value) => value,
        Err(err) => {
            print_error("rename analysis failed", &[&format_llm_error(&err)]);
            return Ok(());
        }
    };

    let response = match parse_rename_json_payload(&llm_result.final_text) {
        Ok(value) => value,
        Err(message) => {
            print_error("LLM returned malformed JSON", &[&message]);
            return Ok(());
        }
    };

    persist_agentic_transcript(&repl.store, session.id, &llm_result)?;

    let suggestions = match build_suggestions(
        function_addr,
        &function_name,
        response,
        &repl.store,
        session.id,
    ) {
        Ok(value) => value,
        Err(message) => {
            print_error("LLM response failed validation", &[&message]);
            return Ok(());
        }
    };

    let counters =
        apply_suggestions_and_render(&repl.runtime, &repl.store, session.id, client, suggestions)?;
    println!(
        "\n  Applied: {}   Queued: {}   Discarded: {}",
        counters.applied, counters.queued, counters.discarded
    );
    if counters.queued > 0 {
        println!("\n  Run 'review' to inspect queued suggestions.");
    }

    Ok(())
}

fn handle_rename_all(repl: &mut Repl, command: &RenameCommand) -> Result<()> {
    let Some(session) = repl.active_session.as_ref() else {
        print_error(
            "no active session",
            &["Run 'analyze <path>' or 'session <id>' to set an active session first."],
        );
        return Ok(());
    };

    let Some(client) = repl.ida_client.as_ref() else {
        print_error(
            "IDA Pro is not connected",
            &[
                "'rename --llm' requires an active IDA connection.",
                "Run 'connect' to connect, then retry.",
            ],
        );
        return Ok(());
    };

    let mut config = Config::load().context("failed to load config")?;
    apply_resolved_credentials(&mut config).context("failed to resolve credentials")?;
    let provider_selection = ProviderSelection::parse(&command.provider).ok();
    let router = match LlmRouter::new(
        config.clone(),
        TaskType::FastRename,
        provider_selection,
        !command.no_fallback,
    ) {
        Ok(value) => value,
        Err(err) => {
            print_error(&format_llm_error(&err), &[]);
            return Ok(());
        }
    };

    let provider = match build_provider_for_plan(&config, router.plan().provider) {
        Ok(value) => value,
        Err(message) => {
            print_error(&message, &[]);
            return Ok(());
        }
    };

    let all_functions = repl.runtime.block_on(client.list_functions(None, None))?;
    let generic_functions: Vec<_> = all_functions
        .into_iter()
        .filter(|f| is_generic_function_name(&f.name))
        .collect();

    println!(
        "  Found {} functions with generic names. Starting LLM rename...\n",
        generic_functions.len()
    );

    let mut totals = TierCounters::default();
    let mut skipped = 0u32;

    for (index, function) in generic_functions.iter().enumerate() {
        let current = index as u32 + 1;
        let total = generic_functions.len() as u32;

        let decompile_result = match repl.runtime.block_on(client.decompile(function.address)) {
            Ok(value) => value,
            Err(err) => {
                totals.errors += 1;
                println!(
                    "  [{}/{}]  {}  {}  ->  ✗ decompile failed: {}",
                    current,
                    total,
                    fmt::format_addr(function.address),
                    function.name,
                    err
                );
                continue;
            }
        };

        let llm_result_result = match &provider {
            RenameProvider::Anthropic(provider) => repl.runtime.block_on(run_rename_agentic_loop(
                provider,
                client.clone(),
                &router.plan().model,
                function.address,
                &function.name,
                &decompile_result.pseudocode,
            )),
            RenameProvider::OpenAi(provider) => repl.runtime.block_on(run_rename_agentic_loop(
                provider,
                client.clone(),
                &router.plan().model,
                function.address,
                &function.name,
                &decompile_result.pseudocode,
            )),
        };

        let llm_result = match llm_result_result {
            Ok(value) => value,
            Err(err) => {
                totals.errors += 1;
                println!(
                    "  [{}/{}]  {}  {}  ->  ✗ {}",
                    current,
                    total,
                    fmt::format_addr(function.address),
                    function.name,
                    format_llm_error(&err)
                );
                continue;
            }
        };

        let response = match parse_rename_json_payload(&llm_result.final_text) {
            Ok(value) => value,
            Err(_) => {
                totals.errors += 1;
                println!(
                    "  [{}/{}]  {}  {}  ->  ✗ error: malformed LLM response (saved to debug log)",
                    current,
                    total,
                    fmt::format_addr(function.address),
                    function.name,
                );
                continue;
            }
        };

        persist_agentic_transcript(&repl.store, session.id, &llm_result)?;

        let suggestions = match build_suggestions(
            function.address,
            &function.name,
            response,
            &repl.store,
            session.id,
        ) {
            Ok(value) => value,
            Err(_) => {
                totals.errors += 1;
                println!(
                    "  [{}/{}]  {}  {}  ->  ✗ error: malformed LLM response (saved to debug log)",
                    current,
                    total,
                    fmt::format_addr(function.address),
                    function.name,
                );
                continue;
            }
        };

        let result = apply_suggestions_without_detail(
            &repl.runtime,
            &repl.store,
            session.id,
            client,
            suggestions,
        )?;
        totals.applied += result.applied;
        totals.queued += result.queued;
        totals.discarded += result.discarded;
        totals.errors += result.errors;

        if let Some((name, confidence, marker)) = result.function_line {
            println!(
                "  [{}/{}]  {}  {}  ->  {}  ({:.2})  {}",
                current,
                total,
                fmt::format_addr(function.address),
                function.name,
                name,
                confidence,
                marker
            );
        } else {
            skipped += 1;
            println!(
                "  [{}/{}]  {}  {}  ->  (no rename suggested)",
                current,
                total,
                fmt::format_addr(function.address),
                function.name,
            );
        }
    }

    println!("\n  {}", "═".repeat(88));
    println!("\n  Batch complete.");
    if totals.errors > 0 {
        println!(
            "  Applied: {}   Queued: {}   Discarded: {}   Errors: {}   Skipped (no suggestion): {}",
            totals.applied, totals.queued, totals.discarded, totals.errors, skipped
        );
        println!(
            "\n  {} functions failed. Run 'findings' to see error details.",
            totals.errors
        );
    } else {
        println!(
            "  Applied: {}   Queued: {}   Discarded: {}   Skipped (no suggestion): {}",
            totals.applied, totals.queued, totals.discarded, skipped
        );
    }
    if totals.queued > 0 {
        println!(
            "\n  Run 'review' to inspect {} queued suggestions.",
            totals.queued
        );
    }

    Ok(())
}

fn apply_suggestions_and_render(
    runtime: &Runtime,
    store: &SessionStore,
    session_id: uuid::Uuid,
    client: &IdaClient,
    suggestions: Vec<RenameSuggestion>,
) -> Result<TierCounters> {
    let mut counters = TierCounters::default();
    let mut applied_lines = Vec::new();
    let mut queued_lines = Vec::new();

    for suggestion in suggestions {
        match classify_confidence(suggestion.confidence) {
            ConfidenceTier::Tier1 => {
                if apply_suggestion(runtime, client, &suggestion).is_ok() {
                    counters.applied += 1;
                    applied_lines.push(render_applied_line(&suggestion));
                } else {
                    counters.errors += 1;
                    log_ida_rejected(store, session_id, &suggestion)?;
                }
            }
            ConfidenceTier::Tier2 => {
                counters.queued += 1;
                queue_suggestion(store, session_id, &suggestion)?;
                queued_lines.push(render_queued_line(&suggestion));
            }
            ConfidenceTier::Tier3 => {
                counters.discarded += 1;
                log_discarded(store, session_id, &suggestion)?;
            }
        }
    }

    if !applied_lines.is_empty() || !queued_lines.is_empty() {
        println!();
    }
    for line in applied_lines {
        println!("{line}");
    }
    for line in queued_lines {
        println!("{line}");
    }

    Ok(counters)
}

fn apply_suggestions_without_detail(
    runtime: &Runtime,
    store: &SessionStore,
    session_id: uuid::Uuid,
    client: &IdaClient,
    suggestions: Vec<RenameSuggestion>,
) -> Result<BatchFunctionResult> {
    let mut counters = TierCounters::default();
    let mut function_line = None;

    for suggestion in suggestions {
        match classify_confidence(suggestion.confidence) {
            ConfidenceTier::Tier1 => {
                if apply_suggestion(runtime, client, &suggestion).is_ok() {
                    counters.applied += 1;
                    if matches!(suggestion.kind, RenameSuggestionKind::Function) {
                        function_line = Some((
                            suggestion.proposed_value.clone(),
                            suggestion.confidence,
                            "✓".to_string(),
                        ));
                    }
                } else {
                    counters.errors += 1;
                    log_ida_rejected(store, session_id, &suggestion)?;
                }
            }
            ConfidenceTier::Tier2 => {
                counters.queued += 1;
                queue_suggestion(store, session_id, &suggestion)?;
                if matches!(suggestion.kind, RenameSuggestionKind::Function) {
                    function_line = Some((
                        suggestion.proposed_value.clone(),
                        suggestion.confidence,
                        "~".to_string(),
                    ));
                }
            }
            ConfidenceTier::Tier3 => {
                counters.discarded += 1;
                log_discarded(store, session_id, &suggestion)?;
            }
        }
    }

    Ok(BatchFunctionResult {
        applied: counters.applied,
        queued: counters.queued,
        discarded: counters.discarded,
        errors: counters.errors,
        function_line,
    })
}

fn apply_review_item(repl: &Repl, session_id: uuid::Uuid, item: &ReviewQueueRecord) -> Result<()> {
    let Some(client) = repl.ida_client.as_ref() else {
        print_error(
            "IDA Pro is not connected",
            &["Cannot apply rename. Run 'connect' first, then retry 'review'."],
        );
        return Ok(());
    };

    let result = match item.kind.as_str() {
        "function_rename" => repl.runtime.block_on(client.rename_function(
            item.target_addr.unwrap_or(item.function_addr),
            &item.proposed_value,
        )),
        "variable_rename" => repl.runtime.block_on(client.rename_local(
            item.function_addr,
            &item.current_name,
            &item.proposed_value,
        )),
        "comment" => repl.runtime.block_on(client.set_comment(
            item.target_addr.unwrap_or(item.function_addr),
            &item.proposed_value,
        )),
        _ => Ok(()),
    };

    if result.is_err() {
        print_error(
            &format!(
                "IDA rejected rename '{}' at {}",
                item.proposed_value,
                fmt::format_addr(item.target_addr.unwrap_or(item.function_addr))
            ),
            &[
                "Name may already exist or contain invalid characters.",
                "Suggestion logged to transcript.",
            ],
        );
        return Ok(());
    }

    repl.store.update_review_queue_status(item.id, "accepted")?;
    println!(
        "\n  ✓ Applied: {}  ->  {}  at {}",
        item.current_name,
        item.proposed_value,
        fmt::format_addr(item.target_addr.unwrap_or(item.function_addr))
    );
    let _ = session_id;
    Ok(())
}

fn accept_all_review(
    repl: &Repl,
    session_id: uuid::Uuid,
    pending: &[ReviewQueueRecord],
) -> Result<(u32, u32)> {
    let mut applied = 0u32;
    let mut failed = 0u32;

    for item in pending {
        let before = applied;
        apply_review_item(repl, session_id, item)?;
        let is_pending = repl
            .store
            .list_pending_review_queue(session_id)?
            .iter()
            .any(|entry| entry.id == item.id);
        if is_pending {
            failed += 1;
        } else if applied == before {
            applied += 1;
        }
    }

    Ok((applied, failed))
}

fn classify_confidence(confidence: f64) -> ConfidenceTier {
    if confidence >= 0.7 {
        ConfidenceTier::Tier1
    } else if confidence >= 0.5 {
        ConfidenceTier::Tier2
    } else {
        ConfidenceTier::Tier3
    }
}

fn is_generic_function_name(name: &str) -> bool {
    name.starts_with("sub_") || name.starts_with("j_sub_") || name.starts_with("nullsub_")
}

fn is_valid_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn parse_comment_addr(value: &str) -> Option<u64> {
    let normalized = value.trim();
    if !normalized.starts_with("0x") {
        return None;
    }
    if normalized
        .chars()
        .skip(2)
        .any(|ch| !ch.is_ascii_hexdigit() || ch.is_ascii_uppercase())
    {
        return None;
    }
    u64::from_str_radix(&normalized[2..], 16).ok()
}

fn truncate_for_review(value: &str, width: usize) -> String {
    let mut output = String::new();
    if value.chars().count() <= width {
        return value.to_string();
    }
    for ch in value.chars().take(width.saturating_sub(1)) {
        output.push(ch);
    }
    output.push('…');
    output
}

fn print_error(summary: &str, details: &[&str]) {
    println!("✗ error: {summary}");
    if let Some((first, rest)) = details.split_first() {
        println!("    ╰─ {first}");
        for detail in rest {
            println!("       {detail}");
        }
    }
}

fn read_prompt(prompt: &str) -> Result<String> {
    use std::io::Write;

    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

fn build_provider_for_plan(
    config: &Config,
    provider: endeavour_llm::BackendProvider,
) -> std::result::Result<RenameProvider, String> {
    match provider {
        endeavour_llm::BackendProvider::Anthropic => config
            .anthropic_api_key
            .clone()
            .map(|api_key| RenameProvider::Anthropic(AnthropicProvider::new(api_key)))
            .ok_or_else(|| "no LLM provider configured".to_string()),
        endeavour_llm::BackendProvider::OpenAi => config
            .openai_api_key
            .clone()
            .map(|api_key| RenameProvider::OpenAi(OpenAiProvider::new(api_key)))
            .ok_or_else(|| "no LLM provider configured".to_string()),
    }
}

async fn run_rename_agentic_loop<P: LlmProvider>(
    provider: &P,
    client: Arc<IdaClient>,
    model: &str,
    function_addr: u64,
    function_name: &str,
    pseudocode: &str,
) -> std::result::Result<endeavour_llm::AgenticLoopResult, LlmError> {
    let tool_executor = IdaToolExecutor::new(client);
    let builder = ContextBuilder::new(model)
        .with_system_prompt(RENAME_SYSTEM_PROMPT)
        .with_history(vec![Message {
            role: Role::User,
            content: format!(
                "Analyze function {} at {} and propose names and comments.",
                function_name,
                fmt::format_addr(function_addr)
            ),
            tool_results: Vec::new(),
        }])
        .with_function_context(FunctionContext {
            function_name: Some(function_name.to_string()),
            address: Some(function_addr),
            decompiled_code: pseudocode.to_string(),
            xrefs: Vec::new(),
            strings: Vec::new(),
        })
        .with_temperature(0.1)
        .with_max_tokens(1_200)
        .with_tools(IdaToolExecutor::tool_definitions());

    let mut controller = AgenticLoopController::new(AgenticLoopConfig {
        max_steps: 4,
        ..AgenticLoopConfig::default()
    });

    controller
        .run(provider, builder, &tool_executor, None)
        .await
        .map_err(|err| LlmError::Configuration(err.to_string()))
}

fn parse_rename_json_payload(raw: &str) -> std::result::Result<RenameLlmResponse, String> {
    let value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|_| "Expected rename schema at top level.".to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "Expected rename schema at top level.".to_string())?;

    let mut keys = object.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    if keys != ["comments", "function_rename", "variable_renames"] {
        return Err("Expected rename schema at top level.".to_string());
    }

    serde_json::from_value(value).map_err(|_| "Expected rename schema at top level.".to_string())
}

fn build_suggestions(
    function_addr: u64,
    function_name: &str,
    response: RenameLlmResponse,
    store: &SessionStore,
    session_id: uuid::Uuid,
) -> std::result::Result<Vec<RenameSuggestion>, String> {
    if !(0.0..=1.0).contains(&response.function_rename.confidence) {
        return Err(format!(
            "Field 'confidence' out of range (got: {}, expected: 0.0-1.0).",
            response.function_rename.confidence
        ));
    }

    let mut suggestions = Vec::new();
    if let Some(name) = response.function_rename.proposed_name {
        if is_valid_identifier(&name) {
            suggestions.push(RenameSuggestion {
                kind: RenameSuggestionKind::Function,
                function_addr,
                target_addr: function_addr,
                current_name: function_name.to_string(),
                proposed_value: name,
                confidence: response.function_rename.confidence,
            });
        } else {
            let _ = append_transcript_line(
                store,
                session_id,
                format!(
                    "[SKIPPED] invalid identifier for function rename: '{}'",
                    name
                ),
            );
        }
    }

    for variable in response.variable_renames.into_iter().take(20) {
        if !(0.0..=1.0).contains(&variable.confidence) {
            return Err(format!(
                "Field 'confidence' out of range (got: {}, expected: 0.0-1.0).",
                variable.confidence
            ));
        }
        if !is_valid_identifier(&variable.proposed_name) {
            let _ = append_transcript_line(
                store,
                session_id,
                format!(
                    "[SKIPPED] invalid identifier for variable rename: '{}'",
                    variable.proposed_name
                ),
            );
            continue;
        }
        suggestions.push(RenameSuggestion {
            kind: RenameSuggestionKind::Variable,
            function_addr,
            target_addr: function_addr,
            current_name: variable.current_name,
            proposed_value: variable.proposed_name,
            confidence: variable.confidence,
        });
    }

    for comment in response.comments.into_iter().take(10) {
        if !(0.0..=1.0).contains(&comment.confidence) {
            return Err(format!(
                "Field 'confidence' out of range (got: {}, expected: 0.0-1.0).",
                comment.confidence
            ));
        }
        let Some(addr) = parse_comment_addr(&comment.addr) else {
            let _ = append_transcript_line(
                store,
                session_id,
                format!("[SKIPPED] invalid comment address: '{}'", comment.addr),
            );
            continue;
        };
        suggestions.push(RenameSuggestion {
            kind: RenameSuggestionKind::Comment,
            function_addr,
            target_addr: addr,
            current_name: "comment".to_string(),
            proposed_value: comment.text,
            confidence: comment.confidence,
        });
    }

    suggestions.sort_by_key(|item| match item.kind {
        RenameSuggestionKind::Function => 0,
        RenameSuggestionKind::Comment => 1,
        RenameSuggestionKind::Variable => 2,
    });

    Ok(suggestions)
}

fn apply_suggestion(
    runtime: &Runtime,
    client: &IdaClient,
    suggestion: &RenameSuggestion,
) -> Result<()> {
    match suggestion.kind {
        RenameSuggestionKind::Function => runtime
            .block_on(client.rename_function(suggestion.target_addr, &suggestion.proposed_value))
            .map_err(anyhow::Error::from),
        RenameSuggestionKind::Variable => runtime
            .block_on(client.rename_local(
                suggestion.function_addr,
                &suggestion.current_name,
                &suggestion.proposed_value,
            ))
            .map_err(anyhow::Error::from),
        RenameSuggestionKind::Comment => runtime
            .block_on(client.set_comment(suggestion.target_addr, &suggestion.proposed_value))
            .map_err(anyhow::Error::from),
    }
}

fn queue_suggestion(
    store: &SessionStore,
    session_id: uuid::Uuid,
    suggestion: &RenameSuggestion,
) -> Result<()> {
    store.add_review_queue_entry(
        session_id,
        &NewReviewQueueRecord {
            kind: match suggestion.kind {
                RenameSuggestionKind::Function => "function_rename".to_string(),
                RenameSuggestionKind::Variable => "variable_rename".to_string(),
                RenameSuggestionKind::Comment => "comment".to_string(),
            },
            function_addr: suggestion.function_addr,
            target_addr: Some(suggestion.target_addr),
            current_name: suggestion.current_name.clone(),
            proposed_value: suggestion.proposed_value.clone(),
            confidence: suggestion.confidence,
        },
    )?;
    Ok(())
}

fn render_applied_line(suggestion: &RenameSuggestion) -> String {
    match suggestion.kind {
        RenameSuggestionKind::Comment => format!(
            "  ✓ {}  comment set: \"{}\"  ({:.2})",
            fmt::format_addr(suggestion.target_addr),
            suggestion.proposed_value,
            suggestion.confidence
        ),
        _ => format!(
            "  ✓ {}  {}  ->  {}  ({:.2})",
            fmt::format_addr(suggestion.target_addr),
            suggestion.current_name,
            suggestion.proposed_value,
            suggestion.confidence
        ),
    }
}

fn render_queued_line(suggestion: &RenameSuggestion) -> String {
    if matches!(suggestion.kind, RenameSuggestionKind::Comment) {
        format!(
            "  ~ {}  comment  ->  {}  ({:.2})  queued for review",
            fmt::format_addr(suggestion.target_addr),
            suggestion.proposed_value,
            suggestion.confidence
        )
    } else {
        format!(
            "  ~ {}  {}  ->  {}  ({:.2})  queued for review",
            fmt::format_addr(suggestion.target_addr),
            suggestion.current_name,
            suggestion.proposed_value,
            suggestion.confidence
        )
    }
}

fn persist_agentic_transcript(
    store: &SessionStore,
    session_id: uuid::Uuid,
    result: &endeavour_llm::AgenticLoopResult,
) -> Result<()> {
    let mut records = Vec::new();
    for turn in &result.transcript {
        records.push(NewTranscriptRecord {
            turn_number: turn.round,
            role: "llm".to_string(),
            timestamp: "0".to_string(),
            content_json: serde_json::to_string(&TranscriptContent::Message(Message {
                role: Role::Assistant,
                content: turn.assistant_text.clone(),
                tool_results: Vec::new(),
            }))?,
            usage_json: turn.usage.as_ref().map(serde_json::to_string).transpose()?,
            state: "llm_streaming".to_string(),
            tool_calls_json: Some(serde_json::to_string(&turn.tool_calls)?),
        });
    }
    if !records.is_empty() {
        store.add_transcript_entries(session_id, &records)?;
    }
    Ok(())
}

fn append_transcript_line(
    store: &SessionStore,
    session_id: uuid::Uuid,
    content: String,
) -> Result<()> {
    store.add_transcript_entries(
        session_id,
        &[NewTranscriptRecord {
            turn_number: 0,
            role: "system".to_string(),
            timestamp: "0".to_string(),
            content_json: serde_json::to_string(&TranscriptContent::Message(Message {
                role: Role::System,
                content,
                tool_results: Vec::new(),
            }))?,
            usage_json: None,
            state: "done_success".to_string(),
            tool_calls_json: None,
        }],
    )?;
    Ok(())
}

fn log_discarded(
    store: &SessionStore,
    session_id: uuid::Uuid,
    suggestion: &RenameSuggestion,
) -> Result<()> {
    append_transcript_line(
        store,
        session_id,
        format!(
            "[DISCARDED] {}  {}  ->  {}  ({:.2})",
            fmt::format_addr(suggestion.target_addr),
            suggestion.current_name,
            suggestion.proposed_value,
            suggestion.confidence
        ),
    )
}

fn log_ida_rejected(
    store: &SessionStore,
    session_id: uuid::Uuid,
    suggestion: &RenameSuggestion,
) -> Result<()> {
    append_transcript_line(
        store,
        session_id,
        format!(
            "[IDA_REJECTED] {}  {}  ->  {}  ({:.2})",
            fmt::format_addr(suggestion.target_addr),
            suggestion.current_name,
            suggestion.proposed_value,
            suggestion.confidence
        ),
    )
}

fn log_review_rejected(
    store: &SessionStore,
    session_id: uuid::Uuid,
    item: &ReviewQueueRecord,
) -> Result<()> {
    append_transcript_line(
        store,
        session_id,
        format!(
            "[REJECTED] {}  {}  ->  {}  ({:.2})",
            fmt::format_addr(item.target_addr.unwrap_or(item.function_addr)),
            item.current_name,
            item.proposed_value,
            item.confidence
        ),
    )
}

fn render_decompile_result(function_name: &str, result: &DecompileResult) -> String {
    let mut lines = vec![
        fmt::h2(format!(
            "{} @ {}",
            function_name,
            fmt::format_addr(result.address)
        )),
        fmt::separator(fmt::Separator::Standard, 88),
    ];

    for (index, line) in result.pseudocode.lines().enumerate() {
        lines.push(format!("{:>4} | {}", index + 1, line));
    }

    if result.pseudocode.is_empty() {
        lines.push("   1 |".to_string());
    }

    lines.join("\n")
}

fn build_explain_request(function_name: &str, result: &DecompileResult) -> CompletionRequest {
    let system_prompt = "You are an expert reverse engineer analyzing decompiled code. Explain what this function does, identify key behaviors, potential vulnerabilities, and suggest meaningful names for the function and its variables.";
    let user_prompt = format!(
        "Analyze function {function_name} at {address}.\n\nDecompiled pseudocode:\n```c\n{pseudocode}\n```",
        address = fmt::format_addr(result.address),
        pseudocode = result.pseudocode
    );

    CompletionRequest {
        model: "claude-sonnet-4-5".to_string(),
        messages: vec![
            Message {
                role: Role::System,
                content: system_prompt.to_string(),
                tool_results: Vec::new(),
            },
            Message {
                role: Role::User,
                content: user_prompt,
                tool_results: Vec::new(),
            },
        ],
        max_tokens: Some(1_200),
        temperature: Some(0.1),
        tools: Vec::new(),
    }
}

fn render_explain_result(function_name: &str, address: u64, model: &str, analysis: &str) -> String {
    let title = format!(
        "Function Analysis: {function_name} @ {}",
        fmt::format_addr(address)
    );
    let model_line = format!("Model: {model}");
    let body = if analysis.trim().is_empty() {
        "(No analysis text returned.)"
    } else {
        analysis.trim()
    };

    [
        fmt::h2(title),
        model_line,
        fmt::separator(fmt::Separator::Standard, 88),
        body.to_string(),
        fmt::separator(fmt::Separator::Standard, 88),
    ]
    .join("\n")
}

fn render_callgraph_output(
    runtime: &Runtime,
    client: &IdaClient,
    target: &str,
    depth: u32,
) -> Result<String> {
    let (root_addr, root_name) = resolve_target_address(runtime, client, target)?;
    let edges = runtime
        .block_on(client.call_graph(root_addr, Some(depth)))
        .with_context(|| {
            format!(
                "failed to fetch call graph for {}",
                fmt::format_addr(root_addr)
            )
        })?;

    let mut adjacency: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut node_order = Vec::new();
    let mut seen_nodes = HashSet::new();
    seen_nodes.insert(root_addr);
    for (src, dst) in edges {
        let entry = adjacency.entry(src).or_default();
        if !entry.contains(&dst) {
            entry.push(dst);
        }
        if seen_nodes.insert(src) {
            node_order.push(src);
        }
        if seen_nodes.insert(dst) {
            node_order.push(dst);
        }
    }

    let mut name_cache = HashMap::new();
    name_cache.insert(root_addr, root_name.clone());
    for addr in node_order {
        if name_cache.contains_key(&addr) {
            continue;
        }

        let query = fmt::format_addr(addr);
        let name = runtime
            .block_on(client.lookup_function(&query))
            .ok()
            .and_then(|function| function.map(|item| item.name))
            .unwrap_or_else(|| format!("sub_{addr:x}"));
        name_cache.insert(addr, name);
    }

    let header = format!(
        "Call Graph: {} @ {} (depth={depth})",
        root_name,
        fmt::format_addr(root_addr)
    );
    let mut lines = vec![
        header.clone(),
        fmt::separator(fmt::Separator::Standard, header.chars().count()),
    ];

    let children = adjacency.get(&root_addr).cloned().unwrap_or_default();
    if children.is_empty() {
        lines.push("(no callees)".to_string());
        return Ok(lines.join("\n"));
    }

    let mut ancestors = HashSet::new();
    ancestors.insert(root_addr);
    render_callgraph_branch(
        root_addr,
        &children,
        &adjacency,
        &name_cache,
        "",
        &ancestors,
        &mut lines,
    );

    Ok(lines.join("\n"))
}

fn render_callgraph_branch(
    _parent: u64,
    children: &[u64],
    adjacency: &HashMap<u64, Vec<u64>>,
    names: &HashMap<u64, String>,
    prefix: &str,
    ancestors: &HashSet<u64>,
    lines: &mut Vec<String>,
) {
    for (index, child) in children.iter().enumerate() {
        let is_last = index + 1 == children.len();
        let branch = if is_last { "└── " } else { "├── " };
        let name = names
            .get(child)
            .cloned()
            .unwrap_or_else(|| format!("sub_{child:x}"));

        if ancestors.contains(child) {
            lines.push(format!(
                "{prefix}{branch}{name} @ {} [recursive]",
                fmt::format_addr(*child)
            ));
            continue;
        }

        lines.push(format!(
            "{prefix}{branch}{name} @ {}",
            fmt::format_addr(*child)
        ));

        let mut next_ancestors = ancestors.clone();
        next_ancestors.insert(*child);
        let child_prefix = if is_last {
            format!("{prefix}    ")
        } else {
            format!("{prefix}│   ")
        };

        if let Some(grandchildren) = adjacency.get(child) {
            render_callgraph_branch(
                *child,
                grandchildren,
                adjacency,
                names,
                &child_prefix,
                &next_ancestors,
                lines,
            );
        }
    }
}

fn resolve_target_address(
    runtime: &Runtime,
    client: &IdaClient,
    target: &str,
) -> Result<(u64, String)> {
    if let Some(address) = parse_decompile_target(target) {
        let query = fmt::format_addr(address);
        let name = runtime
            .block_on(client.lookup_function(&query))
            .ok()
            .and_then(|function| function.map(|item| item.name))
            .unwrap_or_else(|| format!("sub_{address:x}"));
        return Ok((address, name));
    }

    let function = runtime
        .block_on(client.lookup_function(target))
        .with_context(|| format!("failed to resolve function '{target}'"))?
        .with_context(|| format!("function '{target}' not found"))?;
    Ok((function.address, function.name))
}

fn format_resolve_target_error(target: &str, err: &anyhow::Error) -> String {
    if is_target_not_found_error(target, err) {
        return format!("No function at address {target}");
    }

    format!("Failed to resolve target '{target}': {err:#}")
}

fn is_target_not_found_error(target: &str, err: &anyhow::Error) -> bool {
    let expected = format!("function '{target}' not found");
    err.chain().any(|cause| cause.to_string() == expected)
}

fn parse_decompile_target(raw: &str) -> Option<u64> {
    let input = raw.trim();
    if let Some(hex) = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }

    if let Ok(value) = input.parse::<u64>() {
        return Some(value);
    }

    if let Some(suffix) = input.strip_prefix("sub_") {
        return u64::from_str_radix(suffix, 16).ok();
    }

    None
}

fn is_missing_function_error(error: &IdaError) -> bool {
    match error {
        IdaError::IdaResponseError(message) | IdaError::DeserializationError(message) => {
            message.to_ascii_lowercase().contains("not found")
        }
        _ => false,
    }
}

fn format_llm_error(error: &LlmError) -> String {
    match error {
        LlmError::AuthFailed => "Authentication failed; verify your API key".to_string(),
        LlmError::RateLimited { retry_after } => {
            if let Some(seconds) = retry_after {
                format!("rate limited; retry in {seconds}s")
            } else {
                "rate limited; retry later".to_string()
            }
        }
        LlmError::ContextWindowExceeded => {
            "prompt too large for the selected model context window".to_string()
        }
        _ => error.to_string(),
    }
}

fn fetch_search_results(
    runtime: &Runtime,
    client: &IdaClient,
    pattern: &str,
) -> Result<Vec<(u64, String)>> {
    runtime
        .block_on(client.find_strings(pattern))
        .with_context(|| format!("failed to search strings for pattern '{pattern}'"))
}

fn rename_symbol(runtime: &Runtime, client: &IdaClient, addr: u64, new_name: &str) -> Result<()> {
    runtime
        .block_on(client.rename_function(addr, new_name))
        .with_context(|| format!("failed to rename function at {}", fmt::format_addr(addr)))
}

fn set_symbol_comment(
    runtime: &Runtime,
    client: &IdaClient,
    addr: u64,
    comment: &str,
) -> Result<()> {
    runtime
        .block_on(client.set_comment(addr, comment))
        .with_context(|| format!("failed to set comment at {}", fmt::format_addr(addr)))
}

fn render_search_output(matches: &[(u64, String)]) -> String {
    let mut table = fmt::Table::new(vec![
        fmt::Column::new("Address", 18, fmt::Align::Left),
        fmt::Column::new("String", 76, fmt::Align::Left),
    ]);

    for (address, text) in matches {
        table.add_row(vec![fmt::format_addr(*address), text.clone()]);
    }

    table.render()
}

#[cfg(test)]
mod tests {
    use super::{parse_decompile_target, parse_rename_json_payload};

    #[test]
    fn analyze_commands_parse_rename_json_schema() {
        let valid = r#"{
            "function_rename": {"proposed_name": "aes_init", "confidence": 0.94},
            "variable_renames": [{"current_name": "a1", "proposed_name": "src", "confidence": 0.83}],
            "comments": [{"addr": "0x401000", "text": "entry", "confidence": 0.77}]
        }"#;
        assert!(parse_rename_json_payload(valid).is_ok());
    }

    #[test]
    fn analyze_commands_parse_decompile_target_variants() {
        assert_eq!(parse_decompile_target("0x401000"), Some(0x401000));
        assert_eq!(parse_decompile_target("4198400"), Some(4_198_400));
        assert_eq!(parse_decompile_target("sub_401000"), Some(0x401000));
    }
}

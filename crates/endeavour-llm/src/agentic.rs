use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::sync::watch;

use crate::context::ContextBuilder;
use crate::error::LlmError;
use crate::provider::LlmProvider;
use crate::types::{
    CompletionRequest, CompletionResponse, Message, Role, StopReason, ToolCall, ToolDefinition,
    ToolResult, Usage,
};

/// State of the agentic loop controller.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgenticLoopState {
    /// Initial idle state before execution starts.
    Idle,
    /// Initial request construction state.
    InitialCall,
    /// Normal LLM call state with tools enabled.
    LlmStreaming,
    /// Tool execution state for the current round.
    ExecuteTools,
    /// Tool-result append state.
    ToolResultsReady,
    /// Recovery state after provider errors.
    RecoverOrAbort,
    /// State that enters force-final mode.
    ForceFinal,
    /// LLM call state with tools disabled.
    LlmStreamingFinal,
    /// Terminal success state.
    DoneSuccess,
    /// Terminal state: max rounds reached.
    DoneMaxRounds,
    /// Terminal state: no convergence.
    DoneNoConvergence,
    /// Terminal state: budget exhausted.
    DoneBudgetExhausted,
    /// Terminal state: cancelled.
    DoneCancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptRole {
    Llm,
    ToolExecutor,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum TranscriptContent {
    Message(Message),
    ToolResult(ToolResult),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TranscriptEntry {
    pub turn_number: u32,
    pub role: TranscriptRole,
    pub timestamp: String,
    pub content: TranscriptContent,
    pub usage: Option<Usage>,
    pub state: AgenticLoopState,
    pub tool_calls: Vec<ToolCall>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Transcript {
    entries: Vec<TranscriptEntry>,
}

impl Transcript {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, entry: TranscriptEntry) {
        self.entries.push(entry);
    }

    pub fn entries(&self) -> &[TranscriptEntry] {
        &self.entries
    }

    pub fn into_entries(self) -> Vec<TranscriptEntry> {
        self.entries
    }

    pub fn next_turn_number(&self) -> u32 {
        self.entries
            .last()
            .map_or(1, |entry| entry.turn_number.saturating_add(1))
    }
}

pub trait TranscriptRecorder: Send + Sync {
    fn record(&self, entry: &TranscriptEntry);
}

/// Trigger events used by the state transition table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgenticLoopEvent {
    /// Start loop execution.
    Start,
    /// A new LLM request should be issued.
    LlmRequestPrepared,
    /// LLM returned at least one tool call.
    LlmResponseWithTools,
    /// LLM returned no tool calls.
    LlmResponseWithoutTools,
    /// Tool execution finished for this round.
    ToolExecutionComplete,
    /// Provider call failed with a retryable error.
    RetryableError,
    /// Recovery retry should resume.
    ResumeAfterRecovery,
    /// Enter force-final mode.
    EnterForceFinal,
    /// Force-final mode was violated.
    FinalViolation,
    /// Terminate due to no convergence.
    NoConvergence,
    /// Terminate due to cancellation.
    Cancelled,
}

/// Final termination reason reported by the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgenticTerminationReason {
    /// Loop converged to a final non-tool answer.
    Success,
    /// Loop hit max tool rounds and forced finalization.
    MaxRounds,
    /// Loop failed to converge.
    NoConvergence,
    /// Loop exhausted token budget.
    BudgetExhausted,
    /// Loop was cancelled.
    Cancelled,
}

/// Configurable limits and controls for the loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgenticLoopConfig {
    /// Maximum tool rounds before force-final mode.
    pub max_steps: u32,
    /// Optional total token budget for the run.
    pub max_tokens_budget: Option<u32>,
    /// Maximum duplicate tool call detections before no-convergence.
    pub max_duplicate_calls: u32,
    /// Maximum stagnation streak before no-convergence.
    pub max_stagnation_steps: u32,
}

impl Default for AgenticLoopConfig {
    fn default() -> Self {
        Self {
            max_steps: 10,
            max_tokens_budget: None,
            max_duplicate_calls: 3,
            max_stagnation_steps: 3,
        }
    }
}

/// Runtime counters tracked by the controller.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgenticLoopCounters {
    /// Completed tool rounds.
    pub step_count: u32,
    /// Number of duplicate tool call detections.
    pub duplicate_tool_call_count: u32,
    /// Number of stagnation detections.
    pub stagnation_count: u32,
    /// Number of force-final violations.
    pub force_final_violations: u32,
    /// Number of malformed-argument repair attempts.
    pub parse_repair_attempts: u32,
}

/// Per-round transcript item.
#[derive(Debug, Clone, PartialEq)]
pub struct AgenticTurn {
    /// 1-based round number.
    pub round: u32,
    /// Assistant text generated for the round.
    pub assistant_text: String,
    /// Tool calls produced in the round.
    pub tool_calls: Vec<ToolCall>,
    /// Tool results generated for the round.
    pub tool_results: Vec<ToolResult>,
    /// Round stop reason, if available.
    pub stop_reason: Option<StopReason>,
    /// Round usage, if available.
    pub usage: Option<Usage>,
}

/// Final output of an agentic loop run.
#[derive(Debug, Clone, PartialEq)]
pub struct AgenticLoopResult {
    /// Final assistant text produced by the loop.
    pub final_text: String,
    /// Full turn-by-turn transcript.
    pub transcript: Vec<AgenticTurn>,
    /// Aggregated usage totals.
    pub usage_totals: Usage,
    /// Final termination reason.
    pub termination_reason: AgenticTerminationReason,
    /// Final counters snapshot.
    pub counters: AgenticLoopCounters,
}

/// Controller errors for invalid lifecycle transitions.
#[derive(Debug, thiserror::Error)]
pub enum AgenticLoopError {
    /// Loop is already running.
    #[error("agentic loop is already running")]
    AlreadyRunning,
    /// Invalid state transition was attempted.
    #[error("invalid transition from {from:?} with event {event:?}")]
    InvalidTransition {
        /// Source state.
        from: AgenticLoopState,
        /// Event that caused the invalid transition.
        event: AgenticLoopEvent,
    },
}

/// Abstraction over tool execution used by the loop.
#[async_trait]
pub trait ToolExecutor: Send + Sync {
    /// Executes one tool call and returns a canonical tool result.
    async fn execute(&self, tool_call: &ToolCall) -> ToolResult;
}

/// Agentic loop state machine controller.
pub struct AgenticLoopController {
    /// Controller configuration limits.
    pub config: AgenticLoopConfig,
    /// Current state.
    pub state: AgenticLoopState,
    /// Runtime counters.
    pub counters: AgenticLoopCounters,
    running: bool,
    recover_resume_state: Option<AgenticLoopState>,
    force_final_target: Option<AgenticTerminationReason>,
    seen_tool_calls: HashMap<String, u32>,
    previous_round_signature: Option<String>,
    transcript_recorder: Option<Arc<dyn TranscriptRecorder>>,
}

#[derive(Debug, Clone, Copy)]
struct RepairRequestContext<'a> {
    messages: &'a [Message],
    tools: &'a [ToolDefinition],
    model: &'a str,
    max_tokens: Option<u32>,
    temperature: Option<f32>,
}

impl AgenticLoopController {
    /// Creates a new controller with the provided configuration.
    pub fn new(config: AgenticLoopConfig) -> Self {
        Self {
            config,
            state: AgenticLoopState::Idle,
            counters: AgenticLoopCounters::default(),
            running: false,
            recover_resume_state: None,
            force_final_target: None,
            seen_tool_calls: HashMap::new(),
            previous_round_signature: None,
            transcript_recorder: None,
        }
    }

    pub fn with_transcript_recorder(mut self, recorder: Arc<dyn TranscriptRecorder>) -> Self {
        self.transcript_recorder = Some(recorder);
        self
    }

    pub fn set_transcript_recorder(&mut self, recorder: Option<Arc<dyn TranscriptRecorder>>) {
        self.transcript_recorder = recorder;
    }

    /// Advances the state machine with one event.
    pub fn transition(&mut self, event: AgenticLoopEvent) -> Result<(), AgenticLoopError> {
        let from = self.state;
        let next = match (self.state, event) {
            (AgenticLoopState::Idle, AgenticLoopEvent::Start) => AgenticLoopState::InitialCall,
            (AgenticLoopState::InitialCall, AgenticLoopEvent::LlmRequestPrepared) => {
                AgenticLoopState::LlmStreaming
            }
            (AgenticLoopState::LlmStreaming, AgenticLoopEvent::LlmResponseWithTools) => {
                AgenticLoopState::ExecuteTools
            }
            (AgenticLoopState::LlmStreaming, AgenticLoopEvent::LlmResponseWithoutTools) => {
                AgenticLoopState::DoneSuccess
            }
            (AgenticLoopState::ExecuteTools, AgenticLoopEvent::ToolExecutionComplete) => {
                AgenticLoopState::ToolResultsReady
            }
            (AgenticLoopState::ToolResultsReady, AgenticLoopEvent::LlmRequestPrepared) => {
                AgenticLoopState::LlmStreaming
            }
            (AgenticLoopState::ToolResultsReady, AgenticLoopEvent::EnterForceFinal) => {
                AgenticLoopState::ForceFinal
            }
            (AgenticLoopState::ForceFinal, AgenticLoopEvent::LlmRequestPrepared) => {
                AgenticLoopState::LlmStreamingFinal
            }
            (AgenticLoopState::LlmStreamingFinal, AgenticLoopEvent::LlmResponseWithoutTools) => {
                match self
                    .force_final_target
                    .unwrap_or(AgenticTerminationReason::Success)
                {
                    AgenticTerminationReason::Success => AgenticLoopState::DoneSuccess,
                    AgenticTerminationReason::MaxRounds => AgenticLoopState::DoneMaxRounds,
                    AgenticTerminationReason::BudgetExhausted => {
                        AgenticLoopState::DoneBudgetExhausted
                    }
                    AgenticTerminationReason::NoConvergence => AgenticLoopState::DoneNoConvergence,
                    AgenticTerminationReason::Cancelled => AgenticLoopState::DoneCancelled,
                }
            }
            (AgenticLoopState::LlmStreamingFinal, AgenticLoopEvent::FinalViolation) => {
                AgenticLoopState::DoneNoConvergence
            }
            (AgenticLoopState::LlmStreaming, AgenticLoopEvent::RetryableError)
            | (AgenticLoopState::LlmStreamingFinal, AgenticLoopEvent::RetryableError) => {
                self.recover_resume_state = Some(self.state);
                AgenticLoopState::RecoverOrAbort
            }
            (AgenticLoopState::RecoverOrAbort, AgenticLoopEvent::ResumeAfterRecovery) => self
                .recover_resume_state
                .unwrap_or(AgenticLoopState::LlmStreaming),
            (_, AgenticLoopEvent::NoConvergence) => AgenticLoopState::DoneNoConvergence,
            (_, AgenticLoopEvent::Cancelled) => AgenticLoopState::DoneCancelled,
            _ => {
                return Err(AgenticLoopError::InvalidTransition { from, event });
            }
        };
        self.state = next;
        Ok(())
    }

    /// Runs the loop until convergence, forced termination, or cancellation.
    pub async fn run<P, E>(
        &mut self,
        provider: &P,
        context_builder: ContextBuilder,
        tool_executor: &E,
        cancellation: Option<&watch::Receiver<bool>>,
    ) -> Result<AgenticLoopResult, AgenticLoopError>
    where
        P: LlmProvider,
        E: ToolExecutor,
    {
        if self.running {
            return Err(AgenticLoopError::AlreadyRunning);
        }

        self.running = true;
        self.counters = AgenticLoopCounters::default();
        self.seen_tool_calls.clear();
        self.previous_round_signature = None;
        self.force_final_target = None;
        self.recover_resume_state = None;
        self.state = AgenticLoopState::Idle;

        let mut transcript = Vec::new();
        let mut transcript_entries = Transcript::new();
        let mut usage_totals = Usage {
            input_tokens: 0,
            output_tokens: 0,
        };

        let initial_request = context_builder.build();
        let mut messages = initial_request.messages;
        let all_tools = initial_request.tools;
        let model = initial_request.model;
        let max_tokens = initial_request.max_tokens;
        let temperature = initial_request.temperature;

        let mut final_text = String::new();
        if self.transition(AgenticLoopEvent::Start).is_err() {
            self.running = false;
            return Err(AgenticLoopError::InvalidTransition {
                from: AgenticLoopState::Idle,
                event: AgenticLoopEvent::Start,
            });
        }
        self.record_system_entry(
            &mut transcript_entries,
            1,
            format!("event=start state={:?}", self.state),
        );
        let _ = self.transition(AgenticLoopEvent::LlmRequestPrepared);
        self.record_system_entry(
            &mut transcript_entries,
            1,
            format!("event=llm_request_prepared state={:?}", self.state),
        );

        loop {
            if is_cancelled(cancellation) {
                let _ = self.transition(AgenticLoopEvent::Cancelled);
                self.record_system_entry(
                    &mut transcript_entries,
                    (transcript.len() + 1) as u32,
                    format!("event=cancelled state={:?}", self.state),
                );
                break;
            }

            if is_terminal(self.state) {
                break;
            }

            if !matches!(
                self.state,
                AgenticLoopState::LlmStreaming | AgenticLoopState::LlmStreamingFinal
            ) {
                if matches!(self.state, AgenticLoopState::ForceFinal) {
                    let _ = self.transition(AgenticLoopEvent::LlmRequestPrepared);
                    self.record_system_entry(
                        &mut transcript_entries,
                        (transcript.len() + 1) as u32,
                        format!("event=llm_request_prepared state={:?}", self.state),
                    );
                    continue;
                }
                if matches!(self.state, AgenticLoopState::ToolResultsReady) {
                    let _ = self.transition(AgenticLoopEvent::LlmRequestPrepared);
                    self.record_system_entry(
                        &mut transcript_entries,
                        (transcript.len() + 1) as u32,
                        format!("event=llm_request_prepared state={:?}", self.state),
                    );
                    continue;
                }
                let _ = self.transition(AgenticLoopEvent::NoConvergence);
                self.record_system_entry(
                    &mut transcript_entries,
                    (transcript.len() + 1) as u32,
                    format!("event=no_convergence state={:?}", self.state),
                );
                continue;
            }

            let tools = if matches!(self.state, AgenticLoopState::LlmStreamingFinal) {
                Vec::new()
            } else {
                all_tools.clone()
            };
            let request = CompletionRequest {
                model: model.clone(),
                messages: messages.clone(),
                max_tokens,
                temperature,
                tools,
            };

            let mut provider_attempt = 0u8;
            let response = loop {
                match provider.complete(request.clone()).await {
                    Ok(response) => break Some(response),
                    Err(err) if is_retryable(&err) && provider_attempt == 0 => {
                        provider_attempt = 1;
                        let _ = self.transition(AgenticLoopEvent::RetryableError);
                        self.record_system_entry(
                            &mut transcript_entries,
                            (transcript.len() + 1) as u32,
                            format!("event=retryable_error state={:?}", self.state),
                        );
                        let _ = self.transition(AgenticLoopEvent::ResumeAfterRecovery);
                        self.record_system_entry(
                            &mut transcript_entries,
                            (transcript.len() + 1) as u32,
                            format!("event=resume_after_recovery state={:?}", self.state),
                        );
                    }
                    Err(_) => {
                        let _ = self.transition(AgenticLoopEvent::NoConvergence);
                        self.record_system_entry(
                            &mut transcript_entries,
                            (transcript.len() + 1) as u32,
                            format!("event=no_convergence state={:?}", self.state),
                        );
                        break None;
                    }
                }
            };

            let Some(response) = response else {
                continue;
            };

            let round_usage = response_usage(&response);
            let round_stop_reason = canonical_stop_reason(&response);
            accumulate_usage(&mut usage_totals, round_usage.as_ref());

            if budget_exhausted(&usage_totals, self.config.max_tokens_budget)
                && !matches!(self.state, AgenticLoopState::LlmStreamingFinal)
            {
                self.force_final_target = Some(AgenticTerminationReason::BudgetExhausted);
                let _ = self.transition(AgenticLoopEvent::EnterForceFinal);
                continue;
            }

            final_text = response.content.clone();
            messages.push(Message {
                role: Role::Assistant,
                content: response.content.clone(),
                tool_results: Vec::new(),
            });
            self.record_transcript_entry(
                &mut transcript_entries,
                TranscriptEntry {
                    turn_number: (transcript.len() + 1) as u32,
                    role: TranscriptRole::Llm,
                    timestamp: unix_timestamp_now(),
                    content: TranscriptContent::Message(Message {
                        role: Role::Assistant,
                        content: response.content.clone(),
                        tool_results: Vec::new(),
                    }),
                    usage: round_usage.clone(),
                    state: self.state,
                    tool_calls: response.tool_calls.clone(),
                },
            );

            if response.tool_calls.is_empty() {
                let event = AgenticLoopEvent::LlmResponseWithoutTools;
                let _ = self.transition(event);
                self.record_system_entry(
                    &mut transcript_entries,
                    (transcript.len() + 1) as u32,
                    format!("event=llm_response_without_tools state={:?}", self.state),
                );
                transcript.push(AgenticTurn {
                    round: (transcript.len() + 1) as u32,
                    assistant_text: response.content,
                    tool_calls: Vec::new(),
                    tool_results: Vec::new(),
                    stop_reason: round_stop_reason,
                    usage: round_usage,
                });
                continue;
            }

            if matches!(self.state, AgenticLoopState::LlmStreamingFinal) {
                self.counters.force_final_violations += 1;
                if self.counters.force_final_violations > 1 {
                    let _ = self.transition(AgenticLoopEvent::FinalViolation);
                    self.record_system_entry(
                        &mut transcript_entries,
                        (transcript.len() + 1) as u32,
                        format!("event=final_violation state={:?}", self.state),
                    );
                } else {
                    messages.push(Message {
                        role: Role::User,
                        content: "Tool use is disabled. Produce a final answer using existing evidence only.".to_string(),
                        tool_results: Vec::new(),
                    });
                }
                transcript.push(AgenticTurn {
                    round: (transcript.len() + 1) as u32,
                    assistant_text: response.content,
                    tool_calls: response.tool_calls,
                    tool_results: Vec::new(),
                    stop_reason: round_stop_reason,
                    usage: round_usage,
                });
                continue;
            }

            let _ = self.transition(AgenticLoopEvent::LlmResponseWithTools);
            self.record_system_entry(
                &mut transcript_entries,
                (transcript.len() + 1) as u32,
                format!("event=llm_response_with_tools state={:?}", self.state),
            );
            let tool_calls = response.tool_calls;

            let signature = round_signature(&tool_calls);
            if self
                .previous_round_signature
                .as_ref()
                .is_some_and(|previous| previous == &signature)
            {
                self.counters.stagnation_count += 1;
            } else {
                self.counters.stagnation_count = 0;
            }
            self.previous_round_signature = Some(signature);

            if self.counters.stagnation_count >= self.config.max_stagnation_steps {
                let _ = self.transition(AgenticLoopEvent::NoConvergence);
                self.record_system_entry(
                    &mut transcript_entries,
                    (transcript.len() + 1) as u32,
                    format!("event=no_convergence state={:?}", self.state),
                );
                transcript.push(AgenticTurn {
                    round: (transcript.len() + 1) as u32,
                    assistant_text: response.content,
                    tool_calls,
                    tool_results: Vec::new(),
                    stop_reason: round_stop_reason,
                    usage: round_usage,
                });
                continue;
            }

            let mut duplicate_abort = false;
            for call in &tool_calls {
                let key = normalize_tool_key(call);
                let entry = self.seen_tool_calls.entry(key).or_insert(0);
                if *entry > 0 {
                    self.counters.duplicate_tool_call_count += 1;
                    if self.counters.duplicate_tool_call_count >= self.config.max_duplicate_calls {
                        duplicate_abort = true;
                    }
                }
                *entry += 1;
            }
            if duplicate_abort {
                let _ = self.transition(AgenticLoopEvent::NoConvergence);
                self.record_system_entry(
                    &mut transcript_entries,
                    (transcript.len() + 1) as u32,
                    format!("event=no_convergence state={:?}", self.state),
                );
                transcript.push(AgenticTurn {
                    round: (transcript.len() + 1) as u32,
                    assistant_text: response.content,
                    tool_calls,
                    tool_results: Vec::new(),
                    stop_reason: round_stop_reason,
                    usage: round_usage,
                });
                continue;
            }

            let mut tool_results = Vec::new();
            for call in tool_calls.clone() {
                if is_cancelled(cancellation) {
                    let _ = self.transition(AgenticLoopEvent::Cancelled);
                    self.record_system_entry(
                        &mut transcript_entries,
                        (transcript.len() + 1) as u32,
                        format!("event=cancelled state={:?}", self.state),
                    );
                    break;
                }

                let effective_call = if call.parse_error.is_some() {
                    self.counters.parse_repair_attempts += 1;
                    let repair_context = RepairRequestContext {
                        messages: &messages,
                        tools: &all_tools,
                        model: &model,
                        max_tokens,
                        temperature,
                    };
                    match self.attempt_repair(provider, repair_context, &call).await {
                        Some(repaired) => repaired,
                        None => {
                            tool_results.push(ToolResult {
                                tool_use_id: call.id.clone(),
                                output: serde_json::json!({
                                    "status": "error",
                                    "code": "tool_arguments_unrepairable",
                                    "tool": call.name,
                                    "input": call.input,
                                    "parse_error": call.parse_error,
                                }),
                                display_summary: format!(
                                    "Tool arguments could not be repaired for '{}'",
                                    call.name
                                ),
                                content: format!(
                                    "Tool arguments could not be repaired for '{}'",
                                    call.name
                                ),
                                is_error: true,
                            });
                            continue;
                        }
                    }
                } else {
                    call
                };

                let mut result = tool_executor.execute(&effective_call).await;
                if result.tool_use_id != effective_call.id {
                    result.tool_use_id = effective_call.id;
                }
                self.record_transcript_entry(
                    &mut transcript_entries,
                    TranscriptEntry {
                        turn_number: (transcript.len() + 1) as u32,
                        role: TranscriptRole::ToolExecutor,
                        timestamp: unix_timestamp_now(),
                        content: TranscriptContent::ToolResult(result.clone()),
                        usage: None,
                        state: self.state,
                        tool_calls: Vec::new(),
                    },
                );
                tool_results.push(result);
            }

            if matches!(self.state, AgenticLoopState::DoneCancelled) {
                break;
            }

            let _ = self.transition(AgenticLoopEvent::ToolExecutionComplete);
            self.record_system_entry(
                &mut transcript_entries,
                (transcript.len() + 1) as u32,
                format!("event=tool_execution_complete state={:?}", self.state),
            );
            messages.push(Message {
                role: Role::ToolResult,
                content: String::new(),
                tool_results: tool_results.clone(),
            });
            self.counters.step_count += 1;

            transcript.push(AgenticTurn {
                round: (transcript.len() + 1) as u32,
                assistant_text: response.content,
                tool_calls,
                tool_results,
                stop_reason: round_stop_reason,
                usage: round_usage,
            });

            if self.counters.step_count >= self.config.max_steps {
                self.force_final_target = Some(AgenticTerminationReason::MaxRounds);
                let _ = self.transition(AgenticLoopEvent::EnterForceFinal);
                self.record_system_entry(
                    &mut transcript_entries,
                    (transcript.len() + 1) as u32,
                    format!("event=enter_force_final state={:?}", self.state),
                );
                continue;
            }
        }

        let termination = match self.state {
            AgenticLoopState::DoneSuccess => AgenticTerminationReason::Success,
            AgenticLoopState::DoneMaxRounds => AgenticTerminationReason::MaxRounds,
            AgenticLoopState::DoneNoConvergence => AgenticTerminationReason::NoConvergence,
            AgenticLoopState::DoneBudgetExhausted => AgenticTerminationReason::BudgetExhausted,
            AgenticLoopState::DoneCancelled => AgenticTerminationReason::Cancelled,
            _ => AgenticTerminationReason::NoConvergence,
        };

        self.running = false;
        Ok(AgenticLoopResult {
            final_text,
            transcript,
            usage_totals,
            termination_reason: termination,
            counters: self.counters.clone(),
        })
    }

    fn record_system_entry(&self, transcript: &mut Transcript, turn_number: u32, content: String) {
        self.record_transcript_entry(
            transcript,
            TranscriptEntry {
                turn_number,
                role: TranscriptRole::System,
                timestamp: unix_timestamp_now(),
                content: TranscriptContent::Message(Message {
                    role: Role::System,
                    content,
                    tool_results: Vec::new(),
                }),
                usage: None,
                state: self.state,
                tool_calls: Vec::new(),
            },
        );
    }

    fn record_transcript_entry(&self, transcript: &mut Transcript, entry: TranscriptEntry) {
        if let Some(recorder) = self.transcript_recorder.as_ref() {
            recorder.record(&entry);
        }
        transcript.push(entry);
    }

    async fn attempt_repair<P>(
        &self,
        provider: &P,
        repair_context: RepairRequestContext<'_>,
        call: &ToolCall,
    ) -> Option<ToolCall>
    where
        P: LlmProvider,
    {
        let mut repair_messages = repair_context.messages.to_vec();
        repair_messages.push(Message {
            role: Role::User,
            content: format!(
                "Return one corrected tool call for '{}' with valid JSON arguments only. Previous parse error: {}",
                call.name,
                call.parse_error
                    .clone()
                    .unwrap_or_else(|| "unknown parse error".to_string())
            ),
            tool_results: Vec::new(),
        });

        let repair_tools: Vec<ToolDefinition> = repair_context
            .tools
            .iter()
            .filter(|tool| tool.name == call.name)
            .cloned()
            .collect();

        let request = CompletionRequest {
            model: repair_context.model.to_string(),
            messages: repair_messages,
            max_tokens: repair_context.max_tokens,
            temperature: repair_context.temperature,
            tools: if repair_tools.is_empty() {
                repair_context.tools.to_vec()
            } else {
                repair_tools
            },
        };

        let response = provider.complete(request).await.ok()?;
        let mut repaired = response.tool_calls.into_iter().next()?;
        if repaired.parse_error.is_some() {
            return None;
        }
        repaired.id = call.id.clone();
        Some(repaired)
    }
}

fn unix_timestamp_now() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs().to_string(),
        Err(_) => "0".to_string(),
    }
}

fn is_terminal(state: AgenticLoopState) -> bool {
    matches!(
        state,
        AgenticLoopState::DoneSuccess
            | AgenticLoopState::DoneMaxRounds
            | AgenticLoopState::DoneNoConvergence
            | AgenticLoopState::DoneBudgetExhausted
            | AgenticLoopState::DoneCancelled
    )
}

fn is_cancelled(cancellation: Option<&watch::Receiver<bool>>) -> bool {
    cancellation.is_some_and(|receiver| *receiver.borrow())
}

fn is_retryable(error: &LlmError) -> bool {
    match error {
        LlmError::RateLimited { .. } => true,
        LlmError::Http(err) => err.is_timeout() || err.is_connect(),
        _ => false,
    }
}

fn accumulate_usage(total: &mut Usage, usage: Option<&Usage>) {
    if let Some(usage) = usage {
        total.input_tokens = total.input_tokens.saturating_add(usage.input_tokens);
        total.output_tokens = total.output_tokens.saturating_add(usage.output_tokens);
    }
}

fn budget_exhausted(total: &Usage, budget: Option<u32>) -> bool {
    let Some(budget) = budget else {
        return false;
    };
    total
        .input_tokens
        .saturating_add(total.output_tokens)
        .ge(&budget)
}

fn canonical_stop_reason(response: &CompletionResponse) -> Option<StopReason> {
    response.stop_reason
}

fn response_usage(response: &CompletionResponse) -> Option<Usage> {
    match (response.input_tokens, response.output_tokens) {
        (Some(input_tokens), Some(output_tokens)) => Some(Usage {
            input_tokens,
            output_tokens,
        }),
        _ => None,
    }
}

fn round_signature(calls: &[ToolCall]) -> String {
    let mut items: Vec<String> = calls.iter().map(normalize_tool_key).collect();
    items.sort_unstable();
    items.join("||")
}

fn normalize_tool_key(call: &ToolCall) -> String {
    let canonical = canonicalize_value(&call.input);
    let serialized = serde_json::to_string(&canonical).unwrap_or_else(|_| "null".to_string());
    format!("{}:{}", call.name, serialized)
}

fn canonicalize_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted = BTreeMap::new();
            for (key, nested) in map {
                sorted.insert(key.clone(), canonicalize_value(nested));
            }
            let mut output = Map::new();
            for (key, nested) in sorted {
                output.insert(key, nested);
            }
            Value::Object(output)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_value).collect()),
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use serde_json::json;

    use super::*;
    use crate::mock::{MockProvider, MockResponse};
    use crate::types::CompletionResponse;
    use std::collections::HashSet;

    #[derive(Debug)]
    struct MockToolExecutor {
        failures_for_ids: HashSet<String>,
    }

    struct RecordingSink {
        entries: Mutex<Vec<TranscriptEntry>>,
    }

    impl RecordingSink {
        fn new() -> Self {
            Self {
                entries: Mutex::new(Vec::new()),
            }
        }

        fn entry_count(&self) -> usize {
            self.entries.lock().map_or(0, |entries| entries.len())
        }
    }

    impl TranscriptRecorder for RecordingSink {
        fn record(&self, entry: &TranscriptEntry) {
            if let Ok(mut entries) = self.entries.lock() {
                entries.push(entry.clone());
            }
        }
    }

    #[async_trait]
    impl ToolExecutor for MockToolExecutor {
        async fn execute(&self, tool_call: &ToolCall) -> ToolResult {
            if self.failures_for_ids.contains(&tool_call.id) {
                return ToolResult {
                    tool_use_id: tool_call.id.clone(),
                    output: json!({"status": "error"}),
                    display_summary: "mock tool failure".to_string(),
                    content: "mock tool failure".to_string(),
                    is_error: true,
                };
            }
            ToolResult {
                tool_use_id: tool_call.id.clone(),
                output: json!({"status": "ok"}),
                display_summary: "ok".to_string(),
                content: "ok".to_string(),
                is_error: false,
            }
        }
    }

    fn response(text: &str, tool_calls: Vec<ToolCall>) -> CompletionResponse {
        CompletionResponse {
            model: "mock-model".to_string(),
            content: text.to_string(),
            stop_reason: Some(if tool_calls.is_empty() {
                StopReason::EndTurn
            } else {
                StopReason::ToolUse
            }),
            input_tokens: Some(5),
            output_tokens: Some(3),
            tool_calls,
        }
    }

    fn tool_call(id: &str, name: &str, input: Value) -> ToolCall {
        ToolCall {
            id: id.to_string(),
            name: name.to_string(),
            input,
            arguments_raw: None,
            parse_error: None,
            provider: Some("mock".to_string()),
            stream_index: None,
        }
    }

    fn builder() -> ContextBuilder {
        ContextBuilder::new("mock-model").with_history(vec![Message {
            role: Role::User,
            content: "Analyze this function".to_string(),
            tool_results: Vec::new(),
        }])
    }

    #[test]
    fn transition_table_covers_core_paths() {
        let mut controller = AgenticLoopController::new(AgenticLoopConfig::default());
        assert!(controller.transition(AgenticLoopEvent::Start).is_ok());
        assert_eq!(controller.state, AgenticLoopState::InitialCall);
        assert!(controller
            .transition(AgenticLoopEvent::LlmRequestPrepared)
            .is_ok());
        assert_eq!(controller.state, AgenticLoopState::LlmStreaming);
        assert!(controller
            .transition(AgenticLoopEvent::LlmResponseWithTools)
            .is_ok());
        assert_eq!(controller.state, AgenticLoopState::ExecuteTools);
        assert!(controller
            .transition(AgenticLoopEvent::ToolExecutionComplete)
            .is_ok());
        assert_eq!(controller.state, AgenticLoopState::ToolResultsReady);
    }

    #[tokio::test]
    async fn run_converges_after_tool_round() {
        let provider = Arc::new(MockProvider::new(vec![
            MockResponse::Completion(Ok(response(
                "Need one tool",
                vec![tool_call("tc1", "decompile", json!({"addr": "0x401000"}))],
            ))),
            MockResponse::Completion(Ok(response("Done", Vec::new()))),
        ]));
        let executor = MockToolExecutor {
            failures_for_ids: HashSet::new(),
        };

        let mut controller = AgenticLoopController::new(AgenticLoopConfig::default());
        let result = controller
            .run(provider.as_ref(), builder(), &executor, None)
            .await;

        assert!(result.is_ok());
        let result = result.unwrap_or_else(|_| unreachable!());
        assert_eq!(result.termination_reason, AgenticTerminationReason::Success);
        assert_eq!(result.counters.step_count, 1);
        assert_eq!(provider.call_count(), 2);
    }

    #[tokio::test]
    async fn duplicate_detection_triggers_no_convergence() {
        let provider = Arc::new(MockProvider::new(vec![
            MockResponse::Completion(Ok(response(
                "Call",
                vec![tool_call("tc1", "decompile", json!({"addr": "0x401000"}))],
            ))),
            MockResponse::Completion(Ok(response(
                "Call again",
                vec![tool_call("tc2", "decompile", json!({"addr": "0x401000"}))],
            ))),
            MockResponse::Completion(Ok(response(
                "Call third",
                vec![tool_call("tc3", "decompile", json!({"addr": "0x401000"}))],
            ))),
        ]));
        let executor = MockToolExecutor {
            failures_for_ids: HashSet::new(),
        };

        let mut controller = AgenticLoopController::new(AgenticLoopConfig {
            max_duplicate_calls: 2,
            ..AgenticLoopConfig::default()
        });
        let result = controller
            .run(provider.as_ref(), builder(), &executor, None)
            .await;

        assert!(result.is_ok());
        let result = result.unwrap_or_else(|_| unreachable!());
        assert_eq!(
            result.termination_reason,
            AgenticTerminationReason::NoConvergence
        );
        assert!(result.counters.duplicate_tool_call_count >= 2);
    }

    #[tokio::test]
    async fn max_steps_enters_force_final_and_stops() {
        let provider = Arc::new(MockProvider::new(vec![
            MockResponse::Completion(Ok(response(
                "tool",
                vec![tool_call("tc1", "decompile", json!({"addr": "0x401000"}))],
            ))),
            MockResponse::Completion(Ok(response(
                "still tool",
                vec![tool_call("tc2", "decompile", json!({"addr": "0x401000"}))],
            ))),
            MockResponse::Completion(Ok(response("final", Vec::new()))),
        ]));
        let executor = MockToolExecutor {
            failures_for_ids: HashSet::new(),
        };

        let mut controller = AgenticLoopController::new(AgenticLoopConfig {
            max_steps: 1,
            ..AgenticLoopConfig::default()
        });
        let result = controller
            .run(provider.as_ref(), builder(), &executor, None)
            .await;

        assert!(result.is_ok());
        let result = result.unwrap_or_else(|_| unreachable!());
        assert_eq!(
            result.termination_reason,
            AgenticTerminationReason::MaxRounds
        );
        assert_eq!(result.counters.step_count, 1);
    }

    #[tokio::test]
    async fn cancellation_terminates_loop() {
        let provider = Arc::new(MockProvider::new(vec![MockResponse::Completion(Ok(
            response("final", Vec::new()),
        ))]));
        let executor = MockToolExecutor {
            failures_for_ids: HashSet::new(),
        };
        let (tx, rx) = watch::channel(true);
        drop(tx);

        let mut controller = AgenticLoopController::new(AgenticLoopConfig::default());
        let result = controller
            .run(provider.as_ref(), builder(), &executor, Some(&rx))
            .await;

        assert!(result.is_ok());
        let result = result.unwrap_or_else(|_| unreachable!());
        assert_eq!(
            result.termination_reason,
            AgenticTerminationReason::Cancelled
        );
        assert_eq!(provider.call_count(), 0);
    }

    #[tokio::test]
    async fn retryable_error_retries_once() {
        let provider = Arc::new(MockProvider::new(vec![
            MockResponse::Completion(Err(LlmError::RateLimited { retry_after: None })),
            MockResponse::Completion(Ok(response("final", Vec::new()))),
        ]));
        let executor = MockToolExecutor {
            failures_for_ids: HashSet::new(),
        };

        let mut controller = AgenticLoopController::new(AgenticLoopConfig::default());
        let result = controller
            .run(provider.as_ref(), builder(), &executor, None)
            .await;

        assert!(result.is_ok());
        let result = result.unwrap_or_else(|_| unreachable!());
        assert_eq!(result.termination_reason, AgenticTerminationReason::Success);
        assert_eq!(provider.call_count(), 2);
    }

    #[tokio::test]
    async fn malformed_tool_args_repairs_once() {
        let malformed = ToolCall {
            id: "tc1".to_string(),
            name: "decompile".to_string(),
            input: Value::Null,
            arguments_raw: Some("{bad".to_string()),
            parse_error: Some("invalid json".to_string()),
            provider: Some("mock".to_string()),
            stream_index: None,
        };

        let provider = Arc::new(MockProvider::new(vec![
            MockResponse::Completion(Ok(response("malformed", vec![malformed]))),
            MockResponse::Completion(Ok(response(
                "repair",
                vec![tool_call(
                    "repair",
                    "decompile",
                    json!({"addr": "0x401000"}),
                )],
            ))),
            MockResponse::Completion(Ok(response("final", Vec::new()))),
        ]));
        let executor = MockToolExecutor {
            failures_for_ids: HashSet::new(),
        };

        let mut controller = AgenticLoopController::new(AgenticLoopConfig::default());
        let result = controller
            .run(provider.as_ref(), builder(), &executor, None)
            .await;

        assert!(result.is_ok());
        let result = result.unwrap_or_else(|_| unreachable!());
        assert_eq!(result.termination_reason, AgenticTerminationReason::Success);
        assert_eq!(result.counters.parse_repair_attempts, 1);
    }

    #[tokio::test]
    async fn run_records_entries_when_recorder_is_set() {
        let provider = Arc::new(MockProvider::new(vec![MockResponse::Completion(Ok(
            response("final", Vec::new()),
        ))]));
        let executor = MockToolExecutor {
            failures_for_ids: HashSet::new(),
        };
        let sink = Arc::new(RecordingSink::new());

        let mut controller = AgenticLoopController::new(AgenticLoopConfig::default())
            .with_transcript_recorder(sink.clone());
        let result = controller
            .run(provider.as_ref(), builder(), &executor, None)
            .await;

        assert!(result.is_ok());
        assert!(sink.entry_count() > 0);
    }
}

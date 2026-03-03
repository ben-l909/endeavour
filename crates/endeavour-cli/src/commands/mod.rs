pub(crate) mod analyze;
pub(crate) mod config;
pub(crate) mod connect;
pub(crate) mod detect_mba;
pub(crate) mod lift;
pub(crate) mod normalize;
pub(crate) mod session;
pub(crate) mod transcript;

pub(crate) use analyze::{
    handle_analyze, handle_cache_clear, handle_cache_stats, handle_callgraph, handle_comment,
    handle_decompile, handle_explain, handle_rename, handle_review, handle_search,
};
pub(crate) use config::{handle_config_get, handle_config_list, handle_config_set};
pub(crate) use connect::{handle_connect, handle_ida_status};
pub(crate) use detect_mba::handle_detect_mba;
pub(crate) use lift::handle_lift;
pub(crate) use normalize::handle_normalize;
pub(crate) use session::{
    handle_findings, handle_info, handle_session_new, handle_session_switch, handle_sessions,
};
pub(crate) use transcript::handle_show_transcript;

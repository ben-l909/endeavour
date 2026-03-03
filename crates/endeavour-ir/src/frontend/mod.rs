/// IDA microcode frontend implementation.
#[cfg(feature = "ida")]
pub mod ida;
/// Capstone-based headless frontend implementation.
pub mod capstone;

#[cfg(feature = "ida")]
pub use ida::{IdaFrontend, McpTransport};
/// Capstone frontend and architecture selector.
pub use capstone::{CapstoneFrontend, InstructionArch};

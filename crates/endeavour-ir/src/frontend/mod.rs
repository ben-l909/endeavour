/// Capstone-based headless frontend implementation.
pub mod capstone;

/// Capstone frontend and architecture selector.
pub use capstone::{CapstoneFrontend, InstructionArch};

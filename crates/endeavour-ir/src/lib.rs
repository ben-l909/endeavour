/// Error and result types for IR operations.
pub mod error;
/// Frontend implementations that lift machine instructions into IR.
pub mod frontend;
/// Core Endeavour IR node definitions.
pub mod ir;

pub use error::{IrError, Result};
#[cfg(feature = "ida")]
pub use frontend::{IdaFrontend, McpTransport};
pub use frontend::{CapstoneFrontend, InstructionArch};
pub use ir::{BinOp, Expr, Stmt, UnOp, ValueId, Width};

/// Returns the crate package name.
pub fn crate_name() -> &'static str {
    "endeavour-ir"
}

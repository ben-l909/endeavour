/// Error and result types for IR operations.
pub mod error;
/// Frontend implementations that lift machine instructions into IR.
pub mod frontend;
/// Core Endeavour IR node definitions.
pub mod ir;
/// IR normalization interfaces and canonicalization routines.
pub mod normalize;

pub use error::{IrError, Result};
pub use frontend::{CapstoneFrontend, InstructionArch};
pub use ir::{BinOp, Expr, Stmt, UnOp, ValueId, Width};
/// Normalization APIs and frontend abstraction exports.
pub use normalize::{normalize_expr, FrontendRegistry, IrFrontend};

/// Returns the crate package name.
pub fn crate_name() -> &'static str {
    "endeavour-ir"
}

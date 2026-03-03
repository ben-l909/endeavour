pub mod error;
pub mod ir;
/// IR normalization interfaces and canonicalization routines.
pub mod normalize;

pub use error::{IrError, Result};
pub use ir::{BinOp, Expr, Stmt, UnOp, ValueId, Width};
/// Normalization APIs and frontend abstraction exports.
pub use normalize::{normalize_expr, FrontendRegistry, IrFrontend};

pub fn crate_name() -> &'static str {
    "endeavour-ir"
}

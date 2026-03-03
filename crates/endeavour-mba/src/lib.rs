//! Minimal MBA simplification PoC inspired by GAMBA-style rewrites.

/// Expression AST for mixed boolean-arithmetic formulas.
pub mod ast;
/// Error types for the MBA crate.
pub mod error;
/// Rewrite-driven simplifier.
pub mod simplify;

pub use ast::Expr;
pub use error::{Error, Result};
pub use simplify::simplify;

/// Returns the crate name.
pub fn crate_name() -> &'static str {
    "endeavour-mba"
}

//! Minimal MBA simplification PoC inspired by GAMBA-style rewrites.

/// Expression AST for mixed boolean-arithmetic formulas.
pub mod ast;
/// Error types for the MBA crate.
pub mod error;
/// Structural linear-MBA matcher for `endeavour-ir` expression trees.
pub mod matcher;
/// Rewrite-driven simplifier.
pub mod simplify;
/// Z3-backed equivalence verifier for MBA rewrite candidates.
pub mod verifier;

pub use ast::Expr;
pub use error::{Error, Result};
pub use matcher::{MbaMatch, MbaMatcher};
pub use simplify::simplify;
pub use verifier::{VerifierResult, Z3Verifier};

/// Returns the crate name.
pub fn crate_name() -> &'static str {
    "endeavour-mba"
}

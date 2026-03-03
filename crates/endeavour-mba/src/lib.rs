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
#[cfg(feature = "z3-verifier")]
pub mod verifier;

/// Re-export of the expression AST type.
pub use ast::Expr;
/// Re-export of error types.
pub use error::{Error, Result};
/// Re-export of MBA matching types.
pub use matcher::{MbaMatch, MbaMatcher};
/// Re-export of the simplification function.
pub use simplify::simplify;
#[cfg(feature = "z3-verifier")]
/// Re-export of Z3 verifier types.
pub use verifier::{VerifierResult, Z3Verifier};

/// Returns the crate name.
pub fn crate_name() -> &'static str {
    "endeavour-mba"
}

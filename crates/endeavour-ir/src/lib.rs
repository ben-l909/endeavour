pub mod error;
pub mod ir;

pub use error::{IrError, Result};
pub use ir::{BinOp, Expr, Stmt, UnOp, ValueId, Width};

pub fn crate_name() -> &'static str {
    "endeavour-ir"
}

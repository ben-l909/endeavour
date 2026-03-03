pub mod error;
pub mod ir;
pub mod parser;

pub use error::{ParseError, Result};
pub use ir::MicrocodeProgram;
pub use parser::parse_microcode_json;

pub fn crate_name() -> &'static str {
    "endeavour-ir"
}

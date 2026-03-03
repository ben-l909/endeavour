use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicrocodeProgram {
    pub function: FunctionInfo,
    pub maturity: String,
    pub blocks: Vec<BasicBlock>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub name: String,
    pub entry_ea: String,
    pub arch: String,
    pub mba_qty: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: u32,
    pub start_ea: String,
    pub end_ea: String,
    pub preds: Vec<u32>,
    pub succs: Vec<u32>,
    pub instructions: Vec<MicroInstruction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroInstruction {
    pub ea: String,
    pub opcode: Operation,
    pub dst: Option<Var>,
    pub args: Vec<Expr>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Assign,
    Store,
    Jump,
    JumpCond,
    Call,
    Return,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Var {
    pub id: String,
    pub name: String,
    pub width: u16,
    pub storage: VarStorage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VarStorage {
    Register,
    Stack,
    Temp,
    Memory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Const {
    pub value: u64,
    pub width: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Expr {
    Var {
        var: Var,
    },
    Const {
        constant: Const,
    },
    Unary {
        op: UnaryOp,
        arg: Box<Expr>,
    },
    Binary {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    Load {
        addr: Box<Expr>,
        width: u16,
    },
    Slice {
        src: Box<Expr>,
        lo: u8,
        hi: u8,
    },
    Concat {
        hi: Box<Expr>,
        lo: Box<Expr>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnaryOp {
    Not,
    Neg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    LShr,
    AShr,
    Rol,
    Ror,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

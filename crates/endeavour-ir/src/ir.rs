use serde::{Deserialize, Serialize};

/// Identifier for a lifted SSA-like IR value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValueId(pub u32);

/// Bit width used by typed IR expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Width {
    /// One-bit boolean width.
    W1,
    /// Eight-bit width.
    W8,
    /// Sixteen-bit width.
    W16,
    /// Thirty-two-bit width.
    W32,
    /// Sixty-four-bit width.
    W64,
    /// One-hundred-twenty-eight-bit width.
    W128,
}

/// Unary operators over a single expression argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnOp {
    /// Two's complement negation.
    Neg,
    /// Bitwise negation.
    BitNot,
    /// Logical negation.
    LogicalNot,
    /// Zero-extension to a wider width.
    ZeroExtend,
    /// Sign-extension to a wider width.
    SignExtend,
}

/// Binary operators over two expression arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinOp {
    /// Integer addition.
    Add,
    /// Integer subtraction.
    Sub,
    /// Integer multiplication.
    Mul,
    /// Unsigned integer division.
    UDiv,
    /// Signed integer division.
    SDiv,
    /// Unsigned integer modulo.
    UMod,
    /// Signed integer modulo.
    SMod,
    /// Bitwise AND.
    And,
    /// Bitwise OR.
    Or,
    /// Bitwise XOR.
    Xor,
    /// Logical left shift.
    Shl,
    /// Logical right shift.
    LShr,
    /// Arithmetic right shift.
    AShr,
    /// Equality comparison.
    Eq,
    /// Inequality comparison.
    Ne,
    /// Unsigned less-than comparison.
    Ult,
    /// Unsigned less-than-or-equal comparison.
    Ule,
    /// Unsigned greater-than comparison.
    Ugt,
    /// Unsigned greater-than-or-equal comparison.
    Uge,
    /// Signed less-than comparison.
    Slt,
    /// Signed less-than-or-equal comparison.
    Sle,
    /// Signed greater-than comparison.
    Sgt,
    /// Signed greater-than-or-equal comparison.
    Sge,
}

/// Expression node in the Endeavour IR tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Expr {
    /// Constant literal value with explicit width.
    Const {
        /// Constant value payload.
        value: u128,
        /// Bit width of the constant.
        width: Width,
    },
    /// Reference to a previously assigned SSA-like value.
    Value {
        /// Referenced value identifier.
        id: ValueId,
    },
    /// Unary operation.
    Unary {
        /// Unary operator.
        op: UnOp,
        /// Input operand.
        arg: Box<Expr>,
        /// Result width.
        width: Width,
    },
    /// Binary operation.
    Binary {
        /// Binary operator.
        op: BinOp,
        /// Left operand.
        lhs: Box<Expr>,
        /// Right operand.
        rhs: Box<Expr>,
        /// Result width.
        width: Width,
    },
    /// Load from memory at address expression.
    Load {
        /// Address expression.
        addr: Box<Expr>,
        /// Load width.
        width: Width,
    },
    /// Bit slice extraction from a source expression.
    Slice {
        /// Source expression.
        src: Box<Expr>,
        /// Low bit index, inclusive.
        lo: u8,
        /// High bit index, inclusive.
        hi: u8,
    },
    /// Concatenation of high and low expressions.
    Concat {
        /// High-half expression.
        hi: Box<Expr>,
        /// Low-half expression.
        lo: Box<Expr>,
    },
}

/// Statement node in the Endeavour IR program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Stmt {
    /// Assign expression result to a destination value id.
    Assign {
        /// Destination value identifier.
        dst: ValueId,
        /// Assigned expression.
        expr: Expr,
    },
    /// Store a value expression into memory.
    Store {
        /// Destination address expression.
        addr: Expr,
        /// Value expression to store.
        value: Expr,
        /// Store width.
        width: Width,
    },
    /// Conditional branch to one of two basic blocks.
    Branch {
        /// Branch condition expression.
        cond: Expr,
        /// Target basic block id when condition is true.
        then_bb: u32,
        /// Target basic block id when condition is false.
        else_bb: u32,
    },
    /// Unconditional jump to another basic block.
    Jump {
        /// Target basic block id.
        target_bb: u32,
    },
    /// Call statement with optional destination value id.
    Call {
        /// Target expression (direct or indirect).
        target: Expr,
        /// Call argument expressions.
        args: Vec<Expr>,
        /// Optional destination value identifier for return value.
        dst: Option<ValueId>,
    },
    /// Return statement with optional return value expression.
    Return {
        /// Optional returned expression.
        value: Option<Expr>,
    },
    /// SSA phi merge from predecessor blocks.
    Phi {
        /// Destination value identifier.
        dst: ValueId,
        /// Incoming values keyed by predecessor block id.
        inputs: Vec<(u32, ValueId)>,
    },
    /// Unmapped backend statement preserved losslessly.
    Unknown {
        /// Backend opcode name.
        opcode: String,
        /// Raw backend representation.
        raw: String,
    },
}

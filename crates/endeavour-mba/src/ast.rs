use std::fmt;
use std::ops::{Add, Mul, Not, Sub};

/// AST node for a mixed boolean-arithmetic expression.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Expr {
    /// Symbolic variable.
    Var(String),
    /// Integer constant.
    Const(i64),
    /// Bitwise negation.
    Not(Box<Expr>),
    /// Addition.
    Add(Box<Expr>, Box<Expr>),
    /// Subtraction.
    Sub(Box<Expr>, Box<Expr>),
    /// Multiplication.
    Mul(Box<Expr>, Box<Expr>),
    /// Bitwise and.
    And(Box<Expr>, Box<Expr>),
    /// Bitwise or.
    Or(Box<Expr>, Box<Expr>),
    /// Bitwise xor.
    Xor(Box<Expr>, Box<Expr>),
}

#[allow(
    clippy::should_implement_trait,
    reason = "public constructor API names are kept stable for downstream callers"
)]
impl Expr {
    /// Constructs a variable expression.
    pub fn var(name: impl Into<String>) -> Self {
        Self::Var(name.into())
    }

    /// Constructs a constant expression.
    pub fn constant(value: i64) -> Self {
        Self::Const(value)
    }

    /// Constructs a negation expression.
    pub fn not(value: Expr) -> Self {
        Self::Not(Box::new(value))
    }

    /// Constructs an addition expression.
    pub fn add(lhs: Expr, rhs: Expr) -> Self {
        Self::Add(Box::new(lhs), Box::new(rhs))
    }

    /// Constructs a subtraction expression.
    pub fn sub(lhs: Expr, rhs: Expr) -> Self {
        Self::Sub(Box::new(lhs), Box::new(rhs))
    }

    /// Constructs a multiplication expression.
    pub fn mul(lhs: Expr, rhs: Expr) -> Self {
        Self::Mul(Box::new(lhs), Box::new(rhs))
    }

    /// Constructs an and expression.
    pub fn and(lhs: Expr, rhs: Expr) -> Self {
        Self::And(Box::new(lhs), Box::new(rhs))
    }

    /// Constructs an or expression.
    pub fn or(lhs: Expr, rhs: Expr) -> Self {
        Self::Or(Box::new(lhs), Box::new(rhs))
    }

    /// Constructs an xor expression.
    pub fn xor(lhs: Expr, rhs: Expr) -> Self {
        Self::Xor(Box::new(lhs), Box::new(rhs))
    }
}

impl Not for Expr {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self::Not(Box::new(self))
    }
}

impl Add for Expr {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self::Add(Box::new(self), Box::new(rhs))
    }
}

impl Sub for Expr {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::Sub(Box::new(self), Box::new(rhs))
    }
}

impl Mul for Expr {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self::Mul(Box::new(self), Box::new(rhs))
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Var(name) => write!(f, "{name}"),
            Self::Const(value) => write!(f, "{value}"),
            Self::Not(inner) => write!(f, "~({inner})"),
            Self::Add(lhs, rhs) => write!(f, "({lhs}) + ({rhs})"),
            Self::Sub(lhs, rhs) => write!(f, "({lhs}) - ({rhs})"),
            Self::Mul(lhs, rhs) => write!(f, "({lhs}) * ({rhs})"),
            Self::And(lhs, rhs) => write!(f, "({lhs}) & ({rhs})"),
            Self::Or(lhs, rhs) => write!(f, "({lhs}) | ({rhs})"),
            Self::Xor(lhs, rhs) => write!(f, "({lhs}) ^ ({rhs})"),
        }
    }
}

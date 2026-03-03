use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;

use crate::error::IrError;
use crate::ir::{BinOp, Expr, Stmt, UnOp, Width};

/// Backend-agnostic frontend abstraction for lifting function IR.
pub trait IrFrontend {
    /// Returns the frontend's stable display name.
    fn name(&self) -> &str;

    /// Lifts a function at `addr` into normalized statement form.
    fn lift_function(&self, addr: u64) -> Result<Vec<Stmt>, IrError>;
}

/// Runtime registry for frontend implementations with active-selection state.
#[derive(Default)]
pub struct FrontendRegistry {
    frontends: HashMap<String, Arc<dyn IrFrontend>>,
    active_name: Option<String>,
}

impl FrontendRegistry {
    /// Creates an empty frontend registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a frontend under `name`, replacing an existing entry if present.
    ///
    /// The first registered frontend becomes active automatically.
    pub fn register_frontend<S>(&mut self, name: S, frontend: Arc<dyn IrFrontend>)
    where
        S: Into<String>,
    {
        let name = name.into();
        self.frontends.insert(name.clone(), frontend);

        if self.active_name.is_none() {
            self.active_name = Some(name);
        }
    }

    /// Sets the active frontend by its registered name.
    ///
    /// Returns `IrError::BackendUnavailable` when `name` is not registered.
    pub fn set_active_frontend(&mut self, name: &str) -> Result<(), IrError> {
        if self.frontends.contains_key(name) {
            self.active_name = Some(name.to_owned());
            return Ok(());
        }

        Err(IrError::BackendUnavailable)
    }

    /// Returns the currently active frontend name.
    #[must_use]
    pub fn active_frontend_name(&self) -> Option<&str> {
        self.active_name.as_deref()
    }

    /// Returns the currently active frontend implementation.
    #[must_use]
    pub fn active_frontend(&self) -> Option<Arc<dyn IrFrontend>> {
        let name = self.active_name.as_ref()?;
        self.frontends.get(name).cloned()
    }

    /// Returns a registered frontend by name.
    #[must_use]
    pub fn frontend(&self, name: &str) -> Option<Arc<dyn IrFrontend>> {
        self.frontends.get(name).cloned()
    }
}

/// Returns a canonicalized expression suitable for structural equivalence checks.
///
/// The pass is idempotent and recursively normalizes subexpressions. For
/// commutative binary operators (`Add`, `Mul`, `And`, `Or`, `Xor`), operands are
/// sorted using a deterministic structural ordering.
#[must_use]
pub fn normalize_expr(expr: &Expr) -> Expr {
    match expr {
        Expr::Const { value, width } => Expr::Const {
            value: *value,
            width: *width,
        },
        Expr::Value { id } => Expr::Value { id: *id },
        Expr::Unary { op, arg, width } => Expr::Unary {
            op: *op,
            arg: Box::new(normalize_expr(arg)),
            width: *width,
        },
        Expr::Binary {
            op,
            lhs,
            rhs,
            width,
        } => {
            let lhs = normalize_expr(lhs);
            let rhs = normalize_expr(rhs);

            if is_commutative(*op) && compare_expr(&lhs, &rhs) == Ordering::Greater {
                Expr::Binary {
                    op: *op,
                    lhs: Box::new(rhs),
                    rhs: Box::new(lhs),
                    width: *width,
                }
            } else {
                Expr::Binary {
                    op: *op,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                    width: *width,
                }
            }
        }
        Expr::Load { addr, width } => Expr::Load {
            addr: Box::new(normalize_expr(addr)),
            width: *width,
        },
        Expr::Slice { src, lo, hi } => Expr::Slice {
            src: Box::new(normalize_expr(src)),
            lo: *lo,
            hi: *hi,
        },
        Expr::Concat { hi, lo } => Expr::Concat {
            hi: Box::new(normalize_expr(hi)),
            lo: Box::new(normalize_expr(lo)),
        },
    }
}

fn is_commutative(op: BinOp) -> bool {
    matches!(
        op,
        BinOp::Add | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor
    )
}

fn compare_expr(lhs: &Expr, rhs: &Expr) -> Ordering {
    let lhs_tag = expr_tag(lhs);
    let rhs_tag = expr_tag(rhs);
    let tag_ord = lhs_tag.cmp(&rhs_tag);
    if tag_ord != Ordering::Equal {
        return tag_ord;
    }

    match (lhs, rhs) {
        (
            Expr::Const {
                value: lhs_value,
                width: lhs_width,
            },
            Expr::Const {
                value: rhs_value,
                width: rhs_width,
            },
        ) => width_rank(*lhs_width)
            .cmp(&width_rank(*rhs_width))
            .then_with(|| lhs_value.cmp(rhs_value)),
        (Expr::Value { id: lhs_id }, Expr::Value { id: rhs_id }) => lhs_id.0.cmp(&rhs_id.0),
        (
            Expr::Unary {
                op: lhs_op,
                arg: lhs_arg,
                width: lhs_width,
            },
            Expr::Unary {
                op: rhs_op,
                arg: rhs_arg,
                width: rhs_width,
            },
        ) => unop_rank(*lhs_op)
            .cmp(&unop_rank(*rhs_op))
            .then_with(|| width_rank(*lhs_width).cmp(&width_rank(*rhs_width)))
            .then_with(|| compare_expr(lhs_arg, rhs_arg)),
        (
            Expr::Binary {
                op: lhs_op,
                lhs: lhs_lhs,
                rhs: lhs_rhs,
                width: lhs_width,
            },
            Expr::Binary {
                op: rhs_op,
                lhs: rhs_lhs,
                rhs: rhs_rhs,
                width: rhs_width,
            },
        ) => binop_rank(*lhs_op)
            .cmp(&binop_rank(*rhs_op))
            .then_with(|| width_rank(*lhs_width).cmp(&width_rank(*rhs_width)))
            .then_with(|| compare_expr(lhs_lhs, rhs_lhs))
            .then_with(|| compare_expr(lhs_rhs, rhs_rhs)),
        (
            Expr::Load {
                addr: lhs_addr,
                width: lhs_width,
            },
            Expr::Load {
                addr: rhs_addr,
                width: rhs_width,
            },
        ) => width_rank(*lhs_width)
            .cmp(&width_rank(*rhs_width))
            .then_with(|| compare_expr(lhs_addr, rhs_addr)),
        (
            Expr::Slice {
                src: lhs_src,
                lo: lhs_lo,
                hi: lhs_hi,
            },
            Expr::Slice {
                src: rhs_src,
                lo: rhs_lo,
                hi: rhs_hi,
            },
        ) => lhs_lo
            .cmp(rhs_lo)
            .then_with(|| lhs_hi.cmp(rhs_hi))
            .then_with(|| compare_expr(lhs_src, rhs_src)),
        (
            Expr::Concat {
                hi: lhs_hi,
                lo: lhs_lo,
            },
            Expr::Concat {
                hi: rhs_hi,
                lo: rhs_lo,
            },
        ) => compare_expr(lhs_hi, rhs_hi).then_with(|| compare_expr(lhs_lo, rhs_lo)),
        _ => Ordering::Equal,
    }
}

fn expr_tag(expr: &Expr) -> u8 {
    match expr {
        Expr::Const { .. } => 0,
        Expr::Value { .. } => 1,
        Expr::Unary { .. } => 2,
        Expr::Binary { .. } => 3,
        Expr::Load { .. } => 4,
        Expr::Slice { .. } => 5,
        Expr::Concat { .. } => 6,
    }
}

fn width_rank(width: Width) -> u8 {
    match width {
        Width::W1 => 0,
        Width::W8 => 1,
        Width::W16 => 2,
        Width::W32 => 3,
        Width::W64 => 4,
        Width::W128 => 5,
    }
}

fn unop_rank(op: UnOp) -> u8 {
    match op {
        UnOp::Neg => 0,
        UnOp::BitNot => 1,
        UnOp::LogicalNot => 2,
        UnOp::ZeroExtend => 3,
        UnOp::SignExtend => 4,
    }
}

fn binop_rank(op: BinOp) -> u8 {
    match op {
        BinOp::Add => 0,
        BinOp::Sub => 1,
        BinOp::Mul => 2,
        BinOp::UDiv => 3,
        BinOp::SDiv => 4,
        BinOp::UMod => 5,
        BinOp::SMod => 6,
        BinOp::And => 7,
        BinOp::Or => 8,
        BinOp::Xor => 9,
        BinOp::Shl => 10,
        BinOp::LShr => 11,
        BinOp::AShr => 12,
        BinOp::Eq => 13,
        BinOp::Ne => 14,
        BinOp::Ult => 15,
        BinOp::Ule => 16,
        BinOp::Ugt => 17,
        BinOp::Uge => 18,
        BinOp::Slt => 19,
        BinOp::Sle => 20,
        BinOp::Sgt => 21,
        BinOp::Sge => 22,
    }
}

#[cfg(test)]
mod tests {
    use super::{normalize_expr, FrontendRegistry, IrFrontend};
    use crate::error::IrError;
    use crate::ir::{BinOp, Expr, Stmt, ValueId, Width};
    use std::sync::Arc;

    struct MockFrontend {
        name: &'static str,
    }

    impl IrFrontend for MockFrontend {
        fn name(&self) -> &str {
            self.name
        }

        fn lift_function(&self, _addr: u64) -> Result<Vec<Stmt>, IrError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn normalizes_commutative_add_to_same_form() {
        let x = Expr::Value { id: ValueId(1) };
        let y = Expr::Value { id: ValueId(2) };

        let left = Expr::Binary {
            op: BinOp::Add,
            lhs: Box::new(x.clone()),
            rhs: Box::new(y.clone()),
            width: Width::W64,
        };

        let right = Expr::Binary {
            op: BinOp::Add,
            lhs: Box::new(y),
            rhs: Box::new(x),
            width: Width::W64,
        };

        assert_eq!(normalize_expr(&left), normalize_expr(&right));
    }

    #[test]
    fn normalization_is_idempotent() {
        let expr = Expr::Binary {
            op: BinOp::Xor,
            lhs: Box::new(Expr::Value { id: ValueId(7) }),
            rhs: Box::new(Expr::Value { id: ValueId(3) }),
            width: Width::W32,
        };

        let once = normalize_expr(&expr);
        let twice = normalize_expr(&once);

        assert_eq!(once, twice);
    }

    #[test]
    fn registry_tracks_active_frontend_name() {
        let ida = Arc::new(MockFrontend { name: "ida" });
        let capstone = Arc::new(MockFrontend { name: "capstone" });

        let mut registry = FrontendRegistry::new();
        registry.register_frontend("ida", ida);
        registry.register_frontend("capstone", capstone);

        assert_eq!(registry.active_frontend_name(), Some("ida"));

        assert!(registry.set_active_frontend("capstone").is_ok());
        assert_eq!(registry.active_frontend_name(), Some("capstone"));
    }

    #[test]
    fn setting_unknown_frontend_returns_error() {
        let mut registry = FrontendRegistry::new();
        let err = registry.set_active_frontend("missing");
        assert!(matches!(err, Err(IrError::BackendUnavailable)));
    }
}

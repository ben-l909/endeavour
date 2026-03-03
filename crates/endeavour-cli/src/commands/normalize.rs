use endeavour_ir::{normalize_expr, BinOp, Expr, FrontendRegistry, IrError, Stmt, UnOp, Width};

/// Result payload produced by the `normalize` command renderer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizeRender {
    /// Message-history lines for normalized IR output.
    pub(crate) lines: Vec<String>,
    /// Number of expressions that changed after normalization.
    pub(crate) normalized_count: usize,
    /// Active frontend name used for this normalization.
    pub(crate) active_frontend: Option<String>,
}

/// Errors emitted by the `normalize` command flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NormalizeCommandError {
    /// Input address is malformed.
    InvalidAddress,
    /// Active IR backend is unavailable.
    BackendUnavailable,
    /// Lift execution failed with a backend-specific message.
    LiftFailed(String),
}

impl NormalizeCommandError {
    /// Converts this error into user-facing multi-line display text.
    pub(crate) fn render(&self) -> String {
        match self {
            Self::InvalidAddress => {
                "✗ error: invalid address\n    ╰─ Use a hex address like 'normalize 0x100004a20'."
                    .to_string()
            }
            Self::BackendUnavailable => {
                "✗ error: IR backend unavailable\n    ╰─ Connect to IDA first with 'connect <host:port>'."
                    .to_string()
            }
            Self::LiftFailed(message) => {
                format!("✗ error: failed to lift IR\n    ╰─ {message}")
            }
        }
    }
}

/// Lifts IR for `raw_address`, canonicalizes expressions, and prepares rendered output.
pub(crate) fn handle_normalize(
    registry: &FrontendRegistry,
    raw_address: &str,
) -> Result<NormalizeRender, NormalizeCommandError> {
    let address = parse_hex_address(raw_address)?;
    let frontend = registry
        .active_frontend()
        .ok_or(NormalizeCommandError::BackendUnavailable)?;

    let statements = frontend
        .lift_function(address)
        .map_err(map_ir_error_to_normalize_error)?;

    let active_frontend = registry.active_frontend_name().map(ToString::to_string);
    let mut normalized_count = 0usize;
    let mut lines = Vec::new();
    lines.push(format!("Normalized IR ({} statements):", statements.len()));

    for stmt in &statements {
        let (normalized_stmt, changed) = normalize_stmt(stmt);
        normalized_count += changed;
        lines.push(format!("  [bb0]  {}", render_stmt(&normalized_stmt)));
    }

    Ok(NormalizeRender {
        lines,
        normalized_count,
        active_frontend,
    })
}

fn parse_hex_address(raw: &str) -> Result<u64, NormalizeCommandError> {
    let trimmed = raw.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .ok_or(NormalizeCommandError::InvalidAddress)?;

    u64::from_str_radix(hex, 16).map_err(|_| NormalizeCommandError::InvalidAddress)
}

fn map_ir_error_to_normalize_error(error: IrError) -> NormalizeCommandError {
    match error {
        IrError::BackendUnavailable => NormalizeCommandError::BackendUnavailable,
        other => NormalizeCommandError::LiftFailed(other.to_string()),
    }
}

fn normalize_stmt(stmt: &Stmt) -> (Stmt, usize) {
    match stmt {
        Stmt::Assign { dst, expr } => {
            let (expr, changed) = normalize_tracked(expr);
            (Stmt::Assign { dst: *dst, expr }, changed)
        }
        Stmt::Store { addr, value, width } => {
            let (addr, changed_addr) = normalize_tracked(addr);
            let (value, changed_value) = normalize_tracked(value);
            (
                Stmt::Store {
                    addr,
                    value,
                    width: *width,
                },
                changed_addr + changed_value,
            )
        }
        Stmt::Branch {
            cond,
            then_bb,
            else_bb,
        } => {
            let (cond, changed) = normalize_tracked(cond);
            (
                Stmt::Branch {
                    cond,
                    then_bb: *then_bb,
                    else_bb: *else_bb,
                },
                changed,
            )
        }
        Stmt::Jump { target_bb } => (
            Stmt::Jump {
                target_bb: *target_bb,
            },
            0,
        ),
        Stmt::Call { target, args, dst } => {
            let (target, changed_target) = normalize_tracked(target);
            let mut changed_args = 0usize;
            let args = args
                .iter()
                .map(|arg| {
                    let (normalized, changed) = normalize_tracked(arg);
                    changed_args += changed;
                    normalized
                })
                .collect::<Vec<_>>();
            (
                Stmt::Call {
                    target,
                    args,
                    dst: *dst,
                },
                changed_target + changed_args,
            )
        }
        Stmt::Return { value } => {
            if let Some(expr) = value {
                let (normalized, changed) = normalize_tracked(expr);
                (
                    Stmt::Return {
                        value: Some(normalized),
                    },
                    changed,
                )
            } else {
                (Stmt::Return { value: None }, 0)
            }
        }
        Stmt::Phi { dst, inputs } => (
            Stmt::Phi {
                dst: *dst,
                inputs: inputs.clone(),
            },
            0,
        ),
        Stmt::Unknown {
            opcode,
            dst,
            args,
            note,
        } => {
            let mut changed_args = 0usize;
            let args = args
                .iter()
                .map(|arg| {
                    let (normalized, changed) = normalize_tracked(arg);
                    changed_args += changed;
                    normalized
                })
                .collect::<Vec<_>>();
            (
                Stmt::Unknown {
                    opcode: opcode.clone(),
                    dst: *dst,
                    args,
                    note: note.clone(),
                },
                changed_args,
            )
        }
    }
}

fn normalize_tracked(expr: &Expr) -> (Expr, usize) {
    let normalized = normalize_expr(expr);
    let changed = usize::from(normalized != *expr);
    (normalized, changed)
}

fn render_stmt(stmt: &Stmt) -> String {
    match stmt {
        Stmt::Assign { dst, expr } => format!("{} = {}", render_value_id(*dst), render_expr(expr)),
        Stmt::Store { addr, value, width } => format!(
            "store({}, {}, {})",
            render_expr(addr),
            render_expr(value),
            render_width(*width)
        ),
        Stmt::Branch {
            cond,
            then_bb,
            else_bb,
        } => format!(
            "branch {} -> bb{}, bb{}",
            render_expr(cond),
            then_bb,
            else_bb
        ),
        Stmt::Jump { target_bb } => format!("jump -> bb{target_bb}"),
        Stmt::Call { target, args, dst } => {
            let rendered_args = args.iter().map(render_expr).collect::<Vec<_>>().join(", ");
            let call_body = format!("call({}, {rendered_args})", render_expr(target));
            if let Some(dst) = dst {
                format!("{} = {call_body}", render_value_id(*dst))
            } else {
                call_body
            }
        }
        Stmt::Return { value } => value.as_ref().map_or_else(
            || "return".to_string(),
            |expr| format!("return {}", render_expr(expr)),
        ),
        Stmt::Phi { dst, inputs } => {
            let rendered = inputs
                .iter()
                .map(|(bb, value)| format!("bb{bb}: {}", render_value_id(*value)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} = phi({rendered})", render_value_id(*dst))
        }
        Stmt::Unknown {
            opcode, dst, args, ..
        } => {
            let rendered_args = args.iter().map(render_expr).collect::<Vec<_>>().join(", ");
            let body = format!("unknown[{opcode}]({rendered_args})");
            if let Some(dst) = dst {
                format!("{} = {body}", render_value_id(*dst))
            } else {
                body
            }
        }
    }
}

fn render_expr(expr: &Expr) -> String {
    match expr {
        Expr::Const { value, width } => format!("0x{value:x}:{}", render_width(*width)),
        Expr::Value { id } => render_value_id(*id),
        Expr::Unary { op, arg, .. } => match op {
            UnOp::Neg => format!("-({})", render_expr(arg)),
            UnOp::BitNot => format!("~({})", render_expr(arg)),
            UnOp::LogicalNot => format!("!({})", render_expr(arg)),
            UnOp::ZeroExtend => format!("zext({})", render_expr(arg)),
            UnOp::SignExtend => format!("sext({})", render_expr(arg)),
        },
        Expr::Binary { op, lhs, rhs, .. } => {
            format!(
                "{} {} {}",
                render_expr(lhs),
                render_binop(*op),
                render_expr(rhs)
            )
        }
        Expr::Load { addr, width } => {
            format!("load({}, {})", render_expr(addr), render_width(*width))
        }
        Expr::Slice { src, lo, hi } => format!("{}[{lo}:{hi}]", render_expr(src)),
        Expr::Concat { hi, lo } => format!("concat({}, {})", render_expr(hi), render_expr(lo)),
    }
}

fn render_binop(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::UDiv => "udiv",
        BinOp::SDiv => "/",
        BinOp::UMod => "umod",
        BinOp::SMod => "%",
        BinOp::And => "&",
        BinOp::Or => "|",
        BinOp::Xor => "^",
        BinOp::Shl => "<<",
        BinOp::LShr => ">>",
        BinOp::AShr => "a>>",
        BinOp::Eq => "==",
        BinOp::Ne => "!=",
        BinOp::Ult => "u<",
        BinOp::Ule => "u<=",
        BinOp::Ugt => "u>",
        BinOp::Uge => "u>=",
        BinOp::Slt => "<",
        BinOp::Sle => "<=",
        BinOp::Sgt => ">",
        BinOp::Sge => ">=",
    }
}

fn render_width(width: Width) -> &'static str {
    match width {
        Width::W1 => "w1",
        Width::W8 => "w8",
        Width::W16 => "w16",
        Width::W32 => "w32",
        Width::W64 => "w64",
        Width::W128 => "w128",
    }
}

fn render_value_id(id: endeavour_ir::ValueId) -> String {
    format!("v{}", id.0)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use endeavour_ir::{BinOp, Expr, FrontendRegistry, IrError, IrFrontend, Stmt, ValueId, Width};

    use super::{handle_normalize, NormalizeCommandError};

    struct MockFrontend {
        name: &'static str,
        statements: Vec<Stmt>,
        fail: bool,
    }

    impl IrFrontend for MockFrontend {
        fn name(&self) -> &str {
            self.name
        }

        fn lift_function(&self, _addr: u64) -> Result<Vec<Stmt>, IrError> {
            if self.fail {
                return Err(IrError::BackendUnavailable);
            }
            Ok(self.statements.clone())
        }
    }

    #[test]
    fn counts_only_changed_expressions() {
        let mut registry = FrontendRegistry::new();
        registry.register_frontend(
            "ida",
            Arc::new(MockFrontend {
                name: "ida",
                statements: vec![
                    Stmt::Assign {
                        dst: ValueId(1),
                        expr: Expr::Binary {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Value { id: ValueId(2) }),
                            rhs: Box::new(Expr::Value { id: ValueId(1) }),
                            width: Width::W64,
                        },
                    },
                    Stmt::Assign {
                        dst: ValueId(2),
                        expr: Expr::Binary {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Value { id: ValueId(1) }),
                            rhs: Box::new(Expr::Value { id: ValueId(3) }),
                            width: Width::W64,
                        },
                    },
                ],
                fail: false,
            }),
        );

        let render = match handle_normalize(&registry, "0x100004a20") {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error:?}"),
        };
        assert_eq!(render.active_frontend.as_deref(), Some("ida"));
        assert_eq!(render.normalized_count, 1);
        assert_eq!(render.lines[0], "Normalized IR (2 statements):");
        assert_eq!(render.lines[1], "  [bb0]  v1 = v1 + v2");
        assert_eq!(render.lines[2], "  [bb0]  v2 = v1 + v3");
    }

    #[test]
    fn renders_backend_unavailable_message() {
        let registry = FrontendRegistry::new();
        let error = match handle_normalize(&registry, "0x100004a20") {
            Ok(_) => panic!("expected backend unavailable error"),
            Err(err) => err,
        };
        assert_eq!(error, NormalizeCommandError::BackendUnavailable);
        assert_eq!(
            error.render(),
            "✗ error: IR backend unavailable\n    ╰─ Connect to IDA first with 'connect <host:port>'."
        );
    }

    #[test]
    fn rejects_non_hex_address_input() {
        let registry = FrontendRegistry::new();
        let error = match handle_normalize(&registry, "100004a20") {
            Ok(_) => panic!("expected invalid address error"),
            Err(err) => err,
        };
        assert_eq!(error, NormalizeCommandError::InvalidAddress);
    }
}

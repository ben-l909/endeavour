use endeavour_ir::{BinOp, Expr, FrontendRegistry, IrError, Stmt, UnOp, Width};

const PREVIEW_STATEMENT_LIMIT: usize = 20;

/// Result payload produced by the `lift` command renderer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiftRender {
    /// Message-history lines for the IR preview body.
    pub(crate) preview_lines: Vec<String>,
    /// Optional truncation payload for expandable `show_ir` entries.
    pub(crate) truncation: Option<LiftTruncation>,
    /// Active frontend name used for this lift.
    pub(crate) active_frontend: Option<String>,
}

/// Expandable truncation payload for IR output beyond preview threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiftTruncation {
    /// Tool name used by the TUI expandable footer entry.
    pub(crate) tool_name: String,
    /// Tool argument payload (address string).
    pub(crate) tool_args: String,
    /// One-line truncated preview text.
    pub(crate) preview: String,
    /// Full remaining statement text, line-delimited.
    pub(crate) full_result: String,
}

/// Errors emitted by the `lift` command flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LiftCommandError {
    /// Input address is malformed.
    InvalidAddress,
    /// Active IR backend is unavailable.
    BackendUnavailable,
    /// Lift execution failed with a backend-specific message.
    LiftFailed(String),
}

impl LiftCommandError {
    /// Converts this error into user-facing multi-line display text.
    pub(crate) fn render(&self) -> String {
        match self {
            Self::InvalidAddress => "✗ error: invalid address\n    ╰─ Use a hex address like 'lift 0x100004a20'.".to_string(),
            Self::BackendUnavailable => {
                "✗ error: IR backend unavailable\n    ╰─ Connect to IDA first with 'connect <host:port>'."
                    .to_string()
            }
            Self::LiftFailed(message) => format!("✗ error: failed to lift IR\n    ╰─ {message}"),
        }
    }
}

/// Lifts IR for `raw_address` through the active frontend and prepares TUI preview output.
pub(crate) fn handle_lift(
    registry: &FrontendRegistry,
    raw_address: &str,
) -> Result<LiftRender, LiftCommandError> {
    let address = parse_hex_address(raw_address)?;
    let frontend = registry
        .active_frontend()
        .ok_or(LiftCommandError::BackendUnavailable)?;

    let statements = frontend
        .lift_function(address)
        .map_err(map_ir_error_to_lift_error)?;

    let active_frontend = registry.active_frontend_name().map(ToString::to_string);
    let mut preview_lines = Vec::new();

    let total = statements.len();
    if total > PREVIEW_STATEMENT_LIMIT {
        preview_lines.push(format!(
            "IR preview (showing {} of {total} statements):",
            PREVIEW_STATEMENT_LIMIT
        ));
    } else {
        preview_lines.push(format!("IR preview ({total} statements):"));
    }

    for stmt in statements.iter().take(PREVIEW_STATEMENT_LIMIT) {
        preview_lines.push(format!("  [bb0]  {}", render_stmt(stmt)));
    }

    let truncation = if total > PREVIEW_STATEMENT_LIMIT {
        let remaining = total - PREVIEW_STATEMENT_LIMIT;
        preview_lines.push(String::new());

        let full_result = statements
            .iter()
            .skip(PREVIEW_STATEMENT_LIMIT)
            .map(|stmt| format!("  [bb0]  {}", render_stmt(stmt)))
            .collect::<Vec<_>>()
            .join("\n");

        Some(LiftTruncation {
            tool_name: "show_ir".to_string(),
            tool_args: format!("0x{address:x}"),
            preview: format!("{remaining} more statements"),
            full_result,
        })
    } else {
        None
    };

    Ok(LiftRender {
        preview_lines,
        truncation,
        active_frontend,
    })
}

fn parse_hex_address(raw: &str) -> Result<u64, LiftCommandError> {
    let trimmed = raw.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .ok_or(LiftCommandError::InvalidAddress)?;

    u64::from_str_radix(hex, 16).map_err(|_| LiftCommandError::InvalidAddress)
}

fn map_ir_error_to_lift_error(error: IrError) -> LiftCommandError {
    match error {
        IrError::BackendUnavailable => LiftCommandError::BackendUnavailable,
        other => LiftCommandError::LiftFailed(other.to_string()),
    }
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

    use endeavour_ir::{FrontendRegistry, IrError, IrFrontend, Stmt, ValueId, Width};

    use super::{handle_lift, LiftCommandError};

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
    fn renders_ir_preview_without_truncation() {
        let mut registry = FrontendRegistry::new();
        registry.register_frontend(
            "ida",
            Arc::new(MockFrontend {
                name: "ida",
                statements: vec![Stmt::Assign {
                    dst: ValueId(2),
                    expr: endeavour_ir::Expr::Const {
                        value: 16,
                        width: Width::W64,
                    },
                }],
                fail: false,
            }),
        );

        let render = match handle_lift(&registry, "0x100004a20") {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error:?}"),
        };
        assert_eq!(render.active_frontend.as_deref(), Some("ida"));
        assert_eq!(render.preview_lines[0], "IR preview (1 statements):");
        assert_eq!(render.preview_lines[1], "  [bb0]  v2 = 0x10:w64");
        assert!(render.truncation.is_none());
    }

    #[test]
    fn renders_backend_unavailable_message() {
        let registry = FrontendRegistry::new();
        let error = match handle_lift(&registry, "0x100004a20") {
            Ok(_) => panic!("expected backend unavailable error"),
            Err(err) => err,
        };
        assert_eq!(error, LiftCommandError::BackendUnavailable);
        assert_eq!(
            error.render(),
            "✗ error: IR backend unavailable\n    ╰─ Connect to IDA first with 'connect <host:port>'."
        );
    }

    #[test]
    fn creates_expandable_truncation_payload() {
        let mut registry = FrontendRegistry::new();
        let mut statements = Vec::new();
        for idx in 0..25 {
            statements.push(Stmt::Assign {
                dst: ValueId(idx),
                expr: endeavour_ir::Expr::Const {
                    value: idx as u128,
                    width: Width::W64,
                },
            });
        }

        registry.register_frontend(
            "ida",
            Arc::new(MockFrontend {
                name: "ida",
                statements,
                fail: false,
            }),
        );

        let render = match handle_lift(&registry, "0x100004a20") {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error:?}"),
        };

        assert_eq!(
            render.preview_lines[0],
            "IR preview (showing 20 of 25 statements):"
        );
        assert_eq!(render.preview_lines.len(), 22);

        let truncation = match render.truncation {
            Some(value) => value,
            None => panic!("expected truncation payload"),
        };
        assert_eq!(truncation.tool_name, "show_ir");
        assert_eq!(truncation.tool_args, "0x100004a20");
        assert_eq!(truncation.preview, "5 more statements");
        assert!(truncation.full_result.contains("v24 = 0x18:w64"));
    }
}

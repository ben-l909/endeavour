use std::sync::Arc;

use anyhow::{Context, Result};
use endeavour_ida::IdaClient;
use endeavour_ir::error::IrError;
use endeavour_ir::ir::{BinOp, Expr, Stmt, UnOp, ValueId, Width};
use endeavour_ir::{FrontendRegistry, IrFrontend};
use endeavour_mba::{MbaMatch, MbaMatcher};
#[cfg(feature = "z3-verifier")]
use endeavour_mba::{VerifierResult, Z3Verifier};
use serde::Deserialize;
use serde_json::Value;

use crate::fmt;
use crate::repl::Repl;

/// Runs the lift -> scan -> verify MBA detection pipeline for a function target.
pub(crate) fn handle_detect_mba(repl: &Repl, target: &str) -> Result<()> {
    let Some(client) = repl.ida_client.as_ref() else {
        println!("Not connected. Run: connect <host:port>");
        return Ok(());
    };

    let (address, function_name) = resolve_target_address(repl, target)?;

    let frontend = Arc::new(IdaRegistryFrontend::new(
        repl.runtime.handle().clone(),
        Arc::clone(client),
    ));
    let mut registry = FrontendRegistry::new();
    registry.register_frontend("ida", frontend);

    let active_frontend = registry
        .active_frontend()
        .context("no active frontend available")?;
    let stmts = active_frontend
        .lift_function(address)
        .with_context(|| format!("failed to lift function at {}", fmt::format_addr(address)))?;

    let matcher = MbaMatcher::new();
    let mut matches = matcher.scan(&stmts);
    verify_matches(&mut matches);

    render_detect_mba_output(&function_name, address, &matches);
    Ok(())
}

fn resolve_target_address(repl: &Repl, target: &str) -> Result<(u64, String)> {
    let Some(client) = repl.ida_client.as_ref() else {
        return Err(anyhow::anyhow!("IDA client is not connected"));
    };

    if let Some(address) = parse_detect_target(target) {
        let query = fmt::format_addr(address);
        let name = repl
            .runtime
            .block_on(client.lookup_function(&query))
            .ok()
            .and_then(|function| function.map(|item| item.name))
            .unwrap_or_else(|| format!("sub_{address:x}"));
        return Ok((address, name));
    }

    let function = repl
        .runtime
        .block_on(client.lookup_function(target))
        .with_context(|| format!("failed to resolve function '{target}'"))?
        .with_context(|| format!("function '{target}' not found"))?;
    Ok((function.address, function.name))
}

fn parse_detect_target(raw: &str) -> Option<u64> {
    let input = raw.trim();
    if let Some(hex) = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }

    if let Ok(value) = input.parse::<u64>() {
        return Some(value);
    }

    if let Some(suffix) = input.strip_prefix("sub_") {
        return u64::from_str_radix(suffix, 16).ok();
    }

    None
}

#[cfg(feature = "z3-verifier")]
fn verify_matches(matches: &mut [MbaMatch]) {
    let verifier = Z3Verifier::default();
    for detected in matches {
        let width = infer_expr_width(&detected.original);
        detected.verified = matches!(
            verifier.prove_equivalent(&detected.original, &detected.simplified, width),
            VerifierResult::Equivalent
        );
    }
}

#[cfg(not(feature = "z3-verifier"))]
fn verify_matches(_matches: &mut [MbaMatch]) {}

#[cfg(feature = "z3-verifier")]
fn infer_expr_width(expr: &Expr) -> Width {
    match expr {
        Expr::Const { width, .. }
        | Expr::Unary { width, .. }
        | Expr::Binary { width, .. }
        | Expr::Load { width, .. } => *width,
        Expr::Slice { lo, hi, .. } => {
            let bit_count = u16::from(*hi)
                .saturating_sub(u16::from(*lo))
                .saturating_add(1);
            width_from_bits(bit_count)
        }
        Expr::Concat { hi, lo } => {
            let bits =
                width_bits(infer_expr_width(hi)).saturating_add(width_bits(infer_expr_width(lo)));
            width_from_bits(bits)
        }
        Expr::Value { .. } => Width::W64,
    }
}

fn render_detect_mba_output(function_name: &str, address: u64, matches: &[MbaMatch]) {
    let location = format!("{} ({})", function_name, fmt::format_addr(address));

    if matches.is_empty() {
        println!("No MBA expressions detected in {location}.");
        return;
    }

    println!("Found {} MBA expression(s) in {location}.", matches.len());

    for (index, detected) in matches.iter().enumerate() {
        let badge = if detected.verified {
            "[verified]"
        } else {
            "[candidate]"
        };

        println!(
            "  ● Match {} — bb0, stmt {} {}",
            index + 1,
            detected.stmt_index,
            badge
        );
        println!("  ●   Original:    {}", render_expr(&detected.original));
        println!("  ●   Simplified:  {}", render_expr(&detected.simplified));

        if index + 1 != matches.len() {
            println!("  ●");
        }
    }

    println!("  ● Simplifications are display-only and have not been applied to the binary.");
}

fn render_expr(expr: &Expr) -> String {
    render_expr_with_context(expr, false)
}

fn render_expr_with_context(expr: &Expr, nested: bool) -> String {
    match expr {
        Expr::Const { value, width } => format!("0x{value:x}:{}", width_label(*width)),
        Expr::Value { id } => format!("v{}", id.0),
        Expr::Unary { op, arg, .. } => {
            let inner = render_expr_with_context(arg, true);
            match op {
                UnOp::Neg => format!("-({inner})"),
                UnOp::BitNot => format!("~({inner})"),
                UnOp::LogicalNot => format!("!({inner})"),
                UnOp::ZeroExtend => format!("zext({inner})"),
                UnOp::SignExtend => format!("sext({inner})"),
            }
        }
        Expr::Binary { op, lhs, rhs, .. } => {
            let lhs_rendered = render_expr_with_context(lhs, true);
            let rhs_rendered = render_expr_with_context(rhs, true);
            let rendered = format!("{lhs_rendered} {} {rhs_rendered}", binary_operator(*op));
            if nested {
                format!("({rendered})")
            } else {
                rendered
            }
        }
        Expr::Load { addr, width } => {
            format!(
                "load({}, {})",
                render_expr_with_context(addr, false),
                width_label(*width)
            )
        }
        Expr::Slice { src, lo, hi } => {
            format!(
                "slice({}, {lo}, {hi})",
                render_expr_with_context(src, false)
            )
        }
        Expr::Concat { hi, lo } => {
            format!(
                "concat({}, {})",
                render_expr_with_context(hi, false),
                render_expr_with_context(lo, false)
            )
        }
    }
}

fn binary_operator(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::UDiv => "/",
        BinOp::SDiv => "/s",
        BinOp::UMod => "%",
        BinOp::SMod => "%s",
        BinOp::And => "&",
        BinOp::Or => "|",
        BinOp::Xor => "^",
        BinOp::Shl => "<<",
        BinOp::LShr => ">>",
        BinOp::AShr => ">>s",
        BinOp::Eq => "==",
        BinOp::Ne => "!=",
        BinOp::Ult => "<u",
        BinOp::Ule => "<=u",
        BinOp::Ugt => ">u",
        BinOp::Uge => ">=u",
        BinOp::Slt => "<s",
        BinOp::Sle => "<=s",
        BinOp::Sgt => ">s",
        BinOp::Sge => ">=s",
    }
}

fn width_label(width: Width) -> &'static str {
    match width {
        Width::W1 => "w1",
        Width::W8 => "w8",
        Width::W16 => "w16",
        Width::W32 => "w32",
        Width::W64 => "w64",
        Width::W128 => "w128",
    }
}

#[cfg(feature = "z3-verifier")]
fn width_bits(width: Width) -> u16 {
    match width {
        Width::W1 => 1,
        Width::W8 => 8,
        Width::W16 => 16,
        Width::W32 => 32,
        Width::W64 => 64,
        Width::W128 => 128,
    }
}

struct IdaRegistryFrontend {
    runtime: tokio::runtime::Handle,
    client: Arc<IdaClient>,
}

impl IdaRegistryFrontend {
    fn new(runtime: tokio::runtime::Handle, client: Arc<IdaClient>) -> Self {
        Self { runtime, client }
    }
}

impl IrFrontend for IdaRegistryFrontend {
    fn name(&self) -> &str {
        "ida"
    }

    fn lift_function(&self, addr: u64) -> std::result::Result<Vec<Stmt>, IrError> {
        let script = build_microcode_script(addr);
        let response = self
            .runtime
            .block_on(self.client.py_eval(&script))
            .map_err(|_| IrError::BackendUnavailable)?;
        let payload = normalize_payload(response)?;

        if payload.backend_unavailable {
            return Err(IrError::BackendUnavailable);
        }

        Ok(payload
            .instructions
            .into_iter()
            .map(map_instruction)
            .collect())
    }
}

#[derive(Debug, Deserialize)]
struct LiftPayload {
    #[serde(default)]
    backend_unavailable: bool,
    #[serde(default)]
    instructions: Vec<RawInstruction>,
}

#[derive(Debug, Deserialize)]
struct RawInstruction {
    opcode: String,
    #[serde(default)]
    dst: Option<u32>,
    #[serde(default)]
    args: Vec<RawArg>,
    width: Option<u16>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RawArg {
    Const { value: u128, width: Option<u16> },
    Value { id: u32 },
}

fn normalize_payload(value: Value) -> std::result::Result<LiftPayload, IrError> {
    if let Ok(payload) = serde_json::from_value::<LiftPayload>(value.clone()) {
        return Ok(payload);
    }

    if let Some(result) = value.get("result") {
        if let Ok(payload) = serde_json::from_value::<LiftPayload>(result.clone()) {
            return Ok(payload);
        }
    }

    if let Some(stdout) = value.get("stdout").and_then(Value::as_str) {
        if let Ok(payload) = serde_json::from_str::<LiftPayload>(stdout) {
            return Ok(payload);
        }
    }

    Ok(LiftPayload {
        backend_unavailable: false,
        instructions: Vec::new(),
    })
}

fn map_instruction(raw: RawInstruction) -> Stmt {
    let width = raw.width.map(width_from_bits).unwrap_or(Width::W64);
    let lowered_args = raw.args.into_iter().map(lower_arg).collect::<Vec<_>>();

    if let Some(un_op) = map_unary_opcode(&raw.opcode) {
        if let (Some(dst), Some(arg)) = (raw.dst, lowered_args.first().cloned()) {
            return Stmt::Assign {
                dst: ValueId(dst),
                expr: Expr::Unary {
                    op: un_op,
                    arg: Box::new(arg),
                    width,
                },
            };
        }
    }

    if let Some(bin_op) = map_binary_opcode(&raw.opcode) {
        if let (Some(dst), Some(lhs), Some(rhs)) = (
            raw.dst,
            lowered_args.first().cloned(),
            lowered_args.get(1).cloned(),
        ) {
            return Stmt::Assign {
                dst: ValueId(dst),
                expr: Expr::Binary {
                    op: bin_op,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                    width,
                },
            };
        }
    }

    Stmt::Unknown {
        opcode: raw.opcode,
        dst: raw.dst.map(ValueId),
        args: lowered_args,
        note: None,
    }
}

fn lower_arg(arg: RawArg) -> Expr {
    match arg {
        RawArg::Const { value, width } => Expr::Const {
            value,
            width: width.map(width_from_bits).unwrap_or(Width::W64),
        },
        RawArg::Value { id } => Expr::Value { id: ValueId(id) },
    }
}

fn map_unary_opcode(opcode: &str) -> Option<UnOp> {
    match opcode.trim().to_ascii_lowercase().as_str() {
        "m_neg" | "neg" => Some(UnOp::Neg),
        "m_bnot" | "m_not" | "not" => Some(UnOp::BitNot),
        _ => None,
    }
}

fn map_binary_opcode(opcode: &str) -> Option<BinOp> {
    match opcode.trim().to_ascii_lowercase().as_str() {
        "m_add" | "add" => Some(BinOp::Add),
        "m_sub" | "sub" => Some(BinOp::Sub),
        "m_mul" | "mul" => Some(BinOp::Mul),
        "m_and" | "and" => Some(BinOp::And),
        "m_or" | "or" => Some(BinOp::Or),
        "m_xor" | "xor" => Some(BinOp::Xor),
        "m_shl" | "m_lsl" | "shl" | "lsl" => Some(BinOp::Shl),
        "m_shr" | "m_lsr" | "shr" | "lsr" => Some(BinOp::LShr),
        "m_sar" | "m_asr" | "sar" | "asr" => Some(BinOp::AShr),
        _ => None,
    }
}

fn width_from_bits(bits: u16) -> Width {
    match bits {
        1 => Width::W1,
        8 => Width::W8,
        16 => Width::W16,
        32 => Width::W32,
        64 => Width::W64,
        128 => Width::W128,
        _ => Width::W64,
    }
}

fn build_microcode_script(addr: u64) -> String {
    format!(
        r#"import json
import ida_funcs
import ida_hexrays

def op_name_map():
    mapping = {{}}
    for key, value in ida_hexrays.__dict__.items():
        if key.startswith('m_') and isinstance(value, int):
            mapping[value] = key
    return mapping

def normalize_arg(arg):
    if arg is None:
        return {{"kind": "value", "id": 0}}

    mop_n = getattr(ida_hexrays, 'mop_n', None)
    if mop_n is not None and arg.t == mop_n:
        num = getattr(arg, 'nnn', None)
        value = getattr(num, 'value', 0)
        width = int(getattr(arg, 'size', 8)) * 8
        return {{"kind": "const", "value": int(value), "width": width}}

    text = str(arg)
    stable = abs(hash(text)) & 0xFFFFFFFF
    return {{"kind": "value", "id": int(stable)}}

result = {{"backend_unavailable": False, "instructions": []}}

if not ida_hexrays.init_hexrays_plugin():
    result = {{"backend_unavailable": True, "instructions": []}}
else:
    func = ida_funcs.get_func(0x{addr:x})
    if func is None:
        result = {{"backend_unavailable": False, "instructions": []}}
    else:
        mbr = ida_hexrays.mba_ranges_t(func)
        hf = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.gen_microcode(mbr, hf, None, ida_hexrays.DECOMP_WARNINGS, ida_hexrays.MMAT_GENERATED)

        if mba is None:
            result = {{"backend_unavailable": False, "instructions": []}}
        else:
            names = op_name_map()
            qty = int(getattr(mba, 'qty', 0))
            for block_idx in range(qty):
                blk = mba.get_mblock(block_idx)
                insn = getattr(blk, 'head', None)
                while insn is not None:
                    opcode = names.get(int(insn.opcode), str(int(insn.opcode)))
                    dst = abs(hash(str(getattr(insn, 'd', '')))) & 0xFFFFFFFF
                    width = int(getattr(insn, 'd', None).size) * 8 if getattr(insn, 'd', None) is not None else 64
                    result['instructions'].append({{
                        'opcode': opcode,
                        'dst': int(dst),
                        'args': [normalize_arg(getattr(insn, 'l', None)), normalize_arg(getattr(insn, 'r', None))],
                        'width': int(width),
                    }})
                    insn = getattr(insn, 'next', None)

json.dumps(result)"#
    )
}

#[cfg(test)]
mod tests {
    use super::render_expr;
    use endeavour_ir::ir::{BinOp, Expr, ValueId, Width};

    #[test]
    fn render_binary_expression_without_outer_parens() {
        let expr = Expr::Binary {
            op: BinOp::Add,
            lhs: Box::new(Expr::Value { id: ValueId(1) }),
            rhs: Box::new(Expr::Value { id: ValueId(2) }),
            width: Width::W64,
        };

        assert_eq!(render_expr(&expr), "v1 + v2");
    }

    #[test]
    fn render_nested_expression_with_grouping() {
        let expr = Expr::Binary {
            op: BinOp::Add,
            lhs: Box::new(Expr::Binary {
                op: BinOp::Xor,
                lhs: Box::new(Expr::Value { id: ValueId(1) }),
                rhs: Box::new(Expr::Value { id: ValueId(2) }),
                width: Width::W64,
            }),
            rhs: Box::new(Expr::Binary {
                op: BinOp::Mul,
                lhs: Box::new(Expr::Const {
                    value: 2,
                    width: Width::W64,
                }),
                rhs: Box::new(Expr::Binary {
                    op: BinOp::And,
                    lhs: Box::new(Expr::Value { id: ValueId(1) }),
                    rhs: Box::new(Expr::Value { id: ValueId(2) }),
                    width: Width::W64,
                }),
                width: Width::W64,
            }),
            width: Width::W64,
        };

        assert_eq!(render_expr(&expr), "(v1 ^ v2) + (0x2:w64 * (v1 & v2))");
    }
}

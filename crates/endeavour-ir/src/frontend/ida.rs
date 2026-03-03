use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::{BinOp, Expr, IrError, Stmt, UnOp, ValueId, Width};

const DEFAULT_WIDTH: Width = Width::W64;

/// Async MCP bridge abstraction used by the IDA frontend.
#[async_trait]
pub trait McpTransport: Send + Sync {
    /// Executes Python code in IDA and returns JSON output.
    async fn py_eval(&self, code: &str) -> std::result::Result<Value, String>;
}

/// Frontend that lifts IDA microcode into `endeavour-ir` statements.
pub struct IdaFrontend<T: McpTransport> {
    transport: T,
}

impl<T: McpTransport> IdaFrontend<T> {
    /// Creates a new IDA frontend with the provided transport.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Lifts the function at `addr` into a list of Endeavour IR statements.
    pub fn lift_function(&self, addr: u64) -> Result<Vec<Stmt>, IrError> {
        let response = self.eval_microcode(addr)?;
        let payload = normalize_payload(response)?;

        if payload.backend_unavailable {
            return Err(IrError::BackendUnavailable);
        }

        let mut statements = Vec::with_capacity(payload.instructions.len());
        for instruction in payload.instructions {
            statements.push(map_instruction(instruction));
        }
        Ok(statements)
    }

    fn eval_microcode(&self, addr: u64) -> Result<Value, IrError> {
        let script = build_microcode_script(addr);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| IrError::BackendUnavailable)?;

        runtime
            .block_on(self.transport.py_eval(&script))
            .map_err(|_| IrError::BackendUnavailable)
    }
}

#[async_trait]
impl McpTransport for endeavour_ida::IdaClient {
    async fn py_eval(&self, code: &str) -> std::result::Result<Value, String> {
        endeavour_ida::IdaClient::py_eval(self, code)
            .await
            .map_err(|err| err.to_string())
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

fn normalize_payload(value: Value) -> Result<LiftPayload, IrError> {
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
    let width = raw.width.map(width_from_bits).unwrap_or(DEFAULT_WIDTH);
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
            width: width.map(width_from_bits).unwrap_or(DEFAULT_WIDTH),
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
        _ => DEFAULT_WIDTH,
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
    use super::*;

    struct MockTransport {
        response: std::result::Result<Value, String>,
    }

    #[async_trait]
    impl McpTransport for MockTransport {
        async fn py_eval(&self, _code: &str) -> std::result::Result<Value, String> {
            self.response.clone()
        }
    }

    #[test]
    fn maps_binary_and_unary_subset() {
        let frontend = IdaFrontend::new(MockTransport {
            response: Ok(serde_json::json!({
                "instructions": [
                    {
                        "opcode": "m_add",
                        "dst": 7,
                        "args": [
                            {"kind": "value", "id": 1},
                            {"kind": "const", "value": 9, "width": 64}
                        ],
                        "width": 64
                    },
                    {
                        "opcode": "m_bnot",
                        "dst": 8,
                        "args": [
                            {"kind": "value", "id": 7}
                        ],
                        "width": 64
                    }
                ]
            })),
        });

        let lifted = frontend.lift_function(0x401000);
        assert!(lifted.is_ok());
        let lifted = match lifted {
            Ok(value) => value,
            Err(err) => panic!("unexpected error: {err}"),
        };

        assert!(matches!(
            &lifted[0],
            Stmt::Assign {
                expr: Expr::Binary { op: BinOp::Add, .. },
                ..
            }
        ));
        assert!(matches!(
            &lifted[1],
            Stmt::Assign {
                expr: Expr::Unary { op: UnOp::BitNot, .. },
                ..
            }
        ));
    }

    #[test]
    fn maps_unmapped_ops_to_unknown() {
        let frontend = IdaFrontend::new(MockTransport {
            response: Ok(serde_json::json!({
                "instructions": [
                    {
                        "opcode": "m_setp",
                        "dst": 11,
                        "args": [
                            {"kind": "value", "id": 1},
                            {"kind": "value", "id": 2}
                        ],
                        "width": 1
                    }
                ]
            })),
        });

        let lifted = frontend.lift_function(0x401000);
        assert!(lifted.is_ok());
        let lifted = match lifted {
            Ok(value) => value,
            Err(err) => panic!("unexpected error: {err}"),
        };

        assert!(matches!(
            &lifted[0],
            Stmt::Unknown { opcode, .. } if opcode == "m_setp"
        ));
    }

    #[test]
    fn returns_backend_unavailable_when_transport_fails() {
        let frontend = IdaFrontend::new(MockTransport {
            response: Err("connection refused".to_string()),
        });

        let lifted = frontend.lift_function(0x401000);
        assert!(matches!(lifted, Err(IrError::BackendUnavailable)));
    }
}

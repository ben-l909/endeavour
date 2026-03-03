use async_trait::async_trait;
use endeavour_ir::{BinOp, Expr, IrError, Stmt, UnOp, ValueId, Width};
use serde::Deserialize;
use serde_json::{json, Value};

const DEFAULT_WIDTH: Width = Width::W64;

#[async_trait]
trait McpTransport: Send + Sync {
    async fn py_eval(&self, code: &str) -> Result<Value, String>;
}

struct IdaFrontend<T: McpTransport> {
    transport: T,
}

impl<T: McpTransport> IdaFrontend<T> {
    fn new(transport: T) -> Self {
        Self { transport }
    }

    fn lift_function(&self, addr: u64) -> Result<Vec<Stmt>, IrError> {
        let response = self.eval_microcode(addr)?;
        let payload = normalize_payload(response)?;

        if payload.backend_unavailable {
            return Err(IrError::BackendUnavailable);
        }

        Ok(payload.instructions.into_iter().map(map_instruction).collect())
    }

    fn eval_microcode(&self, addr: u64) -> Result<Value, IrError> {
        let script = format!("# mock script for 0x{addr:x}");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| IrError::BackendUnavailable)?;

        runtime
            .block_on(self.transport.py_eval(&script))
            .map_err(|_| IrError::BackendUnavailable)
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
    Const { value: u64, width: Option<u16> },
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
        if let (Some(dst), Some(lhs), Some(rhs)) =
            (raw.dst, lowered_args.first().cloned(), lowered_args.get(1).cloned())
        {
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
            value: u128::from(value),
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

#[derive(Clone)]
struct MockIdaTransport {
    response: Result<Value, String>,
}

#[async_trait]
impl McpTransport for MockIdaTransport {
    async fn py_eval(&self, _code: &str) -> Result<Value, String> {
        self.response.clone()
    }
}

fn microcode_fixture_response() -> Value {
    json!({
        "backend_unavailable": false,
        "instructions": [
            {
                "opcode": "m_add",
                "dst": 7u64,
                "args": [
                    {"kind": "value", "id": 1u64},
                    {"kind": "const", "value": 0x20u64, "width": 64u64}
                ],
                "width": 64u64
            },
            {
                "opcode": "m_neg",
                "dst": 8u64,
                "args": [{"kind": "value", "id": 7u64}],
                "width": 64u64
            },
            {
                "opcode": "m_jcnd",
                "dst": 0u64,
                "args": [
                    {"kind": "value", "id": 8u64},
                    {"kind": "const", "value": 0x401080u64, "width": 64u64}
                ],
                "width": 1u64
            },
            {
                "opcode": "m_call",
                "dst": 9u64,
                "args": [
                    {"kind": "const", "value": 0x401200u64, "width": 64u64},
                    {"kind": "value", "id": 8u64}
                ],
                "width": 64u64
            }
        ]
    })
}

#[test]
fn ida_frontend_lifts_microcode_fixture_to_expected_stmt_structure() {
    let frontend = IdaFrontend::new(MockIdaTransport {
        response: Ok(microcode_fixture_response()),
    });

    let lifted = frontend
        .lift_function(0x401000)
        .expect("fixture transport should lift");

    assert_eq!(
        lifted,
        vec![
            Stmt::Assign {
                dst: ValueId(7),
                expr: Expr::Binary {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Value { id: ValueId(1) }),
                    rhs: Box::new(Expr::Const {
                        value: 0x20,
                        width: Width::W64,
                    }),
                    width: Width::W64,
                },
            },
            Stmt::Assign {
                dst: ValueId(8),
                expr: Expr::Unary {
                    op: UnOp::Neg,
                    arg: Box::new(Expr::Value { id: ValueId(7) }),
                    width: Width::W64,
                },
            },
            Stmt::Unknown {
                opcode: "m_jcnd".to_string(),
                dst: Some(ValueId(0)),
                args: vec![
                    Expr::Value { id: ValueId(8) },
                    Expr::Const {
                        value: 0x401080,
                        width: Width::W64,
                    },
                ],
                note: None,
            },
            Stmt::Unknown {
                opcode: "m_call".to_string(),
                dst: Some(ValueId(9)),
                args: vec![
                    Expr::Const {
                        value: 0x401200,
                        width: Width::W64,
                    },
                    Expr::Value { id: ValueId(8) },
                ],
                note: None,
            }
        ]
    );
}

#[test]
fn ida_frontend_returns_empty_when_function_not_found_payload_is_empty() {
    let frontend = IdaFrontend::new(MockIdaTransport {
        response: Ok(json!({
            "backend_unavailable": false,
            "instructions": []
        })),
    });

    let lifted = frontend
        .lift_function(0xDEAD_BEEF)
        .expect("missing function should map to empty instruction list");
    assert!(lifted.is_empty());
}

#[test]
fn ida_frontend_returns_backend_unavailable_on_transport_error() {
    let frontend = IdaFrontend::new(MockIdaTransport {
        response: Err("transport offline".to_string()),
    });

    assert!(matches!(
        frontend.lift_function(0x401000),
        Err(IrError::BackendUnavailable)
    ));
}

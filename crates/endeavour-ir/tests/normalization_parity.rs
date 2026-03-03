use std::collections::HashMap;

use endeavour_ir::{
    normalize_expr, BinOp, CapstoneFrontend, Expr, InstructionArch, Stmt, ValueId, Width,
};
use serde::Deserialize;

/// Acceptable frontend differences for this parity check:
/// - SSA value identifiers may differ (renumbered during canonicalization).
/// - Commutative operand ordering may differ (normalized via `normalize_expr`).
///
/// Not covered by this test (and therefore not accepted here):
/// - Control-flow shaping differences (block splits/merges).
/// - Phi node placement differences from backend-specific CFG recovery.
#[test]
fn ida_mock_and_capstone_fixture_produce_equivalent_normalized_ir() {
    let ida_mock = lift_ida_mock_fixture();
    let capstone_fixture = lift_capstone_fixture();

    let ida_normalized = canonicalize_stmts(&ida_mock);
    let capstone_normalized = canonicalize_stmts(&capstone_fixture);

    assert_eq!(
        ida_normalized, capstone_normalized,
        "frontends should match after normalization and SSA-id canonicalization"
    );
}

fn lift_capstone_fixture() -> Vec<Stmt> {
    const X86_64_XOR_REG_FIXTURE: [u8; 3] = [0x48, 0x31, 0xd8];
    let frontend = CapstoneFrontend::new();
    frontend.lift_bytes(&X86_64_XOR_REG_FIXTURE, InstructionArch::X86_64)
}

fn lift_ida_mock_fixture() -> Vec<Stmt> {
    #[derive(Debug, Deserialize)]
    struct IdaFixture {
        instructions: Vec<RawInstruction>,
    }

    #[derive(Debug, Deserialize)]
    struct RawInstruction {
        opcode: String,
        dst: u32,
        args: Vec<RawArg>,
        width: u16,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum RawArg {
        Value { id: u32 },
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

    fn lower_arg(arg: RawArg) -> Expr {
        match arg {
            RawArg::Value { id } => Expr::Value { id: ValueId(id) },
        }
    }

    fn map_binary_opcode(opcode: &str) -> Option<BinOp> {
        match opcode {
            "m_xor" => Some(BinOp::Xor),
            "m_add" => Some(BinOp::Add),
            "m_sub" => Some(BinOp::Sub),
            "m_and" => Some(BinOp::And),
            "m_or" => Some(BinOp::Or),
            _ => None,
        }
    }

    const IDA_MOCK_FIXTURE: &str = r#"
    {
      "instructions": [
        {
          "opcode": "m_xor",
          "dst": 777,
          "args": [
            {"kind": "value", "id": 1234},
            {"kind": "value", "id": 4321}
          ],
          "width": 64
        }
      ]
    }
    "#;

    let fixture: IdaFixture =
        serde_json::from_str(IDA_MOCK_FIXTURE).expect("IDA mock fixture should parse");

    fixture
        .instructions
        .into_iter()
        .map(|raw| {
            let lowered_args = raw.args.into_iter().map(lower_arg).collect::<Vec<_>>();
            let width = width_from_bits(raw.width);

            if let Some(op) = map_binary_opcode(raw.opcode.as_str()) {
                return Stmt::Assign {
                    dst: ValueId(raw.dst),
                    expr: Expr::Binary {
                        op,
                        lhs: Box::new(
                            lowered_args
                                .first()
                                .cloned()
                                .expect("mock instruction has lhs"),
                        ),
                        rhs: Box::new(
                            lowered_args
                                .get(1)
                                .cloned()
                                .expect("mock instruction has rhs"),
                        ),
                        width,
                    },
                };
            }

            Stmt::Unknown {
                opcode: raw.opcode,
                dst: Some(ValueId(raw.dst)),
                args: lowered_args,
                note: None,
            }
        })
        .collect()
}

fn canonicalize_stmts(stmts: &[Stmt]) -> Vec<Stmt> {
    let mut value_map = HashMap::<u32, u32>::new();
    let mut next_id = 0_u32;

    stmts
        .iter()
        .map(|stmt| canonicalize_stmt(stmt, &mut value_map, &mut next_id))
        .collect()
}

fn canonicalize_stmt(stmt: &Stmt, value_map: &mut HashMap<u32, u32>, next_id: &mut u32) -> Stmt {
    match stmt {
        Stmt::Assign { dst, expr } => Stmt::Assign {
            dst: remap_value_id(*dst, value_map, next_id),
            expr: normalize_expr(&remap_expr_ids(expr, value_map, next_id)),
        },
        Stmt::Store { addr, value, width } => Stmt::Store {
            addr: normalize_expr(&remap_expr_ids(addr, value_map, next_id)),
            value: normalize_expr(&remap_expr_ids(value, value_map, next_id)),
            width: *width,
        },
        Stmt::Branch {
            cond,
            then_bb,
            else_bb,
        } => Stmt::Branch {
            cond: normalize_expr(&remap_expr_ids(cond, value_map, next_id)),
            then_bb: *then_bb,
            else_bb: *else_bb,
        },
        Stmt::Jump { target_bb } => Stmt::Jump {
            target_bb: *target_bb,
        },
        Stmt::Call { target, args, dst } => Stmt::Call {
            target: normalize_expr(&remap_expr_ids(target, value_map, next_id)),
            args: args
                .iter()
                .map(|arg| normalize_expr(&remap_expr_ids(arg, value_map, next_id)))
                .collect(),
            dst: dst.map(|id| remap_value_id(id, value_map, next_id)),
        },
        Stmt::Return { value } => Stmt::Return {
            value: value
                .as_ref()
                .map(|expr| normalize_expr(&remap_expr_ids(expr, value_map, next_id))),
        },
        Stmt::Phi { dst, inputs } => {
            let mut normalized_inputs = inputs
                .iter()
                .map(|(bb, id)| (*bb, remap_value_id(*id, value_map, next_id)))
                .collect::<Vec<_>>();
            normalized_inputs.sort_unstable_by_key(|(bb, id)| (*bb, id.0));
            Stmt::Phi {
                dst: remap_value_id(*dst, value_map, next_id),
                inputs: normalized_inputs,
            }
        }
        Stmt::Unknown {
            opcode,
            dst,
            args,
            note,
        } => Stmt::Unknown {
            opcode: opcode.clone(),
            dst: dst.map(|id| remap_value_id(id, value_map, next_id)),
            args: args
                .iter()
                .map(|arg| normalize_expr(&remap_expr_ids(arg, value_map, next_id)))
                .collect(),
            note: note.clone(),
        },
    }
}

fn remap_expr_ids(expr: &Expr, value_map: &mut HashMap<u32, u32>, next_id: &mut u32) -> Expr {
    match expr {
        Expr::Const { value, width } => Expr::Const {
            value: *value,
            width: *width,
        },
        Expr::Value { id } => Expr::Value {
            id: remap_value_id(*id, value_map, next_id),
        },
        Expr::Unary { op, arg, width } => Expr::Unary {
            op: *op,
            arg: Box::new(remap_expr_ids(arg, value_map, next_id)),
            width: *width,
        },
        Expr::Binary {
            op,
            lhs,
            rhs,
            width,
        } => Expr::Binary {
            op: *op,
            lhs: Box::new(remap_expr_ids(lhs, value_map, next_id)),
            rhs: Box::new(remap_expr_ids(rhs, value_map, next_id)),
            width: *width,
        },
        Expr::Load { addr, width } => Expr::Load {
            addr: Box::new(remap_expr_ids(addr, value_map, next_id)),
            width: *width,
        },
        Expr::Slice { src, lo, hi } => Expr::Slice {
            src: Box::new(remap_expr_ids(src, value_map, next_id)),
            lo: *lo,
            hi: *hi,
        },
        Expr::Concat { hi, lo } => Expr::Concat {
            hi: Box::new(remap_expr_ids(hi, value_map, next_id)),
            lo: Box::new(remap_expr_ids(lo, value_map, next_id)),
        },
    }
}

fn remap_value_id(id: ValueId, value_map: &mut HashMap<u32, u32>, next_id: &mut u32) -> ValueId {
    if let Some(existing) = value_map.get(&id.0) {
        return ValueId(*existing);
    }

    let normalized = *next_id;
    let _ = value_map.insert(id.0, normalized);
    *next_id = next_id.saturating_add(1);
    ValueId(normalized)
}

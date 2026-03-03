use std::collections::HashMap;

use capstone::arch;
use capstone::prelude::*;

use crate::ir::{BinOp, Expr, Stmt, UnOp, ValueId, Width};

/// Architecture selector for the Capstone headless frontend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionArch {
    /// AArch64 instruction stream.
    Arm64,
    /// x86_64 instruction stream.
    X86_64,
}

/// Headless instruction lifter backed by Capstone disassembly.
#[derive(Debug, Default)]
pub struct CapstoneFrontend;

impl CapstoneFrontend {
    /// Creates a new Capstone-based frontend instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Lifts a raw instruction byte stream into Endeavour IR statements.
    #[must_use]
    pub fn lift_bytes(&self, bytes: &[u8], arch: InstructionArch) -> Vec<Stmt> {
        let mut state = LiftState::default();
        let cs = match build_disassembler(arch) {
            Ok(cs) => cs,
            Err(err) => {
                return vec![Stmt::Unknown {
                    opcode: "capstone_init".to_string(),
                    dst: None,
                    args: Vec::new(),
                    note: Some(err.to_string()),
                }];
            }
        };

        let insns = match cs.disasm_all(bytes, 0) {
            Ok(insns) => insns,
            Err(err) => {
                return vec![Stmt::Unknown {
                    opcode: "disasm_all".to_string(),
                    dst: None,
                    args: Vec::new(),
                    note: Some(err.to_string()),
                }];
            }
        };

        let mut lifted = Vec::with_capacity(insns.len());
        for insn in insns.iter() {
            let mnemonic = insn
                .mnemonic()
                .map(str::to_ascii_lowercase)
                .unwrap_or_default();
            let op_str = insn.op_str().unwrap_or_default();

            let stmt = match arch {
                InstructionArch::Arm64 => lift_arm64(&mut state, &mnemonic, op_str),
                InstructionArch::X86_64 => lift_x86_64(&mut state, &mnemonic, op_str),
            }
            .unwrap_or_else(|| Stmt::Unknown {
                opcode: mnemonic.clone(),
                dst: None,
                args: Vec::new(),
                note: Some(op_str.to_string()),
            });

            lifted.push(stmt);
        }

        lifted
    }
}

fn build_disassembler(arch: InstructionArch) -> Result<Capstone, capstone::Error> {
    match arch {
        InstructionArch::Arm64 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build(),
        InstructionArch::X86_64 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .build(),
    }
}

#[derive(Default)]
struct LiftState {
    next_value_id: u32,
    reg_values: HashMap<String, ValueId>,
}

impl LiftState {
    fn read_reg_expr(&mut self, reg: &str, width: Width) -> Expr {
        if is_zero_reg(reg) {
            return Expr::Const { value: 0, width };
        }

        let key = reg.to_ascii_lowercase();
        let id = if let Some(existing) = self.reg_values.get(&key) {
            *existing
        } else {
            let fresh = self.fresh_value_id();
            let _ = self.reg_values.insert(key, fresh);
            fresh
        };

        Expr::Value { id }
    }

    fn write_reg(&mut self, reg: &str) -> ValueId {
        let key = reg.to_ascii_lowercase();
        let id = self.fresh_value_id();
        let _ = self.reg_values.insert(key, id);
        id
    }

    fn fresh_value_id(&mut self) -> ValueId {
        let id = ValueId(self.next_value_id);
        self.next_value_id = self.next_value_id.saturating_add(1);
        id
    }
}

// Reference: Arm ARM A64 base instruction semantics for ADD/SUB/MUL,
// AND/ORR/EOR/MVN, and LSL/LSR/ASR aliases.
fn lift_arm64(state: &mut LiftState, mnemonic: &str, op_str: &str) -> Option<Stmt> {
    let operands = split_operands(op_str);
    match mnemonic {
        "add" => lift_arm64_binary(state, BinOp::Add, &operands),
        "sub" => lift_arm64_binary(state, BinOp::Sub, &operands),
        "mul" => lift_arm64_binary(state, BinOp::Mul, &operands),
        "and" => lift_arm64_binary(state, BinOp::And, &operands),
        "orr" => lift_arm64_binary(state, BinOp::Or, &operands),
        "eor" => lift_arm64_binary(state, BinOp::Xor, &operands),
        "mov" => lift_arm64_mov(state, &operands),
        "lsl" => lift_arm64_binary(state, BinOp::Shl, &operands),
        "lsr" => lift_arm64_binary(state, BinOp::LShr, &operands),
        "asr" => lift_arm64_binary(state, BinOp::AShr, &operands),
        "mvn" => lift_arm64_unary(state, UnOp::BitNot, &operands),
        _ => None,
    }
}

fn lift_arm64_binary(state: &mut LiftState, op: BinOp, operands: &[&str]) -> Option<Stmt> {
    if operands.len() != 3 {
        return None;
    }

    let dst_reg = normalize_reg(operands[0])?;
    let width = arm64_reg_width(&dst_reg)?;
    let lhs = parse_arm64_operand(state, operands[1], width)?;
    let rhs = parse_arm64_operand(state, operands[2], width)?;
    let dst = state.write_reg(&dst_reg);

    Some(Stmt::Assign {
        dst,
        expr: Expr::Binary {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
            width,
        },
    })
}

fn lift_arm64_unary(state: &mut LiftState, op: UnOp, operands: &[&str]) -> Option<Stmt> {
    if operands.len() != 2 {
        return None;
    }

    let dst_reg = normalize_reg(operands[0])?;
    let width = arm64_reg_width(&dst_reg)?;
    let arg = parse_arm64_operand(state, operands[1], width)?;
    let dst = state.write_reg(&dst_reg);

    Some(Stmt::Assign {
        dst,
        expr: Expr::Unary {
            op,
            arg: Box::new(arg),
            width,
        },
    })
}

fn lift_arm64_mov(state: &mut LiftState, operands: &[&str]) -> Option<Stmt> {
    if operands.len() != 2 {
        return None;
    }

    let dst_reg = normalize_reg(operands[0])?;
    let width = arm64_reg_width(&dst_reg)?;
    let src = parse_arm64_operand(state, operands[1], width)?;
    let dst = state.write_reg(&dst_reg);

    Some(Stmt::Assign { dst, expr: src })
}

fn parse_arm64_operand(state: &mut LiftState, operand: &str, width: Width) -> Option<Expr> {
    let trimmed = operand.trim();
    if let Some(reg) = normalize_reg(trimmed) {
        return Some(state.read_reg_expr(&reg, width));
    }

    let value = parse_immediate(trimmed)?;
    Some(Expr::Const {
        value: trunc_to_width(value, width),
        width,
    })
}

fn arm64_reg_width(reg: &str) -> Option<Width> {
    if reg == "sp" || reg == "xzr" || reg == "xsp" || reg.starts_with('x') {
        return Some(Width::W64);
    }
    if reg == "wsp" || reg == "wzr" || reg.starts_with('w') {
        return Some(Width::W32);
    }
    None
}

// Reference: Intel SDM Vol. 2 integer instruction semantics for
// ADD/SUB/IMUL/AND/OR/XOR/NOT/NEG and SHL/SHR/SAR (SAL == SHL).
fn lift_x86_64(state: &mut LiftState, mnemonic: &str, op_str: &str) -> Option<Stmt> {
    let operands = split_operands(op_str);
    match mnemonic {
        "add" => lift_x86_64_binary(state, BinOp::Add, &operands),
        "sub" => lift_x86_64_binary(state, BinOp::Sub, &operands),
        "imul" => lift_x86_64_binary(state, BinOp::Mul, &operands),
        "and" => lift_x86_64_binary(state, BinOp::And, &operands),
        "or" => lift_x86_64_binary(state, BinOp::Or, &operands),
        "xor" => lift_x86_64_binary(state, BinOp::Xor, &operands),
        "mov" => lift_x86_64_mov(state, &operands),
        "shl" | "sal" => lift_x86_64_binary(state, BinOp::Shl, &operands),
        "shr" => lift_x86_64_binary(state, BinOp::LShr, &operands),
        "sar" => lift_x86_64_binary(state, BinOp::AShr, &operands),
        "not" => lift_x86_64_unary(state, UnOp::BitNot, &operands),
        "neg" => lift_x86_64_unary(state, UnOp::Neg, &operands),
        _ => None,
    }
}

fn lift_x86_64_binary(state: &mut LiftState, op: BinOp, operands: &[&str]) -> Option<Stmt> {
    if operands.len() != 2 {
        return None;
    }

    let dst_reg = normalize_reg(operands[0])?;
    let width = x86_reg_width(&dst_reg)?;
    let lhs = state.read_reg_expr(&dst_reg, width);
    let rhs = parse_x86_operand(state, operands[1], width)?;
    let dst = state.write_reg(&dst_reg);

    Some(Stmt::Assign {
        dst,
        expr: Expr::Binary {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
            width,
        },
    })
}

fn lift_x86_64_unary(state: &mut LiftState, op: UnOp, operands: &[&str]) -> Option<Stmt> {
    if operands.len() != 1 {
        return None;
    }

    let dst_reg = normalize_reg(operands[0])?;
    let width = x86_reg_width(&dst_reg)?;
    let arg = state.read_reg_expr(&dst_reg, width);
    let dst = state.write_reg(&dst_reg);

    Some(Stmt::Assign {
        dst,
        expr: Expr::Unary {
            op,
            arg: Box::new(arg),
            width,
        },
    })
}

fn lift_x86_64_mov(state: &mut LiftState, operands: &[&str]) -> Option<Stmt> {
    if operands.len() != 2 {
        return None;
    }

    let dst_reg = normalize_reg(operands[0])?;
    let width = x86_reg_width(&dst_reg)?;
    let src = parse_x86_operand(state, operands[1], width)?;
    let dst = state.write_reg(&dst_reg);

    Some(Stmt::Assign { dst, expr: src })
}

fn parse_x86_operand(state: &mut LiftState, operand: &str, width: Width) -> Option<Expr> {
    let trimmed = operand.trim();
    if let Some(reg) = normalize_reg(trimmed) {
        let reg_width = x86_reg_width(&reg).unwrap_or(width);
        return Some(state.read_reg_expr(&reg, reg_width));
    }

    let value = parse_immediate(trimmed)?;
    Some(Expr::Const {
        value: trunc_to_width(value, width),
        width,
    })
}

fn split_operands(op_str: &str) -> Vec<&str> {
    op_str
        .split(',')
        .map(str::trim)
        .filter(|operand| !operand.is_empty())
        .collect()
}

fn normalize_reg(token: &str) -> Option<String> {
    let candidate = token.trim().to_ascii_lowercase();
    if candidate.is_empty() {
        return None;
    }
    if candidate.contains(' ') || candidate.contains('[') {
        return None;
    }
    if candidate.starts_with('#') {
        return None;
    }
    Some(candidate)
}

fn parse_immediate(token: &str) -> Option<i128> {
    let normalized = token
        .trim()
        .trim_start_matches('#')
        .trim_start_matches("$")
        .replace('_', "");
    if normalized.is_empty() {
        return None;
    }

    if let Some(hex) = normalized
        .strip_prefix("-0x")
        .or_else(|| normalized.strip_prefix("-0X"))
    {
        let value = i128::from_str_radix(hex, 16).ok()?;
        return Some(-value);
    }
    if let Some(hex) = normalized
        .strip_prefix("0x")
        .or_else(|| normalized.strip_prefix("0X"))
    {
        let value = i128::from_str_radix(hex, 16).ok()?;
        return Some(value);
    }

    normalized.parse::<i128>().ok()
}

fn x86_reg_width(reg: &str) -> Option<Width> {
    let width = match reg {
        "al" | "ah" | "bl" | "bh" | "cl" | "ch" | "dl" | "dh" | "sil" | "dil" | "spl" | "bpl"
        | "r8b" | "r9b" | "r10b" | "r11b" | "r12b" | "r13b" | "r14b" | "r15b" => Width::W8,
        "ax" | "bx" | "cx" | "dx" | "si" | "di" | "sp" | "bp" | "r8w" | "r9w" | "r10w" | "r11w"
        | "r12w" | "r13w" | "r14w" | "r15w" => Width::W16,
        "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "esp" | "ebp" | "r8d" | "r9d" | "r10d"
        | "r11d" | "r12d" | "r13d" | "r14d" | "r15d" => Width::W32,
        "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rsp" | "rbp" | "r8" | "r9" | "r10"
        | "r11" | "r12" | "r13" | "r14" | "r15" | "rip" => Width::W64,
        _ => return None,
    };

    Some(width)
}

fn trunc_to_width(value: i128, width: Width) -> u128 {
    match width {
        Width::W1 => (value as u128) & 0x1,
        Width::W8 => (value as u128) & 0xff,
        Width::W16 => (value as u128) & 0xffff,
        Width::W32 => (value as u128) & 0xffff_ffff,
        Width::W64 => (value as u128) & 0xffff_ffff_ffff_ffff,
        Width::W128 => value as u128,
    }
}

fn is_zero_reg(reg: &str) -> bool {
    matches!(reg, "xzr" | "wzr")
}

#[cfg(test)]
mod tests {
    use super::{CapstoneFrontend, InstructionArch};
    use crate::ir::{BinOp, Expr, Stmt, UnOp, ValueId, Width};

    fn assert_binary_stmt(stmt: &Stmt, op: BinOp) {
        assert!(matches!(
            stmt,
            Stmt::Assign {
                dst: ValueId(_),
                expr: Expr::Binary {
                    op: actual_op,
                    lhs,
                    rhs,
                    width: Width::W64,
                },
            } if *actual_op == op
                && matches!(lhs.as_ref(), Expr::Value { .. })
                && matches!(rhs.as_ref(), Expr::Value { .. } | Expr::Const { .. })
        ));
    }

    fn assert_unary_stmt(stmt: &Stmt, op: UnOp) {
        assert!(matches!(
            stmt,
            Stmt::Assign {
                dst: ValueId(_),
                expr: Expr::Unary {
                    op: actual_op,
                    arg,
                    width: Width::W64,
                },
            } if *actual_op == op && matches!(arg.as_ref(), Expr::Value { .. })
        ));
    }

    fn assert_mov_stmt(stmt: &Stmt) {
        assert!(matches!(
            stmt,
            Stmt::Assign {
                dst: ValueId(_),
                expr: Expr::Value { .. },
            }
        ));
    }

    #[test]
    fn lifts_arm64_binary_opcode_subset() {
        let frontend = CapstoneFrontend::new();
        let bytes = [
            0x20_u8, 0x00, 0x02, 0xcb, 0x20_u8, 0x00, 0x02, 0x8a, 0x20_u8, 0x00, 0x02, 0xaa,
            0x20_u8, 0x00, 0x02, 0xca,
        ];
        let stmts = frontend.lift_bytes(&bytes, InstructionArch::Arm64);

        assert_eq!(stmts.len(), 4);
        assert_binary_stmt(&stmts[0], BinOp::Sub);
        assert_binary_stmt(&stmts[1], BinOp::And);
        assert_binary_stmt(&stmts[2], BinOp::Or);
        assert_binary_stmt(&stmts[3], BinOp::Xor);
    }

    #[test]
    fn lifts_x86_64_binary_opcode_subset() {
        let frontend = CapstoneFrontend::new();
        let bytes = [
            0x48_u8, 0x29, 0xd8, 0x48_u8, 0x21, 0xd8, 0x48_u8, 0x09, 0xd8, 0x48_u8, 0x31, 0xd8,
            0x48_u8, 0xd1, 0xe0, 0x48_u8, 0xd1, 0xe8,
        ];
        let stmts = frontend.lift_bytes(&bytes, InstructionArch::X86_64);

        assert_eq!(stmts.len(), 6);
        assert_binary_stmt(&stmts[0], BinOp::Sub);
        assert_binary_stmt(&stmts[1], BinOp::And);
        assert_binary_stmt(&stmts[2], BinOp::Or);
        assert_binary_stmt(&stmts[3], BinOp::Xor);
        assert_binary_stmt(&stmts[4], BinOp::Shl);
        assert_binary_stmt(&stmts[5], BinOp::LShr);
    }

    #[test]
    fn lifts_x86_64_unary_and_mov_subset() {
        let frontend = CapstoneFrontend::new();
        let bytes = [
            0x48_u8, 0x89, 0xd8, 0x48_u8, 0xf7, 0xd0, 0x48_u8, 0xf7, 0xd8,
        ];
        let stmts = frontend.lift_bytes(&bytes, InstructionArch::X86_64);

        assert_eq!(stmts.len(), 3);
        assert_mov_stmt(&stmts[0]);
        assert_unary_stmt(&stmts[1], UnOp::BitNot);
        assert_unary_stmt(&stmts[2], UnOp::Neg);
    }

    #[test]
    fn lifts_arm64_mov_instruction() {
        let frontend = CapstoneFrontend::new();
        // MOV X0, X1
        let bytes = [0x20_u8, 0x00, 0x00, 0xaa];
        let stmts = frontend.lift_bytes(&bytes, InstructionArch::Arm64);

        assert_eq!(stmts.len(), 1);
        assert_mov_stmt(&stmts[0]);
    }

    #[test]
    fn lifts_arm64_shift_operations() {
        let frontend = CapstoneFrontend::new();
        // LSL X0, X1, #1 and LSR X0, X1, #1
        let bytes = [
            0x20_u8, 0x04, 0x01, 0xd3, // LSL X0, X1, #1
            0x20_u8, 0x04, 0x41, 0xd3, // LSR X0, X1, #1
        ];
        let stmts = frontend.lift_bytes(&bytes, InstructionArch::Arm64);

        assert_eq!(stmts.len(), 2);
        assert_binary_stmt(&stmts[0], BinOp::Shl);
        assert_binary_stmt(&stmts[1], BinOp::LShr);
    }

    #[test]
    fn lifts_arm64_unary_operations() {
        let frontend = CapstoneFrontend::new();
        // MVN X0, X1 and NEG X0, X1
        let bytes = [
            0x20_u8, 0x00, 0x02, 0xaa, // MOV X0, X1 (for baseline)
            0x20_u8, 0x00, 0x22, 0xaa, // MVN X0, X1
            0x20_u8, 0x00, 0x00, 0xcb, // NEG X0, X1
        ];
        let stmts = frontend.lift_bytes(&bytes, InstructionArch::Arm64);

        assert_eq!(stmts.len(), 3);
        assert_mov_stmt(&stmts[0]);
        assert_unary_stmt(&stmts[1], UnOp::BitNot);
        assert_unary_stmt(&stmts[2], UnOp::Neg);
    }
}

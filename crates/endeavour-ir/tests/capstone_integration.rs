use endeavour_ir::{BinOp, CapstoneFrontend, Expr, InstructionArch, Stmt, ValueId, Width};

#[test]
fn lifts_arm64_add_bytes_to_expected_ir_stmt() {
    let frontend = CapstoneFrontend::new();
    let bytes = [0x20_u8, 0x00, 0x02, 0x8b];

    let stmts = frontend.lift_bytes(&bytes, InstructionArch::Arm64);

    assert_eq!(
        stmts,
        vec![Stmt::Assign {
            dst: ValueId(2),
            expr: Expr::Binary {
                op: BinOp::Add,
                lhs: Box::new(Expr::Value { id: ValueId(0) }),
                rhs: Box::new(Expr::Value { id: ValueId(1) }),
                width: Width::W64,
            },
        }]
    );
}

#[test]
fn lifts_x86_64_xor_bytes_to_expected_ir_stmt() {
    let frontend = CapstoneFrontend::new();
    let bytes = [0x31_u8, 0xd8];

    let stmts = frontend.lift_bytes(&bytes, InstructionArch::X86_64);

    assert_eq!(
        stmts,
        vec![Stmt::Assign {
            dst: ValueId(2),
            expr: Expr::Binary {
                op: BinOp::Xor,
                lhs: Box::new(Expr::Value { id: ValueId(0) }),
                rhs: Box::new(Expr::Value { id: ValueId(1) }),
                width: Width::W32,
            },
        }]
    );
}

#[test]
fn lifts_arm64_multiple_instruction_sequence() {
    let frontend = CapstoneFrontend::new();
    let bytes = [0x20_u8, 0x00, 0x02, 0x8b, 0x03_u8, 0x00, 0x04, 0xcb];

    let stmts = frontend.lift_bytes(&bytes, InstructionArch::Arm64);

    assert_eq!(
        stmts,
        vec![
            Stmt::Assign {
                dst: ValueId(2),
                expr: Expr::Binary {
                    op: BinOp::Add,
                    lhs: Box::new(Expr::Value { id: ValueId(0) }),
                    rhs: Box::new(Expr::Value { id: ValueId(1) }),
                    width: Width::W64,
                },
            },
            Stmt::Assign {
                dst: ValueId(4),
                expr: Expr::Binary {
                    op: BinOp::Sub,
                    lhs: Box::new(Expr::Value { id: ValueId(2) }),
                    rhs: Box::new(Expr::Value { id: ValueId(3) }),
                    width: Width::W64,
                },
            },
        ]
    );
}

#[test]
fn lifts_unknown_instruction_to_unknown_stmt() {
    let frontend = CapstoneFrontend::new();
    let bytes = [0x90_u8];

    let stmts = frontend.lift_bytes(&bytes, InstructionArch::X86_64);

    assert_eq!(
        stmts,
        vec![Stmt::Unknown {
            opcode: "nop".to_string(),
            dst: None,
            args: Vec::new(),
            note: Some(String::new()),
        }]
    );
}

use endeavour_ir::{BinOp, Expr, Stmt, UnOp, ValueId, Width};

fn c(value: u128, width: Width) -> Expr {
    Expr::Const { value, width }
}

fn v(id: u32) -> Expr {
    Expr::Value { id: ValueId(id) }
}

#[test]
fn constructs_const_expr() {
    let expr = Expr::Const {
        value: 0x2a,
        width: Width::W8,
    };

    assert_eq!(expr, c(0x2a, Width::W8));
}

#[test]
fn constructs_value_expr() {
    let expr = Expr::Value { id: ValueId(7) };

    assert_eq!(expr, v(7));
}

#[test]
fn constructs_unary_expr() {
    let expr = Expr::Unary {
        op: UnOp::BitNot,
        arg: Box::new(v(1)),
        width: Width::W32,
    };

    assert_eq!(
        expr,
        Expr::Unary {
            op: UnOp::BitNot,
            arg: Box::new(v(1)),
            width: Width::W32,
        }
    );
}

#[test]
fn constructs_binary_expr() {
    let expr = Expr::Binary {
        op: BinOp::Add,
        lhs: Box::new(c(1, Width::W32)),
        rhs: Box::new(v(2)),
        width: Width::W32,
    };

    assert_eq!(
        expr,
        Expr::Binary {
            op: BinOp::Add,
            lhs: Box::new(c(1, Width::W32)),
            rhs: Box::new(v(2)),
            width: Width::W32,
        }
    );
}

#[test]
fn constructs_load_expr() {
    let expr = Expr::Load {
        addr: Box::new(v(4)),
        width: Width::W64,
    };

    assert_eq!(
        expr,
        Expr::Load {
            addr: Box::new(v(4)),
            width: Width::W64,
        }
    );
}

#[test]
fn constructs_slice_expr() {
    let expr = Expr::Slice {
        src: Box::new(c(0xff00, Width::W16)),
        lo: 8,
        hi: 15,
    };

    assert_eq!(
        expr,
        Expr::Slice {
            src: Box::new(c(0xff00, Width::W16)),
            lo: 8,
            hi: 15,
        }
    );
}

#[test]
fn constructs_concat_expr() {
    let expr = Expr::Concat {
        hi: Box::new(c(0xaa, Width::W8)),
        lo: Box::new(c(0x55, Width::W8)),
    };

    assert_eq!(
        expr,
        Expr::Concat {
            hi: Box::new(c(0xaa, Width::W8)),
            lo: Box::new(c(0x55, Width::W8)),
        }
    );
}

#[test]
fn structurally_identical_exprs_are_equal() {
    let left = c(1, Width::W32);
    let right = v(8);

    let built_top_down = Expr::Binary {
        op: BinOp::Mul,
        lhs: Box::new(left.clone()),
        rhs: Box::new(right.clone()),
        width: Width::W32,
    };

    let built_bottom_up = {
        let lhs = Box::new(left);
        let rhs = Box::new(right);
        Expr::Binary {
            op: BinOp::Mul,
            lhs,
            rhs,
            width: Width::W32,
        }
    };

    assert_eq!(built_top_down, built_bottom_up);
}

#[test]
#[ignore = "Requires ENG-056 normalize module"]
fn normalize_is_idempotent_for_distinct_expressions() {
    // Requires ENG-056 normalize module
    let cases = vec![
        c(0, Width::W8),
        v(9),
        Expr::Unary {
            op: UnOp::Neg,
            arg: Box::new(c(7, Width::W32)),
            width: Width::W32,
        },
        Expr::Binary {
            op: BinOp::Xor,
            lhs: Box::new(v(1)),
            rhs: Box::new(c(0xff, Width::W32)),
            width: Width::W32,
        },
        Expr::Concat {
            hi: Box::new(Expr::Slice {
                src: Box::new(c(0x1234, Width::W16)),
                lo: 8,
                hi: 15,
            }),
            lo: Box::new(Expr::Load {
                addr: Box::new(v(3)),
                width: Width::W8,
            }),
        },
    ];

    let _ = cases;
}

#[test]
fn stmt_json_round_trip_for_all_variants() {
    let stmts = vec![
        Stmt::Assign {
            dst: ValueId(1),
            expr: v(123),
        },
        Stmt::Store {
            addr: v(2),
            value: v(9),
            width: Width::W8,
        },
        Stmt::Branch {
            cond: Expr::Binary {
                op: BinOp::Eq,
                lhs: Box::new(v(1)),
                rhs: Box::new(v(0)),
                width: Width::W1,
            },
            then_bb: 10,
            else_bb: 11,
        },
        Stmt::Jump { target_bb: 12 },
        Stmt::Call {
            target: v(20),
            args: vec![v(1), v(2)],
            dst: Some(ValueId(30)),
        },
        Stmt::Return { value: Some(v(42)) },
        Stmt::Phi {
            dst: ValueId(5),
            inputs: vec![(0, ValueId(2)), (1, ValueId(3))],
        },
        Stmt::Unknown {
            opcode: "backend_op".to_string(),
            dst: None,
            args: vec![v(99)],
            note: Some("preserved".to_string()),
        },
    ];

    for stmt in stmts {
        let encoded = serde_json::to_string(&stmt).expect("stmt should serialize");
        let decoded: Stmt = serde_json::from_str(&encoded).expect("stmt should deserialize");
        assert_eq!(decoded, stmt);
    }
}

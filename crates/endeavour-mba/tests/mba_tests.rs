use endeavour_ir::ir::{BinOp, Expr, Stmt, UnOp, ValueId, Width};
use endeavour_mba::MbaMatcher;

#[cfg(feature = "z3-verifier")]
use endeavour_mba::{VerifierResult, Z3Verifier};

fn value(id: u32) -> Expr {
    Expr::Value { id: ValueId(id) }
}

fn const_w(value: u128, width: Width) -> Expr {
    Expr::Const { value, width }
}

fn unary(op: UnOp, arg: Expr, width: Width) -> Expr {
    Expr::Unary {
        op,
        arg: Box::new(arg),
        width,
    }
}

fn binary(op: BinOp, lhs: Expr, rhs: Expr, width: Width) -> Expr {
    Expr::Binary {
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
        width,
    }
}

fn benchmark_pairs(width: Width) -> Vec<(Expr, Expr)> {
    let x = value(1);
    let y = value(2);
    let two = const_w(2, width);

    vec![
        (
            binary(
                BinOp::Add,
                binary(BinOp::Xor, x.clone(), y.clone(), width),
                binary(
                    BinOp::Mul,
                    two.clone(),
                    binary(BinOp::And, x.clone(), y.clone(), width),
                    width,
                ),
                width,
            ),
            binary(BinOp::Add, x.clone(), y.clone(), width),
        ),
        (
            binary(
                BinOp::Sub,
                binary(BinOp::Or, x.clone(), y.clone(), width),
                binary(BinOp::Xor, x.clone(), y.clone(), width),
                width,
            ),
            binary(BinOp::And, x.clone(), y.clone(), width),
        ),
        (
            binary(
                BinOp::Add,
                binary(BinOp::And, x.clone(), y.clone(), width),
                binary(BinOp::Or, x.clone(), y.clone(), width),
                width,
            ),
            binary(BinOp::Add, x.clone(), y.clone(), width),
        ),
        (
            binary(
                BinOp::Add,
                binary(
                    BinOp::Mul,
                    two.clone(),
                    binary(BinOp::And, x.clone(), y.clone(), width),
                    width,
                ),
                binary(BinOp::Xor, x.clone(), y.clone(), width),
                width,
            ),
            binary(BinOp::Add, x.clone(), y.clone(), width),
        ),
        (
            binary(
                BinOp::Add,
                binary(BinOp::Or, x.clone(), y.clone(), width),
                binary(BinOp::And, x.clone(), y.clone(), width),
                width,
            ),
            binary(BinOp::Add, x.clone(), y.clone(), width),
        ),
        (
            binary(
                BinOp::Sub,
                binary(
                    BinOp::Or,
                    unary(UnOp::BitNot, x.clone(), width),
                    y.clone(),
                    width,
                ),
                unary(UnOp::BitNot, x.clone(), width),
                width,
            ),
            binary(BinOp::And, x.clone(), y.clone(), width),
        ),
        (
            binary(
                BinOp::Or,
                binary(
                    BinOp::And,
                    x.clone(),
                    unary(UnOp::BitNot, y.clone(), width),
                    width,
                ),
                binary(
                    BinOp::And,
                    unary(UnOp::BitNot, x.clone(), width),
                    y.clone(),
                    width,
                ),
                width,
            ),
            binary(BinOp::Xor, x.clone(), y.clone(), width),
        ),
        (
            unary(
                UnOp::BitNot,
                binary(
                    BinOp::And,
                    unary(UnOp::BitNot, x.clone(), width),
                    unary(UnOp::BitNot, y.clone(), width),
                    width,
                ),
                width,
            ),
            binary(BinOp::Or, x.clone(), y.clone(), width),
        ),
        (
            unary(
                UnOp::BitNot,
                binary(
                    BinOp::Or,
                    unary(UnOp::BitNot, x.clone(), width),
                    unary(UnOp::BitNot, y.clone(), width),
                    width,
                ),
                width,
            ),
            binary(BinOp::And, x.clone(), y.clone(), width),
        ),
        (
            binary(
                BinOp::Sub,
                binary(BinOp::Add, x.clone(), y.clone(), width),
                binary(
                    BinOp::Mul,
                    two,
                    binary(BinOp::And, x.clone(), y.clone(), width),
                    width,
                ),
                width,
            ),
            binary(BinOp::Xor, x, y, width),
        ),
    ]
}

fn scan_single(expr: Expr) -> Vec<endeavour_mba::MbaMatch> {
    let stmts = vec![Stmt::Assign {
        dst: ValueId(99),
        expr,
    }];
    MbaMatcher::new().scan(&stmts)
}

#[test]
fn detects_all_10_benchmarks_for_w32_and_w64() {
    for width in [Width::W32, Width::W64] {
        for (index, (expr, expected_simplified)) in benchmark_pairs(width).into_iter().enumerate() {
            let matches = scan_single(expr.clone());
            assert!(
                !matches.is_empty(),
                "expected benchmark {} to match for width {width:?}",
                index + 1
            );
            assert!(
                matches.iter().any(|m| m.original == expr),
                "expected original benchmark {} expression in matches for width {width:?}",
                index + 1
            );
            assert!(
                matches.iter().any(|m| m.simplified == expected_simplified),
                "expected simplified benchmark {} form for width {width:?}",
                index + 1
            );
        }
    }
}

#[test]
fn does_not_match_simple_non_mba_expression() {
    for width in [Width::W32, Width::W64] {
        let x = value(1);
        let y = value(2);
        let non_mba = binary(BinOp::Add, x, y, width);
        let matches = scan_single(non_mba);
        assert!(
            matches.is_empty(),
            "expected no matches for non-MBA expression at width {width:?}"
        );
    }
}

#[cfg(feature = "z3-verifier")]
#[test]
fn z3_proves_all_10_benchmarks_equivalent_for_w32_and_w64() {
    use std::time::Duration;

    let verifier = Z3Verifier::new(Duration::from_millis(500));

    for width in [Width::W32, Width::W64] {
        for (index, (expr, expected_simplified)) in benchmark_pairs(width).into_iter().enumerate() {
            let matches = scan_single(expr.clone());
            assert!(
                matches.iter().any(|m| m.simplified == expected_simplified),
                "expected benchmark {} simplification to be detected for width {width:?}",
                index + 1
            );

            let result = verifier.prove_equivalent(&expr, &expected_simplified, width);
            assert_eq!(
                result,
                VerifierResult::Equivalent,
                "expected equivalence for benchmark {} at width {width:?}",
                index + 1
            );
        }
    }
}

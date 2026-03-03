use std::collections::BTreeMap;
use std::time::Duration;

use endeavour_ir::ir::{BinOp, Expr, UnOp, Width};
use z3::ast::{Ast, Bool, BV};
use z3::{Config, Context, Params, SatResult, Solver};

/// Z3-backed bit-vector equivalence verifier for MBA candidates.
#[derive(Debug, Clone)]
pub struct Z3Verifier {
    timeout: Duration,
}

/// Result of attempting to prove two expressions equivalent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifierResult {
    /// The expressions are equivalent for all assignments.
    Equivalent,
    /// The expressions differ for at least one assignment.
    NotEquivalent {
        /// Concrete variable assignment that witnesses non-equivalence.
        counterexample: Vec<(String, u128)>,
    },
    /// The solver exceeded the configured timeout.
    Timeout,
    /// The verifier could not encode or solve the query.
    Error(String),
}

impl Z3Verifier {
    /// Creates a verifier with a custom solver timeout.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Proves bit-vector equivalence of `orig` and `simp` at the given width.
    #[must_use]
    pub fn prove_equivalent(&self, orig: &Expr, simp: &Expr, width: Width) -> VerifierResult {
        if self.timeout.is_zero() {
            return VerifierResult::Timeout;
        }

        let mut config = Config::new();
        config.set_model_generation(true);
        let ctx = Context::new(&config);
        let solver = Solver::new(&ctx);

        let timeout_ms = self.timeout.as_millis();
        let timeout_u32 = u32::try_from(timeout_ms).unwrap_or(u32::MAX);
        let mut params = Params::new(&ctx);
        params.set_u32("timeout", timeout_u32);
        solver.set_params(&params);

        let root_bits = width_to_bits(width);
        let mut vars = BTreeMap::<String, BV>::new();

        let orig_bv = match expr_to_bv(&ctx, orig, root_bits, &mut vars) {
            Ok(expr) => expr,
            Err(err) => return VerifierResult::Error(err),
        };

        let simp_bv = match expr_to_bv(&ctx, simp, root_bits, &mut vars) {
            Ok(expr) => expr,
            Err(err) => return VerifierResult::Error(err),
        };

        let neq = orig_bv._eq(&simp_bv).not();
        solver.assert(&neq);

        match solver.check() {
            SatResult::Unsat => VerifierResult::Equivalent,
            SatResult::Sat => {
                let model = match solver.get_model() {
                    Some(model) => model,
                    None => {
                        return VerifierResult::Error(
                            "solver reported SAT but did not return a model".to_string(),
                        );
                    }
                };

                let mut counterexample = Vec::with_capacity(vars.len());
                for (name, symbol) in &vars {
                    let value = match model.eval(symbol, true) {
                        Some(value) => value,
                        None => {
                            return VerifierResult::Error(format!(
                                "model did not assign variable {name}"
                            ));
                        }
                    };

                    let parsed = match parse_bv_value(&value) {
                        Ok(v) => v,
                        Err(err) => return VerifierResult::Error(err),
                    };
                    counterexample.push((name.clone(), parsed));
                }

                VerifierResult::NotEquivalent { counterexample }
            }
            SatResult::Unknown => {
                let reason = solver.get_reason_unknown().unwrap_or_default();
                if reason.contains("timeout") || reason.contains("canceled") {
                    VerifierResult::Timeout
                } else {
                    VerifierResult::Error(format!("solver returned unknown: {reason}"))
                }
            }
        }
    }
}

impl Default for Z3Verifier {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(50),
        }
    }
}

fn expr_to_bv<'ctx>(
    ctx: &'ctx Context,
    expr: &Expr,
    fallback_bits: u32,
    vars: &mut BTreeMap<String, BV<'ctx>>,
) -> Result<BV<'ctx>, String> {
    match expr {
        Expr::Const { value, width } => bv_from_u128(ctx, mask_to_width(*value, *width), *width),
        Expr::Value { id } => {
            let name = format!("v{}", id.0);
            if let Some(existing) = vars.get(&name) {
                return Ok(existing.clone());
            }

            let symbol = BV::new_const(ctx, name.clone(), fallback_bits);
            vars.insert(name, symbol.clone());
            Ok(symbol)
        }
        Expr::Unary { op, arg, width } => {
            let result_bits = width_to_bits(*width);
            let arg_bits = infer_expr_bits(arg, result_bits);
            let arg_bv = expr_to_bv(ctx, arg, arg_bits, vars)?;

            match op {
                UnOp::Neg => Ok(coerce_to_width(&arg_bv, result_bits).bvneg()),
                UnOp::BitNot => Ok(coerce_to_width(&arg_bv, result_bits).bvnot()),
                UnOp::LogicalNot => {
                    let co = coerce_to_width(&arg_bv, result_bits);
                    let zero = BV::from_u64(ctx, 0, result_bits);
                    let one = BV::from_u64(ctx, 1, result_bits);
                    Ok(co._eq(&zero).ite(&one, &zero))
                }
                UnOp::ZeroExtend => {
                    if result_bits < arg_bv.get_size() {
                        return Err(
                            "invalid zero-extend: target width is smaller than source".into()
                        );
                    }
                    Ok(arg_bv.zero_ext(result_bits - arg_bv.get_size()))
                }
                UnOp::SignExtend => {
                    if result_bits < arg_bv.get_size() {
                        return Err(
                            "invalid sign-extend: target width is smaller than source".into()
                        );
                    }
                    Ok(arg_bv.sign_ext(result_bits - arg_bv.get_size()))
                }
            }
        }
        Expr::Binary {
            op,
            lhs,
            rhs,
            width,
        } => {
            let result_bits = width_to_bits(*width);
            let lhs_bits = infer_expr_bits(lhs, result_bits);
            let rhs_bits = infer_expr_bits(rhs, result_bits);

            let lhs_bv = expr_to_bv(ctx, lhs, lhs_bits, vars)?;
            let rhs_bv = expr_to_bv(ctx, rhs, rhs_bits, vars)?;

            let lhs_co = coerce_to_width(&lhs_bv, lhs_bv.get_size().max(rhs_bv.get_size()));
            let rhs_co = coerce_to_width(&rhs_bv, lhs_bv.get_size().max(rhs_bv.get_size()));

            let raw = match op {
                BinOp::Add => lhs_co.bvadd(&rhs_co),
                BinOp::Sub => lhs_co.bvsub(&rhs_co),
                BinOp::Mul => lhs_co.bvmul(&rhs_co),
                BinOp::UDiv => lhs_co.bvudiv(&rhs_co),
                BinOp::SDiv => lhs_co.bvsdiv(&rhs_co),
                BinOp::UMod => lhs_co.bvurem(&rhs_co),
                BinOp::SMod => lhs_co.bvsmod(&rhs_co),
                BinOp::And => lhs_co.bvand(&rhs_co),
                BinOp::Or => lhs_co.bvor(&rhs_co),
                BinOp::Xor => lhs_co.bvxor(&rhs_co),
                BinOp::Shl => lhs_co.bvshl(&rhs_co),
                BinOp::LShr => lhs_co.bvlshr(&rhs_co),
                BinOp::AShr => lhs_co.bvashr(&rhs_co),
                BinOp::Eq => bool_to_bv(ctx, lhs_co._eq(&rhs_co), result_bits),
                BinOp::Ne => bool_to_bv(ctx, lhs_co._eq(&rhs_co).not(), result_bits),
                BinOp::Ult => bool_to_bv(ctx, lhs_co.bvult(&rhs_co), result_bits),
                BinOp::Ule => bool_to_bv(ctx, lhs_co.bvule(&rhs_co), result_bits),
                BinOp::Ugt => bool_to_bv(ctx, lhs_co.bvugt(&rhs_co), result_bits),
                BinOp::Uge => bool_to_bv(ctx, lhs_co.bvuge(&rhs_co), result_bits),
                BinOp::Slt => bool_to_bv(ctx, lhs_co.bvslt(&rhs_co), result_bits),
                BinOp::Sle => bool_to_bv(ctx, lhs_co.bvsle(&rhs_co), result_bits),
                BinOp::Sgt => bool_to_bv(ctx, lhs_co.bvsgt(&rhs_co), result_bits),
                BinOp::Sge => bool_to_bv(ctx, lhs_co.bvsge(&rhs_co), result_bits),
            };

            Ok(coerce_to_width(&raw, result_bits))
        }
        Expr::Load { .. } => Err("cannot verify expressions containing memory loads".to_string()),
        Expr::Slice { src, lo, hi } => {
            if hi < lo {
                return Err("invalid slice: high bit is less than low bit".to_string());
            }

            let src_bv = expr_to_bv(ctx, src, infer_expr_bits(src, fallback_bits), vars)?;
            let src_bits = src_bv.get_size();
            let high = u32::from(*hi);
            let low = u32::from(*lo);
            if high >= src_bits {
                return Err("invalid slice: high bit exceeds source width".to_string());
            }
            Ok(src_bv.extract(high, low))
        }
        Expr::Concat { hi, lo } => {
            let hi_bv = expr_to_bv(ctx, hi, infer_expr_bits(hi, fallback_bits), vars)?;
            let lo_bv = expr_to_bv(ctx, lo, infer_expr_bits(lo, fallback_bits), vars)?;
            Ok(hi_bv.concat(&lo_bv))
        }
    }
}

fn infer_expr_bits(expr: &Expr, fallback_bits: u32) -> u32 {
    match expr {
        Expr::Const { width, .. } => width_to_bits(*width),
        Expr::Value { .. } => fallback_bits,
        Expr::Unary { width, .. } => width_to_bits(*width),
        Expr::Binary { width, .. } => width_to_bits(*width),
        Expr::Load { width, .. } => width_to_bits(*width),
        Expr::Slice { lo, hi, .. } => u32::from(*hi) - u32::from(*lo) + 1,
        Expr::Concat { hi, lo } => {
            infer_expr_bits(hi, fallback_bits) + infer_expr_bits(lo, fallback_bits)
        }
    }
}

fn bool_to_bv<'ctx>(ctx: &'ctx Context, cond: Bool<'ctx>, width: u32) -> BV<'ctx> {
    let one = BV::from_u64(ctx, 1, width);
    let zero = BV::from_u64(ctx, 0, width);
    cond.ite(&one, &zero)
}

fn coerce_to_width<'ctx>(expr: &BV<'ctx>, width: u32) -> BV<'ctx> {
    let current = expr.get_size();
    if current == width {
        return expr.clone();
    }
    if current < width {
        return expr.zero_ext(width - current);
    }
    expr.extract(width - 1, 0)
}

fn parse_bv_value(value: &BV) -> Result<u128, String> {
    if let Some(v) = value.as_u64() {
        return Ok(u128::from(v));
    }

    let rendered = value.to_string();
    if let Some(rest) = rendered.strip_prefix("#x") {
        return u128::from_str_radix(rest, 16)
            .map_err(|err| format!("failed to parse model hex value `{rendered}`: {err}"));
    }
    if let Some(rest) = rendered.strip_prefix("#b") {
        return u128::from_str_radix(rest, 2)
            .map_err(|err| format!("failed to parse model binary value `{rendered}`: {err}"));
    }

    rendered
        .parse::<u128>()
        .map_err(|err| format!("failed to parse model value `{rendered}`: {err}"))
}

fn bv_from_u128<'ctx>(ctx: &'ctx Context, value: u128, width: Width) -> Result<BV<'ctx>, String> {
    let bits = width_to_bits(width);
    if bits > 64 {
        let rendered = format!("#x{:0width$x}", value, width = (bits as usize) / 4);
        return BV::from_str(ctx, bits, &rendered)
            .ok_or_else(|| format!("failed to encode {bits}-bit constant `{rendered}`"));
    }

    let narrowed = match u64::try_from(value) {
        Ok(v) => v,
        Err(_) => {
            return Err(format!(
                "constant `{value}` does not fit in {} bits for solver encoding",
                bits
            ));
        }
    };
    Ok(BV::from_u64(ctx, narrowed, bits))
}

fn mask_to_width(value: u128, width: Width) -> u128 {
    let bits = width_to_bits(width);
    if bits == 128 {
        return value;
    }
    value & ((1u128 << bits) - 1)
}

fn width_to_bits(width: Width) -> u32 {
    match width {
        Width::W1 => 1,
        Width::W8 => 8,
        Width::W16 => 16,
        Width::W32 => 32,
        Width::W64 => 64,
        Width::W128 => 128,
    }
}

#[cfg(test)]
mod tests {
    use super::{VerifierResult, Z3Verifier};
    use endeavour_ir::ir::{BinOp, Expr, UnOp, ValueId, Width};
    use std::time::Duration;

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

    #[test]
    fn verifies_all_benchmark_identities() {
        let verifier = Z3Verifier::new(Duration::from_millis(500));
        for (orig, simp) in benchmark_pairs(Width::W32) {
            assert_eq!(
                verifier.prove_equivalent(&orig, &simp, Width::W32),
                VerifierResult::Equivalent
            );
        }
    }

    #[test]
    fn verifies_across_supported_widths() {
        let verifier = Z3Verifier::new(Duration::from_secs(5));
        for width in [Width::W8, Width::W16, Width::W32, Width::W64] {
            for (index, (orig, simp)) in benchmark_pairs(width).into_iter().enumerate() {
                let result = verifier.prove_equivalent(&orig, &simp, width);
                assert_eq!(
                    result,
                    VerifierResult::Equivalent,
                    "unexpected result for width {width:?} benchmark {}",
                    index + 1
                );
            }
        }
    }

    #[test]
    fn reports_counterexample_for_non_equivalent_expressions() {
        let verifier = Z3Verifier::default();
        let width = Width::W8;
        let x = value(1);
        let y = value(2);
        let orig = binary(BinOp::Add, x.clone(), y.clone(), width);
        let simp = binary(BinOp::Xor, x, y, width);

        let result = verifier.prove_equivalent(&orig, &simp, width);
        match result {
            VerifierResult::NotEquivalent { counterexample } => {
                assert!(!counterexample.is_empty());
            }
            other => panic!("expected counterexample, got {other:?}"),
        }
    }

    #[test]
    fn enforces_timeout() {
        let verifier = Z3Verifier::new(Duration::from_millis(0));
        let width = Width::W32;
        let x = value(1);
        let y = value(2);
        let orig = binary(BinOp::Add, x.clone(), y.clone(), width);
        let simp = binary(BinOp::Add, x, y, width);

        assert_eq!(
            verifier.prove_equivalent(&orig, &simp, width),
            VerifierResult::Timeout
        );
    }
}

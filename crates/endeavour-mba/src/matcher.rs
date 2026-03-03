use endeavour_ir::ir::{BinOp, Expr, Stmt, UnOp, Width};

/// A detected MBA simplification candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbaMatch {
    /// Index of the statement that contains the matched expression.
    pub stmt_index: usize,
    /// Original expression subtree that matched the catalog entry.
    pub original: Expr,
    /// Structurally simplified expression produced by the matched identity.
    pub simplified: Expr,
    /// Z3-equivalence verification state.
    pub verified: bool,
}

type PatternFn = fn(&Expr) -> Option<Expr>;

/// Structural matcher for known linear MBA identities.
#[derive(Debug, Clone)]
pub struct MbaMatcher {
    patterns: Vec<PatternFn>,
}

impl MbaMatcher {
    /// Creates a matcher loaded with the benchmark pattern catalog.
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: vec![
                pattern_benchmark_1,
                pattern_benchmark_2,
                pattern_benchmark_3,
                pattern_benchmark_4,
                pattern_benchmark_5,
                pattern_benchmark_6,
                pattern_benchmark_7,
                pattern_benchmark_8,
                pattern_benchmark_9,
                pattern_benchmark_10,
            ],
        }
    }

    /// Scans all statements and returns MBA matches found in expression trees.
    #[must_use]
    pub fn scan(&self, stmts: &[Stmt]) -> Vec<MbaMatch> {
        let mut matches = Vec::new();

        for (stmt_index, stmt) in stmts.iter().enumerate() {
            self.visit_stmt(stmt_index, stmt, &mut matches);
        }

        matches
    }

    fn visit_stmt(&self, stmt_index: usize, stmt: &Stmt, matches: &mut Vec<MbaMatch>) {
        match stmt {
            Stmt::Assign { expr, .. } => self.visit_expr(stmt_index, expr, matches),
            Stmt::Store { addr, value, .. } => {
                self.visit_expr(stmt_index, addr, matches);
                self.visit_expr(stmt_index, value, matches);
            }
            Stmt::Branch { cond, .. } => self.visit_expr(stmt_index, cond, matches),
            Stmt::Call { target, args, .. } => {
                self.visit_expr(stmt_index, target, matches);
                for arg in args {
                    self.visit_expr(stmt_index, arg, matches);
                }
            }
            Stmt::Return { value } => {
                if let Some(expr) = value {
                    self.visit_expr(stmt_index, expr, matches);
                }
            }
            Stmt::Unknown { args, .. } => {
                for arg in args {
                    self.visit_expr(stmt_index, arg, matches);
                }
            }
            Stmt::Jump { .. } | Stmt::Phi { .. } => {}
        }
    }

    fn visit_expr(&self, stmt_index: usize, expr: &Expr, matches: &mut Vec<MbaMatch>) {
        if let Some(simplified) = self.match_expr(expr) {
            matches.push(MbaMatch {
                stmt_index,
                original: expr.clone(),
                simplified,
                verified: false,
            });
        }

        match expr {
            Expr::Unary { arg, .. } => self.visit_expr(stmt_index, arg, matches),
            Expr::Binary { lhs, rhs, .. } => {
                self.visit_expr(stmt_index, lhs, matches);
                self.visit_expr(stmt_index, rhs, matches);
            }
            Expr::Load { addr, .. } => self.visit_expr(stmt_index, addr, matches),
            Expr::Slice { src, .. } => self.visit_expr(stmt_index, src, matches),
            Expr::Concat { hi, lo } => {
                self.visit_expr(stmt_index, hi, matches);
                self.visit_expr(stmt_index, lo, matches);
            }
            Expr::Const { .. } | Expr::Value { .. } => {}
        }
    }

    fn match_expr(&self, expr: &Expr) -> Option<Expr> {
        for pattern in &self.patterns {
            if let Some(simplified) = pattern(expr) {
                return Some(simplified);
            }
        }

        None
    }
}

impl Default for MbaMatcher {
    fn default() -> Self {
        Self::new()
    }
}

fn pattern_benchmark_1(expr: &Expr) -> Option<Expr> {
    let (xor_expr, mul_expr, width) = match_add_commutative(expr)?;
    let (x, y, _) = match_binary(BinOp::Xor, xor_expr)?;
    let (ax, ay) = match_two_times_and(mul_expr)?;

    if same_pair(x, y, ax, ay) {
        return Some(bin(BinOp::Add, x.clone(), y.clone(), width));
    }

    None
}

fn pattern_benchmark_2(expr: &Expr) -> Option<Expr> {
    let (or_expr, xor_expr, width) = match_binary(BinOp::Sub, expr)?;
    let (x1, y1, _) = match_binary(BinOp::Or, or_expr)?;
    let (x2, y2, _) = match_binary(BinOp::Xor, xor_expr)?;

    if same_pair(x1, y1, x2, y2) {
        return Some(bin(BinOp::And, x1.clone(), y1.clone(), width));
    }

    None
}

fn pattern_benchmark_3(expr: &Expr) -> Option<Expr> {
    let (and_expr, or_expr, width) = match_add_commutative(expr)?;
    let (x1, y1, _) = match_binary(BinOp::And, and_expr)?;
    let (x2, y2, _) = match_binary(BinOp::Or, or_expr)?;

    if same_pair(x1, y1, x2, y2) {
        return Some(bin(BinOp::Add, x1.clone(), y1.clone(), width));
    }

    None
}

fn pattern_benchmark_4(expr: &Expr) -> Option<Expr> {
    pattern_benchmark_1(expr)
}

fn pattern_benchmark_5(expr: &Expr) -> Option<Expr> {
    pattern_benchmark_3(expr)
}

fn pattern_benchmark_6(expr: &Expr) -> Option<Expr> {
    let (or_expr, not_x_expr, width) = match_binary(BinOp::Sub, expr)?;
    let x = match_unary(UnOp::BitNot, not_x_expr)?;

    let (or_lhs, or_rhs, _) = match_binary(BinOp::Or, or_expr)?;
    if let Some(left_inner) = match_unary(UnOp::BitNot, or_lhs) {
        if left_inner == x {
            return Some(bin(BinOp::And, x.clone(), or_rhs.clone(), width));
        }
    }

    if let Some(right_inner) = match_unary(UnOp::BitNot, or_rhs) {
        if right_inner == x {
            return Some(bin(BinOp::And, x.clone(), or_lhs.clone(), width));
        }
    }

    None
}

fn pattern_benchmark_7(expr: &Expr) -> Option<Expr> {
    let (lhs, rhs, width) = match_binary(BinOp::Or, expr)?;

    for (primary, secondary) in [(lhs, rhs), (rhs, lhs)] {
        let (a1, a2, _) = match_binary(BinOp::And, primary)?;
        let (b1, b2, _) = match_binary(BinOp::And, secondary)?;

        if let (Some(not_a2), Some(not_b1)) =
            (match_unary(UnOp::BitNot, a2), match_unary(UnOp::BitNot, b1))
        {
            if a1 == not_b1 && not_a2 == b2 {
                return Some(bin(BinOp::Xor, a1.clone(), b2.clone(), width));
            }
        }

        if let (Some(not_a1), Some(not_b2)) =
            (match_unary(UnOp::BitNot, a1), match_unary(UnOp::BitNot, b2))
        {
            if a2 == not_b2 && not_a1 == b1 {
                return Some(bin(BinOp::Xor, a2.clone(), b1.clone(), width));
            }
        }
    }

    None
}

fn pattern_benchmark_8(expr: &Expr) -> Option<Expr> {
    let (inner, width) = match_unary_only(UnOp::BitNot, expr)?;
    let (n1, n2, _) = match_binary(BinOp::And, inner)?;
    let x = match_unary(UnOp::BitNot, n1)?;
    let y = match_unary(UnOp::BitNot, n2)?;
    Some(bin(BinOp::Or, x.clone(), y.clone(), width))
}

fn pattern_benchmark_9(expr: &Expr) -> Option<Expr> {
    let (inner, width) = match_unary_only(UnOp::BitNot, expr)?;
    let (n1, n2, _) = match_binary(BinOp::Or, inner)?;
    let x = match_unary(UnOp::BitNot, n1)?;
    let y = match_unary(UnOp::BitNot, n2)?;
    Some(bin(BinOp::And, x.clone(), y.clone(), width))
}

fn pattern_benchmark_10(expr: &Expr) -> Option<Expr> {
    let (add_expr, mul_expr, width) = match_binary(BinOp::Sub, expr)?;
    let (x, y, _) = match_binary(BinOp::Add, add_expr)?;
    let (ax, ay) = match_two_times_and(mul_expr)?;

    if same_pair(x, y, ax, ay) {
        return Some(bin(BinOp::Xor, x.clone(), y.clone(), width));
    }

    None
}

fn match_add_commutative(expr: &Expr) -> Option<(&Expr, &Expr, Width)> {
    let (lhs, rhs, width) = match_binary(BinOp::Add, expr)?;

    if matches_binary(BinOp::Xor, lhs) && matches_binary(BinOp::Mul, rhs) {
        return Some((lhs, rhs, width));
    }

    if matches_binary(BinOp::Xor, rhs) && matches_binary(BinOp::Mul, lhs) {
        return Some((rhs, lhs, width));
    }

    if matches_binary(BinOp::And, lhs) && matches_binary(BinOp::Or, rhs) {
        return Some((lhs, rhs, width));
    }

    if matches_binary(BinOp::And, rhs) && matches_binary(BinOp::Or, lhs) {
        return Some((rhs, lhs, width));
    }

    None
}

fn match_two_times_and(expr: &Expr) -> Option<(&Expr, &Expr)> {
    let (lhs, rhs, _) = match_binary(BinOp::Mul, expr)?;

    if is_const_equivalent(lhs, 2) {
        return match_binary(BinOp::And, rhs).map(|(a, b, _)| (a, b));
    }

    if is_const_equivalent(rhs, 2) {
        return match_binary(BinOp::And, lhs).map(|(a, b, _)| (a, b));
    }

    None
}

fn match_unary(op: UnOp, expr: &Expr) -> Option<&Expr> {
    if let Expr::Unary {
        op: candidate, arg, ..
    } = expr
    {
        if *candidate == op {
            return Some(arg);
        }
    }

    None
}

fn match_unary_only(op: UnOp, expr: &Expr) -> Option<(&Expr, Width)> {
    if let Expr::Unary {
        op: candidate,
        arg,
        width,
    } = expr
    {
        if *candidate == op {
            return Some((arg, *width));
        }
    }

    None
}

fn match_binary(op: BinOp, expr: &Expr) -> Option<(&Expr, &Expr, Width)> {
    if let Expr::Binary {
        op: candidate,
        lhs,
        rhs,
        width,
    } = expr
    {
        if *candidate == op {
            return Some((lhs, rhs, *width));
        }
    }

    None
}

fn matches_binary(op: BinOp, expr: &Expr) -> bool {
    match_binary(op, expr).is_some()
}

fn same_pair(a1: &Expr, a2: &Expr, b1: &Expr, b2: &Expr) -> bool {
    (a1 == b1 && a2 == b2) || (a1 == b2 && a2 == b1)
}

fn is_const_equivalent(expr: &Expr, expected: u128) -> bool {
    if let Expr::Const { value, width } = expr {
        return normalize_const(*value, *width) == normalize_const(expected, *width);
    }

    false
}

fn normalize_const(value: u128, width: Width) -> u128 {
    let bits = width_bits(width);
    if bits == 128 {
        return value;
    }

    let mask = (1u128 << bits) - 1;
    value & mask
}

fn width_bits(width: Width) -> u32 {
    match width {
        Width::W1 => 1,
        Width::W8 => 8,
        Width::W16 => 16,
        Width::W32 => 32,
        Width::W64 => 64,
        Width::W128 => 128,
    }
}

fn bin(op: BinOp, lhs: Expr, rhs: Expr, width: Width) -> Expr {
    Expr::Binary {
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
        width,
    }
}

#[cfg(test)]
mod tests {
    use super::MbaMatcher;
    use endeavour_ir::ir::{BinOp, Expr, Stmt, UnOp, ValueId, Width};

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

    #[test]
    fn benchmark_expressions_detected() {
        let width = Width::W32;
        let x = value(1);
        let y = value(2);
        let two = const_w(2, width);

        let expressions = vec![
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
            binary(
                BinOp::Sub,
                binary(BinOp::Or, x.clone(), y.clone(), width),
                binary(BinOp::Xor, x.clone(), y.clone(), width),
                width,
            ),
            binary(
                BinOp::Add,
                binary(BinOp::And, x.clone(), y.clone(), width),
                binary(BinOp::Or, x.clone(), y.clone(), width),
                width,
            ),
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
            binary(
                BinOp::Add,
                binary(BinOp::Or, x.clone(), y.clone(), width),
                binary(BinOp::And, x.clone(), y.clone(), width),
                width,
            ),
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
        ];

        let stmts: Vec<Stmt> = expressions
            .into_iter()
            .enumerate()
            .map(|(index, expr)| Stmt::Assign {
                dst: ValueId(index as u32),
                expr,
            })
            .collect();

        let matcher = MbaMatcher::new();
        let matches = matcher.scan(&stmts);

        assert_eq!(matches.len(), 10);
        assert!(matches.iter().all(|entry| !entry.verified));
    }
}

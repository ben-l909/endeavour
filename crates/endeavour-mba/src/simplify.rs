use crate::ast::Expr;

/// Simplifies an MBA expression using rewrite rules until fixed point.
pub fn simplify(expr: &Expr) -> Expr {
    let mut current = expr.clone();

    loop {
        let next = simplify_once(&current);
        if next == current {
            return next;
        }
        current = next;
    }
}

fn simplify_once(expr: &Expr) -> Expr {
    let rewritten_children = match expr {
        Expr::Var(_) | Expr::Const(_) => expr.clone(),
        Expr::Not(inner) => Expr::not(simplify(inner)),
        Expr::Add(lhs, rhs) => Expr::add(simplify(lhs), simplify(rhs)),
        Expr::Sub(lhs, rhs) => Expr::sub(simplify(lhs), simplify(rhs)),
        Expr::Mul(lhs, rhs) => Expr::mul(simplify(lhs), simplify(rhs)),
        Expr::And(lhs, rhs) => Expr::and(simplify(lhs), simplify(rhs)),
        Expr::Or(lhs, rhs) => Expr::or(simplify(lhs), simplify(rhs)),
        Expr::Xor(lhs, rhs) => Expr::xor(simplify(lhs), simplify(rhs)),
    };

    apply_basic_identities(rewritten_children)
}

fn apply_basic_identities(expr: Expr) -> Expr {
    let expr = match expr {
        Expr::Add(lhs, rhs) if matches!(*lhs, Expr::Const(0)) => *rhs,
        Expr::Add(lhs, rhs) if matches!(*rhs, Expr::Const(0)) => *lhs,
        Expr::Sub(lhs, rhs) if matches!(*rhs, Expr::Const(0)) => *lhs,
        Expr::Mul(lhs, rhs) if matches!(*lhs, Expr::Const(1)) => *rhs,
        Expr::Mul(lhs, rhs) if matches!(*rhs, Expr::Const(1)) => *lhs,
        Expr::Mul(_, rhs) if matches!(*rhs, Expr::Const(0)) => Expr::constant(0),
        Expr::Mul(lhs, _) if matches!(*lhs, Expr::Const(0)) => Expr::constant(0),
        Expr::And(lhs, rhs) if lhs == rhs => *lhs,
        Expr::Or(lhs, rhs) if lhs == rhs => *lhs,
        Expr::Xor(lhs, rhs) if lhs == rhs => Expr::constant(0),
        other => other,
    };

    if let Some(rewrite) = rule_xor_plus_two_and_to_add(&expr) {
        return rewrite;
    }

    if let Some(rewrite) = rule_or_minus_and_not_to_rhs(&expr) {
        return rewrite;
    }

    if let Some(rewrite) = rule_and_partition_to_lhs(&expr) {
        return rewrite;
    }

    expr
}

fn rule_xor_plus_two_and_to_add(expr: &Expr) -> Option<Expr> {
    let (left, right) = binary_operands(expr, BinaryKind::Add)?;
    let (xor_side, mul_side) = if is_xor(left) {
        (left, right)
    } else if is_xor(right) {
        (right, left)
    } else {
        return None;
    };

    let (x, y) = binary_operands(xor_side, BinaryKind::Xor)?;
    let (and_x, and_y) = two_times_and_operands(mul_side)?;
    if same_pair(x, y, and_x, and_y) {
        return Some(Expr::add(x.clone(), y.clone()));
    }

    None
}

fn rule_or_minus_and_not_to_rhs(expr: &Expr) -> Option<Expr> {
    let (left, right) = binary_operands(expr, BinaryKind::Sub)?;
    let (or_lhs, or_rhs) = binary_operands(left, BinaryKind::Or)?;
    let (and_lhs, and_rhs) = binary_operands(right, BinaryKind::And)?;

    if or_lhs != and_lhs {
        return None;
    }

    let not_inner = not_operand(and_rhs)?;
    if or_rhs == not_inner {
        return Some(or_rhs.clone());
    }

    None
}

fn rule_and_partition_to_lhs(expr: &Expr) -> Option<Expr> {
    let (left, right) = binary_operands(expr, BinaryKind::Or)?;
    and_partition_match(left, right).or_else(|| and_partition_match(right, left))
}

fn and_partition_match(primary: &Expr, secondary: &Expr) -> Option<Expr> {
    let (lhs_a, lhs_b) = binary_operands(primary, BinaryKind::And)?;
    let (rhs_a, rhs_b) = binary_operands(secondary, BinaryKind::And)?;

    if lhs_a != rhs_a {
        return None;
    }

    let negated = not_operand(rhs_b)?;
    if lhs_b == negated {
        return Some(lhs_a.clone());
    }

    None
}

fn two_times_and_operands(expr: &Expr) -> Option<(&Expr, &Expr)> {
    let (lhs, rhs) = binary_operands(expr, BinaryKind::Mul)?;

    if matches!(lhs, Expr::Const(2)) {
        return binary_operands(rhs, BinaryKind::And);
    }

    if matches!(rhs, Expr::Const(2)) {
        return binary_operands(lhs, BinaryKind::And);
    }

    None
}

fn same_pair(a1: &Expr, a2: &Expr, b1: &Expr, b2: &Expr) -> bool {
    (a1 == b1 && a2 == b2) || (a1 == b2 && a2 == b1)
}

fn is_xor(expr: &Expr) -> bool {
    matches!(expr, Expr::Xor(_, _))
}

fn not_operand(expr: &Expr) -> Option<&Expr> {
    if let Expr::Not(inner) = expr {
        return Some(inner);
    }
    None
}

fn binary_operands(expr: &Expr, kind: BinaryKind) -> Option<(&Expr, &Expr)> {
    match (kind, expr) {
        (BinaryKind::Add, Expr::Add(lhs, rhs))
        | (BinaryKind::Sub, Expr::Sub(lhs, rhs))
        | (BinaryKind::Mul, Expr::Mul(lhs, rhs))
        | (BinaryKind::And, Expr::And(lhs, rhs))
        | (BinaryKind::Or, Expr::Or(lhs, rhs))
        | (BinaryKind::Xor, Expr::Xor(lhs, rhs)) => Some((lhs, rhs)),
        _ => None,
    }
}

#[derive(Copy, Clone)]
enum BinaryKind {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
}

#[cfg(test)]
mod tests {
    use crate::{simplify, Expr};

    #[test]
    fn simplifies_xor_plus_two_and_to_add() {
        let x = Expr::var("x");
        let y = Expr::var("y");
        let expr = Expr::add(
            Expr::xor(x.clone(), y.clone()),
            Expr::mul(Expr::constant(2), Expr::and(x.clone(), y.clone())),
        );

        let simplified = simplify(&expr);
        assert_eq!(simplified, Expr::add(x, y));
    }

    #[test]
    fn simplifies_or_minus_and_not_to_rhs() {
        let x = Expr::var("x");
        let y = Expr::var("y");
        let expr = Expr::sub(
            Expr::or(x.clone(), y.clone()),
            Expr::and(x, Expr::not(y.clone())),
        );

        let simplified = simplify(&expr);
        assert_eq!(simplified, y);
    }

    #[test]
    fn simplifies_and_partition_to_lhs() {
        let x = Expr::var("x");
        let y = Expr::var("y");
        let expr = Expr::or(
            Expr::and(x.clone(), y.clone()),
            Expr::and(x.clone(), Expr::not(y)),
        );

        let simplified = simplify(&expr);
        assert_eq!(simplified, x);
    }
}

//! `ast.dump(expr, annotate_fields=False)` as CPython 3.13 prints it — what
//! `swallowed-exception` names a handler's type by when it is not a bare
//! name (`except (A, B):`, `except mod.Error:`).
//!
//! 3.13's `dump` omits `None` optional fields and empty lists: an omitted
//! optional field (one whose class default is `None`) switches every later
//! field to `name=value` form, while an omitted empty list is only buffered
//! and printed (as `[]`) if a later field is printed positionally.

use crate::pyast::{py_boolop_name, py_cmpop_name, py_operator_name, py_unaryop_name};
use crate::unparse::{py_repr_bytes, py_repr_str, write_constant_repr};
use rustpython_ast::{
    Arguments, Comprehension, Constant, ConversionFlag, Expr, ExprContext, Keyword,
};

enum Field {
    /// A `None` in a field whose class default is `None`.
    OptionalNone,
    /// An empty list (or a `None` in a required field): buffered.
    Empty(&'static str),
    Value(String),
}

fn node(name: &str, fields: Vec<(&str, Field)>) -> String {
    let mut args: Vec<String> = Vec::new();
    let mut buffer: Vec<&str> = Vec::new();
    let mut keywords = false;
    for (field, value) in fields {
        match value {
            Field::OptionalNone => keywords = true,
            Field::Empty(repr) => buffer.push(repr),
            Field::Value(v) => {
                if keywords {
                    args.push(format!("{field}={v}"));
                } else {
                    args.extend(buffer.drain(..).map(str::to_string));
                    args.push(v);
                }
            }
        }
    }
    format!("{name}({})", args.join(", "))
}

fn list(items: Vec<String>) -> Field {
    if items.is_empty() {
        Field::Empty("[]")
    } else {
        Field::Value(format!("[{}]", items.join(", ")))
    }
}

fn exprs(items: &[Expr]) -> Field {
    list(items.iter().map(dump_expr).collect())
}

fn opt(e: Option<&Expr>) -> Field {
    e.map_or(Field::OptionalNone, |e| Field::Value(dump_expr(e)))
}

fn val(e: &Expr) -> Field {
    Field::Value(dump_expr(e))
}

fn ctx(c: &ExprContext) -> Field {
    Field::Value(
        match c {
            ExprContext::Load => "Load()",
            ExprContext::Store => "Store()",
            ExprContext::Del => "Del()",
        }
        .to_string(),
    )
}

fn op(name: &str) -> Field {
    Field::Value(format!("{name}()"))
}

fn ident(s: &str) -> Field {
    Field::Value(py_repr_str(s))
}

fn constant_value(c: &Constant) -> String {
    match c {
        Constant::Ellipsis => "Ellipsis".to_string(),
        Constant::Str(s) => py_repr_str(s),
        Constant::Bytes(b) => py_repr_bytes(b),
        other => write_constant_repr(other),
    }
}

fn keyword(k: &Keyword) -> String {
    node(
        "keyword",
        vec![
            (
                "arg",
                k.arg
                    .as_ref()
                    .map_or(Field::OptionalNone, |a| ident(a.as_str())),
            ),
            ("value", val(&k.value)),
        ],
    )
}

fn comprehension(c: &Comprehension) -> String {
    node(
        "comprehension",
        vec![
            ("target", val(&c.target)),
            ("iter", val(&c.iter)),
            ("ifs", exprs(&c.ifs)),
            ("is_async", Field::Value(u8::from(c.is_async).to_string())),
        ],
    )
}

fn arg(a: &rustpython_ast::Arg) -> String {
    node(
        "arg",
        vec![
            ("arg", ident(a.arg.as_str())),
            ("annotation", opt(a.annotation.as_deref())),
        ],
    )
}

fn arguments(a: &Arguments) -> String {
    let defaults: Vec<String> = a
        .posonlyargs
        .iter()
        .chain(&a.args)
        .filter_map(|p| p.default.as_deref().map(dump_expr))
        .collect();
    let kw_defaults: Vec<String> = a
        .kwonlyargs
        .iter()
        .map(|p| p.default.as_deref().map_or("None".to_string(), dump_expr))
        .collect();
    node(
        "arguments",
        vec![
            (
                "posonlyargs",
                list(a.posonlyargs.iter().map(|p| arg(&p.def)).collect()),
            ),
            ("args", list(a.args.iter().map(|p| arg(&p.def)).collect())),
            (
                "vararg",
                a.vararg
                    .as_deref()
                    .map_or(Field::OptionalNone, |v| Field::Value(arg(v))),
            ),
            (
                "kwonlyargs",
                list(a.kwonlyargs.iter().map(|p| arg(&p.def)).collect()),
            ),
            ("kw_defaults", list(kw_defaults)),
            (
                "kwarg",
                a.kwarg
                    .as_deref()
                    .map_or(Field::OptionalNone, |k| Field::Value(arg(k))),
            ),
            ("defaults", list(defaults)),
        ],
    )
}

/// `ast.dump(expr, annotate_fields=False)`.
pub fn dump_expr(e: &Expr) -> String {
    match e {
        Expr::BoolOp(b) => node(
            "BoolOp",
            vec![
                ("op", op(py_boolop_name(&b.op))),
                ("values", exprs(&b.values)),
            ],
        ),
        Expr::NamedExpr(n) => node(
            "NamedExpr",
            vec![("target", val(&n.target)), ("value", val(&n.value))],
        ),
        Expr::BinOp(b) => node(
            "BinOp",
            vec![
                ("left", val(&b.left)),
                ("op", op(py_operator_name(&b.op))),
                ("right", val(&b.right)),
            ],
        ),
        Expr::UnaryOp(u) => node(
            "UnaryOp",
            vec![
                ("op", op(py_unaryop_name(&u.op))),
                ("operand", val(&u.operand)),
            ],
        ),
        Expr::Lambda(l) => node(
            "Lambda",
            vec![
                ("args", Field::Value(arguments(&l.args))),
                ("body", val(&l.body)),
            ],
        ),
        Expr::IfExp(i) => node(
            "IfExp",
            vec![
                ("test", val(&i.test)),
                ("body", val(&i.body)),
                ("orelse", val(&i.orelse)),
            ],
        ),
        Expr::Dict(d) => node(
            "Dict",
            vec![
                (
                    "keys",
                    list(
                        d.keys
                            .iter()
                            .map(|k| k.as_ref().map_or("None".to_string(), dump_expr))
                            .collect(),
                    ),
                ),
                ("values", exprs(&d.values)),
            ],
        ),
        Expr::Set(s) => node("Set", vec![("elts", exprs(&s.elts))]),
        Expr::ListComp(c) => node(
            "ListComp",
            vec![
                ("elt", val(&c.elt)),
                (
                    "generators",
                    list(c.generators.iter().map(comprehension).collect()),
                ),
            ],
        ),
        Expr::SetComp(c) => node(
            "SetComp",
            vec![
                ("elt", val(&c.elt)),
                (
                    "generators",
                    list(c.generators.iter().map(comprehension).collect()),
                ),
            ],
        ),
        Expr::DictComp(c) => node(
            "DictComp",
            vec![
                ("key", val(&c.key)),
                ("value", val(&c.value)),
                (
                    "generators",
                    list(c.generators.iter().map(comprehension).collect()),
                ),
            ],
        ),
        Expr::GeneratorExp(c) => node(
            "GeneratorExp",
            vec![
                ("elt", val(&c.elt)),
                (
                    "generators",
                    list(c.generators.iter().map(comprehension).collect()),
                ),
            ],
        ),
        Expr::Await(a) => node("Await", vec![("value", val(&a.value))]),
        Expr::Yield(y) => node("Yield", vec![("value", opt(y.value.as_deref()))]),
        Expr::YieldFrom(y) => node("YieldFrom", vec![("value", val(&y.value))]),
        Expr::Compare(c) => node(
            "Compare",
            vec![
                ("left", val(&c.left)),
                (
                    "ops",
                    list(
                        c.ops
                            .iter()
                            .map(|o| format!("{}()", py_cmpop_name(o)))
                            .collect(),
                    ),
                ),
                ("comparators", exprs(&c.comparators)),
            ],
        ),
        Expr::Call(c) => node(
            "Call",
            vec![
                ("func", val(&c.func)),
                ("args", exprs(&c.args)),
                ("keywords", list(c.keywords.iter().map(keyword).collect())),
            ],
        ),
        Expr::FormattedValue(f) => {
            let conversion = match f.conversion {
                ConversionFlag::None => -1,
                ConversionFlag::Str => i32::from(b's'),
                ConversionFlag::Ascii => i32::from(b'a'),
                ConversionFlag::Repr => i32::from(b'r'),
            };
            node(
                "FormattedValue",
                vec![
                    ("value", val(&f.value)),
                    ("conversion", Field::Value(conversion.to_string())),
                    ("format_spec", opt(f.format_spec.as_deref())),
                ],
            )
        }
        Expr::JoinedStr(j) => node("JoinedStr", vec![("values", exprs(&j.values))]),
        Expr::Constant(c) => node(
            "Constant",
            vec![
                ("value", Field::Value(constant_value(&c.value))),
                ("kind", c.kind.as_deref().map_or(Field::OptionalNone, ident)),
            ],
        ),
        Expr::Attribute(a) => node(
            "Attribute",
            vec![
                ("value", val(&a.value)),
                ("attr", ident(a.attr.as_str())),
                ("ctx", ctx(&a.ctx)),
            ],
        ),
        Expr::Subscript(s) => node(
            "Subscript",
            vec![
                ("value", val(&s.value)),
                ("slice", val(&s.slice)),
                ("ctx", ctx(&s.ctx)),
            ],
        ),
        Expr::Starred(s) => node(
            "Starred",
            vec![("value", val(&s.value)), ("ctx", ctx(&s.ctx))],
        ),
        Expr::Name(n) => node(
            "Name",
            vec![("id", ident(n.id.as_str())), ("ctx", ctx(&n.ctx))],
        ),
        Expr::List(l) => node("List", vec![("elts", exprs(&l.elts)), ("ctx", ctx(&l.ctx))]),
        Expr::Tuple(t) => node(
            "Tuple",
            vec![("elts", exprs(&t.elts)), ("ctx", ctx(&t.ctx))],
        ),
        Expr::Slice(s) => node(
            "Slice",
            vec![
                ("lower", opt(s.lower.as_deref())),
                ("upper", opt(s.upper.as_deref())),
                ("step", opt(s.step.as_deref())),
            ],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::dump_expr;
    use rustpython_parser::Parse;

    #[test]
    fn matches_cpython_313_dump() {
        // Expected: `ast.dump(ast.parse(src, mode="eval").body, annotate_fields=False)`.
        for (src, expected) in [
            (
                "(A, B)",
                "Tuple([Name('A', Load()), Name('B', Load())], Load())",
            ),
            (
                "f(k=1)",
                "Call(Name('f', Load()), [], [keyword('k', Constant(1))])",
            ),
            ("C()", "Call(Name('C', Load()))"),
            (
                "f(*a, **k)",
                "Call(Name('f', Load()), [Starred(Name('a', Load()), Load())], [keyword(value=Name('k', Load()))])",
            ),
            (
                "a[::2]",
                "Subscript(Name('a', Load()), Slice(step=Constant(2)), Load())",
            ),
            (
                "A | B",
                "BinOp(Name('A', Load()), BitOr(), Name('B', Load()))",
            ),
            ("(yield)", "Yield()"),
            ("lambda: 0", "Lambda(arguments(), Constant(0))"),
            ("u\"s\"", "Constant('s', 'u')"),
            ("None", "Constant(None)"),
            ("...", "Constant(Ellipsis)"),
        ] {
            let e = rustpython_ast::Expr::parse(src, "<t>").unwrap();
            assert_eq!(dump_expr(&e), expected, "{src}");
        }
    }
}

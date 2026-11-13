//! A Python-`ast`-shaped view of rustpython's tree: each node's CPython class
//! name and its children in `ast.iter_child_nodes` order (the `_fields`
//! order of Python 3.13), with operators surfaced as the nodes they are in
//! CPython (`Add`, `And`, `Eq`, ...).
//!
//! The metrics and the clone detector are specified in terms of the CPython
//! tree, and their numbers must match the Python port bit for bit, so every
//! traversal they do goes through this one mapping rather than through
//! rustpython's `Visitor` (which has no hook for several auxiliary nodes and
//! visits fields in rustpython's own order).

use rustpython_ast::text_size::TextSize;
use rustpython_ast::{
    Alias, Arg, Arguments, BoolOp, CmpOp, Comprehension, ExceptHandler, ExceptHandlerExceptHandler,
    Expr, Keyword, MatchCase, Operator, Pattern, Ranged, Stmt, TypeParam, UnaryOp, WithItem,
};

/// One node of the Python-shaped tree.
#[derive(Clone, Copy)]
pub enum Node<'a> {
    Stmt(&'a Stmt),
    Expr(&'a Expr),
    Pattern(&'a Pattern),
    Handler(&'a ExceptHandlerExceptHandler),
    Arguments(&'a Arguments),
    Arg(&'a Arg),
    Keyword(&'a Keyword),
    Alias(&'a Alias),
    WithItem(&'a WithItem),
    MatchCase(&'a MatchCase),
    Comprehension(&'a Comprehension),
    TypeParam(&'a TypeParam),
    /// An `operator`, `boolop`, `unaryop` or `cmpop` node — a leaf in CPython.
    Op(&'static str),
}

fn operator_name(op: &Operator) -> &'static str {
    match op {
        Operator::Add => "Add",
        Operator::Sub => "Sub",
        Operator::Mult => "Mult",
        Operator::MatMult => "MatMult",
        Operator::Div => "Div",
        Operator::Mod => "Mod",
        Operator::Pow => "Pow",
        Operator::LShift => "LShift",
        Operator::RShift => "RShift",
        Operator::BitOr => "BitOr",
        Operator::BitXor => "BitXor",
        Operator::BitAnd => "BitAnd",
        Operator::FloorDiv => "FloorDiv",
    }
}

fn boolop_name(op: &BoolOp) -> &'static str {
    match op {
        BoolOp::And => "And",
        BoolOp::Or => "Or",
    }
}

fn unaryop_name(op: &UnaryOp) -> &'static str {
    match op {
        UnaryOp::Invert => "Invert",
        UnaryOp::Not => "Not",
        UnaryOp::UAdd => "UAdd",
        UnaryOp::USub => "USub",
    }
}

fn cmpop_name(op: &CmpOp) -> &'static str {
    match op {
        CmpOp::Eq => "Eq",
        CmpOp::NotEq => "NotEq",
        CmpOp::Lt => "Lt",
        CmpOp::LtE => "LtE",
        CmpOp::Gt => "Gt",
        CmpOp::GtE => "GtE",
        CmpOp::Is => "Is",
        CmpOp::IsNot => "IsNot",
        CmpOp::In => "In",
        CmpOp::NotIn => "NotIn",
    }
}

/// `type(node).__name__` for a `BinOp`/`AugAssign` operator.
pub fn py_operator_name(op: &Operator) -> &'static str {
    operator_name(op)
}

/// `type(node).__name__` for a `BoolOp` operator.
pub fn py_boolop_name(op: &BoolOp) -> &'static str {
    boolop_name(op)
}

/// `type(node).__name__` for a `UnaryOp` operator.
pub fn py_unaryop_name(op: &UnaryOp) -> &'static str {
    unaryop_name(op)
}

/// `type(node).__name__` for a `Compare` operator.
pub fn py_cmpop_name(op: &CmpOp) -> &'static str {
    cmpop_name(op)
}

fn stmts<'a>(out: &mut Vec<Node<'a>>, body: &'a [Stmt]) {
    out.extend(body.iter().map(Node::Stmt));
}

fn exprs<'a>(out: &mut Vec<Node<'a>>, body: &'a [Expr]) {
    out.extend(body.iter().map(Node::Expr));
}

fn opt<'a>(out: &mut Vec<Node<'a>>, e: &'a Option<Box<Expr>>) {
    if let Some(e) = e {
        out.push(Node::Expr(e));
    }
}

impl<'a> Node<'a> {
    /// `type(node).__name__`.
    pub fn py_name(self) -> &'static str {
        match self {
            Node::Stmt(s) => match s {
                Stmt::FunctionDef(_) => "FunctionDef",
                Stmt::AsyncFunctionDef(_) => "AsyncFunctionDef",
                Stmt::ClassDef(_) => "ClassDef",
                Stmt::Return(_) => "Return",
                Stmt::Delete(_) => "Delete",
                Stmt::Assign(_) => "Assign",
                Stmt::TypeAlias(_) => "TypeAlias",
                Stmt::AugAssign(_) => "AugAssign",
                Stmt::AnnAssign(_) => "AnnAssign",
                Stmt::For(_) => "For",
                Stmt::AsyncFor(_) => "AsyncFor",
                Stmt::While(_) => "While",
                Stmt::If(_) => "If",
                Stmt::With(_) => "With",
                Stmt::AsyncWith(_) => "AsyncWith",
                Stmt::Match(_) => "Match",
                Stmt::Raise(_) => "Raise",
                Stmt::Try(_) => "Try",
                Stmt::TryStar(_) => "TryStar",
                Stmt::Assert(_) => "Assert",
                Stmt::Import(_) => "Import",
                Stmt::ImportFrom(_) => "ImportFrom",
                Stmt::Global(_) => "Global",
                Stmt::Nonlocal(_) => "Nonlocal",
                Stmt::Expr(_) => "Expr",
                Stmt::Pass(_) => "Pass",
                Stmt::Break(_) => "Break",
                Stmt::Continue(_) => "Continue",
            },
            Node::Expr(e) => match e {
                Expr::BoolOp(_) => "BoolOp",
                Expr::NamedExpr(_) => "NamedExpr",
                Expr::BinOp(_) => "BinOp",
                Expr::UnaryOp(_) => "UnaryOp",
                Expr::Lambda(_) => "Lambda",
                Expr::IfExp(_) => "IfExp",
                Expr::Dict(_) => "Dict",
                Expr::Set(_) => "Set",
                Expr::ListComp(_) => "ListComp",
                Expr::SetComp(_) => "SetComp",
                Expr::DictComp(_) => "DictComp",
                Expr::GeneratorExp(_) => "GeneratorExp",
                Expr::Await(_) => "Await",
                Expr::Yield(_) => "Yield",
                Expr::YieldFrom(_) => "YieldFrom",
                Expr::Compare(_) => "Compare",
                Expr::Call(_) => "Call",
                Expr::FormattedValue(_) => "FormattedValue",
                Expr::JoinedStr(_) => "JoinedStr",
                Expr::Constant(_) => "Constant",
                Expr::Attribute(_) => "Attribute",
                Expr::Subscript(_) => "Subscript",
                Expr::Starred(_) => "Starred",
                Expr::Name(_) => "Name",
                Expr::List(_) => "List",
                Expr::Tuple(_) => "Tuple",
                Expr::Slice(_) => "Slice",
            },
            Node::Pattern(p) => match p {
                Pattern::MatchValue(_) => "MatchValue",
                Pattern::MatchSingleton(_) => "MatchSingleton",
                Pattern::MatchSequence(_) => "MatchSequence",
                Pattern::MatchMapping(_) => "MatchMapping",
                Pattern::MatchClass(_) => "MatchClass",
                Pattern::MatchStar(_) => "MatchStar",
                Pattern::MatchAs(_) => "MatchAs",
                Pattern::MatchOr(_) => "MatchOr",
            },
            Node::Handler(_) => "ExceptHandler",
            Node::Arguments(_) => "arguments",
            Node::Arg(_) => "arg",
            Node::Keyword(_) => "keyword",
            Node::Alias(_) => "alias",
            Node::WithItem(_) => "withitem",
            Node::MatchCase(_) => "match_case",
            Node::Comprehension(_) => "comprehension",
            Node::TypeParam(t) => match t {
                TypeParam::TypeVar(_) => "TypeVar",
                TypeParam::ParamSpec(_) => "ParamSpec",
                TypeParam::TypeVarTuple(_) => "TypeVarTuple",
            },
            Node::Op(name) => name,
        }
    }

    /// How many of CPython's string-valued identifier fields (`id`, `arg`,
    /// `attr`, `name`, `asname`, `module`, `rest`) this node carries a value
    /// for.
    pub fn identifier_count(self) -> usize {
        match self {
            Node::Expr(Expr::Name(_)) | Node::Expr(Expr::Attribute(_)) | Node::Arg(_) => 1,
            Node::Stmt(Stmt::FunctionDef(_))
            | Node::Stmt(Stmt::AsyncFunctionDef(_))
            | Node::Stmt(Stmt::ClassDef(_))
            | Node::TypeParam(_) => 1,
            Node::Stmt(Stmt::ImportFrom(i)) => usize::from(i.module.is_some()),
            Node::Keyword(k) => usize::from(k.arg.is_some()),
            Node::Alias(a) => 1 + usize::from(a.asname.is_some()),
            Node::Handler(h) => usize::from(h.name.is_some()),
            Node::Pattern(Pattern::MatchAs(p)) => usize::from(p.name.is_some()),
            Node::Pattern(Pattern::MatchStar(p)) => usize::from(p.name.is_some()),
            Node::Pattern(Pattern::MatchMapping(p)) => usize::from(p.rest.is_some()),
            _ => 0,
        }
    }

    /// Start offset for nodes that have a `lineno` in CPython; `None` for
    /// `arguments`, `comprehension`, `withitem` and `match_case`, which do
    /// not (they inherit their parent's line wherever a line is needed).
    pub fn start(self) -> Option<TextSize> {
        match self {
            Node::Stmt(s) => Some(s.range().start()),
            Node::Expr(e) => Some(e.range().start()),
            Node::Pattern(p) => Some(p.range().start()),
            Node::Handler(h) => Some(h.range.start()),
            Node::Arg(a) => Some(a.range.start()),
            Node::Keyword(k) => Some(k.range.start()),
            Node::Alias(a) => Some(a.range.start()),
            Node::TypeParam(t) => Some(t.range().start()),
            Node::Arguments(_)
            | Node::WithItem(_)
            | Node::MatchCase(_)
            | Node::Comprehension(_)
            | Node::Op(_) => None,
        }
    }

    pub fn is_scope_def(self) -> bool {
        matches!(
            self,
            Node::Stmt(Stmt::FunctionDef(_) | Stmt::AsyncFunctionDef(_) | Stmt::ClassDef(_))
        )
    }

    /// `ast.iter_child_nodes(node)`: every direct child AST node, in field
    /// order, skipping `None` fields and non-node values (identifiers,
    /// constants, `expr_context`, ints).
    pub fn children(self) -> Vec<Node<'a>> {
        let mut out: Vec<Node<'a>> = Vec::new();
        match self {
            Node::Stmt(s) => match s {
                Stmt::FunctionDef(f) => {
                    out.push(Node::Arguments(&f.args));
                    stmts(&mut out, &f.body);
                    exprs(&mut out, &f.decorator_list);
                    opt(&mut out, &f.returns);
                    out.extend(f.type_params.iter().map(Node::TypeParam));
                }
                Stmt::AsyncFunctionDef(f) => {
                    out.push(Node::Arguments(&f.args));
                    stmts(&mut out, &f.body);
                    exprs(&mut out, &f.decorator_list);
                    opt(&mut out, &f.returns);
                    out.extend(f.type_params.iter().map(Node::TypeParam));
                }
                Stmt::ClassDef(c) => {
                    exprs(&mut out, &c.bases);
                    out.extend(c.keywords.iter().map(Node::Keyword));
                    stmts(&mut out, &c.body);
                    exprs(&mut out, &c.decorator_list);
                    out.extend(c.type_params.iter().map(Node::TypeParam));
                }
                Stmt::Return(r) => opt(&mut out, &r.value),
                Stmt::Delete(d) => exprs(&mut out, &d.targets),
                Stmt::Assign(a) => {
                    exprs(&mut out, &a.targets);
                    out.push(Node::Expr(&a.value));
                }
                Stmt::TypeAlias(t) => {
                    out.push(Node::Expr(&t.name));
                    out.extend(t.type_params.iter().map(Node::TypeParam));
                    out.push(Node::Expr(&t.value));
                }
                Stmt::AugAssign(a) => {
                    out.push(Node::Expr(&a.target));
                    out.push(Node::Op(operator_name(&a.op)));
                    out.push(Node::Expr(&a.value));
                }
                Stmt::AnnAssign(a) => {
                    out.push(Node::Expr(&a.target));
                    out.push(Node::Expr(&a.annotation));
                    opt(&mut out, &a.value);
                }
                Stmt::For(f) => {
                    out.push(Node::Expr(&f.target));
                    out.push(Node::Expr(&f.iter));
                    stmts(&mut out, &f.body);
                    stmts(&mut out, &f.orelse);
                }
                Stmt::AsyncFor(f) => {
                    out.push(Node::Expr(&f.target));
                    out.push(Node::Expr(&f.iter));
                    stmts(&mut out, &f.body);
                    stmts(&mut out, &f.orelse);
                }
                Stmt::While(w) => {
                    out.push(Node::Expr(&w.test));
                    stmts(&mut out, &w.body);
                    stmts(&mut out, &w.orelse);
                }
                Stmt::If(i) => {
                    out.push(Node::Expr(&i.test));
                    stmts(&mut out, &i.body);
                    stmts(&mut out, &i.orelse);
                }
                Stmt::With(w) => {
                    out.extend(w.items.iter().map(Node::WithItem));
                    stmts(&mut out, &w.body);
                }
                Stmt::AsyncWith(w) => {
                    out.extend(w.items.iter().map(Node::WithItem));
                    stmts(&mut out, &w.body);
                }
                Stmt::Match(m) => {
                    out.push(Node::Expr(&m.subject));
                    out.extend(m.cases.iter().map(Node::MatchCase));
                }
                Stmt::Raise(r) => {
                    opt(&mut out, &r.exc);
                    opt(&mut out, &r.cause);
                }
                Stmt::Try(t) => {
                    stmts(&mut out, &t.body);
                    out.extend(t.handlers.iter().map(|h| {
                        let ExceptHandler::ExceptHandler(h) = h;
                        Node::Handler(h)
                    }));
                    stmts(&mut out, &t.orelse);
                    stmts(&mut out, &t.finalbody);
                }
                Stmt::TryStar(t) => {
                    stmts(&mut out, &t.body);
                    out.extend(t.handlers.iter().map(|h| {
                        let ExceptHandler::ExceptHandler(h) = h;
                        Node::Handler(h)
                    }));
                    stmts(&mut out, &t.orelse);
                    stmts(&mut out, &t.finalbody);
                }
                Stmt::Assert(a) => {
                    out.push(Node::Expr(&a.test));
                    opt(&mut out, &a.msg);
                }
                Stmt::Import(i) => out.extend(i.names.iter().map(Node::Alias)),
                Stmt::ImportFrom(i) => out.extend(i.names.iter().map(Node::Alias)),
                Stmt::Global(_) | Stmt::Nonlocal(_) | Stmt::Pass(_) | Stmt::Break(_) => {}
                Stmt::Continue(_) => {}
                Stmt::Expr(e) => out.push(Node::Expr(&e.value)),
            },
            Node::Expr(e) => match e {
                Expr::BoolOp(b) => {
                    out.push(Node::Op(boolop_name(&b.op)));
                    exprs(&mut out, &b.values);
                }
                Expr::NamedExpr(n) => {
                    out.push(Node::Expr(&n.target));
                    out.push(Node::Expr(&n.value));
                }
                Expr::BinOp(b) => {
                    out.push(Node::Expr(&b.left));
                    out.push(Node::Op(operator_name(&b.op)));
                    out.push(Node::Expr(&b.right));
                }
                Expr::UnaryOp(u) => {
                    out.push(Node::Op(unaryop_name(&u.op)));
                    out.push(Node::Expr(&u.operand));
                }
                Expr::Lambda(l) => {
                    out.push(Node::Arguments(&l.args));
                    out.push(Node::Expr(&l.body));
                }
                Expr::IfExp(i) => {
                    out.push(Node::Expr(&i.test));
                    out.push(Node::Expr(&i.body));
                    out.push(Node::Expr(&i.orelse));
                }
                Expr::Dict(d) => {
                    out.extend(d.keys.iter().flatten().map(Node::Expr));
                    exprs(&mut out, &d.values);
                }
                Expr::Set(s) => exprs(&mut out, &s.elts),
                Expr::ListComp(c) => {
                    out.push(Node::Expr(&c.elt));
                    out.extend(c.generators.iter().map(Node::Comprehension));
                }
                Expr::SetComp(c) => {
                    out.push(Node::Expr(&c.elt));
                    out.extend(c.generators.iter().map(Node::Comprehension));
                }
                Expr::DictComp(c) => {
                    out.push(Node::Expr(&c.key));
                    out.push(Node::Expr(&c.value));
                    out.extend(c.generators.iter().map(Node::Comprehension));
                }
                Expr::GeneratorExp(c) => {
                    out.push(Node::Expr(&c.elt));
                    out.extend(c.generators.iter().map(Node::Comprehension));
                }
                Expr::Await(a) => out.push(Node::Expr(&a.value)),
                Expr::Yield(y) => opt(&mut out, &y.value),
                Expr::YieldFrom(y) => out.push(Node::Expr(&y.value)),
                Expr::Compare(c) => {
                    out.push(Node::Expr(&c.left));
                    out.extend(c.ops.iter().map(|op| Node::Op(cmpop_name(op))));
                    exprs(&mut out, &c.comparators);
                }
                Expr::Call(c) => {
                    out.push(Node::Expr(&c.func));
                    exprs(&mut out, &c.args);
                    out.extend(c.keywords.iter().map(Node::Keyword));
                }
                Expr::FormattedValue(f) => {
                    out.push(Node::Expr(&f.value));
                    opt(&mut out, &f.format_spec);
                }
                Expr::JoinedStr(j) => exprs(&mut out, &j.values),
                Expr::Constant(_) | Expr::Name(_) => {}
                Expr::Attribute(a) => out.push(Node::Expr(&a.value)),
                Expr::Subscript(s) => {
                    out.push(Node::Expr(&s.value));
                    out.push(Node::Expr(&s.slice));
                }
                Expr::Starred(s) => out.push(Node::Expr(&s.value)),
                Expr::List(l) => exprs(&mut out, &l.elts),
                Expr::Tuple(t) => exprs(&mut out, &t.elts),
                Expr::Slice(s) => {
                    opt(&mut out, &s.lower);
                    opt(&mut out, &s.upper);
                    opt(&mut out, &s.step);
                }
            },
            Node::Pattern(p) => match p {
                Pattern::MatchValue(v) => out.push(Node::Expr(&v.value)),
                Pattern::MatchSingleton(_) | Pattern::MatchStar(_) => {}
                Pattern::MatchSequence(s) => out.extend(s.patterns.iter().map(Node::Pattern)),
                Pattern::MatchMapping(m) => {
                    exprs(&mut out, &m.keys);
                    out.extend(m.patterns.iter().map(Node::Pattern));
                }
                Pattern::MatchClass(c) => {
                    out.push(Node::Expr(&c.cls));
                    out.extend(c.patterns.iter().map(Node::Pattern));
                    out.extend(c.kwd_patterns.iter().map(Node::Pattern));
                }
                Pattern::MatchAs(a) => {
                    if let Some(p) = &a.pattern {
                        out.push(Node::Pattern(p));
                    }
                }
                Pattern::MatchOr(o) => out.extend(o.patterns.iter().map(Node::Pattern)),
            },
            Node::Handler(h) => {
                opt(&mut out, &h.type_);
                stmts(&mut out, &h.body);
            }
            Node::Arguments(a) => {
                // CPython: posonlyargs, args, vararg, kwonlyargs, kw_defaults,
                // kwarg, defaults — the defaults come *after* the parameters.
                out.extend(a.posonlyargs.iter().map(|p| Node::Arg(&p.def)));
                out.extend(a.args.iter().map(|p| Node::Arg(&p.def)));
                if let Some(v) = &a.vararg {
                    out.push(Node::Arg(v));
                }
                out.extend(a.kwonlyargs.iter().map(|p| Node::Arg(&p.def)));
                out.extend(
                    a.kwonlyargs
                        .iter()
                        .filter_map(|p| p.default.as_deref())
                        .map(Node::Expr),
                );
                if let Some(k) = &a.kwarg {
                    out.push(Node::Arg(k));
                }
                out.extend(
                    a.posonlyargs
                        .iter()
                        .chain(&a.args)
                        .filter_map(|p| p.default.as_deref())
                        .map(Node::Expr),
                );
            }
            Node::Arg(a) => opt(&mut out, &a.annotation),
            Node::Keyword(k) => out.push(Node::Expr(&k.value)),
            Node::Alias(_) | Node::Op(_) => {}
            Node::WithItem(w) => {
                out.push(Node::Expr(&w.context_expr));
                opt(&mut out, &w.optional_vars);
            }
            Node::MatchCase(c) => {
                out.push(Node::Pattern(&c.pattern));
                opt(&mut out, &c.guard);
                stmts(&mut out, &c.body);
            }
            Node::Comprehension(c) => {
                out.push(Node::Expr(&c.target));
                out.push(Node::Expr(&c.iter));
                exprs(&mut out, &c.ifs);
            }
            Node::TypeParam(t) => {
                if let TypeParam::TypeVar(v) = t {
                    opt(&mut out, &v.bound);
                }
            }
        }
        out
    }
}

/// `list(ast.walk(node))`: `node` itself, then every descendant in
/// CPython's breadth-first order (a FIFO queue fed by `iter_child_nodes`).
/// Checks that emit findings while iterating `ast.walk(tree)` must iterate
/// this to report in the same order.
pub fn walk<'a>(node: Node<'a>) -> Vec<Node<'a>> {
    let mut out = vec![node];
    let mut i = 0;
    while i < out.len() {
        let children = out[i].children();
        out.extend(children);
        i += 1;
    }
    out
}

/// `list(ast.walk(tree))` for a module, minus the `Module` node itself.
pub fn walk_module(body: &[Stmt]) -> Vec<Node<'_>> {
    let mut out: Vec<Node<'_>> = body.iter().map(Node::Stmt).collect();
    let mut i = 0;
    while i < out.len() {
        let children = out[i].children();
        out.extend(children);
        i += 1;
    }
    out
}

/// `ast.walk(node)` restricted to `node`'s descendants (not `node` itself):
/// calls `f` on every descendant, pre-order. Order only matters to callers
/// that count, so pre-order is as good as CPython's breadth-first walk.
pub fn for_each_descendant<'a>(node: Node<'a>, f: &mut impl FnMut(Node<'a>)) {
    for child in node.children() {
        f(child);
        for_each_descendant(child, f);
    }
}

/// Python's `str.splitlines()`: splits on every line boundary Python knows
/// (`\n`, `\r\n`, `\r`, `\x0b`, `\x0c`, `\x1c`-`\x1e`, `\x85`, ` `,
/// ` `), without a trailing empty line.
pub fn py_splitlines(source: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut iter = source.char_indices().peekable();
    while let Some((i, c)) = iter.next() {
        let is_break = matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !is_break {
            continue;
        }
        lines.push(&source[start..i]);
        let mut end = i + c.len_utf8();
        if c == '\r' && iter.peek().is_some_and(|&(_, next)| next == '\n') {
            iter.next();
            end += 1;
        }
        start = end;
    }
    if start < source.len() {
        lines.push(&source[start..]);
    }
    lines
}

/// Python's `str.isspace()` for one character.
pub fn is_py_space(c: char) -> bool {
    matches!(
        c,
        ' ' | '\t'
            | '\n'
            | '\x0b'
            | '\x0c'
            | '\r'
            | '\x1c'
            | '\x1d'
            | '\x1e'
            | '\x1f'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
    )
}

/// Python's `str.strip()` with no argument.
pub fn py_strip(s: &str) -> &str {
    s.trim_matches(is_py_space)
}

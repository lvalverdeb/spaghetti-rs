//! A statement-level `ast.unparse()`-equivalent, needed for
//! `sync-async-duplication` (compares `ast.unparse(node)` text via
//! `difflib.SequenceMatcher`).
//!
//! `rustpython_ast`'s `unparse` feature only implements `Display` for
//! `Expr` (confirmed by reading `unparse.rs` — no `Stmt`/`Mod` impl exists).
//! Rather than a from-scratch unparser, this is a thin statement-level shell
//! (indentation + control-flow keywords) that delegates every leaf
//! expression to that existing, working `Display for Expr`.
//!
//! Exact fidelity to Python's own `ast.unparse()` output doesn't matter
//! here — the two unparsed strings are only ever compared against each
//! other (via `similarity::sequence_matcher_ratio`), both produced by this
//! same renderer, so what matters is that structurally-similar code
//! produces textually-similar output and structurally-different code
//! doesn't, not that the exact tokens match Python's own unparser
//! byte-for-byte.

use rustpython_ast::{Stmt, WithItem};
use std::fmt::Write as _;

fn indent_str(depth: usize) -> String {
    "    ".repeat(depth)
}

fn unparse_withitem(item: &WithItem) -> String {
    match &item.optional_vars {
        Some(v) => format!("{} as {v}", item.context_expr),
        None => format!("{}", item.context_expr),
    }
}

/// Renders one parameter including its annotation and default, if present
/// (e.g. `cols: Sequence[str] | None = None`) — dropping these was a real
/// bug caught by the Phase 3 conformance diff: two sync/async twins whose
/// bodies were identical but whose parameter annotations/return types
/// differed would otherwise unparse to *more* similar text than Python's
/// real `ast.unparse()` produces, silently distorting the ratio.
fn unparse_arg_with_default(arg: &rustpython_ast::ArgWithDefault) -> String {
    let mut s = arg.def.arg.to_string();
    if let Some(ann) = &arg.def.annotation {
        let _ = write!(s, ": {ann}");
    }
    if let Some(default) = &arg.default {
        // Python's ast.unparse always uses `=` with no surrounding spaces
        // for defaults, annotated or not — verified directly, not assumed.
        let _ = write!(s, "={default}");
    }
    s
}

fn unparse_params(args: &rustpython_ast::Arguments) -> String {
    let mut parts: Vec<String> = Vec::new();
    for a in &args.posonlyargs {
        parts.push(unparse_arg_with_default(a));
    }
    if !args.posonlyargs.is_empty() {
        parts.push("/".to_string());
    }
    for a in &args.args {
        parts.push(unparse_arg_with_default(a));
    }
    if let Some(va) = &args.vararg {
        let ann = va
            .annotation
            .as_ref()
            .map(|a| format!(": {a}"))
            .unwrap_or_default();
        parts.push(format!("*{}{ann}", va.arg));
    } else if !args.kwonlyargs.is_empty() {
        parts.push("*".to_string());
    }
    for a in &args.kwonlyargs {
        parts.push(unparse_arg_with_default(a));
    }
    if let Some(kw) = &args.kwarg {
        let ann = kw
            .annotation
            .as_ref()
            .map(|a| format!(": {a}"))
            .unwrap_or_default();
        parts.push(format!("**{}{ann}", kw.arg));
    }
    parts.join(", ")
}

fn return_annotation(returns: &Option<Box<rustpython_ast::Expr>>) -> String {
    returns
        .as_ref()
        .map(|r| format!(" -> {r}"))
        .unwrap_or_default()
}

/// Appends `@decorator\n` lines (at `depth` indentation) for a
/// function/class's `decorator_list` — omitting these was a real bug caught
/// by the Phase 3 conformance diff: a `@classmethod`-decorated sync/async
/// twin pair unparsed to text missing that identical prefix on both sides,
/// shrinking the compared strings enough to tip a borderline case
/// (`ChunkedLoadExecutor.load`/`aload` in `boti-data`) to the wrong side of
/// the 0.6 similarity threshold.
fn write_decorators(decorators: &[rustpython_ast::Expr], pad: &str, out: &mut String) {
    for dec in decorators {
        let _ = writeln!(out, "{pad}@{dec}");
    }
}

/// Appends the unparsed form of `stmt` (at `depth` levels of indentation,
/// trailing newline included) to `out`.
fn unparse_stmt_into(stmt: &Stmt, depth: usize, out: &mut String) {
    let pad = indent_str(depth);
    match stmt {
        Stmt::FunctionDef(f) => {
            write_decorators(&f.decorator_list, &pad, out);
            let _ = writeln!(
                out,
                "{pad}def {}({}){}:",
                f.name,
                unparse_params(&f.args),
                return_annotation(&f.returns)
            );
            unparse_body_into(&f.body, depth + 1, out);
        }
        Stmt::AsyncFunctionDef(f) => {
            write_decorators(&f.decorator_list, &pad, out);
            let _ = writeln!(
                out,
                "{pad}async def {}({}){}:",
                f.name,
                unparse_params(&f.args),
                return_annotation(&f.returns)
            );
            unparse_body_into(&f.body, depth + 1, out);
        }
        Stmt::ClassDef(c) => {
            write_decorators(&c.decorator_list, &pad, out);
            let _ = writeln!(out, "{pad}class {}:", c.name);
            unparse_body_into(&c.body, depth + 1, out);
        }
        Stmt::Return(r) => match &r.value {
            Some(v) => {
                let _ = writeln!(out, "{pad}return {v}");
            }
            None => {
                let _ = writeln!(out, "{pad}return");
            }
        },
        Stmt::Delete(d) => {
            let targets: Vec<String> = d.targets.iter().map(|t| t.to_string()).collect();
            let _ = writeln!(out, "{pad}del {}", targets.join(", "));
        }
        Stmt::Assign(a) => {
            let targets: Vec<String> = a.targets.iter().map(|t| t.to_string()).collect();
            let _ = writeln!(out, "{pad}{} = {}", targets.join(" = "), a.value);
        }
        Stmt::TypeAlias(t) => {
            let _ = writeln!(out, "{pad}type {} = {}", t.name, t.value);
        }
        Stmt::AugAssign(a) => {
            let _ = writeln!(out, "{pad}{} {:?}= {}", a.target, a.op, a.value);
        }
        Stmt::AnnAssign(a) => match &a.value {
            Some(v) => {
                let _ = writeln!(out, "{pad}{}: {} = {v}", a.target, a.annotation);
            }
            None => {
                let _ = writeln!(out, "{pad}{}: {}", a.target, a.annotation);
            }
        },
        Stmt::For(f) => {
            let _ = writeln!(out, "{pad}for {} in {}:", f.target, f.iter);
            unparse_body_into(&f.body, depth + 1, out);
            if !f.orelse.is_empty() {
                let _ = writeln!(out, "{pad}else:");
                unparse_body_into(&f.orelse, depth + 1, out);
            }
        }
        Stmt::AsyncFor(f) => {
            let _ = writeln!(out, "{pad}async for {} in {}:", f.target, f.iter);
            unparse_body_into(&f.body, depth + 1, out);
            if !f.orelse.is_empty() {
                let _ = writeln!(out, "{pad}else:");
                unparse_body_into(&f.orelse, depth + 1, out);
            }
        }
        Stmt::While(w) => {
            let _ = writeln!(out, "{pad}while {}:", w.test);
            unparse_body_into(&w.body, depth + 1, out);
            if !w.orelse.is_empty() {
                let _ = writeln!(out, "{pad}else:");
                unparse_body_into(&w.orelse, depth + 1, out);
            }
        }
        Stmt::If(i) => {
            let _ = writeln!(out, "{pad}if {}:", i.test);
            unparse_body_into(&i.body, depth + 1, out);
            if !i.orelse.is_empty() {
                let _ = writeln!(out, "{pad}else:");
                unparse_body_into(&i.orelse, depth + 1, out);
            }
        }
        Stmt::With(w) => {
            let items: Vec<String> = w.items.iter().map(unparse_withitem).collect();
            let _ = writeln!(out, "{pad}with {}:", items.join(", "));
            unparse_body_into(&w.body, depth + 1, out);
        }
        Stmt::AsyncWith(w) => {
            let items: Vec<String> = w.items.iter().map(unparse_withitem).collect();
            let _ = writeln!(out, "{pad}async with {}:", items.join(", "));
            unparse_body_into(&w.body, depth + 1, out);
        }
        Stmt::Match(m) => {
            let _ = writeln!(out, "{pad}match {}:", m.subject);
            for case in &m.cases {
                let _ = writeln!(out, "{pad}    case ...:");
                unparse_body_into(&case.body, depth + 2, out);
            }
        }
        Stmt::Raise(r) => match (&r.exc, &r.cause) {
            (Some(e), Some(c)) => {
                let _ = writeln!(out, "{pad}raise {e} from {c}");
            }
            (Some(e), None) => {
                let _ = writeln!(out, "{pad}raise {e}");
            }
            _ => {
                let _ = writeln!(out, "{pad}raise");
            }
        },
        Stmt::Try(t) => {
            let _ = writeln!(out, "{pad}try:");
            unparse_body_into(&t.body, depth + 1, out);
            for handler in &t.handlers {
                let rustpython_ast::ExceptHandler::ExceptHandler(h) = handler;
                match &h.type_ {
                    Some(ty) => {
                        let _ = writeln!(out, "{pad}except {ty}:");
                    }
                    None => {
                        let _ = writeln!(out, "{pad}except:");
                    }
                }
                unparse_body_into(&h.body, depth + 1, out);
            }
            if !t.orelse.is_empty() {
                let _ = writeln!(out, "{pad}else:");
                unparse_body_into(&t.orelse, depth + 1, out);
            }
            if !t.finalbody.is_empty() {
                let _ = writeln!(out, "{pad}finally:");
                unparse_body_into(&t.finalbody, depth + 1, out);
            }
        }
        Stmt::TryStar(t) => {
            let _ = writeln!(out, "{pad}try:");
            unparse_body_into(&t.body, depth + 1, out);
            for handler in &t.handlers {
                let rustpython_ast::ExceptHandler::ExceptHandler(h) = handler;
                match &h.type_ {
                    Some(ty) => {
                        let _ = writeln!(out, "{pad}except* {ty}:");
                    }
                    None => {
                        let _ = writeln!(out, "{pad}except*:");
                    }
                }
                unparse_body_into(&h.body, depth + 1, out);
            }
            if !t.orelse.is_empty() {
                let _ = writeln!(out, "{pad}else:");
                unparse_body_into(&t.orelse, depth + 1, out);
            }
            if !t.finalbody.is_empty() {
                let _ = writeln!(out, "{pad}finally:");
                unparse_body_into(&t.finalbody, depth + 1, out);
            }
        }
        Stmt::Assert(a) => match &a.msg {
            Some(m) => {
                let _ = writeln!(out, "{pad}assert {}, {m}", a.test);
            }
            None => {
                let _ = writeln!(out, "{pad}assert {}", a.test);
            }
        },
        Stmt::Import(i) => {
            let names: Vec<String> = i
                .names
                .iter()
                .map(|a| match &a.asname {
                    Some(asn) => format!("{} as {asn}", a.name),
                    None => a.name.to_string(),
                })
                .collect();
            let _ = writeln!(out, "{pad}import {}", names.join(", "));
        }
        Stmt::ImportFrom(i) => {
            let names: Vec<String> = i
                .names
                .iter()
                .map(|a| match &a.asname {
                    Some(asn) => format!("{} as {asn}", a.name),
                    None => a.name.to_string(),
                })
                .collect();
            let module = i.module.as_deref().unwrap_or("");
            let _ = writeln!(out, "{pad}from {module} import {}", names.join(", "));
        }
        Stmt::Global(g) => {
            let names: Vec<String> = g.names.iter().map(|n| n.to_string()).collect();
            let _ = writeln!(out, "{pad}global {}", names.join(", "));
        }
        Stmt::Nonlocal(n) => {
            let names: Vec<String> = n.names.iter().map(|n| n.to_string()).collect();
            let _ = writeln!(out, "{pad}nonlocal {}", names.join(", "));
        }
        Stmt::Expr(e) => {
            let _ = writeln!(out, "{pad}{}", e.value);
        }
        Stmt::Pass(_) => {
            let _ = writeln!(out, "{pad}pass");
        }
        Stmt::Break(_) => {
            let _ = writeln!(out, "{pad}break");
        }
        Stmt::Continue(_) => {
            let _ = writeln!(out, "{pad}continue");
        }
    }
}

fn unparse_body_into(body: &[Stmt], depth: usize, out: &mut String) {
    for stmt in body {
        unparse_stmt_into(stmt, depth, out);
    }
}

/// Mirrors `ast.unparse(node)` where `node` is a whole
/// `FunctionDef`/`AsyncFunctionDef` — includes the `def name(...):`
/// signature line, not just the body (`sync-async-duplication` compares
/// `ast.unparse(node)` on the function statement itself, and Phase 0's
/// ground-truth ratios were computed the same way — confirmed by
/// re-reading that spike's own extraction script).
pub fn unparse_function(stmt: &Stmt) -> String {
    let mut out = String::new();
    unparse_stmt_into(stmt, 0, &mut out);
    out
}

/// Mirrors `ast.dump`-adjacent whole-block unparsing for an arbitrary
/// statement list (not currently used by any ported rule, but kept as the
/// general building block `unparse_function` is a thin wrapper around).
#[allow(dead_code)]
pub fn unparse_body(body: &[Stmt]) -> String {
    let mut out = String::new();
    unparse_body_into(body, 0, &mut out);
    out
}

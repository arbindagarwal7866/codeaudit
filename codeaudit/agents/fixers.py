"""Deterministic AST fixers — used offline, and as a fallback when the LLM agent fails.

Each fixer returns a Change (whole new file texts) or None if the pattern isn't safe to rewrite.
The Validator still checks every one of them.

  CODE_INJECTION            eval(x)                 -> ast.literal_eval(x)
  INSECURE_DESERIALIZATION  yaml.load(x)            -> yaml.safe_load(x)
  COMMAND_INJECTION         run(f"cmd {a}", shell=True) / os.system(...)  -> run(["cmd", a])
  SQL_INJECTION             execute(f"... {x}")     -> execute("... ?", (x,))   (also q = f"..."; execute(q))
  WEAK_HASH                 hashlib.md5(...)        -> hashlib.sha256(...)
  TLS_VERIFY_DISABLED       verify=False            -> removed (secure default)
  HARDCODED_SECRET          KEY = "..."             -> KEY = os.environ.get("KEY", "")
  DEAD_CODE                 delete the unreachable symbol
  CYCLIC_DEPENDENCY         delete dead code that is the only user of an edge + the now-unused import
  DEEP_NESTING              guard clauses (if not x: continue / return) and merged nested ifs
"""
from __future__ import annotations
import ast
import copy
import re

from ..graph import CodeGraph
from ..models import Finding, SymbolKind
from ..parse import call_name, _resolve_relative
from .validator import Change, file_text, replace_symbol


# ---------------------------------------------------------------------- text editing
def _offsets(text: str) -> list[int]:
    """byte offset of the start of each line (ast columns are UTF-8 byte offsets)."""
    offs, total = [0], 0
    for line in text.splitlines(keepends=True):
        total += len(line.encode("utf-8"))
        offs.append(total)
    return offs


def apply_edits(text: str, edits: list[tuple[ast.AST, str]]) -> str:
    """Replace the source span of each node with new text (edits must not overlap)."""
    data = text.encode("utf-8")
    offs = _offsets(text)
    spans = []
    for node, new in edits:
        a = offs[node.lineno - 1] + node.col_offset
        b = offs[node.end_lineno - 1] + node.end_col_offset
        spans.append((a, b, new.encode("utf-8")))
    for a, b, new in sorted(spans, reverse=True):
        data = data[:a] + new + data[b:]
    return data.decode("utf-8")


def ensure_import(text: str, module: str) -> str:
    if re.search(rf"^\s*import {re.escape(module)}\b", text, re.M):
        return text
    tree = ast.parse(text)
    last = 0
    for n in tree.body:
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            last = n.end_lineno
        elif isinstance(n, ast.Expr) and isinstance(getattr(n, "value", None), ast.Constant) and last == 0:
            last = n.end_lineno                              # after module docstring
        elif last:
            break
    lines = text.splitlines(keepends=True)
    if last == 0:
        lines.insert(0, f"import {module}\n")
    else:
        lines.insert(last, f"import {module}\n")
    return "".join(lines)


def _calls_at(tree: ast.AST, line: int, name_pred) -> list[ast.Call]:
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno == line
            and name_pred(call_name(n) or "")]


# ---------------------------------------------------------------------- security fixers
def fix_code_injection(cg, f):
    if f.evidence.get("call") != "eval":
        return None
    text = file_text(cg, f.file)
    calls = _calls_at(ast.parse(text), f.start_line, lambda n: n == "eval")
    if len(calls) != 1 or len(calls[0].args) != 1 or calls[0].keywords:
        return None
    new = apply_edits(text, [(calls[0].func, "ast.literal_eval")])
    return Change({f.file: ensure_import(new, "ast")},
                  "eval() -> ast.literal_eval(): only Python literals are accepted, no code runs", "deterministic")


def fix_yaml(cg, f):
    text = file_text(cg, f.file)
    calls = _calls_at(ast.parse(text), f.start_line, lambda n: n.endswith("yaml.load"))
    if len(calls) != 1 or not calls[0].args:
        return None
    c = calls[0]
    new_call = f"{ast.unparse(c.func)[:-len('load')]}safe_load({ast.unparse(c.args[0])})"
    return Change({f.file: apply_edits(text, [(c, new_call)])}, "yaml.load -> yaml.safe_load", "deterministic")


def _argv_from_fstring(node: ast.AST) -> list[str] | None:
    """Split a constant/f-string command into argv; each {value} must be a whole token."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if any(q in node.value for q in "'\"|;&$`<>*"):
            return None
        return [repr(t) for t in node.value.split()]
    if not isinstance(node, ast.JoinedStr):
        return None
    tokens: list[str] = []
    prev_ends_space = True
    vals = node.values
    for i, v in enumerate(vals):
        if isinstance(v, ast.Constant):
            s = str(v.value)
            if any(q in s for q in "'\"|;&$`<>*"):
                return None
            if not prev_ends_space and s and not s[0].isspace():
                return None
            nxt_is_value = i + 1 < len(vals) and not isinstance(vals[i + 1], ast.Constant)
            if nxt_is_value and s and not s[-1].isspace():
                return None                                # prefix{x} -> one token, can't split
            tokens.extend(repr(p) for p in s.split())
            prev_ends_space = (not s) or s[-1].isspace()
        else:
            if not prev_ends_space:
                return None
            if v.format_spec is not None or v.conversion not in (-1, None):
                return None
            tokens.append(f"str({ast.unparse(v.value)})")
            prev_ends_space = False
    return tokens


def fix_command_injection(cg, f):
    text = file_text(cg, f.file)
    tree = ast.parse(text)
    calls = _calls_at(tree, f.start_line, lambda n: n.startswith("subprocess.") or n in ("os.system", "os.popen"))
    if len(calls) != 1 or not calls[0].args:
        return None
    c = calls[0]
    argv = _argv_from_fstring(c.args[0])
    if not argv:
        return None
    name = call_name(c)
    if name in ("os.system", "os.popen"):
        stmt = next((n for n in ast.walk(tree) if isinstance(n, ast.Expr) and n.value is c), None)
        if stmt is None or name == "os.popen":
            return None                                    # return value used -> semantics differ
        new_call = f"subprocess.run([{', '.join(argv)}], check=False)"
        new = ensure_import(apply_edits(text, [(c, new_call)]), "subprocess")
    else:
        kws = [k for k in c.keywords if k.arg != "shell"]
        args = [f"[{', '.join(argv)}]"] + [ast.unparse(a) for a in c.args[1:]] + \
               [f"{k.arg}={ast.unparse(k.value)}" if k.arg else f"**{ast.unparse(k.value)}" for k in kws]
        new = apply_edits(text, [(c, f"{ast.unparse(c.func)}({', '.join(args)})")])
    return Change({f.file: new}, "shell command string -> argument list without shell=True "
                                 "(arguments can no longer inject shell syntax)", "deterministic")


def _sql_parts(node: ast.AST) -> list | None:
    """Flatten an f-string / "a" + x + "b" into [str | ast.expr]."""
    if isinstance(node, ast.JoinedStr):
        out = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                out.append(str(v.value))
            elif v.format_spec is None:
                out.append(v.value)
            else:
                return None
        return out
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _sql_parts(node.left), _sql_parts(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.Call) and call_name(node) == "str" and len(node.args) == 1:
        return [node.args[0]]
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return [node]
    return None


def _parameterize(parts: list, ph: str) -> tuple[str, list[str]] | None:
    sql, params = "", []
    for i, p in enumerate(parts):
        if isinstance(p, str):
            sql += p
            continue
        if sql.endswith(("'", '"')):                       # '{x}' -> ? (quotes belong to the literal)
            q = sql[-1]
            nxt = parts[i + 1] if i + 1 < len(parts) else ""
            if isinstance(nxt, str) and nxt.startswith(q):
                sql = sql[:-1]
                parts[i + 1] = nxt[1:]
        sql += ph
        params.append(ast.unparse(p))
    if not params:
        return None
    return sql, params


def fix_sql_injection(cg, f):
    text = file_text(cg, f.file)
    tree = ast.parse(text)
    calls = _calls_at(tree, f.start_line, lambda n: n.split(".")[-1] in ("execute", "executemany"))
    if len(calls) != 1 or len(calls[0].args) != 1:
        return None
    c = calls[0]
    ph = "?" if re.search(r"^\s*(import sqlite3|from sqlite3)", text, re.M) else "%s"
    arg = c.args[0]
    edits = []
    if isinstance(arg, ast.Name):
        fn = next((n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                   and n.lineno <= c.lineno <= n.end_lineno), None)
        assigns = [n for n in ast.walk(fn or tree) if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == arg.id for t in n.targets)]
        if len(assigns) != 1:
            return None
        parts = _sql_parts(assigns[0].value)
        if parts is None:
            return None
        res = _parameterize(parts, ph)
        if not res:
            return None
        sql, params = res
        edits.append((assigns[0].value, repr(sql)))
        edits.append((c, f"{ast.unparse(c.func)}({arg.id}, ({', '.join(params)},))"))
    else:
        parts = _sql_parts(arg)
        if parts is None:
            return None
        res = _parameterize(parts, ph)
        if not res:
            return None
        sql, params = res
        edits.append((c, f"{ast.unparse(c.func)}({sql!r}, ({', '.join(params)},))"))
    return Change({f.file: apply_edits(text, edits)},
                  f"string-built SQL -> parameterised query with '{ph}' placeholders "
                  "(the driver escapes values, so input can't change the query)", "deterministic")


def fix_weak_hash(cg, f):
    if f.evidence.get("mode") == "library":
        return None                     # changing a library's hash output breaks its users: advice only
    text = file_text(cg, f.file)
    calls = _calls_at(ast.parse(text), f.start_line, lambda n: n.endswith(("hashlib.md5", "hashlib.sha1")))
    if len(calls) != 1:
        return None
    func = calls[0].func
    new_name = ast.unparse(func).rsplit(".", 1)[0] + ".sha256"
    return Change({f.file: apply_edits(text, [(func, new_name)])}, "MD5/SHA-1 -> SHA-256", "deterministic",
                  notes=["BREAKING for stored data: values hashed with the old algorithm (e.g. saved passwords) "
                         "will no longer match; plan a migration (re-hash on next login)"])


def fix_tls(cg, f):
    text = file_text(cg, f.file)
    calls = [n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.Call) and n.lineno == f.start_line
             and any(k.arg == "verify" for k in n.keywords)]
    if len(calls) != 1:
        return None
    c = copy.deepcopy(calls[0])
    c.keywords = [k for k in c.keywords if k.arg != "verify"]
    return Change({f.file: apply_edits(text, [(calls[0], ast.unparse(c))])},
                  "removed verify=False: certificates are verified again", "deterministic")


def fix_secret(cg, f):
    if f.evidence.get("looks_like_url"):
        return None
    text = file_text(cg, f.file)
    name = f.evidence.get("call")
    assigns = [n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.Assign) and n.lineno == f.start_line
               and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
    if len(assigns) != 1:
        return None
    new = apply_edits(text, [(assigns[0].value, f'os.environ.get("{name}", "")')])
    return Change({f.file: ensure_import(new, "os")},
                  f"secret moved out of the code: read from the {name} environment variable", "deterministic")


# ---------------------------------------------------------------------- dead code / cycles
def fix_dead_code(cg, f):
    s = cg.symbols[f.symbol_id]
    if s.kind == SymbolKind.MODULE or f.evidence.get("possibly_dynamic"):
        return None
    return Change({f.file: replace_symbol(cg, f.symbol_id, None)},
                  f"deleted unreachable {s.kind.value} {s.qualname} ({s.length} lines)", "deterministic")


def remove_unused_imports_of(cg: CodeGraph, text: str, src_mod: str, dst_mod: str) -> str:
    tree = ast.parse(text)
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | \
           {n.value.id for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)}
    path = cg.modules[src_mod]

    rec = type("R", (), {"module": src_mod, "path": path})()      # minimal FileRecord stand-in
    edits = []
    for n in tree.body:
        if isinstance(n, ast.ImportFrom):
            base = _resolve_relative(rec, n.module, n.level)
            targets = [(a, f"{base}.{a.name}") for a in n.names]
        elif isinstance(n, ast.Import):
            targets = [(a, a.name) for a in n.names]
        else:
            continue
        keep = []
        for a, fq in targets:
            hits_dst = fq == dst_mod or fq.startswith(dst_mod + ".") or (
                isinstance(n, ast.ImportFrom) and _resolve_relative(rec, n.module, n.level) == dst_mod)
            alias = a.asname or a.name.split(".")[0]
            if hits_dst and alias not in used:
                continue
            keep.append(a)
        if len(keep) == len(n.names):
            continue
        if not keep:
            edits.append((n, ""))
        else:
            m = copy.deepcopy(n)
            m.names = keep
            edits.append((n, ast.unparse(m)))
    out = apply_edits(text, edits)
    return re.sub(r"\n[ \t]*\n(?=[ \t]*\n)", "\n", out) if edits else out


def fix_cycle(cg, f):
    edges = [e for e in f.evidence.get("edges", []) if e["dead_users_only"] or e["unused_import"]]
    if not edges:
        return None
    e = edges[0]
    src_mod = e["src"]
    rel = cg.modules[src_mod]
    text = file_text(cg, rel)
    removed = []
    for u in sorted(e["users"], key=lambda x: -cg.symbols[x].start_line):
        if cg.symbols[u].kind == SymbolKind.MODULE:
            return None
        text = replace_symbol(cg, u, None, text=text)
        removed.append(cg.symbols[u].qualname)
    text = remove_unused_imports_of(cg, text, src_mod, e["dst"])
    what = f"deleted dead code {', '.join(removed)} and " if removed else ""
    return Change({rel: text}, f"{what}removed the now-unused import {src_mod} -> {e['dst']}; "
                               "the import cycle is gone", "deterministic")


# ---------------------------------------------------------------------- deep nesting
def _negate(test: ast.expr) -> ast.expr:
    inv = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.GtE, ast.GtE: ast.Lt, ast.Gt: ast.LtE,
           ast.LtE: ast.Gt, ast.In: ast.NotIn, ast.NotIn: ast.In, ast.Is: ast.IsNot, ast.IsNot: ast.Is}
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and type(test.ops[0]) in inv:
        return ast.Compare(left=test.left, ops=[inv[type(test.ops[0])]()], comparators=test.comparators)
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return test.operand
    return ast.UnaryOp(op=ast.Not(), operand=test)


_EXITS = (ast.Return, ast.Raise, ast.Continue, ast.Break)


def _flatten_block(stmts: list[ast.stmt], in_loop: bool) -> list[ast.stmt]:
    out = []
    for i, st in enumerate(stmts):
        _flatten_node(st)
        is_last = i == len(stmts) - 1
        if (is_last and in_loop and isinstance(st, ast.If) and not st.orelse
                and not any(isinstance(n, (ast.Continue, ast.Break)) for n in ast.walk(st))):
            out.append(ast.If(test=_negate(st.test), body=[ast.Continue()], orelse=[]))
            out.extend(st.body)                         # guard clause in a loop
            continue
        if isinstance(st, ast.If) and st.orelse and st.body and isinstance(st.body[-1], _EXITS):
            out.append(ast.If(test=st.test, body=st.body, orelse=[]))
            out.extend(st.orelse)                       # else after return/raise is redundant
            continue
        out.append(st)
    return out


def _flatten_node(node: ast.AST):
    if isinstance(node, ast.If) and not node.orelse and len(node.body) == 1 \
            and isinstance(node.body[0], ast.If) and not node.body[0].orelse:
        inner = node.body[0]
        node.test = ast.BoolOp(op=ast.And(), values=[node.test, inner.test])
        node.body = inner.body                          # if a: if b: X  ->  if a and b: X
        _flatten_node(node)
        return
    for field_name in ("body", "orelse", "finalbody"):
        block = getattr(node, field_name, None)
        if isinstance(block, list) and block and isinstance(block[0], ast.stmt):
            loop = isinstance(node, (ast.For, ast.AsyncFor, ast.While)) and field_name == "body"
            setattr(node, field_name, _flatten_block(block, loop))
    for h in getattr(node, "handlers", []) or []:
        h.body = _flatten_block(h.body, False)


def fix_deep_nesting(cg, f):
    from ..parse import max_nesting
    s = cg.symbols[f.symbol_id]
    text = file_text(cg, f.file)
    fn = next((n for n in ast.walk(ast.parse(text)) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
               and n.lineno == s.def_line), None)
    if fn is None:
        return None
    import io
    import tokenize
    try:
        src = cg.source(f.symbol_id, max_lines=100_000)
        if any(t.type == tokenize.COMMENT for t in tokenize.generate_tokens(io.StringIO(src).readline)):
            return None              # an AST rewrite would drop comments (e.g. `# type: ignore`): leave it to the LLM agent
    except (tokenize.TokenError, IndentationError):
        return None
    before = max_nesting(fn)
    new_fn = copy.deepcopy(fn)
    for _ in range(4):
        _flatten_node(new_fn)
        last = new_fn.body[-1]
        if isinstance(last, ast.If) and not last.orelse and len(new_fn.body) >= 1 \
                and not any(isinstance(n, ast.Yield) for n in ast.walk(new_fn)):
            new_fn.body = new_fn.body[:-1] + [ast.If(test=_negate(last.test), body=[ast.Return(value=None)],
                                                      orelse=[])] + last.body
    ast.fix_missing_locations(new_fn)
    after = max_nesting(new_fn)
    if after >= before:
        return None
    new_src = ast.unparse(new_fn)
    return Change({f.file: replace_symbol(cg, f.symbol_id, new_src, text=text, protect_strings=True)},
                  f"guard clauses + merged conditions: nesting {before} -> {after}", "deterministic",
                  notes=["the function was re-printed from its syntax tree, so quote style may change"])


FIXERS = {
    "CODE_INJECTION": fix_code_injection,
    "INSECURE_DESERIALIZATION": fix_yaml,
    "COMMAND_INJECTION": fix_command_injection,
    "SQL_INJECTION": fix_sql_injection,
    "WEAK_HASH": fix_weak_hash,
    "TLS_VERIFY_DISABLED": fix_tls,
    "HARDCODED_SECRET": fix_secret,
    "DEAD_CODE": fix_dead_code,
    "CYCLIC_DEPENDENCY": fix_cycle,
    "DEEP_NESTING": fix_deep_nesting,
}


def deterministic_fix(cg: CodeGraph, f: Finding) -> Change | None:
    fx = FIXERS.get(f.rule)
    if not fx:
        return None
    try:
        return fx(cg, f)
    except (SyntaxError, ValueError, KeyError, IndexError, AttributeError):
        return None

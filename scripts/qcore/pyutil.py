"""Small helpers on top of the stdlib `ast` module."""

from __future__ import annotations

import ast
from typing import Dict, Iterator, List, Optional, Tuple


def parse(source) -> Optional[ast.AST]:
    if source.tree is not None:
        return source.tree
    try:
        source.tree = ast.parse(source.text)
    except (SyntaxError, RecursionError):
        # See `lexer.Source._scan_python`: a pathologically nested expression
        # overflows the recursive parser. "No tree" is the right answer there,
        # not an exception that takes the rest of the project down with it.
        source.tree = None
    return source.tree


def parent_map(tree: ast.AST) -> Dict[ast.AST, ast.AST]:
    parents: Dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def dotted_name(node: Optional[ast.AST]) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return (base + "." + node.attr) if base else node.attr
    if isinstance(node, ast.Call):
        return dotted_name(node.func)
    if isinstance(node, ast.Subscript):
        return dotted_name(node.value)
    return ""


def iter_calls(tree: ast.AST) -> Iterator[Tuple[ast.Call, str]]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node, dotted_name(node.func)


def enclosing(node: ast.AST, parents: Dict[ast.AST, ast.AST], kinds) -> Optional[ast.AST]:
    cur = parents.get(node)
    while cur is not None:
        if isinstance(cur, kinds):
            return cur
        cur = parents.get(cur)
    return None


def enclosing_functions(tree: ast.AST) -> List[ast.AST]:
    return [
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def function_name(node: ast.AST) -> str:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return node.name
    if isinstance(node, ast.ClassDef):
        return node.name
    return ""


def module_imports(tree: ast.AST) -> List[Tuple[str, int]]:
    out: List[Tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.append((alias.name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                out.append((node.module, node.lineno))
            elif node.module:
                out.append((node.module, node.lineno))
    return out


def is_docstring_expr(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def signature(node: ast.AST) -> str:
    """Stable textual signature for a function/method definition."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return ""
    args = node.args
    parts = []
    positional = list(args.posonlyargs) + list(args.args)
    defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
    for arg, default in zip(positional, defaults):
        piece = arg.arg
        if arg.annotation is not None:
            piece += ":" + ast.unparse(arg.annotation)
        if default is not None:
            piece += "=" + ast.unparse(default)
        parts.append(piece)
    if args.vararg:
        parts.append("*" + args.vararg.arg)
    elif args.kwonlyargs:
        parts.append("*")
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        piece = arg.arg
        if arg.annotation is not None:
            piece += ":" + ast.unparse(arg.annotation)
        if default is not None:
            piece += "=" + ast.unparse(default)
        parts.append(piece)
    if args.kwarg:
        parts.append("**" + args.kwarg.arg)
    ret = "->" + ast.unparse(node.returns) if node.returns is not None else ""
    return "(%s)%s" % (", ".join(parts), ret)


def is_public(name: str) -> bool:
    return bool(name) and not name.startswith("_")


def constant_value(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None

"""
ast_consumer.py — Consume AST del compilador huésped (Python)
=========================================================

Este módulo reemplaza al lexer y parser personalizados.
Cumple con la Fase 1 del README: "No reimplementa el lexer ni el parser;
consume directamente el AST producido por el compilador huésped."

Usa el módulo ast estándar de Python como compilador huésped.
"""

import ast
from typing import Any, List, Optional, Union

from ast_nodes import (
    ASTNode,
    Module, AssignStatement, AugAssignStatement, ExprStatement,
    IfStatement, ElifClause, WhileStatement, ForStatement,
    FunctionDef, Param, ReturnStatement, ImportStatement,
    Literal, Name, BinaryOp, UnaryOp, BoolOp, Compare,
    Keyword, FCall, Attribute, Subscript,
    JoinedStr, FormattedValue, PercentFormat,
    Tuple, PyList,
)


class ASTConsumer:
    """
    Convierte el AST de Python (ast.Module) al AST propio del proyecto.

    Uso:
        from ast_consumer import ASTConsumer

        consumer = ASTConsumer()
        tree = consumer.consume(source_code)
    """

    def consume(self, source: str) -> Module:
        """
        Parsea el código fuente usando ast.parse y convierte al AST del proyecto.
        """
        std_ast = ast.parse(source)
        return self._convert_module(std_ast)

    def _convert_module(self, node: ast.Module) -> Module:
        """Convierte ast.Module al AST del proyecto."""
        body = [self._convert_stmt(stmt) for stmt in node.body]
        return Module(body=body, line=1, col=1)

    def _convert_stmt(self, node: ast.stmt) -> ASTNode:
        """Convierte cualquier sentencia al AST del proyecto."""
        meth = f"_convert_{type(node).__name__}"
        conv = getattr(self, meth, self._generic_convert)
        return conv(node)

    def _convert_Assign(self, node: ast.Assign) -> AssignStatement:
        targets = [self._convert_expr(t) for t in node.targets]
        value = self._convert_expr(node.value)
        return AssignStatement(targets=targets, value=value, line=node.lineno, col=node.col_offset)

    def _convert_AugAssign(self, node: ast.AugAssign) -> AugAssignStatement:
        target = self._convert_expr(node.target)
        op = self._translate_op(node.op)
        value = self._convert_expr(node.value)
        return AugAssignStatement(target=target, op=op, value=value, line=node.lineno, col=node.col_offset)

    def _convert_Expr(self, node: ast.Expr) -> ExprStatement:
        expr = self._convert_expr(node.value)
        return ExprStatement(expression=expr, line=node.lineno, col=node.col_offset)

    def _convert_If(self, node: ast.If) -> IfStatement:
        condition = self._convert_expr(node.test)
        then_body = [self._convert_stmt(s) for s in node.body]
        elif_clauses: List[ElifClause] = []
        else_body: List[ASTNode] = []

        # Extract elif chains from orelse
        current_orelse = node.orelse
        while len(current_orelse) == 1 and isinstance(current_orelse[0], ast.If):
            elif_node = current_orelse[0]
            elif_condition = self._convert_expr(elif_node.test)
            elif_body = [self._convert_stmt(s) for s in elif_node.body]
            elif_clauses.append(ElifClause(
                condition=elif_condition, body=elif_body,
                line=elif_node.lineno, col=elif_node.col_offset,
            ))
            current_orelse = elif_node.orelse

        # Remaining orelse is the else body
        else_body = [self._convert_stmt(s) for s in current_orelse]

        return IfStatement(
            condition=condition,
            then_body=then_body,
            elif_clauses=elif_clauses,
            else_body=else_body,
            line=node.lineno,
            col=node.col_offset,
        )

    def _convert_While(self, node: ast.While) -> WhileStatement:
        condition = self._convert_expr(node.test)
        body = [self._convert_stmt(s) for s in node.body]
        return WhileStatement(condition=condition, body=body, line=node.lineno, col=node.col_offset)

    def _convert_For(self, node: ast.For) -> ForStatement:
        target = self._convert_expr(node.target)
        iter_ = self._convert_expr(node.iter)
        body = [self._convert_stmt(s) for s in node.body]
        return ForStatement(target=target, iter=iter_, body=body, line=node.lineno, col=node.col_offset)

    def _convert_FunctionDef(self, node: ast.FunctionDef) -> FunctionDef:
        name = node.name
        params = [self._convert_param(arg) for arg in node.args.args]
        body = [self._convert_stmt(s) for s in node.body]
        return FunctionDef(name=name, params=params, body=body, line=node.lineno, col=node.col_offset)

    def _convert_Return(self, node: ast.Return) -> ReturnStatement:
        value = self._convert_expr(node.value) if node.value else None
        return ReturnStatement(value=value, line=node.lineno, col=node.col_offset)

    def _convert_Import(self, node: ast.Import) -> ImportStatement:
        names = [alias.name for alias in node.names]
        return ImportStatement(module="", names=names, is_from=False, line=node.lineno, col=node.col_offset)

    def _convert_ImportFrom(self, node: ast.ImportFrom) -> ImportStatement:
        return ImportStatement(
            module=node.module or "",
            names=[alias.name for alias in node.names],
            is_from=True,
            line=node.lineno,
            col=node.col_offset,
        )

    def _convert_param(self, arg: ast.arg) -> Param:
        return Param(name=arg.arg, default=None, line=arg.lineno, col=arg.col_offset)

    def _convert_expr(self, node: ast.expr) -> ASTNode:
        """Convierte cualquier expresión al AST del proyecto."""
        if node is None:
            return None
        meth = f"_convert_{type(node).__name__}"
        conv = getattr(self, meth, self._generic_convert_expr)
        return conv(node)

    def _generic_convert_expr(self, node: ast.expr) -> ASTNode:
        """Convertidor genérico para expresiones no manejadas explícitamente."""
        return Name(name=repr(node), line=node.lineno, col=node.col_offset)

    def _generic_convert(self, node: ast.stmt) -> ASTNode:
        """Convertidor genérico para sentencias no manejadas explícitamente."""
        return ExprStatement(
            expression=Name(name=repr(node), line=node.lineno, col=node.col_offset),
            line=node.lineno,
            col=node.col_offset,
        )

    def _convert_Constant(self, node: ast.Constant) -> Literal:
        kind = self._infer_kind(node.value)
        return Literal(value=node.value, kind=kind, line=node.lineno, col=node.col_offset)

    def _convert_Name(self, node: ast.Name) -> Name:
        return Name(name=node.id, line=node.lineno, col=node.col_offset)

    def _convert_BinOp(self, node: ast.BinOp) -> BinaryOp:
        left = self._convert_expr(node.left)
        op = self._translate_op(node.op)
        right = self._convert_expr(node.right)
        if op == "%":
            return PercentFormat(left=left, right=right, line=node.lineno, col=node.col_offset)
        return BinaryOp(left=left, op=op, right=right, line=node.lineno, col=node.col_offset)

    def _convert_UnaryOp(self, node: ast.UnaryOp) -> UnaryOp:
        op = self._translate_op(node.op)
        operand = self._convert_expr(node.operand)
        return UnaryOp(op=op, operand=operand, line=node.lineno, col=node.col_offset)

    def _convert_BoolOp(self, node: ast.BoolOp) -> BoolOp:
        op = self._translate_op(node.op)
        values = [self._convert_expr(v) for v in node.values]
        return BoolOp(op=op, values=values, line=node.lineno, col=node.col_offset)

    def _convert_Compare(self, node: ast.Compare) -> Compare:
        left = self._convert_expr(node.left)
        ops = [self._translate_op(op) for op in node.ops]
        comparators = [self._convert_expr(c) for c in node.comparators]
        return Compare(left=left, ops=ops, comparators=comparators, line=node.lineno, col=node.col_offset)

    def _convert_Call(self, node: ast.Call) -> FCall:
        func = self._convert_expr(node.func)
        args = [self._convert_expr(arg) for arg in node.args]
        keywords = [
            Keyword(key=kw.arg, value=self._convert_expr(kw.value), line=kw.lineno, col=kw.col_offset)
            for kw in node.keywords
        ]
        return FCall(func=func, args=args, keywords=keywords, line=node.lineno, col=node.col_offset)

    def _convert_Attribute(self, node: ast.Attribute) -> Attribute:
        obj = self._convert_expr(node.value)
        return Attribute(obj=obj, attr=node.attr, line=node.lineno, col=node.col_offset)

    def _convert_Subscript(self, node: ast.Subscript) -> Subscript:
        obj = self._convert_expr(node.value)
        key = self._convert_expr(node.slice) if isinstance(node.slice, ast.expr) else None
        return Subscript(obj=obj, key=key, line=node.lineno, col=node.col_offset)

    def _convert_JoinedStr(self, node: ast.JoinedStr) -> JoinedStr:
        values = [self._convert_expr(v) for v in node.values]
        return JoinedStr(values=values, line=node.lineno, col=node.col_offset)

    def _convert_FormattedValue(self, node: ast.FormattedValue) -> FormattedValue:
        value = self._convert_expr(node.value)
        conversion = None
        if node.conversion is not None and node.conversion >= 0:
            conversion = {0: "s", 1: "r", 2: "a"}.get(node.conversion)
        return FormattedValue(value=value, conversion=conversion, line=node.lineno, col=node.col_offset)

    def _convert_Tuple(self, node: ast.Tuple) -> Tuple:
        elements = [self._convert_expr(e) for e in node.elts]
        return Tuple(elements=elements, line=node.lineno, col=node.col_offset)

    def _convert_List(self, node: ast.List) -> PyList:
        elements = [self._convert_expr(e) for e in node.elts]
        return PyList(elements=elements, line=node.lineno, col=node.col_offset)

    def _translate_op(self, op: Union[ast.operator, ast.unaryop, ast.cmpop]) -> str:
        """Traduce operadores de ast a string."""
        op_map = {
            ast.Add: "+", ast.Sub: "-", ast.Mult: "*", ast.Div: "/",
            ast.FloorDiv: "//", ast.Mod: "%", ast.Pow: "**",
            ast.LShift: "<<", ast.RShift: ">>", ast.BitOr: "|",
            ast.BitXor: "^", ast.BitAnd: "&",
            ast.Eq: "==", ast.NotEq: "!=", ast.Lt: "<", ast.Gt: ">",
            ast.LtE: "<=", ast.GtE: ">=",
            ast.Is: "is", ast.IsNot: "is not", ast.In: "in", ast.NotIn: "not in",
            ast.Invert: "~", ast.UAdd: "+", ast.USub: "-",
            ast.And: "and", ast.Or: "or", ast.Not: "not",
        }
        return op_map.get(type(op), repr(op))

    def _infer_kind(self, value: Any) -> str:
        """Infiere el tipo de un literal."""
        if value is None:
            return "none"
        if isinstance(value, bool):
            return "bool"
        if isinstance(value, int):
            return "int"
        if isinstance(value, float):
            return "float"
        if isinstance(value, str):
            return "str"
        return "str"
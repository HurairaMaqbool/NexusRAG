"""
src/secure_rag/tools/calculator.py — AST-Safe Math Evaluator
Evaluates arithmetic expressions via Python AST without using eval().
"""

import ast
import operator
import re

_MAX_AST_DEPTH = 20
_MAX_POW_EXPONENT = 10
_MAX_ABS_RESULT = 1e12

_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.FloorDiv: operator.floordiv,
}


def _ast_depth(node: ast.AST, current: int = 0) -> int:
    """Measures the maximum depth of an AST tree."""
    max_child = current
    for child in ast.iter_child_nodes(node):
        max_child = max(max_child, _ast_depth(child, current + 1))
    return max_child


def _check_result(value):
    """Rejects results whose absolute value exceeds the safety cap."""
    if isinstance(value, (int, float)) and abs(value) > _MAX_ABS_RESULT:
        raise ValueError("Result magnitude exceeds safety limit")
    return value


def safe_eval(expr: str):
    """Safely evaluates math expressions using AST — no eval() used."""

    def _eval(node, depth=0):
        if depth > _MAX_AST_DEPTH:
            raise ValueError("Expression too deeply nested")
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        elif isinstance(node, ast.BinOp):
            op_type = type(node.op)
            if op_type not in _BIN_OPS:
                raise ValueError(f"Unsupported operator: {op_type}")
            left = _eval(node.left, depth + 1)
            right = _eval(node.right, depth + 1)
            if op_type in (ast.Div, ast.FloorDiv, ast.Mod) and right == 0:
                raise ZeroDivisionError("Division by zero")
            if op_type is ast.Pow:
                if abs(right) > _MAX_POW_EXPONENT:
                    raise ValueError(
                        f"Exponent {right} exceeds maximum allowed ({_MAX_POW_EXPONENT})"
                    )
            result = _BIN_OPS[op_type](left, right)
            return _check_result(result)
        elif isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.USub):
                return -_eval(node.operand, depth + 1)
            elif isinstance(node.op, ast.UAdd):
                return _eval(node.operand, depth + 1)
        raise ValueError(f"Unsupported expression type: {type(node).__name__}")

    try:
        clean = expr.strip().replace('^', '**')
        if len(clean) > 200:
            return "Expression too long."
        tree = ast.parse(clean, mode='eval')
        if _ast_depth(tree) > _MAX_AST_DEPTH:
            return "Math error: Expression too deeply nested"
        result = _eval(tree.body)
        if isinstance(result, float) and result.is_integer():
            return int(result)
        if isinstance(result, float):
            return round(result, 10)
        return result
    except ZeroDivisionError:
        return "Error: Division by zero."
    except Exception as e:
        return f"Math error: {str(e)}"


def calculator_tool(query: str) -> str:
    """Extract and safely evaluate a math expression from query text."""
    normalized = query
    for pattern, symbol in (
        (r"(?i)\bdivided by\b", "/"),
        (r"(?i)\bmultiplied by\b", "*"),
        (r"(?i)\btimes\b", "*"),
        (r"(?i)\bplus\b", "+"),
        (r"(?i)\bminus\b", "-"),
    ):
        normalized = re.sub(pattern, symbol, normalized)

    # Extract sequences of digits, arithmetic operators, and parentheses
    matches = re.findall(r"[\(\)\d\.\s\+\-\*\/\^%]+", normalized)
    valid_candidates = []
    for cand in matches:
        cand_str = cand.strip(" ,;?!")
        if re.search(r"[\+\-\*\/\^%]", cand_str) and re.search(r"\d", cand_str):
            valid_candidates.append(cand_str)

    if not valid_candidates:
        return "No valid mathematical expression found in your query."

    # Sort candidates by length (longest expression first)
    valid_candidates.sort(key=len, reverse=True)
    for candidate in valid_candidates:
        res = safe_eval(candidate)
        if not str(res).startswith("Math error:"):
            return f"Result: {res}"

    # Fallback to the longest candidate's error message
    result = safe_eval(valid_candidates[0])
    return f"Result: {result}"

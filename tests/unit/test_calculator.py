"""tests/unit/test_calculator.py — AST-safe calculator and tool extraction."""

from secure_rag.tools.calculator import calculator_tool, safe_eval


def test_safe_eval_basic():
    assert safe_eval("2 + 2") == 4
    assert safe_eval("10 / 2") == 5
    assert safe_eval("2 ^ 3") == 8


def test_safe_eval_guards():
    assert "zero" in str(safe_eval("10 / 0")).lower()
    assert "error" in str(safe_eval("2 ** 20")).lower() or "exceed" in str(safe_eval("2 ** 20")).lower()


def test_calculator_tool_operators():
    assert "100" in calculator_tool("what is 25 + 75")
    assert "81" in calculator_tool("compute 9 * 9")
    assert "20" in calculator_tool("calculate 100 divided by 5")


def test_calculator_tool_no_expression():
    result = calculator_tool("no numbers here")
    assert "No valid" in result


def test_calculator_tool_stray_number():
    result = calculator_tool("tell me about policy 15")
    assert "No valid" in result

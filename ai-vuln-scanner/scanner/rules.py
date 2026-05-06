from __future__ import annotations

import ast
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Finding:
    vulnerability: str
    severity: str
    line: int
    code: str
    reason: str
    recommendation: str
    rule_id: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


SQL_KEYWORDS = ("select", "insert", "update", "delete", "drop", "where", "from")
COMMAND_MODULES = {"os", "subprocess"}
COMMAND_FUNCTIONS = {
    ("os", "system"),
    ("os", "popen"),
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "Popen"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "getoutput"),
}
PATH_SINKS = {"open", "remove", "unlink", "rmdir", "send_file"}
USER_VAR_HINTS = ("user", "input", "filename", "file_name", "filepath", "path", "upload")


def analyze_code(source: str) -> list[Finding]:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [
            Finding(
                vulnerability="Syntax Error",
                severity="info",
                line=exc.lineno or 1,
                code=exc.text.strip() if exc.text else "",
                reason="코드를 파싱할 수 없어 취약점 분석을 진행하지 못했습니다.",
                recommendation="먼저 Python 문법 오류를 수정한 뒤 다시 분석하세요.",
                rule_id="PY-SYNTAX-001",
            )
        ]

    visitor = RuleVisitor(source)
    visitor.visit(tree)
    return visitor.findings


class RuleVisitor(ast.NodeVisitor):
    def __init__(self, source: str) -> None:
        self.source = source
        self.findings: list[Finding] = []
        self.dynamic_sql_vars: set[str] = set()
        self.user_controlled_vars: set[str] = set()

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                if (
                    self._is_user_input(node.value)
                    or self._looks_user_controlled_expr(node.value)
                    or self._name_looks_user_controlled(target.id)
                ):
                    self.user_controlled_vars.add(target.id)
                if self._is_sql_like(node.value) and self._is_dynamic(node.value):
                    self.dynamic_sql_vars.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._check_sql_injection(node)
        self._check_command_injection(node)
        self._check_path_traversal(node)
        self.generic_visit(node)

    def _check_sql_injection(self, node: ast.Call) -> None:
        if not self._is_attr_call(node.func, {"execute", "executemany"}):
            return
        if not node.args:
            return

        query = node.args[0]
        if self._is_dynamic_sql_argument(query):
            self._add_finding(
                vulnerability="SQL Injection",
                severity="high",
                node=node,
                reason="SQL 쿼리에 외부 입력이나 변수가 직접 결합된 형태로 보입니다.",
                recommendation="문자열 결합 대신 파라미터 바인딩을 사용하세요. 예: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                rule_id="SQL-INJECTION-001",
            )

    def _check_command_injection(self, node: ast.Call) -> None:
        call_name = self._call_name(node.func)
        if call_name not in COMMAND_FUNCTIONS:
            return

        first_arg = node.args[0] if node.args else None
        shell_true = any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        )

        if first_arg and (self._is_dynamic(first_arg) or self._looks_user_controlled_expr(first_arg) or shell_true):
            severity = "critical" if shell_true else "high"
            self._add_finding(
                vulnerability="Command Injection",
                severity=severity,
                node=node,
                reason="외부 입력이 시스템 명령 실행 함수로 전달될 가능성이 있습니다.",
                recommendation="shell=True를 피하고, 허용된 명령만 리스트 인자로 실행하세요. 사용자 입력은 화이트리스트로 검증하세요.",
                rule_id="COMMAND-INJECTION-001",
            )

    def _check_path_traversal(self, node: ast.Call) -> None:
        if self._is_name_call(node.func, PATH_SINKS) and node.args:
            path_arg = node.args[0]
            if self._looks_user_controlled_expr(path_arg) or self._contains_parent_traversal(path_arg):
                self._add_finding(
                    vulnerability="Path Traversal",
                    severity="high",
                    node=node,
                    reason="사용자 입력이 파일 경로로 직접 사용되어 상위 디렉터리 접근이 가능할 수 있습니다.",
                    recommendation="허용된 기본 디렉터리 안에서만 접근하도록 경로를 정규화하고, 확장자와 파일명을 화이트리스트로 검증하세요.",
                    rule_id="PATH-TRAVERSAL-001",
                )

        call_name = self._call_name(node.func)
        if call_name in {("os.path", "join"), ("pathlib", "Path")}:
            if any(self._looks_user_controlled_expr(arg) or self._contains_parent_traversal(arg) for arg in node.args):
                self._add_finding(
                    vulnerability="Path Traversal",
                    severity="medium",
                    node=node,
                    reason="사용자 입력이 파일 경로 조합에 사용되고 있습니다.",
                    recommendation="safe_join 방식으로 기본 디렉터리 밖으로 벗어나지 않는지 검사하세요.",
                    rule_id="PATH-TRAVERSAL-002",
                )

    def _dynamic_name(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Name) and node.id in self.dynamic_sql_vars

    def _is_dynamic_sql_argument(self, node: ast.AST) -> bool:
        return self._dynamic_name(node) or (self._is_sql_like(node) and self._is_dynamic(node))

    def _is_sql_like(self, node: ast.AST) -> bool:
        text = ast.get_source_segment(self.source, node) or ""
        return any(keyword in text.lower() for keyword in SQL_KEYWORDS)

    def _is_dynamic(self, node: ast.AST) -> bool:
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True
        if isinstance(node, ast.Call) and self._is_attr_call(node.func, {"format"}):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.user_controlled_vars or self._name_looks_user_controlled(node.id)
        return False

    def _is_user_input(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            if self._is_name_call(node.func, {"input"}):
                return True
            text = ast.get_source_segment(self.source, node) or ""
            return any(token in text for token in ("request.args", "request.form", "request.files", "request.json"))
        return False

    def _looks_user_controlled_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.user_controlled_vars or self._name_looks_user_controlled(node.id)
        if isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Call, ast.Subscript, ast.Attribute)):
            text = (ast.get_source_segment(self.source, node) or "").lower()
            return any(hint in text for hint in USER_VAR_HINTS) or any(
                var.lower() in text for var in self.user_controlled_vars
            )
        return False

    def _contains_parent_traversal(self, node: ast.AST) -> bool:
        text = ast.get_source_segment(self.source, node) or ""
        return "../" in text or "..\\" in text

    def _name_looks_user_controlled(self, name: str) -> bool:
        lowered = name.lower()
        return any(hint in lowered for hint in USER_VAR_HINTS)

    def _is_name_call(self, func: ast.AST, names: set[str]) -> bool:
        return isinstance(func, ast.Name) and func.id in names

    def _is_attr_call(self, func: ast.AST, attrs: set[str]) -> bool:
        return isinstance(func, ast.Attribute) and func.attr in attrs

    def _call_name(self, func: ast.AST) -> tuple[str, str] | tuple[str, str, str] | None:
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                return (func.value.id, func.attr)
            if isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name):
                return (f"{func.value.value.id}.{func.value.attr}", func.attr)
        return None

    def _add_finding(
        self,
        vulnerability: str,
        severity: str,
        node: ast.AST,
        reason: str,
        recommendation: str,
        rule_id: str,
    ) -> None:
        self.findings.append(
            Finding(
                vulnerability=vulnerability,
                severity=severity,
                line=getattr(node, "lineno", 1),
                code=(ast.get_source_segment(self.source, node) or "").strip(),
                reason=reason,
                recommendation=recommendation,
                rule_id=rule_id,
            )
        )

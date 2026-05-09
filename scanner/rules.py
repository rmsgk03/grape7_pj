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
PATH_FUNCTIONS = {
    ("builtins", "open"),
    ("os", "remove"),
    ("os", "unlink"),
    ("os", "rmdir"),
    ("flask", "send_file"),
}
USER_VAR_HINTS = ("user", "input", "filename", "file_name", "filepath", "path", "upload", "param")
REQUEST_TOKENS = ("request.args", "request.form", "request.files", "request.json", "request.get_json")


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
                recommendation="Python 문법 오류를 먼저 수정한 뒤 다시 분석하세요.",
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
        self.import_aliases: dict[str, str] = {}
        self.function_aliases: dict[str, tuple[str, str]] = {}
        self.user_controlled_vars: set[str] = set()
        self.sql_like_vars: set[str] = set()
        self.dynamic_sql_vars: set[str] = set()
        self.path_like_vars: set[str] = set()
        self._seen: set[tuple[str, int, str]] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root_name = alias.name.split(".", 1)[0]
            local_name = alias.asname or root_name
            self.import_aliases[local_name] = root_name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if not node.module:
            return
        module = node.module.split(".", 1)[0]
        for alias in node.names:
            local_name = alias.asname or alias.name
            self.function_aliases[local_name] = (module, alias.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._record_assignment_aliases(node)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._record_value_flow(target.id, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            self._record_value_flow(node.target.id, node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if isinstance(node.target, ast.Name):
            target = node.target.id
            if self._expr_uses_user_controlled(node.value):
                self.user_controlled_vars.add(target)
            if target in self.sql_like_vars and self._is_dynamic_expr(node.value):
                self.dynamic_sql_vars.add(target)
            if target in self.path_like_vars and self._expr_uses_user_controlled(node.value):
                self.path_like_vars.add(target)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._check_sql_injection(node)
        self._check_command_injection(node)
        self._check_path_traversal(node)
        self.generic_visit(node)

    def _record_assignment_aliases(self, node: ast.Assign) -> None:
        canonical = self._canonical_function_ref(node.value)
        if canonical is None:
            return
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.function_aliases[target.id] = canonical

    def _record_value_flow(self, target: str, value: ast.AST) -> None:
        if self._is_user_input(value) or self._expr_uses_user_controlled(value) or self._name_looks_user_controlled(target):
            self.user_controlled_vars.add(target)

        if self._is_sql_like(value) or self._expr_uses_vars(value, self.sql_like_vars):
            self.sql_like_vars.add(target)

        if target in self.sql_like_vars and self._is_dynamic_expr(value):
            self.dynamic_sql_vars.add(target)
        if self._expr_uses_vars(value, self.dynamic_sql_vars):
            self.dynamic_sql_vars.add(target)

        if self._contains_parent_traversal(value) or self._name_looks_path_like(target):
            self.path_like_vars.add(target)
        if self._expr_uses_user_controlled(value) and (target in self.path_like_vars or self._name_looks_path_like(target)):
            self.path_like_vars.add(target)

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
                reason="사용자 입력이나 동적으로 조합된 문자열이 SQL 쿼리에 포함될 가능성이 있습니다.",
                recommendation=(
                    "문자열 결합 대신 파라미터 바인딩을 사용하세요. "
                    "예: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
                ),
                rule_id="SQL-INJECTION-001",
            )

    def _check_command_injection(self, node: ast.Call) -> None:
        call_name = self._canonical_call_name(node.func)
        if call_name not in COMMAND_FUNCTIONS:
            return

        first_arg = node.args[0] if node.args else None
        shell_true = any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        )

        risky_arg = first_arg is not None and (
            self._is_dynamic_expr(first_arg) or self._expr_uses_user_controlled(first_arg)
        )
        if risky_arg or shell_true:
            self._add_finding(
                vulnerability="Command Injection",
                severity="critical" if shell_true else "high",
                node=node,
                reason="사용자 입력값이 시스템 명령 실행 함수로 전달될 가능성이 있습니다.",
                recommendation=(
                    "shell=True 사용을 피하고, 명령어는 고정된 리스트 인자로 실행하세요. "
                    "사용자 입력은 허용 목록 방식으로 검증한 뒤 사용하세요."
                ),
                rule_id="COMMAND-INJECTION-001",
            )

    def _check_path_traversal(self, node: ast.Call) -> None:
        call_name = self._canonical_call_name(node.func)
        if call_name in PATH_FUNCTIONS and node.args:
            path_arg = node.args[0]
            if (
                self._expr_uses_user_controlled(path_arg)
                or self._expr_uses_vars(path_arg, self.path_like_vars)
                or self._contains_parent_traversal(path_arg)
            ):
                self._add_finding(
                    vulnerability="Path Traversal",
                    severity="high",
                    node=node,
                    reason="사용자 입력값이 파일 경로로 사용될 가능성이 있습니다.",
                    recommendation=(
                        "고정된 기본 디렉터리를 기준으로 경로를 정규화하고, 해당 디렉터리 밖으로 벗어나지 않는지 확인하세요. "
                        "파일명과 확장자는 허용 목록으로 검증하세요."
                    ),
                    rule_id="PATH-TRAVERSAL-001",
                )

        if call_name in {("os.path", "join"), ("pathlib", "Path")}:
            if any(self._expr_uses_user_controlled(arg) or self._contains_parent_traversal(arg) for arg in node.args):
                self._add_finding(
                    vulnerability="Path Traversal",
                    severity="medium",
                    node=node,
                    reason="사용자 입력값이 파일 경로를 조합하는 과정에 사용되고 있습니다.",
                    recommendation="safe_join 방식의 검사를 사용하고, 정규화된 경로가 기본 디렉터리 내부에 있는지 확인하세요.",
                    rule_id="PATH-TRAVERSAL-002",
                )

    def _is_dynamic_sql_argument(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name) and node.id in self.dynamic_sql_vars:
            return True
        return (self._is_sql_like(node) or self._expr_uses_vars(node, self.sql_like_vars)) and self._is_dynamic_expr(node)

    def _is_sql_like(self, node: ast.AST) -> bool:
        text = (ast.get_source_segment(self.source, node) or "").lower()
        return any(keyword in text for keyword in SQL_KEYWORDS)

    def _is_dynamic_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True
        if isinstance(node, ast.Call) and self._is_attr_call(node.func, {"format", "join"}):
            return True
        return self._expr_uses_user_controlled(node)

    def _is_user_input(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        if self._is_name_call(node.func, {"input"}):
            return True
        text = ast.get_source_segment(self.source, node) or ""
        return any(token in text for token in REQUEST_TOKENS)

    def _expr_uses_user_controlled(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.user_controlled_vars or self._name_looks_user_controlled(node.id)
        if self._is_user_input(node):
            return True
        text = (ast.get_source_segment(self.source, node) or "").lower()
        if any(token in text for token in REQUEST_TOKENS):
            return True
        return any(isinstance(child, ast.Name) and child.id in self.user_controlled_vars for child in ast.walk(node))

    def _expr_uses_vars(self, node: ast.AST, names: set[str]) -> bool:
        return any(isinstance(child, ast.Name) and child.id in names for child in ast.walk(node))

    def _contains_parent_traversal(self, node: ast.AST) -> bool:
        text = ast.get_source_segment(self.source, node) or ""
        return "../" in text or "..\\" in text

    def _name_looks_user_controlled(self, name: str) -> bool:
        lowered = name.lower()
        return any(hint in lowered for hint in USER_VAR_HINTS)

    def _name_looks_path_like(self, name: str) -> bool:
        lowered = name.lower()
        return any(hint in lowered for hint in ("filename", "file_name", "filepath", "path", "upload"))

    def _is_name_call(self, func: ast.AST, names: set[str]) -> bool:
        return isinstance(func, ast.Name) and func.id in names

    def _is_attr_call(self, func: ast.AST, attrs: set[str]) -> bool:
        return isinstance(func, ast.Attribute) and func.attr in attrs

    def _canonical_call_name(self, func: ast.AST) -> tuple[str, str] | None:
        if isinstance(func, ast.Name):
            if func.id in self.function_aliases:
                return self.function_aliases[func.id]
            if func.id == "open":
                return ("builtins", "open")
            return None
        return self._canonical_function_ref(func)

    def _canonical_function_ref(self, func: ast.AST) -> tuple[str, str] | None:
        if isinstance(func, ast.Attribute):
            dotted = self._dotted_name(func)
            if dotted is None:
                return None
            parts = dotted.split(".")
            if len(parts) == 2:
                module = self.import_aliases.get(parts[0], parts[0])
                return (module, parts[1])
            if len(parts) >= 3 and parts[0] in self.import_aliases:
                module = self.import_aliases[parts[0]]
                return (f"{module}.{parts[1]}", parts[-1])
            return (".".join(parts[:-1]), parts[-1])
        if isinstance(func, ast.Name) and func.id in self.function_aliases:
            return self.function_aliases[func.id]
        return None

    def _dotted_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._dotted_name(node.value)
            if parent is None:
                return None
            return f"{parent}.{node.attr}"
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
        key = (rule_id, getattr(node, "lineno", 1), ast.get_source_segment(self.source, node) or "")
        if key in self._seen:
            return
        self._seen.add(key)
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

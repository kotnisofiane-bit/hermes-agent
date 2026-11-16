from __future__ import annotations

import ast
from pathlib import Path


_ALLOWED_RAW_HOOK_TABLE_SCOPES = {
    ("agent/outbound_webhooks.py", "register_from_config"),
    ("agent/shell_hooks.py", "register_from_config"),
    ("hermes_cli/plugins.py", "PluginContext.register_hook"),
    ("hermes_cli/plugins.py", "PluginManager.__init__"),
    ("hermes_cli/plugins_ledger.py", "PluginLedgerMixin._reset_after_unload_all"),
}


class _HookRoutingInventory(ast.NodeVisitor):
    def __init__(self, relative_path: str):
        self.relative_path = relative_path
        self.scope: list[str] = []
        self.violations: list[str] = []
        self.iter_aliases: set[str] = set()

    @property
    def qualified_scope(self) -> str:
        return ".".join(self.scope)

    def _is_selector(self) -> bool:
        return (
            self.relative_path == "hermes_cli/plugins_dispatch.py"
            and self.qualified_scope.endswith("._dispatch_hook_callbacks")
        )

    def _is_allowed_table_scope(self) -> bool:
        return (self.relative_path, self.qualified_scope) in _ALLOWED_RAW_HOOK_TABLE_SCOPES

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "hermes_cli.plugins":
            self.iter_aliases.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name == "iter_hook_callbacks"
            )
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr == "_hooks" and not (self._is_selector() or self._is_allowed_table_scope()):
            self.violations.append(
                f"{self.relative_path}:{node.lineno}: raw _hooks table access outside selector or registration site"
            )
        if node.attr == "iter_hook_callbacks" and not self._is_selector():
            self.violations.append(
                f"{self.relative_path}:{node.lineno}: iter_hook_callbacks access outside selector"
            )
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if (
            node.id == "iter_hook_callbacks" or node.id in self.iter_aliases
        ) and not self._is_selector():
            self.violations.append(
                f"{self.relative_path}:{node.lineno}: iter_hook_callbacks reference outside selector"
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) > 1
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == "_hooks"
            and not (self._is_selector() or self._is_allowed_table_scope())
        ):
            self.violations.append(
                f"{self.relative_path}:{node.lineno}: getattr(..., '_hooks') outside selector or registration site"
            )
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) > 1
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == "iter_hook_callbacks"
            and not self._is_selector()
        ):
            self.violations.append(
                f"{self.relative_path}:{node.lineno}: getattr(..., 'iter_hook_callbacks') outside selector"
            )
        self.generic_visit(node)


def test_hook_callback_selection_has_one_structural_seam():
    repo_root = Path(__file__).resolve().parents[2]
    violations = []
    for directory in ("agent", "gateway", "hermes_cli"):
        for source in sorted((repo_root / directory).rglob("*.py")):
            relative_path = source.relative_to(repo_root).as_posix()
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=relative_path)
            inventory = _HookRoutingInventory(relative_path)
            inventory.visit(tree)
            violations.extend(inventory.violations)

    assert violations == [], "\n".join(violations)

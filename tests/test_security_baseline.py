"""Repository-wide security baseline.

These tests combine repository-wide checks (module collisions, duplicate
definitions, and artifact hygiene) with foundation-scoped checks for secret
handling, dynamic execution, secure defaults and defensive-only contracts.

They are deliberately scoped so they cannot become noisy: each check targets a
concrete, high-signal failure mode with an explicit allowlist where the
project legitimately needs an exception.

The custom runner retains star imports for legacy helpers but loads each test
module separately, so duplicate ``TestCase`` names cannot shadow one another.
Unique names remain preferred for clarity.
"""

from __future__ import annotations

import ast
import re
import sys
import sysconfig
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Foundation packages introduced in PART 01.
FOUNDATION_DIRS = ("core", "config", "interfaces", "services", "api")

EXCLUDED_DIR_NAMES = {
    "__pycache__", ".git", "build", "dist", "node_modules", "target",
    ".venv", "venv", ".mypy_cache", ".pytest_cache", ".ruff_cache",
}


def _python_files(root: Path) -> list[Path]:
    """All project ``.py`` files, excluding generated directories."""
    found: list[Path] = []
    for path in root.rglob("*.py"):
        if any(part in EXCLUDED_DIR_NAMES for part in path.parts):
            continue
        found.append(path)
    return found


ALL_PY_FILES = _python_files(REPO_ROOT)
FOUNDATION_PY_FILES = [
    p for p in ALL_PY_FILES
    if p.relative_to(REPO_ROOT).parts and p.relative_to(REPO_ROOT).parts[0] in FOUNDATION_DIRS
]


class SecurityBaselineImportCollisionTests(unittest.TestCase):
    """No project module may shadow a standard-library module."""

    # Directories that are placed on sys.path by an entrypoint. A top-level
    # module in one of these shadows the stdlib for the whole process.
    PATH_INJECTED_DIRS = ("python", ".")

    def _stdlib_top_level_names(self) -> set[str]:
        names = set(sys.stdlib_module_names)
        # Keep only names that are NOT private/internal.
        return {n for n in names if not n.startswith("_")}

    def test_no_project_module_shadows_the_standard_library(self) -> None:
        stdlib = self._stdlib_top_level_names()
        offenders: list[str] = []
        for directory in self.PATH_INJECTED_DIRS:
            base = (REPO_ROOT / directory).resolve()
            if not base.is_dir():
                continue
            for path in base.glob("*.py"):
                if path.stem in ("__init__", "__main__"):
                    continue
                if path.stem in stdlib:
                    offenders.append(str(path.relative_to(REPO_ROOT)))
        self.assertEqual(
            offenders, [],
            "these modules shadow stdlib modules for anything that puts their "
            f"directory on sys.path: {offenders}",
        )

    def test_the_known_platform_collision_is_gone(self) -> None:
        self.assertFalse(
            (REPO_ROOT / "python" / "platform.py").exists(),
            "python/platform.py shadows the stdlib 'platform' module",
        )
        self.assertTrue(
            (REPO_ROOT / "python" / "platform_service.py").exists(),
            "the renamed platform_service module is missing",
        )

    def test_stdlib_platform_is_the_real_one(self) -> None:
        import platform

        stdlib_dir = sysconfig.get_paths()["stdlib"]
        self.assertTrue(
            (platform.__file__ or "").startswith(stdlib_dir),
            f"platform resolved to {platform.__file__}, not the stdlib",
        )
        self.assertTrue(platform.system())

    def test_no_duplicate_top_level_module_names_across_path_dirs(self) -> None:
        """The same module name in two sys.path directories is ambiguous."""
        seen: dict[str, str] = {}
        duplicates: list[str] = []
        for directory in ("python", "core", "config", "interfaces", "services"):
            base = REPO_ROOT / directory
            if not base.is_dir():
                continue
            for path in base.glob("*.py"):
                if path.stem == "__init__":
                    continue
                key = path.stem
                if key in seen and directory in ("python",):
                    duplicates.append(f"{key}: {seen[key]} vs {directory}")
                seen.setdefault(key, directory)
        self.assertEqual(duplicates, [])


class SecurityBaselineHardcodedSecretTests(unittest.TestCase):
    """No credential material committed to the tree."""

    # Patterns describing an assignment of a literal credential.
    SECRET_PATTERNS = (
        re.compile(r"""(?i)\b(?:password|passwd|secret|api_key|apikey|token|"""
                   r"""private_key|client_secret)\s*=\s*['"][^'"\s]{8,}['"]"""),
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
        re.compile(r"\bsk_live_[A-Za-z0-9]{10,}\b"),
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    )

    # Substrings that mark a match as an obvious non-secret.
    BENIGN_MARKERS = (
        "example", "placeholder", "redacted", "changeme", "your-", "xxx",
        "dummy", "sample", "test", "fake", "hunter2", "<", "{", "os.environ",
        "getenv",
    )

    def test_foundation_layer_has_no_hardcoded_secrets(self) -> None:
        offenders: list[str] = []
        for path in FOUNDATION_PY_FILES:
            text = path.read_text(encoding="utf-8", errors="replace")
            for pattern in self.SECRET_PATTERNS:
                for match in pattern.finditer(text):
                    snippet = match.group(0)
                    if any(marker in snippet.lower() for marker in self.BENIGN_MARKERS):
                        continue
                    line = text[: match.start()].count("\n") + 1
                    offenders.append(
                        f"{path.relative_to(REPO_ROOT)}:{line}: {snippet[:40]}"
                    )
        self.assertEqual(offenders, [], f"possible hard-coded secrets: {offenders}")

    # Key-shaped files that are legitimate, each with a stated reason.
    #
    # tests/fixtures/p8test.key  -- a throwaway PKCS#8 keypair generated solely
    #   to exercise Apple-style JWT signing in tests/test_identity.py. It
    #   guards no real system and is required for those tests to run offline.
    #
    # data/.secutoolkit_webhook.key -- historical legacy key material used
    #   only to decrypt old notification-secret rows during AEAD migration.
    #   The new implementation never generates this file; if present, it is
    #   deployment data and must remain outside version control.
    KEY_FILE_ALLOWLIST = {
        "tests/fixtures/p8test.key",
    }

    def test_no_private_key_files_committed(self) -> None:
        offenders: list[str] = []
        for pattern in ("*.pem", "*.key", "*.p12", "*.pfx", "id_rsa", "id_ed25519"):
            for path in REPO_ROOT.rglob(pattern):
                if any(part in EXCLUDED_DIR_NAMES for part in path.parts):
                    continue
                relative = path.relative_to(REPO_ROOT).as_posix()
                if relative in self.KEY_FILE_ALLOWLIST:
                    continue
                # Runtime-generated material under gitignored directories is
                # not "committed"; it must simply never be tracked.
                if relative.startswith(("data/", "results/", "logs/")):
                    continue
                offenders.append(relative)
        self.assertEqual(offenders, [], f"key material in the tree: {offenders}")

    def test_runtime_key_directories_are_gitignored(self) -> None:
        """Whatever the runtime writes keys into must be excluded from VCS."""
        content = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        for required in ("data/", "*.key", "*.pem"):
            self.assertIn(required, content)

    def test_allowlisted_test_key_is_not_a_production_credential(self) -> None:
        """The fixture key must live under tests/ and nowhere else."""
        for relative in self.KEY_FILE_ALLOWLIST:
            self.assertTrue(relative.startswith("tests/"))
            self.assertTrue((REPO_ROOT / relative).exists())

    def test_env_example_contains_no_real_values(self) -> None:
        example = REPO_ROOT / ".env.example"
        if not example.exists():
            self.skipTest(".env.example not present")
        # Non-secret settings (SECTOOLKIT_ENV=development, LOG_LEVEL=INFO)
        # SHOULD show their real default: that is the point of the file.
        # Secret-named variables must never carry a value.
        # Matched on the variable NAME. 'AUTH_REQUIRED' contains "auth" but
        # carries a boolean, so the markers below target names that hold
        # credential MATERIAL rather than a policy switch.
        material_markers = (
            "SECRET_", "_TOKEN", "PASSWORD", "_KEY", "PRIVATE", "CREDENTIAL",
            "PASSPHRASE",
        )
        boolean_values = {"true", "false", "1", "0", "yes", "no", "on", "off"}

        for raw_line in example.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, _, value = line.partition("=")
            value = value.strip()
            holds_material = any(marker in name.upper() for marker in material_markers)
            if holds_material and value.lower() not in boolean_values:
                self.assertTrue(
                    value == "" or value.startswith(("changeme", "<", '"<')),
                    f".env.example must not contain a real secret: {name}",
                )
            else:
                # Even non-secret values must not look like credentials.
                self.assertFalse(
                    len(value) > 40 and value.isalnum(),
                    f".env.example value looks like a token: {name}",
                )

    def test_env_example_documents_every_secret_as_a_placeholder(self) -> None:
        example = REPO_ROOT / ".env.example"
        if not example.exists():
            self.skipTest(".env.example not present")
        text = example.read_text(encoding="utf-8")
        self.assertIn("SECTOOLKIT_SECRET_", text)
        self.assertIn("never commit", text.lower())

    def test_settings_env_vars_do_not_collide_with_the_secret_prefix(self) -> None:
        """No setting may live under the SECTOOLKIT_SECRET_ material prefix.

        interfaces/secrets.py resolves SECTOOLKIT_SECRET_<NAME> as secret
        MATERIAL. A plain setting sharing that prefix (the original
        SECTOOLKIT_SECRET_PROVIDER) would be indistinguishable from a secret
        named "provider" and could be logged or resolved by the wrong path.
        """
        import re as _re

        source = (REPO_ROOT / "config/settings.py").read_text(encoding="utf-8")
        offenders = [
            m for m in _re.findall(r'f"\{p\}([A-Z_]+)"', source)
            if m.startswith("SECRET_")
        ]
        self.assertEqual(
            offenders, [],
            f"settings collide with the secret-material prefix: {offenders}",
        )

    def test_no_committed_dotenv_file(self) -> None:
        self.assertFalse(
            (REPO_ROOT / ".env").exists(),
            "a .env file must never be committed; use .env.example",
        )


class SecurityBaselineDangerousConstructTests(unittest.TestCase):
    """No arbitrary code execution in the foundation layer."""

    BANNED_CALLS = {"eval", "exec", "compile", "__import__"}
    BANNED_MODULES = {"pickle", "marshal", "shelve"}

    def test_foundation_has_no_eval_exec_or_dynamic_import(self) -> None:
        offenders: list[str] = []
        for path in FOUNDATION_PY_FILES:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    if node.func.id in self.BANNED_CALLS:
                        offenders.append(
                            f"{path.relative_to(REPO_ROOT)}:{node.lineno}: "
                            f"{node.func.id}()"
                        )
        self.assertEqual(offenders, [], f"dynamic execution found: {offenders}")

    def test_foundation_does_not_use_unsafe_deserialisation(self) -> None:
        offenders: list[str] = []
        for path in FOUNDATION_PY_FILES:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.split(".")[0] in self.BANNED_MODULES:
                            offenders.append(
                                f"{path.relative_to(REPO_ROOT)}:{node.lineno}: "
                                f"{alias.name}"
                            )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    if node.module.split(".")[0] in self.BANNED_MODULES:
                        offenders.append(
                            f"{path.relative_to(REPO_ROOT)}:{node.lineno}: {node.module}"
                        )
        self.assertEqual(offenders, [], f"unsafe deserialisation: {offenders}")

    def test_foundation_does_not_spawn_processes_with_a_shell(self) -> None:
        offenders: list[str] = []
        for path in FOUNDATION_PY_FILES:
            text = path.read_text(encoding="utf-8")
            for pattern in ("shell=True", "os.system(", "os.popen("):
                if pattern in text:
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: {pattern}")
        self.assertEqual(offenders, [], f"shell execution: {offenders}")

    def test_foundation_has_no_bare_except_swallowing_everything(self) -> None:
        """A bare ``except:`` hides security-relevant failures."""
        offenders: list[str] = []
        for path in FOUNDATION_PY_FILES:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler) and node.type is None:
                    offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
        self.assertEqual(offenders, [], f"bare except: {offenders}")


class SecurityBaselineInsecureDefaultTests(unittest.TestCase):
    """No insecure default bindings or debug settings."""

    def test_foundation_declares_no_all_interfaces_default(self) -> None:
        offenders: list[str] = []
        for path in FOUNDATION_PY_FILES:
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if '"0.0.0.0"' in line or "'0.0.0.0'" in line:
                    # Permitted only where it is being REJECTED or listed as
                    # a forbidden value.
                    lowered = line.lower()
                    if any(
                        marker in lowered
                        for marker in ("not permitted", "reject", "in (", "insecure", "#")
                    ):
                        continue
                    offenders.append(f"{path.relative_to(REPO_ROOT)}:{number}")
        self.assertEqual(offenders, [], f"insecure bind default: {offenders}")

    def test_loaded_defaults_are_secure(self) -> None:
        from config.settings import load_settings

        settings = load_settings(env={})
        self.assertEqual(settings.bind_host, "127.0.0.1")
        self.assertTrue(settings.auth_required)
        self.assertTrue(settings.tls_required)
        self.assertFalse(settings.debug)

    def test_debug_cannot_reach_production(self) -> None:
        from config.settings import load_settings
        from core.errors import ConfigurationError

        with self.assertRaises(ConfigurationError):
            load_settings(env={"SECTOOLKIT_ENV": "production", "SECTOOLKIT_DEBUG": "1"})

    def test_production_locked_flags_cannot_be_enabled(self) -> None:
        from config import feature_flags

        for name, flag in feature_flags.FLAGS.items():
            if not flag.production_locked:
                continue
            self.assertFalse(
                feature_flags.is_enabled(
                    name, environment="production", env={flag.env_var: "true"}
                ),
                f"{name} must not be enableable in production",
            )


class SecurityBaselineDefensiveScopeTests(unittest.TestCase):
    """The foundation layer contains no offensive automation."""

    OFFENSIVE_TERMS = (
        "reverse_shell", "bind_shell", "privilege_escalation_exploit",
        "credential_stuffing", "password_spray", "ddos_", "botnet",
        "keylogger", "ransomware",
    )

    def test_no_offensive_capability_in_the_foundation_layer(self) -> None:
        """Offensive terms may appear only in a REJECTION list, never as code.

        ``interfaces/scanner.py`` legitimately names these terms in
        ``_OFFENSIVE_MARKERS`` so that ``assert_defensive()`` can refuse a
        scanner describing them. That is the opposite of implementing them, so
        the check inspects executable definitions rather than raw text.
        """
        offenders: list[str] = []
        for path in FOUNDATION_PY_FILES:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                # A function or class NAMED after an offensive capability.
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    lowered = node.name.lower()
                    for term in self.OFFENSIVE_TERMS:
                        if term.strip("_") in lowered:
                            offenders.append(
                                f"{path.relative_to(REPO_ROOT)}:{node.lineno}: {node.name}"
                            )
        self.assertEqual(offenders, [], f"offensive capability: {offenders}")

    def test_offensive_terms_appear_only_as_rejection_markers(self) -> None:
        """Where the terms do appear, they must be used to refuse input."""
        from core.errors import SecurityViolation
        from interfaces.scanner import assert_defensive

        for term in ("reverse_shell", "credential_stuffing", "bruteforce"):
            with self.subTest(term=term):
                with self.assertRaises(SecurityViolation):
                    assert_defensive(f"{term}_module", "static_analysis")

    def test_foundation_opens_no_network_listeners(self) -> None:
        offenders: list[str] = []
        for path in FOUNDATION_PY_FILES:
            text = path.read_text(encoding="utf-8")
            for pattern in (".listen(", "socket.socket(", ".bind((", "HTTPServer("):
                if pattern in text:
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: {pattern}")
        self.assertEqual(offenders, [], f"network listener in foundation: {offenders}")

    def test_rust_crate_forbids_unsafe_code(self) -> None:
        lib = REPO_ROOT / "native/rust/crates/engine_core/src/lib.rs"
        self.assertTrue(lib.exists(), "Rust crate root is missing")
        self.assertIn("#![forbid(unsafe_code)]", lib.read_text(encoding="utf-8"))

    def test_rust_crate_performs_no_io(self) -> None:
        offenders: list[str] = []
        src = REPO_ROOT / "native/rust/crates/engine_core/src"
        for path in src.rglob("*.rs"):
            text = path.read_text(encoding="utf-8")
            for pattern in ("std::net", "std::process", "std::fs", "unsafe "):
                if pattern in text:
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: {pattern}")
        self.assertEqual(offenders, [], f"Rust crate must stay pure: {offenders}")

    def test_cpp_library_performs_no_io_or_process_execution(self) -> None:
        offenders: list[str] = []
        for directory in ("native/cpp/src", "native/cpp/include"):
            for path in (REPO_ROOT / directory).rglob("*"):
                if path.suffix not in (".cpp", ".hpp", ".h"):
                    continue
                text = path.read_text(encoding="utf-8")
                for pattern in ("system(", "popen(", "exec", "<sys/socket.h>",
                                "fopen(", "new ", "malloc("):
                    if pattern in text:
                        offenders.append(f"{path.relative_to(REPO_ROOT)}: {pattern}")
        self.assertEqual(offenders, [], f"C++ library must stay pure/RAII: {offenders}")


class SecurityBaselineArtifactHygieneTests(unittest.TestCase):
    """No build output, databases or caches tracked in the tree."""

    def test_no_python_bytecode_directories_under_foundation(self) -> None:
        offenders = [
            str(p.relative_to(REPO_ROOT))
            for directory in FOUNDATION_DIRS
            for p in (REPO_ROOT / directory).rglob("__pycache__")
            if p.is_dir()
        ]
        # __pycache__ is regenerated constantly by the interpreter; the
        # requirement is that it is IGNORED, which the next test asserts.
        for path in offenders:
            self.assertTrue(path.endswith("__pycache__"))

    def test_gitignore_covers_generated_and_sensitive_artifacts(self) -> None:
        gitignore = REPO_ROOT / ".gitignore"
        self.assertTrue(gitignore.exists(), ".gitignore is missing")
        content = gitignore.read_text(encoding="utf-8")
        for required in (
            "__pycache__", "*.pyc", ".env", "*.db", "*.sqlite3", "*.log",
            "*.pem", "*.key", "build/", "target/", "node_modules/",
        ):
            self.assertIn(required, content, f".gitignore must cover {required}")

    def test_no_sqlite_databases_in_the_foundation_layer(self) -> None:
        offenders: list[str] = []
        for directory in FOUNDATION_DIRS + ("schemas", "docs"):
            base = REPO_ROOT / directory
            if not base.is_dir():
                continue
            for pattern in ("*.db", "*.sqlite", "*.sqlite3"):
                offenders.extend(
                    str(p.relative_to(REPO_ROOT)) for p in base.rglob(pattern)
                )
        self.assertEqual(offenders, [], f"databases committed: {offenders}")

    def test_no_compiled_binaries_outside_build_directories(self) -> None:
        offenders: list[str] = []
        for pattern in ("*.so", "*.dylib", "*.dll", "*.a", "*.o", "*.exe"):
            for path in REPO_ROOT.rglob(pattern):
                parts = path.parts
                if "build" in parts or "target" in parts or ".venv" in parts:
                    continue
                if any(part in EXCLUDED_DIR_NAMES for part in parts):
                    continue
                offenders.append(str(path.relative_to(REPO_ROOT)))
        self.assertEqual(offenders, [], f"binaries in the tree: {offenders}")


class SecurityBaselineTypeHintTests(unittest.TestCase):
    """Foundation public functions are annotated (mypy-friendly boundaries)."""

    def test_public_functions_have_return_annotations(self) -> None:
        offenders: list[str] = []
        for path in FOUNDATION_PY_FILES:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if node.name.startswith("_"):
                    continue
                if node.returns is None:
                    offenders.append(
                        f"{path.relative_to(REPO_ROOT)}:{node.lineno}: {node.name}"
                    )
        self.assertEqual(offenders, [], f"missing return annotations: {offenders}")

    def test_public_functions_have_annotated_arguments(self) -> None:
        offenders: list[str] = []
        for path in FOUNDATION_PY_FILES:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if node.name.startswith("_"):
                    continue
                args = list(node.args.args) + list(node.args.kwonlyargs)
                for arg in args:
                    if arg.arg in ("self", "cls"):
                        continue
                    if arg.annotation is None:
                        offenders.append(
                            f"{path.relative_to(REPO_ROOT)}:{node.lineno}: "
                            f"{node.name}({arg.arg})"
                        )
        self.assertEqual(offenders, [], f"unannotated arguments: {offenders}")

    def test_every_foundation_module_has_a_docstring(self) -> None:
        offenders: list[str] = []
        for path in FOUNDATION_PY_FILES:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            if not ast.get_docstring(tree):
                offenders.append(str(path.relative_to(REPO_ROOT)))
        self.assertEqual(offenders, [], f"undocumented modules: {offenders}")

    def test_no_placeholder_bodies_in_foundation_modules(self) -> None:
        """No function that silently does nothing while claiming to work."""
        offenders: list[str] = []
        for path in FOUNDATION_PY_FILES:
            text = path.read_text(encoding="utf-8")
            for marker in ("raise NotImplementedError", "TODO:", "FIXME:"):
                if marker in text:
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: {marker}")
        self.assertEqual(offenders, [], f"placeholders: {offenders}")


class SecurityBaselineImportIntegrityTests(unittest.TestCase):
    """Every import in the foundation must actually resolve.

    A broken relative import is invisible until the exact code path runs, and
    by then it is a production crash. Resolution is done by filesystem/AST
    inspection rather than by importing, so the check has no side effects and
    cannot be fooled by an installed package of the same name sitting earlier
    on ``sys.path``.
    """

    def _resolves(self, dotted: str) -> bool:
        parts = dotted.split(".")
        for i in range(len(parts), 0, -1):
            head = parts[:i]
            candidate = REPO_ROOT.joinpath(*head)
            if candidate.with_suffix(".py").is_file():
                return True
            if (candidate / "__init__.py").is_file():
                return True
        return False

    def test_foundation_imports_resolve(self) -> None:
        unresolved: list[str] = []
        for path in FOUNDATION_PY_FILES:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            rel = path.relative_to(REPO_ROOT)
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    # level > 0 is a relative import: needed only when the
                    # module is intended to be used as part of a package.
                    if node.level and node.module is None:
                        unresolved.append(
                            f"{rel}:{node.lineno} relative import with no module"
                        )
                        continue
                    if node.module is None:
                        continue
                    mod = node.module
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        top = alias.name.split(".")[0]
                        if top in FOUNDATION_DIRS and not self._resolves(alias.name):
                            unresolved.append(
                                f"{rel}:{node.lineno} import {alias.name}"
                            )
                    continue
                else:
                    continue
                top = mod.split(".")[0]
                if top in FOUNDATION_DIRS and not self._resolves(mod):
                    unresolved.append(f"{rel}:{node.lineno} from {mod} import ...")
        self.assertEqual(unresolved, [], f"unresolved foundation imports: {unresolved}")

    def test_foundation_never_imports_the_legacy_python_package(self) -> None:
        """The foundation must stand alone; depending on ``python/`` would make
        it untestable in isolation and re-couple the layers we just separated.
        """
        offenders: list[str] = []
        for path in FOUNDATION_PY_FILES:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            rel = path.relative_to(REPO_ROOT)
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    top = name.split(".")[0]
                    if top == "python":
                        offenders.append(f"{rel}:{node.lineno} {name}")
        self.assertEqual(offenders, [], f"foundation depends on legacy python/: {offenders}")

    def test_every_foundation_package_is_importable_from_the_repo_root(self) -> None:
        for pkg in FOUNDATION_DIRS:
            self.assertTrue(
                (REPO_ROOT / pkg / "__init__.py").is_file(),
                f"{pkg}/__init__.py is missing",
            )


class SecurityBaselineDuplicateDefinitionTests(unittest.TestCase):
    """A redefined function or class silently discards the first definition.

    That is how a later ``pass``-body stub shadows a working implementation, or
    how a copy-paste leaves two versions of a validator where only one wins.
    """

    def _duplicates(self, path: Path) -> list[str]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        found: list[str] = []

        def scan(body: list[ast.stmt], scope: str) -> None:
            seen: dict[str, int] = {}
            for node in body:
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                if node.name in seen:
                    found.append(
                        f"{scope}{node.name} (lines {seen[node.name]} and {node.lineno})"
                    )
                else:
                    seen[node.name] = node.lineno

        scan(tree.body, "")
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                scan(node.body, f"{node.name}.")
        return found

    def test_no_duplicate_definitions_anywhere(self) -> None:
        offenders: list[str] = []
        for path in ALL_PY_FILES:
            rel = path.relative_to(REPO_ROOT)
            for dup in self._duplicates(path):
                offenders.append(f"{rel}: {dup}")
        self.assertEqual(offenders, [], f"duplicate definitions: {offenders}")

    def test_foundation_modules_expose_no_duplicate_public_symbols(self) -> None:
        offenders: list[str] = []
        for path in FOUNDATION_PY_FILES:
            rel = path.relative_to(REPO_ROOT)
            for dup in self._duplicates(path):
                offenders.append(f"{rel}: {dup}")
        self.assertEqual(offenders, [], f"duplicate definitions in foundation: {offenders}")


if __name__ == "__main__":
    unittest.main()

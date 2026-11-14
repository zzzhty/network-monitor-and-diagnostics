"""The architecture checker catches recorded mistakes and accepts the current tree."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_architecture as arch

EMPTY = {"theme_contrast": [], "macos_test_omit": {}}

# a4035eb^, the light ink values and the rules that used them. Footer text
# was #8b95ad on #f2f4f9 (2.73:1). The browser spec added by that fix only
# asserted the footer, so muted and idle nav stayed under 4.5.
BEFORE_FOOTER_FIX = """\
:root{color-scheme:dark;--bg-page:#0d1119;--bg-sunken:#101620;--bg-raised:#151c29;--ink-200:#728199;--ink-300:#92a0b4;--ink-400:#a4b0c3;--ink-700:#dae2ed;color:var(--ink-700);background:var(--bg-page)}
@media (prefers-color-scheme: light){:root{color-scheme:light;--bg-page:#f2f4f9;--bg-sunken:#e9edf5;--bg-raised:#ffffff;--ink-200:#8b95ad;--ink-300:#6a7896;--ink-400:#5f6e90;--ink-700:#2b3956}}
.sidebar{width:230px;flex-shrink:0;border-right:var(--border-size-1) solid var(--border-plain);padding:var(--size-px-7) 22px;display:flex;flex-direction:column;background:var(--bg-sunken)}
.nav{border:0;background:transparent;color:var(--ink-400);text-align:left;padding:14px 12px;border-radius:9px;display:flex;justify-content:space-between;font-size:14px}
.nav span{font-size:10px;opacity:.6}
.card{background:var(--bg-raised);border:var(--border-size-1) solid var(--border-plain);border-radius:12px;padding:23px}
.muted{color:var(--ink-300);font-size:12px;line-height:1.7}
footer{display:flex;justify-content:space-between;gap:var(--size-px-3);border-top:var(--border-size-1) solid var(--border-plain);padding-top:var(--size-px-4);margin-top:35px;font-size:10px;color:var(--ink-200)}
"""

# 029d334^, after a4035eb had set --ink-200 to #5d6c94. Muted text was still
# #6a7896 (4.03:1 on the page, 4.43:1 on a card) and idle nav was 4.34:1.
BEFORE_MUTED_FIX = BEFORE_FOOTER_FIX.replace("--ink-200:#8b95ad", "--ink-200:#5d6c94")

# Token values landed by 029d334. The same selectors clear 4.5 without a floor.
AFTER_BOTH_FIXES = (
    BEFORE_MUTED_FIX
    .replace("--ink-300:#6a7896", "--ink-300:#5d6b8c")
    .replace("--ink-400:#5f6e90", "--ink-400:#53617f")
    .replace(".nav span{font-size:10px;opacity:.6}\n", "")
)

PAGE = """\
<!doctype html>
<html lang="zh-CN">
<head><link rel="stylesheet" href="/style.css"></head>
<body>
<div class="shell">
  <aside class="sidebar"><nav><button class="nav">概览 <span>01</span></button></nav></aside>
  <main>
    <p class="muted">等待监控数据</p>
    <article class="card"><p class="muted">仅统计返回记录</p></article>
    <footer><span>NMD / 本地面板</span></footer>
  </main>
</div>
</body>
</html>
"""

# The macos-tests command as it stood after 3e13506 added test_egress_diagnose.py
# and did not name it. 9248667 had already left the two state modules off the same list.
MACOS_COMMAND = (
    "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=\"tests:scripts:$RUNNER_TEMP/nmd-source-deps\" "
    "python3 -m unittest test_macos test_monitor test_socket_probe test_observability "
    "test_dashboard test_review_regressions test_desktop test_auto_event_retention "
    "test_channels test_auto_state -v"
)


def write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def theme_errors(items):
    return [item for item in items if item.level == "ERROR" and item.rule == "theme-contrast"]


def list_errors(items):
    return [item for item in items if item.level == "ERROR" and item.rule == "macos-test-list"]


class ArchitectureCheckTests(unittest.TestCase):
    def test_current_tree_has_no_errors(self) -> None:
        found = arch.check(ROOT, arch.load_baseline())
        self.assertEqual(
            [(item.path, item.line, item.violation) for item in found if item.level == "ERROR"],
            [],
        )

    def test_cli_passes_on_the_repository(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_architecture.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("[ARCH] Passed", completed.stdout)

    def test_contrast_floors_are_exactly_the_current_failures(self) -> None:
        baseline = arch.load_baseline()
        empty = {"theme_contrast": [], "macos_test_omit": baseline["macos_test_omit"]}
        keys = set()
        for item in theme_errors(arch.check(ROOT, empty)):
            keys.add(item.violation.split(" is ", 1)[0])
        self.assertEqual(keys, {entry["key"] for entry in baseline["theme_contrast"]})

    def test_footer_contrast_before_a4035eb_is_caught(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._page(root, BEFORE_FOOTER_FIX)
            caught = theme_errors(arch.check(root, EMPTY))
            footer = [item for item in caught if "footer>span|4.50 is 2.73:1" in item.violation]
            self.assertEqual(len(footer), 1)
            self.assertIn("a4035eb", footer[0].principle)
            self.assertIn("web/style.css", footer[0].fix)
            rendered = footer[0].render()
            self.assertIn("\n  Violation:", rendered)
            self.assertIn("\n  Fix:", rendered)
            self.assertIn("\n  Principle:", rendered)

    def test_muted_and_idle_nav_before_029d334_are_caught(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._page(root, BEFORE_MUTED_FIX)
            caught = theme_errors(arch.check(root, EMPTY))
            text = "\n".join(item.violation for item in caught)
            self.assertNotIn("footer>span|4.50 is 2.73:1", text)
            self.assertIn("main>p.muted|4.50 is 4.03:1", text)
            self.assertIn("article.card>p.muted|4.50 is 4.43:1", text)
            self.assertIn("button.nav|4.50 is 4.34:1", text)
            self.assertIn("029d334", caught[0].principle)

    def test_landed_ink_tokens_clear_the_historical_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._page(root, AFTER_BOTH_FIXES)
            self.assertEqual(theme_errors(arch.check(root, EMPTY)), [])

    def test_a_lower_contrast_than_the_floor_is_caught(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._page(root, BEFORE_FOOTER_FIX)
            key = "light|html>body>div.shell>main>footer>span|4.50"
            baseline = {"theme_contrast": [{"key": key, "ratio": 4.0}], "macos_test_omit": {}}
            caught = theme_errors(arch.check(root, baseline))
            self.assertTrue(any("dropped from its floor of 4.00:1 to 2.73:1" in item.violation for item in caught))
            self.assertIn("architecture_baseline.json", caught[0].fix)

    def test_a_floor_for_a_pair_that_now_passes_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._page(root, AFTER_BOTH_FIXES)
            baseline = {
                "theme_contrast": [{"key": "light|html>body>div.shell>main>footer>span|4.50", "ratio": 2.73}],
                "macos_test_omit": {},
            }
            caught = theme_errors(arch.check(root, baseline))
            self.assertEqual(len(caught), 1)
            self.assertIn("no longer matches", caught[0].violation)

    def test_diagnose_module_missing_from_the_macos_command_is_caught(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, ".github/workflows/offline-tests.yml", "jobs:\n  macos-tests:\n    steps:\n      - run: " + MACOS_COMMAND + "\n")
            write(root, "tests/test_egress_diagnose.py", '"""Layered egress diagnosis.\n"""\n')
            caught = list_errors(arch.check(root, EMPTY))
            self.assertEqual(len(caught), 1)
            self.assertIn("test_egress_diagnose.py", caught[0].violation)
            self.assertIn("macos-tests", caught[0].fix)
            self.assertIn("3e13506", caught[0].principle)
            self.assertIn("9248667", caught[0].principle)
            allowed = dict(EMPTY, macos_test_omit={"test_egress_diagnose.py": "grandfathered"})
            self.assertEqual(list_errors(arch.check(root, allowed)), [])

    def test_naming_the_module_removes_the_need_for_an_omit_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            command = MACOS_COMMAND.replace("test_auto_state -v", "test_auto_state test_egress_diagnose -v")
            write(root, ".github/workflows/offline-tests.yml", "jobs:\n  macos-tests:\n    steps:\n      - run: " + command + "\n")
            write(root, "tests/test_egress_diagnose.py", '"""Layered egress diagnosis.\n"""\n')
            self.assertEqual(list_errors(arch.check(root, EMPTY)), [])
            stale = dict(EMPTY, macos_test_omit={"test_egress_diagnose.py": "already listed"})
            caught = list_errors(arch.check(root, stale))
            self.assertEqual(len(caught), 1)
            self.assertIn("no longer an omission", caught[0].violation)

    def test_unittest_discover_covers_new_modules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root,
                ".github/workflows/offline-tests.yml",
                "jobs:\n  macos-tests:\n    steps:\n      - run: python3 -m unittest discover -s tests -p 'test_*.py' -v\n",
            )
            write(root, "tests/test_egress_diagnose.py", "\n")
            self.assertEqual(list_errors(arch.check(root, EMPTY)), [])

    def _page(self, root: Path, css: str) -> None:
        write(root, "web/index.html", PAGE)
        write(root, "web/style.css", css)


if __name__ == "__main__":
    unittest.main()

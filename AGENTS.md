# 仓库约束

改完代码后运行 `python3 scripts/check_architecture.py`，再结束。CI 的 Linux 与 macOS 作业执行同一条命令。它有 error 就退出 1。不要抬高 `scripts/architecture_baseline.json` 来放过新的违规。

## 规则与执行方式

| 规则 | 执行方式 |
| --- | --- |
| 面板文字在暗色和亮色下达到 WCAG AA（正文 4.5:1，大字 3:1） | `scripts/check_architecture.py`（`theme-contrast`）。对比度按 `web/*.html` 和它们引用的样式计算，不依赖浏览器。已经低于阈值的导航序号记在基线里，只阻止变差或新增。`web/tests/dashboard.spec.cjs` 仍用真实计算样式检查页脚、弱化文字和未选中导航。 |
| 新的 `tests/test_*.py` 要出现在 macOS 作业的 unittest 名单里 | `scripts/check_architecture.py`（`macos-test-list`）。Linux 用 `unittest discover`。基线里的 `macos_test_omit` 只保留已经不在名单上的模块。 |
| 行为 | `python3 -m unittest discover -s tests -p 'test_*.py'` |

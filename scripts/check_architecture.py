#!/usr/bin/env python3
"""Repository architecture checks. Local and CI run this same command.

    python3 scripts/check_architecture.py

Each finding prints Violation, Fix, and Principle. The script exits 1 when any
finding is an error. Grandfathered contrast floors and macOS test omissions
live in scripts/architecture_baseline.json. Do not raise that file to admit a
new violation.

The checker uses only the standard library.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = Path(__file__).resolve().parent / "architecture_baseline.json"
WORKFLOW = Path(".github/workflows/offline-tests.yml")

PRINCIPLES = {
    "theme-contrast": (
        "Light-theme de-emphasized text missed WCAG AA twice. a4035eb darkened "
        "footer --ink-200 after it measured 2.73:1 and the browser spec only "
        "asserted the footer. 029d334 then darkened --ink-300 and --ink-400 "
        "because muted text was 4.03:1 and idle nav text was 4.34:1 on its "
        "background (docs/todo.md had already recorded the muted miss). Every "
        "shipped text node stays at or above 4.5:1, or 3:1 for large text, in "
        "both color schemes. A floor in scripts/architecture_baseline.json is "
        "a pair that already failed on main; do not lower it."
    ),
    "macos-test-list": (
        "The macOS CI job names unittest modules by hand, and Linux discovers "
        "tests/test_*.py. New modules were left off that list twice: "
        "test_channel_policy_state.py and test_timeline_metrics.py in 9248667 "
        "(docs/diagnostics-runbook.md, from 140969a, still called the omission "
        "out) and test_egress_diagnose.py in 3e13506. A new tests/test_*.py "
        "goes on the macos-tests command. macos_test_omit is only the ratchet "
        "for modules already absent."
    ),
    "syntax": "The architecture check has to read its inputs before the other rules can run.",
}


@dataclass(frozen=True)
class Violation:
    level: str
    path: str
    line: int
    rule: str
    violation: str
    fix: str
    principle: str

    def render(self) -> str:
        return (
            f"[ARCH][{self.level}] {self.path}:{self.line}\n"
            f"  Violation: {self.rule}: {self.violation}\n"
            f"  Fix: {self.fix}\n"
            f"  Principle: {self.principle}\n"
        )


def _violation(path: str, line: int, rule: str, violation: str, fix: str) -> Violation:
    return Violation("ERROR", path, line, rule, violation, fix, PRINCIPLES[rule])


def relpath(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


# --- CSS subset: enough for the shipped stylesheets, not a browser --------

@dataclass
class Compound:
    tag: str | None = None
    ident: str | None = None
    classes: tuple[str, ...] = ()
    attrs: tuple[tuple[str, str | None], ...] = ()
    pseudos: tuple[str, ...] = ()
    nots: tuple[Compound, ...] = ()


@dataclass
class Rule:
    selectors: list[list[tuple[str, Compound]]]
    declarations: list[tuple[str, str, int]]
    order: int
    scheme: str
    source: str


def _blank_comments(css: str) -> str:
    def repl(match: re.Match[str]) -> str:
        return "".join("\n" if char == "\n" else " " for char in match.group(0))

    return re.sub(r"/\*.*?\*/", repl, css, flags=re.S)


def _split_top(text: str, separator: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    for char in text:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        if char == separator and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(char)
    parts.append("".join(buf))
    return parts


def _parse_compound(text: str) -> Compound:
    tag: str | None = None
    ident: str | None = None
    classes: list[str] = []
    attrs: list[tuple[str, str | None]] = []
    pseudos: list[str] = []
    nots: list[Compound] = []
    i = 0
    while i < len(text):
        char = text[i]
        if char in " \t\r\n":
            i += 1
            continue
        if char == "." or char == "#" or (tag is None and (char == "*" or char.isalpha())):
            if char == "*":
                i += 1
                continue
            if char.isalpha():
                j = i + 1
                while j < len(text) and (text[j].isalnum() or text[j] == "-"):
                    j += 1
                tag = text[i:j].lower()
                i = j
                continue
            j = i + 1
            while j < len(text) and text[j] not in ".#:[":
                j += 1
            token = text[i + 1:j]
            if char == ".":
                classes.append(token)
            else:
                ident = token
            i = j
            continue
        if char == "[":
            end = text.find("]", i)
            body = text[i + 1:end if end != -1 else len(text)]
            if "=" in body:
                name, value = body.split("=", 1)
                attrs.append((name.strip().lower(), value.strip().strip("\"'")))
            else:
                attrs.append((body.strip().lower(), None))
            i = (end + 1) if end != -1 else len(text)
            continue
        if char == ":":
            if text.startswith(":not(", i):
                depth = 0
                j = i + 5
                while j < len(text):
                    if text[j] == "(":
                        depth += 1
                    elif text[j] == ")":
                        if depth == 0:
                            break
                        depth -= 1
                    j += 1
                nots.append(_parse_compound(text[i + 5:j]))
                i = j + 1
                continue
            j = i + 1
            while j < len(text) and (text[j].isalnum() or text[j] == "-"):
                j += 1
            pseudos.append(text[i + 1:j].lower())
            i = j
            continue
        i += 1
    return Compound(tag, ident, tuple(classes), tuple(attrs), tuple(pseudos), tuple(nots))


def _parse_complex(selector: str) -> list[tuple[str, Compound]]:
    parts: list[tuple[str, Compound]] = []
    combinator = ""
    i = 0
    while i < len(selector):
        if selector[i] in " \t\r\n":
            if combinator == "":
                combinator = " "
            i += 1
            continue
        if selector[i] == ">":
            combinator = ">"
            i += 1
            continue
        depth = 0
        j = i
        while j < len(selector):
            if selector[j] in "([{":
                depth += 1
            elif selector[j] in ")]}":
                depth -= 1
            elif depth == 0 and (selector[j].isspace() or selector[j] == ">"):
                break
            j += 1
        parts.append((combinator, _parse_compound(selector[i:j])))
        combinator = ""
        i = j
    return parts


def _declarations(body: str, line_base: int, body_start: int, full: str) -> list[tuple[str, str, int]]:
    found: list[tuple[str, str, int]] = []
    for chunk in _split_top(body, ";"):
        if ":" not in chunk:
            continue
        name, value = chunk.split(":", 1)
        name = name.strip().lower()
        value = value.strip()
        if not name or not value:
            continue
        value = value.replace("!important", "").strip()
        offset = full.find(chunk, body_start)
        line = full.count("\n", 0, offset if offset != -1 else body_start) + 1
        if line < line_base:
            line = line_base
        found.append((name, value, line))
    return found


def _media_scheme(prelude: str) -> str | None:
    if "prefers-color-scheme" not in prelude:
        return ""
    if re.search(r"prefers-color-scheme:\s*light", prelude):
        return "light"
    if re.search(r"prefers-color-scheme:\s*dark", prelude):
        return "dark"
    return ""


def _parse_rules(css: str, source: str) -> list[Rule]:
    text = _blank_comments(css)
    rules: list[Rule] = []
    order = 0

    def walk(block: str, scheme: str, origin: int) -> None:
        nonlocal order
        i = 0
        n = len(block)
        while i < n:
            while i < n and block[i].isspace():
                i += 1
            if i >= n:
                return
            if block[i] == "@":
                header = i
                depth = 0
                while i < n and not (block[i] == "{" and depth == 0):
                    if block[i] == "(":
                        depth += 1
                    elif block[i] == ")":
                        depth -= 1
                    i += 1
                prelude = block[header:i]
                if i >= n or block[i] != "{":
                    raise ValueError(f"unclosed at-rule in {source}")
                start = i + 1
                depth = 1
                i += 1
                while i < n and depth:
                    if block[i] == "{":
                        depth += 1
                    elif block[i] == "}":
                        depth -= 1
                    i += 1
                inner = block[start:i - 1]
                kind = _media_scheme(prelude)
                if kind is None or kind == "":
                    continue
                if scheme == "all":
                    walk(inner, kind, origin + start)
                elif scheme == kind:
                    walk(inner, scheme, origin + start)
                continue
            header = i
            while i < n and block[i] != "{":
                i += 1
            if i >= n:
                raise ValueError(f"unclosed rule in {source}")
            selector = block[header:i].strip()
            start = i + 1
            depth = 1
            i += 1
            while i < n and depth:
                if block[i] == "{":
                    depth += 1
                elif block[i] == "}":
                    depth -= 1
                i += 1
            body = block[start:i - 1]
            if not selector:
                continue
            selectors = [_parse_complex(part) for part in _split_top(selector, ",") if part.strip()]
            decls = _declarations(body, text.count("\n", 0, origin + header) + 1, origin + start, text)
            if selectors and decls:
                rules.append(Rule(selectors, decls, order, scheme, source))
                order += 1

    walk(text, "all", 0)
    return rules


def _specificity(compound: Compound) -> tuple[int, int, int]:
    ids = 1 if compound.ident else 0
    classes = len(compound.classes) + len(compound.attrs) + len(compound.pseudos)
    types = 1 if compound.tag else 0
    for inner in compound.nots:
        a, b, c = _specificity(inner)
        ids += a
        classes += b
        types += c
    return ids, classes, types


def _complex_specificity(selector: list[tuple[str, Compound]]) -> tuple[int, int, int]:
    ids = classes = types = 0
    for _combinator, compound in selector:
        a, b, c = _specificity(compound)
        ids += a
        classes += b
        types += c
    return ids, classes, types


# --- document and cascade -----------------------------------------------

@dataclass
class Element:
    tag: str
    attrs: dict[str, str]
    parent: Element | None = None
    children: list[Element] = field(default_factory=list)
    text: list[str] = field(default_factory=list)
    source_line: int = 1

    @property
    def classes(self) -> set[str]:
        return set(self.attrs.get("class", "").split())

    @property
    def id(self) -> str:
        return self.attrs.get("id", "")


VOID_TAGS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
    "source", "track", "wbr",
}


class _DocumentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = Element("html", {})
        self.stack: list[Element] = [self.root]
        self.seen_html = False
        self.ignore: str | None = None
        self.style_buf: list[str] = []
        self.sources: list[tuple[str, str]] = []
        self.html_path: Path | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if self.ignore:
            return
        attr_map = {name.lower(): (value if value is not None else "") for name, value in attrs}
        if tag == "html":
            self.seen_html = True
            self.root.attrs.update(attr_map)
            self.root.source_line = self.getpos()[0]
            return
        if tag == "style":
            self.ignore = "style"
            self.style_buf = []
            return
        if tag == "script":
            self.ignore = "script"
            return
        if tag == "link" and "stylesheet" in attr_map.get("rel", "").split():
            href = attr_map.get("href", "")
            if href and self.html_path is not None:
                relative = href.split("?", 1)[0]
                path = self.html_path.parent / relative.lstrip("/")
                self.sources.append(("file", str(path)))
            return
        element = Element(tag, attr_map, self.stack[-1], source_line=self.getpos()[0])
        self.stack[-1].children.append(element)
        if tag not in VOID_TAGS:
            self.stack.append(element)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self.ignore:
            if tag == self.ignore:
                if tag == "style":
                    self.sources.append(("inline", "".join(self.style_buf)))
                self.ignore = None
            return
        if tag in VOID_TAGS or tag == "html":
            return
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index].tag == tag:
                del self.stack[index:]
                return

    def handle_data(self, data: str) -> None:
        if self.ignore == "style":
            self.style_buf.append(data)
            return
        if self.ignore or not self.stack:
            return
        self.stack[-1].text.append(data)


def _is_first_child(element: Element) -> bool:
    if element.parent is None:
        return False
    return next(child for child in element.parent.children) is element


def _matches_compound(element: Element, compound: Compound) -> bool:
    if compound.tag and element.tag != compound.tag:
        return False
    if compound.ident and element.id != compound.ident:
        return False
    if not set(compound.classes) <= element.classes:
        return False
    for name, value in compound.attrs:
        if name not in element.attrs:
            return False
        if value is not None and element.attrs.get(name) != value:
            return False
    for pseudo in compound.pseudos:
        if pseudo == "root":
            if element.tag != "html":
                return False
        elif pseudo == "disabled":
            # Inactive controls are outside the WCAG AA text contract the two
            # theme fixes measured. Score the enabled colors instead.
            return False
        elif pseudo == "first-child":
            if not _is_first_child(element):
                return False
        elif pseudo in {"hover", "focus", "focus-visible", "active"}:
            return False
        else:
            return False
    for inner in compound.nots:
        if _matches_compound(element, inner):
            return False
    return True


def _matches(element: Element, selector: list[tuple[str, Compound]]) -> bool:
    if not selector or not _matches_compound(element, selector[-1][1]):
        return False
    node: Element | None = element
    for index in range(len(selector) - 2, -1, -1):
        combinator = selector[index + 1][0] or " "
        compound = selector[index][1]
        if combinator == ">":
            node = node.parent if node else None
            if node is None or not _matches_compound(node, compound):
                return False
        else:
            node = node.parent if node else None
            found = False
            while node is not None:
                if _matches_compound(node, compound):
                    found = True
                    break
                node = node.parent
            if not found:
                return False
    return True


def _parse_color(value: str, variables: dict[str, str], inherited: tuple[float, float, float, float], depth: int = 0) -> tuple[float, float, float, float]:
    text = value.strip().lower()
    if depth > 8:
        raise ValueError(f"color {value!r} is nested too deeply")
    if text.startswith("var(") and text.endswith(")"):
        body = text[4:-1]
        name, _sep, fallback = body.partition(",")
        name = name.strip()
        if name not in variables:
            if not fallback:
                raise ValueError(f"missing custom property {name}")
            return _parse_color(fallback, variables, inherited, depth + 1)
        return _parse_color(variables[name], variables, inherited, depth + 1)
    if text in {"transparent", "none"}:
        return (0.0, 0.0, 0.0, 0.0)
    if text in {"inherit", "currentcolor"}:
        return inherited
    if text.startswith("#"):
        hex_text = text[1:]
        if len(hex_text) == 3:
            hex_text = "".join(char * 2 for char in hex_text)
        if len(hex_text) == 4:
            hex_text = "".join(char * 2 for char in hex_text)
        if len(hex_text) not in {6, 8} or any(char not in "0123456789abcdef" for char in hex_text):
            raise ValueError(f"bad color {value!r}")
        channels = [int(hex_text[i:i + 2], 16) / 255 for i in range(0, 6, 2)]
        alpha = int(hex_text[6:8], 16) / 255 if len(hex_text) == 8 else 1.0
        return (channels[0], channels[1], channels[2], alpha)
    match = re.fullmatch(r"rgba?\(([^)]+)\)", text)
    if match:
        parts = [part.strip() for part in match.group(1).replace("/", " ").split(",") if part.strip()]
        if len(parts) < 3:
            parts = match.group(1).replace("/", " ").split()
        if len(parts) not in {3, 4}:
            raise ValueError(f"bad color {value!r}")
        rgb = tuple(int(float(part)) / 255 for part in parts[:3])
        alpha = float(parts[3]) if len(parts) == 4 else 1.0
        return (rgb[0], rgb[1], rgb[2], alpha)
    raise ValueError(f"unsupported color {value!r}")


def _channel(value: float) -> float:
    return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4


def _luminance(color: tuple[float, float, float]) -> float:
    red, green, blue = (_channel(color[0]), _channel(color[1]), _channel(color[2]))
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def _contrast(foreground: tuple[float, float, float], background: tuple[float, float, float]) -> float:
    left, right = _luminance(foreground), _luminance(background)
    lighter, darker = max(left, right), min(left, right)
    return (lighter + 0.05) / (darker + 0.05)


def _mix(top: tuple[float, float, float], bottom: tuple[float, float, float], alpha: float) -> tuple[float, float, float]:
    return tuple(top[i] * alpha + bottom[i] * (1 - alpha) for i in range(3))  # type: ignore[return-value]


def _over(color: tuple[float, float, float, float], bottom: tuple[float, float, float]) -> tuple[float, float, float]:
    return _mix((color[0], color[1], color[2]), bottom, color[3])


def _length_px(value: str, parent: float, root: float) -> float | None:
    match = re.search(r"(-?\d*\.?\d+)(px|rem|em|%)", value.strip().lower())
    if not match:
        return None
    number = float(match.group(1))
    unit = match.group(2)
    if unit == "px":
        return number
    if unit == "rem":
        return number * root
    return number * parent if unit == "em" else number / 100 * parent


def _font_weight(value: str) -> int | None:
    text = value.strip().lower()
    if text == "normal":
        return 400
    if text == "bold":
        return 700
    if text == "inherit":
        return None
    try:
        return int(float(text))
    except ValueError:
        return None


def _font_size_from_shorthand(value: str, parent: float, root: float) -> float | None:
    if value.strip().lower() == "inherit":
        return None
    return _length_px(value, parent, root)


def _threshold(size: float, weight: int) -> float:
    if size >= 24 or (size >= 24 * 14 / 18 and weight >= 700):
        return 3.0
    return 4.5


def _element_path(element: Element) -> str:
    parts: list[str] = []
    node: Element | None = element
    while node is not None:
        classes = "".join(f".{name}" for name in node.attrs.get("class", "").split() if name)
        ident = f"#{node.id}" if node.id else ""
        parts.append(f"{node.tag}{ident}{classes}")
        node = node.parent
    return ">".join(reversed(parts))


def _direct_text(element: Element) -> bool:
    return any(chunk.strip() for chunk in element.text)


@dataclass
class Pair:
    key: str
    ratio: float
    threshold: float
    source: str
    line: int
    scheme: str


def _cascade_document(root_element: Element, rules: list[Rule], scheme: str) -> list[Pair]:
    applicable = [rule for rule in rules if rule.scheme in {scheme, "all"}]
    pairs: list[Pair] = []

    def visit(element: Element, parent_style: dict[str, Any] | None) -> None:
        matched: list[tuple[tuple[int, int, int], int, Rule, list[tuple[str, Compound]]]] = []
        for rule in applicable:
            for selector in rule.selectors:
                if _matches(element, selector):
                    matched.append((_complex_specificity(selector), rule.order, rule, selector))
        matched.sort(key=lambda item: (item[0], item[1]))
        specified: dict[str, tuple[str, int, str]] = {}
        for _spec, _order, rule, _selector in matched:
            for prop, value, line in rule.declarations:
                specified[prop] = (value, line, rule.source)
        variables = dict(parent_style["variables"]) if parent_style else {}
        for prop, (value, _line, _source) in specified.items():
            if prop.startswith("--"):
                variables[prop] = value
        inherited_color = parent_style["color"] if parent_style else (0.0, 0.0, 0.0, 1.0)
        parent_size = parent_style["font_size"] if parent_style else 16.0
        root_size = parent_style["root_size"] if parent_style else 16.0
        parent_weight = parent_style["font_weight"] if parent_style else 400
        color_line = (element.source_line, "inline")
        try:
            if "color" in specified:
                raw, line, source = specified["color"]
                color = _parse_color(raw, variables, inherited_color)
                color_line = (line, source)
            else:
                color = inherited_color
                if parent_style:
                    color_line = parent_style["color_line"]
            background = (0.0, 0.0, 0.0, 0.0)
            if "background-color" in specified:
                background = _parse_color(specified["background-color"][0], variables, color)
            elif "background" in specified:
                raw_bg = specified["background"][0]
                if raw_bg.lower() not in {"none", "transparent"} and not raw_bg.lower().startswith(("url(", "linear-gradient", "repeating")):
                    background = _parse_color(raw_bg.split()[-1] if " " in raw_bg and raw_bg.split()[-1].startswith(("#", "rgb", "var")) else raw_bg, variables, color)
            if "font-size" in specified:
                font_size = _length_px(specified["font-size"][0], parent_size, root_size) or parent_size
            elif "font" in specified:
                font_size = _font_size_from_shorthand(specified["font"][0], parent_size, root_size) or parent_size
            else:
                font_size = parent_size
            if element.tag == "html" and "font-size" not in specified and "font" not in specified:
                font_size = 16.0
            if "font-weight" in specified:
                font_weight = _font_weight(specified["font-weight"][0]) or parent_weight
            else:
                font_weight = parent_weight
            opacity = 1.0
            if "opacity" in specified:
                opacity = float(specified["opacity"][0])
                color_line = (specified["opacity"][1], specified["opacity"][2])
        except (ValueError, IndexError) as exc:
            raise ValueError(f"{element.tag}: {exc}") from exc
        style = {
            "variables": variables,
            "color": color,
            "color_line": color_line,
            "background": background,
            "font_size": font_size,
            "font_weight": font_weight,
            "opacity": opacity,
            "root_size": font_size if element.tag == "html" else root_size,
            "painted": None,
        }
        backdrop = parent_style["painted"] if parent_style else (1.0, 1.0, 1.0)
        used = _over(background, backdrop)
        if opacity < 1:
            painted = _mix(used, backdrop, opacity)
        else:
            painted = used
        style["painted"] = painted
        if _direct_text(element):
            visible_fg = _over(color, used)
            if opacity < 1:
                visible_fg = _mix(visible_fg, backdrop, opacity)
                visible_bg = _mix(used, backdrop, opacity)
            else:
                visible_bg = used
            ratio = _contrast(visible_fg, visible_bg)
            limit = _threshold(font_size, font_weight)
            path = _element_path(element)
            pairs.append(Pair(
                f"{scheme}|{path}|{limit:.2f}",
                ratio,
                limit,
                color_line[1],
                color_line[0],
                scheme,
            ))
        for child in element.children:
            visit(child, style)

    visit(root_element, None)
    return pairs


def _load_documents(root: Path) -> list[tuple[Path, _DocumentParser]]:
    web = root / "web"
    if not web.is_dir():
        return []
    documents = []
    for path in sorted(web.glob("*.html")):
        parser = _DocumentParser()
        parser.html_path = path
        parser.feed(path.read_text(encoding="utf-8"))
        documents.append((path, parser))
    return documents


def _rules_for(root: Path, html_path: Path, parser: _DocumentParser) -> list[Rule]:
    rules: list[Rule] = []
    for kind, payload in parser.sources:
        if kind == "file":
            css_path = Path(payload)
            source = relpath(root, css_path) if css_path.is_file() else relpath(root, html_path)
            if not css_path.is_file():
                raise FileNotFoundError(css_path)
            text = css_path.read_text(encoding="utf-8")
        else:
            source = relpath(root, html_path)
            text = payload
        rules.extend(_parse_rules(text, source))
    return rules


def _contrast_floors(baseline: dict[str, Any]) -> dict[str, float]:
    value = baseline.get("theme_contrast", [])
    if not isinstance(value, list):
        raise ValueError("theme_contrast must be a list")
    floors: dict[str, float] = {}
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("theme_contrast entries must be objects")
        key = item.get("key")
        ratio = item.get("ratio")
        if not isinstance(key, str) or isinstance(ratio, bool) or not isinstance(ratio, (int, float)):
            raise ValueError("theme_contrast entries need a string key and a numeric ratio")
        floors[key] = float(ratio)
    return floors


def _round_ratio(value: float) -> float:
    return round(value + 1e-12, 2)


def check_theme_contrast(root: Path, baseline: dict[str, Any]) -> list[Violation]:
    floors = _contrast_floors(baseline)
    failing: dict[str, Pair] = {}
    try:
        documents = _load_documents(root)
        for html_path, parser in documents:
            rules = _rules_for(root, html_path, parser)
            for scheme in ("dark", "light"):
                for pair in _cascade_document(parser.root, rules, scheme):
                    if _round_ratio(pair.ratio) + 1e-9 >= pair.threshold:
                        continue
                    previous = failing.get(pair.key)
                    if previous is None or pair.ratio < previous.ratio:
                        failing[pair.key] = pair
    except (OSError, ValueError, FileNotFoundError) as exc:
        return [_violation(
            "web/style.css", 1, "syntax",
            f"Theme contrast inputs could not be read: {exc}",
            "Keep web/*.html and the stylesheets they link as UTF-8 the checker can parse.",
        )]
    violations: list[Violation] = []
    fix = (
        "Change the color or background token in web/style.css (or the inline style this "
        "line names) until the pair reaches its threshold. Opacity counts. The dashboard "
        "browser spec covers footer, muted, and idle nav; this check covers every shipped "
        "text node. Do not lower theme_contrast in scripts/architecture_baseline.json to "
        "admit a new or worse pair."
    )
    for key, pair in sorted(failing.items()):
        ratio = _round_ratio(pair.ratio)
        floor = floors.get(key)
        source = pair.source if pair.source != "inline" else "web/index.html"
        if floor is None:
            violations.append(_violation(
                source, pair.line, "theme-contrast",
                f"{key} is {ratio:.2f}:1, below {pair.threshold:.2f}:1.",
                fix,
            ))
        elif ratio + 1e-9 < floor:
            violations.append(_violation(
                source, pair.line, "theme-contrast",
                f"{key} dropped from its floor of {floor:.2f}:1 to {ratio:.2f}:1.",
                fix,
            ))
    for key, floor in sorted(floors.items()):
        pair = failing.get(key)
        if pair is None:
            violations.append(_violation(
                "scripts/architecture_baseline.json", 1, "theme-contrast",
                f"Baseline floor no longer matches a failing pair: {key} ({floor:.2f}:1).",
                "Remove that theme_contrast entry after confirming the pair is gone or now meets its threshold.",
            ))
    return violations


# --- macOS explicit unittest list ----------------------------------------

def _job_text(workflow: str, name: str) -> str | None:
    lines = workflow.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.startswith(f"  {name}:"):
            start = index
            break
    if start is None:
        return None
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if re.match(r"  [A-Za-z0-9_-]+:\s*$", lines[index]):
            end = index
            break
    return "\n".join(lines[start:end])


def _listed_modules(job: str) -> set[str] | None:
    if re.search(r"\bunittest discover\b", job):
        return None
    found: set[str] = set()
    for match in re.finditer(r"\bpython3 -m unittest\b([^\n#]*)", job):
        for token in match.group(1).split():
            if token.startswith("test_"):
                found.add(token if token.endswith(".py") else f"{token}.py")
    return found


def _omit_map(baseline: dict[str, Any]) -> dict[str, str]:
    value = baseline.get("macos_test_omit", {})
    if not isinstance(value, dict):
        raise ValueError("macos_test_omit must be an object of test file to reason")
    mapping: dict[str, str] = {}
    for name, reason in value.items():
        if not isinstance(name, str) or not isinstance(reason, str) or not reason.strip():
            raise ValueError(f"macos_test_omit[{name!r}] needs a non-empty reason")
        mapping[name] = reason
    return mapping


def check_macos_test_list(root: Path, baseline: dict[str, Any]) -> list[Violation]:
    workflow_path = root / WORKFLOW
    if not workflow_path.is_file():
        return []
    allowed = _omit_map(baseline)
    text = workflow_path.read_text(encoding="utf-8")
    job = _job_text(text, "macos-tests")
    if job is None:
        return [_violation(
            WORKFLOW.as_posix(), 1, "macos-test-list",
            "The macos-tests job is missing, so new tests have no explicit list to join.",
            "Restore the macos-tests job and name every tests/test_*.py module on its "
            "python3 -m unittest command, or switch that job to unittest discover.",
        )]
    listed = _listed_modules(job)
    files = sorted(path.name for path in (root / "tests").glob("test_*.py")) if (root / "tests").is_dir() else []
    omitted = set() if listed is None else set(files) - listed
    violations: list[Violation] = []
    fix = (
        "Add this module to the python3 -m unittest command in the macos-tests job of "
        ".github/workflows/offline-tests.yml. Do not add a new macos_test_omit entry to "
        "skip a portable test. The omit map is the ratchet for modules already absent "
        "from that command; Linux already discovers tests/test_*.py."
    )
    line = 1
    for job_line in job.splitlines():
        if "python3 -m unittest" in job_line:
            line = text.splitlines().index(job_line) + 1
            break
    for name in sorted(omitted):
        if name in allowed:
            continue
        violations.append(_violation(
            WORKFLOW.as_posix(), line, "macos-test-list",
            f"{name} is not on the macos-tests unittest command.",
            fix,
        ))
    for name in sorted(allowed):
        if name in omitted:
            continue
        violations.append(_violation(
            "scripts/architecture_baseline.json", 1, "macos-test-list",
            f"macos_test_omit still lists {name}, which is no longer an omission.",
            "Remove that entry from macos_test_omit in scripts/architecture_baseline.json.",
        ))
    return violations


def load_baseline(path: Path = BASELINE_PATH) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("architecture baseline must be a JSON object")
    _contrast_floors(data)
    _omit_map(data)
    return data


def check(root: Path, baseline: dict[str, Any]) -> list[Violation]:
    violations = [
        *check_theme_contrast(root, baseline),
        *check_macos_test_list(root, baseline),
    ]
    violations.sort(key=lambda item: (item.path, item.line, item.rule, item.violation))
    return violations


def exit_code(violations: list[Violation]) -> int:
    return 1 if any(item.level == "ERROR" for item in violations) else 0


def main(argv: list[str] | None = None) -> int:
    if argv:
        raise SystemExit("python3 scripts/check_architecture.py takes no arguments")
    try:
        baseline = load_baseline()
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        item = _violation(
            BASELINE_PATH.name, 1, "syntax",
            f"Architecture baseline could not be read: {exc}",
            "Restore scripts/architecture_baseline.json as the committed ratchet.",
        )
        print(item.render())
        print("[ARCH] Failed with 1 error(s).")
        return 1
    violations = check(REPO_ROOT, baseline)
    for item in violations:
        print(item.render())
    if violations:
        print(f"[ARCH] Failed with {len(violations)} error(s).")
        return 1
    print("[ARCH] Passed with 0 error(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

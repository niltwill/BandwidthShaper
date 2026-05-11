#!/usr/bin/env python3
"""
localization_generate.py
────────────────────────────────────────────────────────────────────────────
Generates localization_data.c from plain-text translation files.

Expected layout:
  localization_ids.h          <- source of truth for enum order
  language/
    en/
      en_01shared.txt         <- S_*  entries  (used by both CLI and GUI)
      en_02cli.txt            <- CLI_* entries  (narrow char only)
      en_03gui.txt            <- GUI_* entries  (wide char only)
    ...

Text-file format (same syntax the .c file already used):
  - One entry per "slot" in the enum.
  - Each entry is one or more lines of C string-literal content.
  - An entry ends at the first line whose last non-whitespace characters
    are  ","  (closing quote + comma).
  - Adjacent-string-literal concatenation across lines is supported:
        "First part "
        "second part",
  - Blank lines between entries are allowed and ignored.

Usage:
  python generate_localization.py [OPTIONS]

Options:
  --header  PATH   localization_ids.h  (default: ./localization_ids.h)
  --langdir PATH   language root dir   (default: ./language)
  --output  PATH   output .c file      (default: ./localization_data.c)
  --default LANG   language whose arrays initialise the global pointers
                   (default: en)
"""

import argparse
import os
import re
import sys
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# 1.  Parse StringId enum from localization_ids.h
# ─────────────────────────────────────────────────────────────────────────────

def parse_string_ids(header_path: str) -> list[tuple[str, str]]:
    """
    Return [(name, category), ...] in enum declaration order.
    category is one of: 'S', 'CLI', 'GUI'
    Sentinel names beginning with '_' are skipped.
    """
    text = Path(header_path).read_text(encoding="utf-8")

    # Locate the StringId enum body
    m = re.search(
        r"typedef\s+enum\s*\{([^}]+)\}\s*StringId\s*;",
        text, re.DOTALL
    )
    if not m:
        sys.exit(f"ERROR: cannot find 'typedef enum {{ ... }} StringId;' in {header_path}")

    body = m.group(1)
    ids = []
    for raw in body.splitlines():
        # Strip inline comments and whitespace
        line = re.sub(r"//.*", "", raw).strip()
        if not line:
            continue
        # Extract leading identifier (ignore = value / comma)
        id_m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)", line)
        if not id_m:
            continue
        name = id_m.group(1)
        if name.startswith("_"):        # _STR_COUNT, _LOC_LANG_COUNT …
            continue
        if name.startswith("GUI_"):
            cat = "GUI"
        elif name.startswith("CLI_"):
            cat = "CLI"
        else:
            cat = "S"                   # S_* and anything else -> shared
        ids.append((name, cat))

    if not ids:
        sys.exit(f"ERROR: no identifiers parsed from StringId enum in {header_path}")
    return ids


# ─────────────────────────────────────────────────────────────────────────────
# 2.  Parse a translation text file into a list of entry strings
# ─────────────────────────────────────────────────────────────────────────────

def parse_entries(filepath: str) -> list[str]:
    """
    Parse a translation file and return a list of entry strings.
    Each entry string is valid C string-literal content (possibly multi-line),
    WITHOUT a trailing comma.  Example single entry:
        '"Error: %s requires an argument.\\n"'
    Example multi-line entry:
        '"First part "\\n"second part"'
    """
    lines = Path(filepath).read_text(encoding="utf-8").splitlines()
    entries: list[str] = []
    current: list[str] = []

    for raw in lines:
        stripped = raw.rstrip()
        if not stripped:
            if current:
                # Blank line mid-entry is unusual; treat as continuation gap.
                # (In practice our files don't have blanks inside an entry.)
                pass
            continue

        current.append(stripped)

        # An entry ends when this line's last non-whitespace content is  ",
        # i.e. the line ends with  ",  (optionally followed only by spaces).
        if stripped.endswith('",'):
            entry_text = "\n".join(current)
            # Strip the trailing comma so we can emit it ourselves.
            entry_text = entry_text.rstrip()
            if entry_text.endswith(","):
                entry_text = entry_text[:-1]
            entries.append(entry_text)
            current = []

    # Flush any unterminated final entry (shouldn't happen in well-formed files).
    if current:
        entry_text = "\n".join(current).rstrip().rstrip(",")
        if entry_text:
            entries.append(entry_text)

    return entries


# ─────────────────────────────────────────────────────────────────────────────
# 3.  Wide-string conversion  ("..." -> L"...")
# ─────────────────────────────────────────────────────────────────────────────

def to_wide(entry: str) -> str:
    """
    Prepend  L  before the opening double-quote of every string-literal piece.

    In our text files every piece always starts at the beginning of a line
    (after optional whitespace), so we only touch  "  in that position -
    never the closing  "  which appears mid-line before  ,  or end-of-line.

    Examples:
        "text" ->  L"text"
        "part one "  ->  L"part one "
        "part two",  ->  L"part two",   (caller strips the comma)
    """
    return re.sub(r'(?m)^(\s*)"', r'\1L"', entry)


# ─────────────────────────────────────────────────────────────────────────────
# 4.  Validate that entry counts match enum slots
# ─────────────────────────────────────────────────────────────────────────────

def validate_counts(
    lang: str,
    ids: list[tuple[str, str]],
    shared: list[str],
    cli: list[str],
    gui: list[str],
) -> bool:
    expected_s   = sum(1 for _, c in ids if c == "S")
    expected_cli = sum(1 for _, c in ids if c == "CLI")
    expected_gui = sum(1 for _, c in ids if c == "GUI")

    ok = True
    for label, got, want in [
        ("shared", len(shared), expected_s),
        ("CLI", len(cli), expected_cli),
        ("GUI", len(gui), expected_gui),
    ]:
        if got != want:
            print(
                f"WARNING [{lang}] {label}: {got} entries in text file "
                f"but {want} slots in enum.",
                file=sys.stderr,
            )
            ok = False
    return ok


# ─────────────────────────────────────────────────────────────────────────────
# 5.  Emit a single array definition
# ─────────────────────────────────────────────────────────────────────────────

EMPTY_NARROW = '""'
EMPTY_WIDE = 'L""'

def _indent_entry(entry: str) -> str:
    """Indent continuation lines of a multi-line entry to align under the first."""
    lines = entry.split("\n")
    if len(lines) == 1:
        return entry
    # First line is already indented by the caller; indent the rest.
    return lines[0] + "\n" + "\n".join("    " + l for l in lines[1:])


def emit_array_cli(
    lang: str,
    ids: list[tuple[str, str]],
    shared: list[str],
    cli: list[str],
) -> list[str]:
    """Return lines for  const char * const lang_cli_<lang>[_STR_COUNT]."""
    out = [
        f"// {'─'*73}",
        f"// {lang.upper()} – CLI (narrow char)",
        f"// {'─'*73}",
        f"const char * const lang_cli_{lang}[_STR_COUNT] = {{",
    ]
    si = ci = 0
    for name, cat in ids:
        if cat == "S":
            val = shared[si] if si < len(shared) else EMPTY_NARROW
            si += 1
        elif cat == "CLI":
            val = cli[ci] if ci < len(cli) else EMPTY_NARROW
            ci += 1
        else:  # GUI
            val = EMPTY_NARROW

        val_indented = _indent_entry(val)
        out.append(f"    /*{name}*/ {val_indented},")

    out.append("};")
    return out


def emit_array_gui(
    lang: str,
    ids: list[tuple[str, str]],
    shared: list[str],
    gui: list[str],
) -> list[str]:
    """Return lines for  const wchar_t * const lang_gui_<lang>[_STR_COUNT]."""
    out = [
        "",
        f"// {'─'*73}",
        f"// {lang.upper()} – GUI (wide char)",
        f"// {'─'*73}",
        f"const wchar_t * const lang_gui_{lang}[_STR_COUNT] = {{",
    ]
    si = gi = 0
    for name, cat in ids:
        if cat == "S":
            val = to_wide(shared[si]) if si < len(shared) else EMPTY_WIDE
            si += 1
        elif cat == "CLI":
            val = EMPTY_WIDE
        else:  # GUI
            val = to_wide(gui[gi]) if gi < len(gui) else EMPTY_WIDE
            gi += 1

        val_indented = _indent_entry(val)
        out.append(f"    /*{name}*/ {val_indented},")

    out.append("};")
    return out


# ─────────────────────────────────────────────────────────────────────────────
# 6.  Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--header",  default="localization_ids.h",
                    help="Path to localization_ids.h")
    ap.add_argument("--langdir", default="language",
                    help="Root directory that contains per-language subdirectories")
    ap.add_argument("--output",  default="localization_data.c",
                    help="Output file path")
    ap.add_argument("--default", default="en", dest="default_lang",
                    help="Language whose arrays initialise the global pointers (default: en)")
    args = ap.parse_args()

    # ── Parse enum ──────────────────────────────────────────────────────────
    ids = parse_string_ids(args.header)
    n_s   = sum(1 for _, c in ids if c == "S")
    n_cli = sum(1 for _, c in ids if c == "CLI")
    n_gui = sum(1 for _, c in ids if c == "GUI")
    total = len(ids)
    print(f"Parsed {total} string IDs  ({n_s} shared, {n_cli} CLI, {n_gui} GUI)")

    # ── Discover languages ──────────────────────────────────────────────────
    lang_root = Path(args.langdir)
    if not lang_root.is_dir():
        sys.exit(f"ERROR: language directory not found: {lang_root}")

    langs = sorted(p.name for p in lang_root.iterdir() if p.is_dir())
    if not langs:
        sys.exit(f"ERROR: no language subdirectories found in {lang_root}")
    print(f"Languages found: {', '.join(langs)}")

    if args.default_lang not in langs:
        sys.exit(f"ERROR: default language '{args.default_lang}' not found in {lang_root}")

    # ── Build output ─────────────────────────────────────────────────────────
    lines: list[str] = []

    lines += [
        "// localization_data.c",
        "// AUTO-GENERATED by generate_localization.py - DO NOT EDIT MANUALLY.",
        "// Edit the files under language/<lang>/ instead, then re-run the script.",
        "//",
        "// String order must stay consistent between CLI and GUI arrays.",
        "// Slots that don't apply to an array are filled with empty literals.",
        "",
        '#include "localization_api.h"',
        "",
    ]

    for lang in langs:
        ld = lang_root / lang
        shared_path = ld / f"{lang}_01shared.txt"
        cli_path    = ld / f"{lang}_02cli.txt"
        gui_path    = ld / f"{lang}_03gui.txt"

        for p in (shared_path, cli_path, gui_path):
            if not p.exists():
                sys.exit(f"ERROR: missing file {p}")

        shared = parse_entries(str(shared_path))
        cli    = parse_entries(str(cli_path))
        gui    = parse_entries(str(gui_path))

        print(f"  [{lang}]  shared={len(shared)}  cli={len(cli)}  gui={len(gui)}")
        validate_counts(lang, ids, shared, cli, gui)

        lines += [
            "",
            f"// {'═'*75}",
            f"// Language: {lang.upper()}",
            f"// {'═'*75}",
        ]
        lines += emit_array_cli(lang, ids, shared, cli)
        lines += emit_array_gui(lang, ids, shared, gui)

    # ── Global state pointers ────────────────────────────────────────────────
    dl = args.default_lang
    lines += [
        "",
        f"// {'═'*75}",
        "// Active Table Pointers (Global State)",
        f"// {'═'*75}",
        f"const char * const *g_cli_strings = lang_cli_{dl};",
        f"const wchar_t * const *g_gui_strings = lang_gui_{dl};",
        "",
        f"// {'═'*75}",
        "// Compile-Time Size Sanity Checks",
        f"// {'═'*75}",
        f"typedef char _loc_cli_size_check_gen[",
        f"    (sizeof(lang_cli_{dl}) / sizeof(lang_cli_{dl}[0]) == _STR_COUNT) ? 1 : -1];",
        f"typedef char _loc_gui_size_check_gen[",
        f"    (sizeof(lang_gui_{dl}) / sizeof(lang_gui_{dl}[0]) == _STR_COUNT) ? 1 : -1];",
        "",
    ]

    # ── Write ────────────────────────────────────────────────────────────────
    out_path = Path(args.output)
    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Written -> {out_path}  ({out_path.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()

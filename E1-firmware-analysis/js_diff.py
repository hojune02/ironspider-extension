#!/usr/bin/env python3
"""
WAGO Firmware JavaScript Diff — Qualitative Functionality Analysis
Compares JS file lists between v3.0.39 (old) and v4.02.13 (new) firmware.
Categorizes new files by functionality to support qualitative analysis.
"""

import os
import json
import subprocess
from pathlib import Path
from collections import defaultdict

OLD_ROOT = Path("/mnt/wago-old/var/www")
NEW_ROOT = Path("/mnt/wago-new/var/www")
SCRIPT_DIR = Path(__file__).parent
OUT_JSON = SCRIPT_DIR / "day7_js_diff.json"
OUT_TXT = SCRIPT_DIR / "day7_summary.txt"

# Functional category keywords (checked against full path, lowercased)
CATEGORIES = [
    ("security",            ["tls", "certificate", "wbm-user", "wbm-security", "aide", "firewall"]),
    ("cloud_remote",        ["cloud", "openvpn", "ipsec", "modem-ng", "wbm-modem"]),
    ("industrial_protocols",["opcua", "bacnet", "profibus", "wda"]),
    ("container_infra",     ["docker", "ipk", "package-server"]),
    ("api_docs",            ["openapi", "redoc"]),
    ("webvisu",             ["ews", "webvisu"]),
    ("monitoring",          ["diagnostic", "statusled", "statusplcswitch", "statusdate",
                             "wbm-information", "runtime-information"]),
    ("core_framework",      ["pfc.js", "boot-mode", "create-image", "massstorage",
                             "legal", "wbm-ports", "runtime-config", "runtime-services",
                             "serial-interface", "service-interface"]),
]


def find_js_files(root: Path) -> list[dict]:
    """Return list of dicts with path info for every .js under root."""
    files = []
    try:
        result = subprocess.run(
            ["find", str(root), "-name", "*.js", "-type", "f"],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.strip().splitlines():
            p = Path(line)
            rel = p.relative_to(root)
            files.append({
                "full_path": str(p),
                "rel_path": str(rel),
                "basename": p.name,
                "stem": p.stem,
            })
    except subprocess.CalledProcessError as e:
        print(f"WARNING: find failed for {root}: {e}")
    return sorted(files, key=lambda f: f["rel_path"])


def categorize(path_str: str) -> str:
    """Assign a category based on keywords in the path."""
    lower = path_str.lower()
    for cat, keywords in CATEGORIES:
        if any(kw in lower for kw in keywords):
            return cat
    return "other"


def read_snippet(path_str: str, lines: int = 30) -> str:
    """Read first N lines of a file for inspection."""
    try:
        with open(path_str, "r", errors="replace") as f:
            return "".join(f.readline() for _ in range(lines))
    except OSError:
        return ""


def extract_api_endpoints(snippet: str) -> list[str]:
    """Heuristically extract URL-like strings from a snippet."""
    import re
    # Match strings that look like REST paths: /api/... or /wbm/...
    return list(set(re.findall(r'["\']/((?:api|wbm|rest|cgi-bin|var)[^"\'<>\s]{2,})["\']', snippet)))


def main():
    print("Collecting JS files from old firmware (v3.0.39)...")
    old_files = find_js_files(OLD_ROOT)
    print(f"  Found {len(old_files)} JS files")

    print("Collecting JS files from new firmware (v4.02.13)...")
    new_files = find_js_files(NEW_ROOT)
    print(f"  Found {len(new_files)} JS files")

    # Build lookup by stem (filename without extension) for overlap detection.
    # Since architecture changed (flat→plugin), we use stem-level matching.
    old_stems = {f["stem"].lower(): f for f in old_files}
    new_stems = {f["stem"].lower(): f for f in new_files}

    old_only_stems = set(old_stems) - set(new_stems)
    new_only_stems = set(new_stems) - set(old_stems)
    shared_stems = set(old_stems) & set(new_stems)

    # For new-only files, build enriched records with category + snippet
    new_only_enriched = []
    categories_map = defaultdict(list)
    for stem in sorted(new_only_stems):
        f = new_stems[stem]
        cat = categorize(f["rel_path"])
        snippet = read_snippet(f["full_path"], lines=30)
        endpoints = extract_api_endpoints(snippet)
        record = {
            "rel_path": f["rel_path"],
            "basename": f["basename"],
            "category": cat,
            "api_endpoints_found": endpoints,
            "snippet_lines": snippet.count("\n"),
        }
        new_only_enriched.append(record)
        categories_map[cat].append(f["rel_path"])

    # Also enrich old-only files (removed functionality)
    old_only_enriched = []
    for stem in sorted(old_only_stems):
        f = old_stems[stem]
        old_only_enriched.append({
            "rel_path": f["rel_path"],
            "basename": f["basename"],
            "category": categorize(f["rel_path"]),
        })

    # Shared files (present in both, possibly renamed/moved)
    shared_enriched = []
    for stem in sorted(shared_stems):
        shared_enriched.append({
            "old_rel_path": old_stems[stem]["rel_path"],
            "new_rel_path": new_stems[stem]["rel_path"],
            "stem": stem,
        })

    # ---- Build output JSON ----
    output = {
        "meta": {
            "old_firmware": "WAGO v3.0.39 (WAGO_FW0750-8xxx_V030039_IX12_r38974.img)",
            "new_firmware": "WAGO v4.02.13 (PFC-G2-Linux_sd_V040213_24_r74297.img)",
            "old_js_count": len(old_files),
            "new_js_count": len(new_files),
            "old_only_count": len(old_only_stems),
            "new_only_count": len(new_only_stems),
            "shared_count": len(shared_stems),
        },
        "new_only_by_category": {cat: sorted(paths) for cat, paths in sorted(categories_map.items())},
        "new_only_files": sorted(new_only_enriched, key=lambda r: (r["category"], r["rel_path"])),
        "old_only_files": old_only_enriched,
        "shared_files": shared_enriched,
        "all_old_files": [f["rel_path"] for f in old_files],
        "all_new_files": [f["rel_path"] for f in new_files],
    }

    with open(OUT_JSON, "w") as fp:
        json.dump(output, fp, indent=2)
    print(f"\nWrote {OUT_JSON}")

    # ---- Build human-readable summary ----
    lines = []
    lines.append("=" * 70)
    lines.append("WAGO Firmware JS Diff: v3.0.39 → v4.02.13")
    lines.append("Day 7 Qualitative Analysis — JavaScript File Diff")
    lines.append("=" * 70)
    lines.append("")
    lines.append("OVERVIEW")
    lines.append(f"  Old firmware JS files : {len(old_files):>4}")
    lines.append(f"  New firmware JS files : {len(new_files):>4}")
    lines.append(f"  Removed (old-only)    : {len(old_only_stems):>4}")
    lines.append(f"  Added   (new-only)    : {len(new_only_stems):>4}")
    lines.append(f"  Carried over (shared) : {len(shared_stems):>4}")
    lines.append("")
    lines.append("NEW FILES BY FUNCTIONAL CATEGORY")
    lines.append("-" * 40)
    for cat, paths in sorted(categories_map.items(), key=lambda kv: -len(kv[1])):
        lines.append(f"\n  [{cat.upper()}] ({len(paths)} files)")
        for p in sorted(paths):
            lines.append(f"    + {p}")

    lines.append("")
    lines.append("FILES REMOVED (OLD-ONLY)")
    lines.append("-" * 40)
    for f in old_only_enriched:
        lines.append(f"  - {f['rel_path']}")

    lines.append("")
    lines.append("SHARED FILES (CARRIED OVER, POSSIBLY RELOCATED)")
    lines.append("-" * 40)
    for f in shared_enriched:
        moved = f["old_rel_path"] != f["new_rel_path"]
        tag = " [RELOCATED]" if moved else ""
        lines.append(f"  = {f['stem']}{tag}")
        if moved:
            lines.append(f"      old: {f['old_rel_path']}")
            lines.append(f"      new: {f['new_rel_path']}")

    lines.append("")
    lines.append("API ENDPOINTS FOUND IN NEW FILES")
    lines.append("-" * 40)
    for rec in new_only_enriched:
        if rec["api_endpoints_found"]:
            lines.append(f"  {rec['rel_path']}:")
            for ep in sorted(rec["api_endpoints_found"]):
                lines.append(f"    -> /{ep}")

    summary_text = "\n".join(lines)
    with open(OUT_TXT, "w") as fp:
        fp.write(summary_text)
    print(f"Wrote {OUT_TXT}")
    print("\n" + summary_text)


if __name__ == "__main__":
    main()

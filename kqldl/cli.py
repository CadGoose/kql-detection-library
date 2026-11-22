"""Command-line entry point: `kqldl validate | export-arm | build-docs | list`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .docs import write_site
from .export_arm import build_template
from .model import DEFAULT_ATTACK_FILE, DEFAULT_DETECTIONS_DIR, load_attack, load_detections
from .validate import validate_all


def _load(args: argparse.Namespace):
    return load_detections(Path(args.detections)), load_attack(Path(args.attack))


def cmd_validate(args: argparse.Namespace) -> int:
    detections, attack = _load(args)
    results = validate_all(detections, attack)
    for path, errs in results.items():
        for e in errs:
            print(f"{path}: {e}")
    if results:
        print(f"\nFAILED: {len(results)} of {len(detections)} detections have problems.", file=sys.stderr)
        return 1
    print(f"OK: {len(detections)} detections valid.")
    return 0


def cmd_export_arm(args: argparse.Namespace) -> int:
    detections, attack = _load(args)
    if validate_all(detections, attack):
        print("Refusing to export: run `kqldl validate` and fix errors first.", file=sys.stderr)
        return 1
    template = build_template(detections, enabled=not args.disabled)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(template, indent=2), encoding="utf-8")
    print(f"Wrote {len(template['resources'])} analytics rules to {out}")
    return 0


def cmd_build_docs(args: argparse.Namespace) -> int:
    detections, attack = _load(args)
    index = write_site(detections, attack, Path(args.output))
    print(f"Wrote {index}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    detections, _ = _load(args)
    for d in sorted(detections, key=lambda d: d.id):
        print(f"{d.id}  {d.get('severity', ''):<8} {', '.join(d.get('techniques') or []):<22} {d.get('name')}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="kqldl", description="KQL detection library tooling")
    p.add_argument("--detections", default=str(DEFAULT_DETECTIONS_DIR), help="detections folder")
    p.add_argument("--attack", default=str(DEFAULT_ATTACK_FILE), help="ATT&CK technique map (JSON)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("validate", help="schema + KQL lint every detection").set_defaults(func=cmd_validate)

    e = sub.add_parser("export-arm", help="export Sentinel analytics rules as an ARM template")
    e.add_argument("-o", "--output", default="dist/sentinel-analytics-rules.json")
    e.add_argument("--disabled", action="store_true", help="deploy rules disabled (staging)")
    e.set_defaults(func=cmd_export_arm)

    b = sub.add_parser("build-docs", help="build the static documentation site")
    b.add_argument("-o", "--output", default="site")
    b.set_defaults(func=cmd_build_docs)

    sub.add_parser("list", help="list detections").set_defaults(func=cmd_list)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

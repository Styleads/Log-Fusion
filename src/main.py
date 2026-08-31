"""CLI Entrypoint for the Universal Log Pre-processing Framework (ULPF)."""

import argparse
import json
import sys
from pathlib import Path
from src.engine.pipeline import NormalizationPipeline


def main():
    parser = argparse.ArgumentParser(
        description="ULPF: Universal Log Pre-processing & OCSF Normalization Engine"
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Path to a raw log file to ingest and normalize",
    )
    parser.add_argument(
        "--mappings",
        "-m",
        help="Custom directory containing YAML mapping configurations",
        default=None,
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file path (writes NDJSON format by default)",
        default=None,
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Print normalized events as pretty-printed JSON",
    )

    args = parser.parse_args()
    pipeline = NormalizationPipeline(mappings_dir_or_loader=args.mappings)

    if not args.file:
        # Read from stdin
        if sys.stdin.isatty():
            print("No log file provided. Enter log lines (Ctrl+D / Ctrl+Z to finish):")
        lines = sys.stdin.readlines()
        events = pipeline.process_lines(lines)
    else:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"Error: File not found: {file_path}", file=sys.stderr)
            sys.exit(1)
        events = pipeline.process_file(file_path)

    if args.output:
        out_path = Path(args.output)
        with open(out_path, "w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")
        print(f"Successfully normalized {len(events)} events to {out_path}")
    else:
        for ev in events:
            if args.pretty:
                print(json.dumps(ev, indent=2))
            else:
                print(json.dumps(ev))


if __name__ == "__main__":
    main()

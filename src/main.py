"""CLI Entrypoint for the Universal Log Pre-processing Framework (ULPF) and Auto-Mapping Assistant."""

import argparse
import json
import sys
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from src.engine.pipeline import NormalizationPipeline
from src.assistant.service import AutoMappingAssistant


def main():
    parser = argparse.ArgumentParser(
        description="ULPF: Universal Log Pre-processing & OCSF Normalization Engine"
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Path to a raw log file to ingest and normalize (or sample file for auto-mapping)",
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
    parser.add_argument(
        "--auto-map",
        help="Auto-generate draft YAML mapping config for unknown log sample using provided source name (e.g. --auto-map 'SonicWall Firewall')",
        default=None,
    )
    parser.add_argument(
        "--device-type",
        help="Device type hint for auto-mapping (e.g. firewall, ids, vpn, router)",
        default=None,
    )
    parser.add_argument(
        "--save-draft",
        action="store_true",
        help="Save generated draft YAML mapping to mappings/<slug>/ directory",
    )
    parser.add_argument(
        "--use-llm",
        action="store_true",
        help="Enable local Ollama fallback for ambiguous fields during auto-mapping",
    )

    args = parser.parse_args()

    # Handle Auto-Mapping Assistant Mode
    if args.auto_map:
        source_name = args.auto_map
        if not args.file:
            if sys.stdin.isatty():
                print(f"Paste sample log lines for '{source_name}' (Ctrl+D / Ctrl+Z to finish):")
            lines = [l.strip() for l in sys.stdin.readlines() if l.strip()]
        else:
            file_path = Path(args.file)
            if not file_path.exists():
                print(f"Error: File not found: {file_path}", file=sys.stderr)
                sys.exit(1)
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = [l.strip() for l in f.readlines() if l.strip()]

        if not lines:
            print("Error: No log lines provided for auto-mapping analysis.", file=sys.stderr)
            sys.exit(1)

        print(f"[*] Analyzing {len(lines)} sample lines for '{source_name}'...")
        assistant = AutoMappingAssistant(mappings_dir=args.mappings)
        analysis = assistant.analyze(
            source_name=source_name,
            raw_lines=lines,
            device_type_hint=args.device_type,
            use_llm=args.use_llm,
        )

        print(f"[*] Detected format: {analysis['detected_format']}")
        print(f"[*] Confidence: {analysis['confidence_label'].upper()} ({analysis['confidence_score']:.2f})")
        print(f"[*] Validation: {'PASSED' if analysis['validation']['valid'] else 'FAILED'}")
        print(f"[*] Successfully normalized events: {analysis['validation']['successful_events']}/{analysis['validation']['total_lines']}")
        print("\n--- GENERATED DRAFT YAML ---")
        print(analysis["yaml_draft"])

        if args.save_draft:
            save_res = assistant.save_draft(source_name, analysis["yaml_draft"], lines, mappings_dir=args.mappings)
            print(f"\n[+] Draft saved to: {save_res['directory']}")
            print(f"[+] YAML configuration: {save_res['yaml_file']}")
            print(f"[+] Verbatim sample: {save_res['sample_file']}")

        if args.pretty and analysis["ocsf_preview"]:
            print("\n--- NORMALIZED OCSF EVENT PREVIEW ---")
            print(json.dumps(analysis["ocsf_preview"][0], indent=2))

        return

    # Normal Ingestion Mode
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

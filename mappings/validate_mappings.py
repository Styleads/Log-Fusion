"""Automated validator and test runner for all YAML log mapping definitions."""

import sys
from pathlib import Path

# Add project root to sys.path so it can import engine modules
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.engine.config_loader import ConfigLoader, MappingConfigError
from src.engine.pipeline import NormalizationPipeline


def validate_all_mappings(mappings_dir: Path) -> bool:
    print(f"[*] Validating YAML mapping configurations in: {mappings_dir}")
    try:
        loader = ConfigLoader(mappings_dir)
        configs = loader.get_all_configs()
        if not configs:
            print(f"[!] Warning: No mapping configurations found in {mappings_dir}")
            return False

        print(f"[✓] Successfully loaded and validated {len(configs)} mapping configurations:")
        for cfg in configs:
            file_name = cfg.file_path.name if cfg.file_path else "inline"
            print(f"    - {cfg.vendor} / {cfg.product} ({cfg.format}) -> {file_name}")
    except MappingConfigError as e:
        print(f"[X] Mapping validation error: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[X] Unexpected error loading mappings: {e}", file=sys.stderr)
        return False

    # Run end-to-end tests against sample logs if present
    print("\n[*] Running normalization tests on sample log files...")
    pipeline = NormalizationPipeline(loader)
    all_passed = True
    tested_samples = 0

    for sample_file in sorted(mappings_dir.rglob("*.log")):
        if sample_file.stat().st_size == 0:
            continue
        tested_samples += 1
        try:
            events = pipeline.process_file(sample_file)
            rel_path = sample_file.relative_to(mappings_dir)
            print(f"    [✓] {rel_path}: Normalized {len(events)} events successfully")
        except Exception as e:
            rel_path = sample_file.relative_to(mappings_dir)
            print(f"    [X] {rel_path}: Failed normalization: {e}", file=sys.stderr)
            all_passed = False

    print(f"\n[✓] Finished validation: Tested {tested_samples} sample files across {len(configs)} mapping configs.")
    return all_passed


if __name__ == "__main__":
    dir_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
    success = validate_all_mappings(dir_path)
    sys.exit(0 if success else 1)

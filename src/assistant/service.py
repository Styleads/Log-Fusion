"""High-level service orchestrator for the Auto-Mapping Assistant."""

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import yaml

from .detector_heuristics import FormatDetector
from .semantic_analyzer import SemanticAnalyzer
from .llm_fallback import OllamaFallback
from .generator import YamlGenerator
from .validator import DraftValidator


def slugify(name: str) -> str:
    """Convert a human-readable source name into a safe directory slug."""
    s = re.sub(r'[^a-zA-Z0-9_]+', '_', name.lower().strip())
    s = re.sub(r'_+', '_', s).strip('_')
    return s or "unknown_source"


class AutoMappingAssistant:
    """Orchestrates format detection, semantic analysis, LLM augmentation, YAML generation, validation, and file storage."""

    def __init__(
        self,
        mappings_dir: Optional[Union[str, Path]] = None,
        enable_llm: bool = True,
    ):
        if mappings_dir:
            self.mappings_dir = Path(mappings_dir)
        else:
            # Default workspace mappings directory
            self.mappings_dir = Path(__file__).resolve().parent.parent.parent / "mappings"

        self.detector = FormatDetector()
        self.semantic_analyzer = SemanticAnalyzer()
        self.llm_fallback = OllamaFallback()
        self.yaml_generator = YamlGenerator()
        self.validator = DraftValidator()
        self.enable_llm = enable_llm

    def analyze(
        self,
        source_name: str,
        raw_lines: List[str],
        device_type_hint: Optional[str] = None,
        use_llm: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Analyze sample raw log lines, generate a draft mapping.yaml, and validate against NormalizationPipeline.
        """
        clean_lines = [l for l in raw_lines if l and l.strip()]
        if not clean_lines:
            raise ValueError("At least one non-empty log line is required for analysis.")

        # 1. Format Detection
        format_result = self.detector.detect(clean_lines)

        # 2. Semantic Analysis
        semantic_result = self.semantic_analyzer.analyze(
            format_result,
            source_name=source_name,
            device_type_hint=device_type_hint,
        )

        # 3. LLM Fallback (Optional for ambiguous fields)
        should_use_llm = self.enable_llm if use_llm is None else use_llm
        if should_use_llm and semantic_result.ambiguous_fields:
            if self.llm_fallback.is_available():
                suggested_mappings = self.llm_fallback.suggest_mappings(
                    raw_samples=clean_lines,
                    ambiguous_fields=semantic_result.ambiguous_fields,
                    known_mappings=semantic_result.field_map,
                )
                if suggested_mappings:
                    for raw_f, ocsf_path in suggested_mappings.items():
                        semantic_result.field_map[raw_f] = ocsf_path

        # 4. Generate YAML Draft
        yaml_content = self.yaml_generator.generate_yaml(
            format_result=format_result,
            semantic_result=semantic_result,
            source_name=source_name,
        )

        # 5. Pipeline Validation
        val_result = self.validator.validate_yaml(yaml_content, clean_lines)

        slug = slugify(source_name)

        return {
            "source_name": source_name,
            "slug": slug,
            "detected_format": format_result.format_type,
            "confidence_score": semantic_result.confidence_score,
            "confidence_label": semantic_result.confidence_label,
            "yaml_draft": yaml_content,
            "validation": {
                "valid": val_result.valid,
                "error": val_result.error,
                "total_lines": val_result.total_lines,
                "successful_events": val_result.successful_events,
                "mapped_fields_count": val_result.mapped_fields_count,
                "unmapped_fields_count": val_result.unmapped_fields_count,
                "mapping_rate": val_result.mapping_rate,
                "field_lineage": val_result.field_lineage,
            },
            "ocsf_preview": val_result.events,
        }

    def save_draft(
        self,
        source_name: str,
        yaml_content: str,
        raw_lines: List[str],
        mappings_dir: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Save the draft configuration to mappings/<slugified_source_name>/mapping.yaml and synthetic_sample.log.
        Guards against overwriting existing reviewed configs.
        """
        base_dir = Path(mappings_dir) if mappings_dir else self.mappings_dir
        base_dir.mkdir(parents=True, exist_ok=True)

        slug_base = slugify(source_name)
        target_dir = base_dir / slug_base

        # Collision protection: If folder exists and is already reviewed, find non-colliding suffix
        counter = 1
        while target_dir.exists():
            yaml_file = target_dir / "mapping.yaml"
            if yaml_file.exists():
                try:
                    with open(yaml_file, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                        if isinstance(data, dict) and data.get("source_identity", {}).get("status") == "reviewed":
                            # Don't overwrite reviewed configs: create new folder name with counter
                            counter += 1
                            target_dir = base_dir / f"{slug_base}_{counter}"
                            continue
                        else:
                            # It's an unreviewed draft, safe to update
                            break
                except Exception:
                    counter += 1
                    target_dir = base_dir / f"{slug_base}_{counter}"
            else:
                break

        target_dir.mkdir(parents=True, exist_ok=True)
        samples_dir = target_dir / "samples"
        samples_dir.mkdir(parents=True, exist_ok=True)

        yaml_path = target_dir / "mapping.yaml"
        with open(yaml_path, "w", encoding="utf-8") as f:
            f.write(yaml_content)

        sample_path = samples_dir / "synthetic_sample.log"
        with open(sample_path, "w", encoding="utf-8") as f:
            for line in raw_lines:
                f.write(line.strip() + "\n")

        return {
            "status": "saved",
            "slug": target_dir.name,
            "directory": str(target_dir),
            "yaml_file": str(yaml_path),
            "sample_file": str(sample_path),
        }

    def list_drafts(self, mappings_dir: Optional[Union[str, Path]] = None) -> List[Dict[str, Any]]:
        """List all configurations with status: draft."""
        base_dir = Path(mappings_dir) if mappings_dir else self.mappings_dir
        drafts = []

        if not base_dir.exists():
            return []

        yaml_files = sorted(list(base_dir.glob("**/*.yaml")) + list(base_dir.glob("**/*.yml")))
        for y_path in yaml_files:
            try:
                with open(y_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if isinstance(data, dict):
                        source_id = data.get("source_identity", {})
                        if source_id.get("status") == "draft":
                            drafts.append({
                                "slug": y_path.parent.name,
                                "vendor": source_id.get("vendor", ""),
                                "product": source_id.get("product", ""),
                                "format": source_id.get("format", ""),
                                "version": source_id.get("version", "1.0"),
                                "status": "draft",
                                "file_path": str(y_path),
                            })
            except Exception:
                continue

        return drafts

    def approve_draft(
        self,
        slug: str,
        mappings_dir: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Transition a draft configuration from status: draft to status: reviewed and remove draft header.
        """
        base_dir = Path(mappings_dir) if mappings_dir else self.mappings_dir
        target_dir = base_dir / slug

        yaml_file = target_dir / "mapping.yaml"
        if not yaml_file.exists():
            # Search for any yaml file in the target directory
            yamls = list(target_dir.glob("*.yaml")) + list(target_dir.glob("*.yml"))
            if yamls:
                yaml_file = yamls[0]
            else:
                raise FileNotFoundError(f"Mapping configuration not found for slug '{slug}' in {base_dir}")

        with open(yaml_file, "r", encoding="utf-8") as f:
            content = f.read()
            data = yaml.safe_load(content)

        if not isinstance(data, dict):
            raise ValueError(f"Invalid YAML dictionary in {yaml_file}")

        # Update status
        if "source_identity" in data and isinstance(data["source_identity"], dict):
            data["source_identity"]["status"] = "reviewed"

        vendor = data.get("source_identity", {}).get("vendor", slug)
        product = data.get("source_identity", {}).get("product", slug)

        # Replace draft header with reviewed header
        new_header = (
            f"# Mapping config: {vendor} ({product})\n"
            "# Status: Reviewed & Approved for Production Normalization\n\n"
        )

        # Dump clean YAML
        yaml_body = yaml.dump(
            data,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )

        with open(yaml_file, "w", encoding="utf-8") as f:
            f.write(new_header + yaml_body)

        return {
            "status": "approved",
            "slug": slug,
            "vendor": vendor,
            "product": product,
            "file_path": str(yaml_file),
        }

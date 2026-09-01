"""Validation runner testing draft YAML mapping configs against the live NormalizationPipeline."""

import yaml
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from src.engine.config_loader import MappingConfig, MappingConfigError
from src.engine.pipeline import NormalizationPipeline


@dataclass
class ValidationResult:
    valid: bool
    events: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    total_lines: int = 0
    successful_events: int = 0
    mapped_fields_count: int = 0
    unmapped_fields_count: int = 0
    mapping_rate: float = 0.0  # mapped / total extracted fields ratio
    field_lineage: Dict[str, Any] = field(default_factory=dict)


class DraftValidator:
    """Validates a draft YAML configuration against the live ULPF normalization pipeline."""

    def __init__(self, pipeline: Optional[NormalizationPipeline] = None):
        self.pipeline = pipeline or NormalizationPipeline()

    def validate_yaml(self, yaml_content: str, raw_lines: List[str]) -> ValidationResult:
        """Parse draft YAML, create a temporary MappingConfig, and normalize sample lines."""
        if not raw_lines:
            return ValidationResult(
                valid=False,
                error="No sample log lines provided for validation.",
            )

        # 1. Parse YAML content
        try:
            parsed_dict = yaml.safe_load(yaml_content)
            if not isinstance(parsed_dict, dict):
                return ValidationResult(valid=False, error="YAML content must be a valid mapping dictionary.")
            mapping_config = MappingConfig(parsed_dict)
        except Exception as e:
            return ValidationResult(valid=False, error=f"Failed to load draft YAML: {str(e)}")

        # 2. Run sample lines through NormalizationPipeline
        events: List[Dict[str, Any]] = []
        total_mapped = 0
        total_unmapped = 0
        sample_lineage: Dict[str, Any] = {}

        for line in raw_lines:
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#"):
                continue

            try:
                event = self.pipeline.process_line(clean_line, config=mapping_config)
                if event is not None:
                    events.append(event)
                    # Count mapped vs unmapped fields in event
                    unmapped = event.get("unmapped", {})
                    unmapped_count = len(unmapped) if isinstance(unmapped, dict) else 0
                    total_unmapped += unmapped_count

                    # Count standard OCSF fields present
                    mapped_count = self._count_ocsf_fields(event)
                    total_mapped += mapped_count

                    if not sample_lineage:
                        sample_lineage = self._extract_sample_lineage(event)
            except Exception as e:
                return ValidationResult(
                    valid=False,
                    error=f"Error normalizing line '{clean_line[:60]}...': {str(e)}",
                    total_lines=len(raw_lines),
                    successful_events=len(events),
                )

        if not events:
            return ValidationResult(
                valid=False,
                error="Pipeline ran without fatal errors, but produced 0 normalized events. Verify parsing delimiter and detection pattern.",
                total_lines=len(raw_lines),
                successful_events=0,
            )

        total_fields = total_mapped + total_unmapped
        mapping_rate = round(total_mapped / total_fields, 2) if total_fields > 0 else 0.0

        return ValidationResult(
            valid=True,
            events=events,
            total_lines=len(raw_lines),
            successful_events=len(events),
            mapped_fields_count=total_mapped,
            unmapped_fields_count=total_unmapped,
            mapping_rate=mapping_rate,
            field_lineage=sample_lineage,
        )

    def _count_ocsf_fields(self, event: Dict[str, Any]) -> int:
        """Count non-empty attributes at root and nested sub-objects (excluding unmapped and raw_data)."""
        count = 0
        for k, v in event.items():
            if k in ("unmapped", "raw_data", "metadata"):
                continue
            if isinstance(v, dict):
                count += len([sub_k for sub_k, sub_v in v.items() if sub_v is not None])
            elif v is not None:
                count += 1
        return count

    def _extract_sample_lineage(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key OCSF values for preview display."""
        lineage = {}
        if "src_endpoint" in event:
            lineage["src_endpoint.ip"] = event["src_endpoint"].get("ip")
            lineage["src_endpoint.port"] = event["src_endpoint"].get("port")
        if "dst_endpoint" in event:
            lineage["dst_endpoint.ip"] = event["dst_endpoint"].get("ip")
            lineage["dst_endpoint.port"] = event["dst_endpoint"].get("port")
        if "connection_info" in event:
            lineage["connection_info.protocol_name"] = event["connection_info"].get("protocol_name")
        if "activity_name" in event:
            lineage["activity_name"] = event.get("activity_name")
        if "time" in event:
            lineage["time"] = event.get("time")
        if "class_name" in event:
            lineage["class_name"] = event.get("class_name")
        return {k: v for k, v in lineage.items() if v is not None}

"""Dotted-path to nested JSON dictionary mapper and schema builder."""

from typing import Any, Dict, List, Optional, Set
from .config_loader import MappingConfig


def set_nested_value(target_dict: Dict[str, Any], dotted_path: str, value: Any) -> None:
    """
    Set a value in a nested dictionary using dot-separated path.
    Example: set_nested_value(d, "src_endpoint.ip", "10.0.0.1")
    produces: {"src_endpoint": {"ip": "10.0.0.1"}}
    """
    parts = dotted_path.split(".")
    curr = target_dict
    for part in parts[:-1]:
        if part not in curr or not isinstance(curr[part], dict):
            curr[part] = {}
        curr = curr[part]
    curr[parts[-1]] = value


def get_nested_value(data: Dict[str, Any], dotted_path: str) -> Any:
    """Retrieve a value from a nested dictionary using a dot-separated path."""
    parts = dotted_path.split(".")
    curr = data
    for part in parts:
        if isinstance(curr, dict) and part in curr:
            curr = curr[part]
        else:
            return None
    return curr


class NestedMapper:
    """Constructs nested OCSF JSON events from flat parsed fields using declarative mappings."""

    def __init__(self, config: MappingConfig):
        self.config = config

    def map_event(
        self,
        parsed_fields: Dict[str, Any],
        transformed_fields: Optional[Dict[str, Any]] = None,
        classification: Optional[Dict[str, Any]] = None,
        event_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build the nested OCSF event dictionary.
        
        Args:
            parsed_fields: The original flat dictionary of parsed raw fields.
            transformed_fields: Dictionary containing transformed/casted field values.
            classification: Dict with class_uid, class_name, activity_id, activity_name.
            event_time: Normalized ISO-8601 UTC timestamp string.
            
        Returns:
            Nested OCSF event dictionary with unmapped fields bucketed.
        """
        result: Dict[str, Any] = {}
        transformed = transformed_fields if transformed_fields is not None else parsed_fields
        consumed_raw_fields: Set[str] = set()

        # 1. Inject Classification Metadata
        if classification:
            for k in ("class_name", "class_uid", "activity_name", "activity_id"):
                if k in classification and classification[k] is not None:
                    result[k] = classification[k]

        # 2. Inject Normalized Event Timestamp
        if event_time:
            result["time"] = event_time

        # 3. Inject Static Fields from Config
        for target_path, static_val in self.config.static_fields.items():
            set_nested_value(result, target_path, static_val)

        # 4. Map Parsed/Transformed Fields to Dotted OCSF Paths
        for raw_field, target_path in self.config.field_map.items():
            consumed_raw_fields.add(raw_field)

            # Check transformed value first, then fallback to parsed
            val = transformed.get(raw_field)
            if val is None and raw_field in parsed_fields:
                val = parsed_fields[raw_field]

            if val is not None:
                set_nested_value(result, target_path, val)

        # 5. Map Transforms with explicit target paths
        for raw_field, transform_rule in self.config.transforms.items():
            if isinstance(transform_rule, dict) and "target" in transform_rule:
                target_path = transform_rule["target"]
                consumed_raw_fields.add(raw_field)
                val = transformed.get(raw_field, parsed_fields.get(raw_field))
                if val is not None:
                    set_nested_value(result, target_path, val)

        # 6. Apply Unmapped Policy (Lossless Bucketing)
        unmapped_policy = self.config.unmapped_policy
        if unmapped_policy.get("action") == "bucket":
            target_bucket = unmapped_policy.get("target", "unmapped")
            unmapped_dict: Dict[str, Any] = {}

            # Identify any fields used in timestamp or classification
            ts_source = self.config.timestamp.get("source_field", "")
            ts_fields = set(ts_source.split("+")) if ts_source else set()

            for raw_field, raw_val in parsed_fields.items():
                # Skip fields that were explicitly mapped or internal parsing artifacts
                if (
                    raw_field not in consumed_raw_fields
                    and raw_field not in ts_fields
                    and raw_field != "raw_message"
                    and not raw_field.startswith("__")
                ):
                    unmapped_dict[raw_field] = raw_val

            if unmapped_dict:
                if target_bucket:
                    set_nested_value(result, target_bucket, unmapped_dict)
                else:
                    result["unmapped"] = unmapped_dict

        return result

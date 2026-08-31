"""Value transformations and type casting module."""

import re
from typing import Any, Dict, Optional
from .config_loader import MappingConfig

# Standard IANA IP protocol number to name mapping
PROTOCOL_NUM_TO_NAME: Dict[int, str] = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    88: "EIGRP",
    89: "OSPF",
    112: "VRRP",
    115: "L2TP",
    132: "SCTP",
}

# Standard OCSF Severity IDs and Names
SEVERITY_MAP: Dict[str, Dict[str, Any]] = {
    "0": {"severity_id": 0, "severity": "Unknown"},
    "1": {"severity_id": 1, "severity": "Informational"},
    "2": {"severity_id": 2, "severity": "Low"},
    "3": {"severity_id": 3, "severity": "Medium"},
    "4": {"severity_id": 4, "severity": "High"},
    "5": {"severity_id": 5, "severity": "Critical"},
    "6": {"severity_id": 6, "severity": "Fatal"},
    "low": {"severity_id": 2, "severity": "Low"},
    "medium": {"severity_id": 3, "severity": "Medium"},
    "high": {"severity_id": 4, "severity": "High"},
    "critical": {"severity_id": 5, "severity": "Critical"},
    "info": {"severity_id": 1, "severity": "Informational"},
    "informational": {"severity_id": 1, "severity": "Informational"},
    "warn": {"severity_id": 3, "severity": "Medium"},
    "warning": {"severity_id": 3, "severity": "Medium"},
    "error": {"severity_id": 4, "severity": "High"},
}


class ValueTransformer:
    """Applies declarative value transformations to parsed raw fields."""

    def __init__(self, config: MappingConfig):
        self.config = config
        self.transforms_def = self.config.transforms

    def transform_all(self, parsed_fields: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply all transforms defined in config to the parsed fields dictionary.
        Returns a dictionary of transformed field values.
        """
        transformed: Dict[str, Any] = dict(parsed_fields)

        for field_name, transform_rule in self.transforms_def.items():
            if field_name not in parsed_fields:
                continue

            raw_val = parsed_fields[field_name]
            if raw_val is None or raw_val == "-":
                continue

            if isinstance(transform_rule, str):
                rule_type = transform_rule
                rule_opts: Dict[str, Any] = {}
            elif isinstance(transform_rule, dict):
                rule_type = transform_rule.get("type", "")
                rule_opts = transform_rule
            else:
                continue

            new_val = self.apply_transform(rule_type, raw_val, rule_opts)

            # Check if this transform redirects to a specific target path
            target_path = rule_opts.get("target")
            if target_path:
                # If target is a dotted path or alternate field name
                transformed[field_name] = new_val
                transformed[target_path] = new_val
            else:
                transformed[field_name] = new_val

        return transformed

    def apply_transform(self, transform_type: str, value: Any, opts: Dict[str, Any]) -> Any:
        """Apply a single transformation rule to a value."""
        t_type = transform_type.lower()

        if t_type == "lookup":
            table = opts.get("table", {})
            val_str = str(value).strip()
            # Try exact match, then case-insensitive match
            if val_str in table:
                return table[val_str]
            for k, v in table.items():
                if str(k).lower() == val_str.lower():
                    return v
            return opts.get("default", value)

        elif t_type in ("integer", "int"):
            try:
                # Clean strings like "51322" or "0x400000"
                val_str = str(value).strip()
                if val_str.startswith("0x") or val_str.startswith("0X"):
                    return int(val_str, 16)
                return int(val_str)
            except (ValueError, TypeError):
                return value

        elif t_type == "float":
            try:
                return float(str(value).strip())
            except (ValueError, TypeError):
                return value

        elif t_type in ("boolean", "bool"):
            val_str = str(value).strip().lower()
            return val_str in ("true", "1", "yes", "t", "y", "enable", "enabled")

        elif t_type == "passthrough_upper":
            return str(value).upper() if value is not None else value

        elif t_type == "passthrough_lower":
            return str(value).lower() if value is not None else value

        elif t_type == "protocol_num_to_name":
            try:
                num = int(value)
                return PROTOCOL_NUM_TO_NAME.get(num, str(value))
            except (ValueError, TypeError):
                return str(value).upper()

        elif t_type == "duration":
            # Converts "H:MM:SS" or "MM:SS" string to total seconds (int)
            val_str = str(value).strip()
            parts = val_str.split(":")
            if len(parts) == 3:
                try:
                    h, m, s = int(parts[0]), int(parts[1]), int(parts[2])
                    return h * 3600 + m * 60 + s
                except ValueError:
                    return value
            elif len(parts) == 2:
                try:
                    m, s = int(parts[0]), int(parts[1])
                    return m * 60 + s
                except ValueError:
                    return value
            try:
                return int(val_str)
            except ValueError:
                return value

        elif t_type == "severity_lookup":
            val_str = str(value).strip().lower()
            if val_str in SEVERITY_MAP:
                return SEVERITY_MAP[val_str]["severity"]
            return value

        return value

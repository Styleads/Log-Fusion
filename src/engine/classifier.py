
"""OCSF Event Classification module."""

from typing import Any, Dict, List, Optional
from .config_loader import MappingConfig

# Standard OCSF Class UIDs for network/security events
OCSF_CLASS_UIDS: Dict[str, int] = {
    "network activity": 4001,
    "security finding": 2001,
    "detection finding": 2001,
    "network detection": 2001,
    "incident finding": 2005,
    "authentication": 3002,
    "account change": 3001,
    "authorize session": 3003,
    "entity management": 3004,
    "user access management": 3005,
    "group management": 3006,
    "http activity": 4002,
    "dns activity": 4003,
    "dhcp activity": 4004,
    "rdp activity": 4005,
    "smb activity": 4006,
    "ssh activity": 4007,
    "ftp activity": 4008,
    "email activity": 4009,
    "file activity": 1001,
    "process activity": 1007,
}


class OCSFClassifier:
    """Classifies parsed log events into OCSF class_uid, class_name, activity_id, and activity_name."""

    def __init__(self, config: MappingConfig):
        self.config = config

    def classify(self, parsed_fields: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate classification rules against parsed fields and return classification metadata.
        Returns a dict containing:
          - class_name (str)
          - class_uid (int)
          - activity_name (Optional[str])
          - activity_id (Optional[int])
        """
        classification_result: Dict[str, Any] = {}

        # 1. Check explicit classification rules
        matched_rule = None
        for rule in self.config.classification_rules:
            when = rule.get("when", {})
            if self._matches_when(when, parsed_fields):
                matched_rule = rule
                break

        if matched_rule:
            if "class_name" in matched_rule:
                classification_result["class_name"] = matched_rule["class_name"]
            if "class_uid" in matched_rule:
                classification_result["class_uid"] = int(matched_rule["class_uid"])
            if "activity_name" in matched_rule:
                classification_result["activity_name"] = matched_rule["activity_name"]
            if "activity_id" in matched_rule:
                classification_result["activity_id"] = int(matched_rule["activity_id"])

        # 2. Fallbacks for missing attributes
        if "class_name" not in classification_result:
            default_name = self.config.default_class_name or "Network Activity"
            classification_result["class_name"] = default_name

        if "class_uid" not in classification_result:
            if self.config.default_class_uid is not None:
                classification_result["class_uid"] = int(self.config.default_class_uid)
            else:
                name_key = classification_result["class_name"].lower()
                classification_result["class_uid"] = OCSF_CLASS_UIDS.get(name_key, 4001)

        return classification_result

    def _matches_when(self, when: Dict[str, Any], parsed_fields: Dict[str, Any]) -> bool:
        """Check if all conditions in a 'when' dictionary match the parsed fields."""
        if not when:
            return False

        for field_name, expected_val in when.items():
            if field_name not in parsed_fields:
                return False
            actual_val = parsed_fields[field_name]
            if actual_val is None:
                return False

            # Case-insensitive string comparison if both are strings
            if isinstance(actual_val, str) and isinstance(expected_val, str):
                if actual_val.strip().lower() != expected_val.strip().lower():
                    return False
            else:
                if str(actual_val).lower() != str(expected_val).lower():
                    return False

        return True

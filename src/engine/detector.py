"""Automatic format and vendor detection module for raw log lines."""

import csv
import io
import json
import re
from typing import Any, Dict, List, Optional, Union
from .config_loader import ConfigLoader, MappingConfig


def normalize_regex(pattern: str) -> str:
    """Convert standard PCRE (?<name>...) syntax to Python (?P<name>...) syntax."""
    return re.sub(r'\(\?<([a-zA-Z_][a-zA-Z0-9_]*)>', r'(?P<\1>', pattern)


def get_nested_json_value(data: Any, path: str) -> Any:
    """Retrieve a value from a nested dict using dot notation."""
    parts = path.split(".")
    curr = data
    for part in parts:
        if isinstance(curr, dict) and part in curr:
            curr = curr[part]
        else:
            return None
    return curr


class LogDetector:
    """Matches incoming raw log lines against loaded mapping configs."""

    def __init__(self, configs_or_loader: Union[List[MappingConfig], ConfigLoader]):
        if isinstance(configs_or_loader, ConfigLoader):
            self.configs = configs_or_loader.configs
        else:
            self.configs = configs_or_loader

    def detect(self, log_line: str, header_context: Optional[List[str]] = None) -> Optional[MappingConfig]:
        """Detect and return the first matching MappingConfig for a raw log line."""
        matches = self.detect_all(log_line, header_context=header_context)
        return matches[0] if matches else None

    def detect_all(self, log_line: str, header_context: Optional[List[str]] = None) -> List[MappingConfig]:
        """Detect all matching MappingConfigs for a raw log line."""
        line = log_line.strip()
        if not line:
            return []

        matched = []
        for config in self.configs:
            if self._matches(config, line, header_context=header_context):
                matched.append(config)
        return matched

    def _matches(self, config: MappingConfig, line: str, header_context: Optional[List[str]] = None) -> bool:
        """Check if a log line matches a specific config's detection rules."""
        detection = config.detection
        if not detection:
            return False

        method = detection.get("method", "").lower()

        if method == "regex":
            pattern = detection.get("pattern", "")
            if not pattern:
                return False
            try:
                py_pattern = normalize_regex(pattern)
                if re.search(py_pattern, line):
                    return True
                # If pattern was anchored with ^ but syslog header preceded it, check unanchored pattern
                if pattern.startswith("^"):
                    unanchored = normalize_regex(pattern[1:])
                    if re.search(unanchored, line):
                        return True
                # Check header pattern from parsing section if present
                header_pattern = config.parsing.get("header", {}).get("pattern")
                if header_pattern:
                    py_header_pattern = normalize_regex(header_pattern)
                    if re.search(py_header_pattern, line):
                        return True
            except re.error:
                return False

        elif method in ("json_match", "json_path", "json"):
            return self._matches_json(detection, line)

        elif method in ("csv_header_and_field", "csv_match", "csv"):
            return self._matches_csv(config, line, header_context=header_context)

        elif method in ("field_presence", "contains"):
            fields = detection.get("fields", [])
            if isinstance(fields, str):
                fields = [fields]
            return all(f in line for f in fields)

        # Fallback: check if parsing.format is regex or syslog with header pattern
        parsing = config.parsing
        header_pattern = parsing.get("header", {}).get("pattern")
        if header_pattern:
            try:
                py_pattern = normalize_regex(header_pattern)
                if re.search(py_pattern, line):
                    return True
            except re.error:
                pass

        return False

    def _matches_json(self, detection: Dict[str, Any], line: str) -> bool:
        """Check if log line is valid JSON and satisfies detection conditions."""
        if not (line.startswith("{") and line.endswith("}")):
            return False
        try:
            data = json.loads(line)
            if not isinstance(data, dict):
                return False
        except (json.JSONDecodeError, ValueError):
            return False

        conditions = detection.get("conditions", [])
        if not conditions:
            # If no conditions specified, valid JSON is sufficient
            return True

        for cond in conditions:
            path = cond.get("path")
            if not path:
                continue
            val = get_nested_json_value(data, path)
            if cond.get("exists") is True and val is None:
                return False
            if "equals" in cond and str(val).lower() != str(cond["equals"]).lower():
                return False

        return True

    def _matches_csv(self, config: MappingConfig, line: str, header_context: Optional[List[str]] = None) -> bool:
        """Check if log line matches CSV detection rules."""
        detection = config.detection
        conditions = detection.get("conditions", [])
        delimiter = config.parsing.get("delimiter", ",")
        quotechar = config.parsing.get("quote_character", '"')

        try:
            reader = csv.reader(io.StringIO(line), delimiter=delimiter, quotechar=quotechar)
            row = next(reader)
        except Exception:
            return False

        # If header context is provided (e.g. list of column names)
        if header_context and len(header_context) == len(row):
            row_dict = dict(zip(header_context, row))
            for cond in conditions:
                header_field = cond.get("header_field")
                if not header_field or header_field not in row_dict:
                    return False
                if cond.get("exists") is True and not row_dict[header_field]:
                    return False
                if "equals" in cond and str(row_dict[header_field]).lower() != str(cond["equals"]).lower():
                    return False
            return True

        # If line itself is the CSV header row
        for cond in conditions:
            header_field = cond.get("header_field")
            if header_field and header_field in row:
                return True

        # Or check parsing.fields header mapping if present
        parsing_fields = config.parsing.get("fields", {})
        if isinstance(parsing_fields, dict):
            # Check if row elements match expected field names or values
            matching_headers = sum(1 for col in row if col in parsing_fields)
            if matching_headers >= 3:
                return True

        return False

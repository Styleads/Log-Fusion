"""Format-specific log parsers: Delimited/CSV, Key-Value, JSON, and Syslog/Regex."""

import csv
import io
import json
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple, Union
from .config_loader import MappingConfig
from .detector import get_nested_json_value, normalize_regex


class BaseParser(ABC):
    """Abstract base class for all log parsers."""

    def __init__(self, config: MappingConfig):
        self.config = config

    @abstractmethod
    def parse(self, log_line: str, header_context: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        """
        Parse a raw log line into a flat dictionary of raw field names -> parsed values.
        Returns None if the line is a non-event line (e.g. comment/header).
        """
        pass


class DelimitedParser(BaseParser):
    """Parser for space-delimited, CSV, TSV, and other character-separated logs."""

    def __init__(self, config: MappingConfig):
        super().__init__(config)
        parsing = self.config.parsing
        self.delimiter = parsing.get("delimiter", ",")
        # Handle space delimiter special cases (single space or whitespace)
        self.is_whitespace_delim = self.delimiter in (" ", "whitespace")
        self.skip_prefix = parsing.get("skip_line_prefix")
        self.quote_char = parsing.get("quote_character", '"')
        self.has_header = bool(parsing.get("header", False))
        self.field_definitions = parsing.get("fields", {})

    def parse(self, log_line: str, header_context: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        line = log_line.strip()
        if not line:
            return None

        # Skip comment or metadata lines starting with configured prefix
        if self.skip_prefix and line.startswith(self.skip_prefix):
            return None

        # Tokenize row
        if self.is_whitespace_delim:
            tokens = line.split()
        else:
            try:
                reader = csv.reader(
                    io.StringIO(line),
                    delimiter=self.delimiter,
                    quotechar=self.quote_char,
                    skipinitialspace=True,
                )
                tokens = next(reader)
            except Exception:
                tokens = line.split(self.delimiter)

        # Check if the line itself is the header row
        if self.has_header and isinstance(self.field_definitions, dict):
            matching_headers = sum(1 for tok in tokens if tok in self.field_definitions)
            if matching_headers >= 3:
                # This is the header row itself, not a data event
                return None

        result: Dict[str, Any] = {}

        # Case 1: Fields defined by column name (header_context or field_definitions by name)
        if header_context and len(header_context) == len(tokens):
            for col_name, val in zip(header_context, tokens):
                target_field = self.field_definitions.get(col_name, col_name)
                result[target_field] = val
            return result

        # Case 2: Fields defined by index (e.g. 0: raw_date, 1: raw_time)
        index_fields: Dict[int, str] = {}
        for k, v in self.field_definitions.items():
            try:
                index_fields[int(k)] = str(v)
            except (ValueError, TypeError):
                pass

        if index_fields:
            for idx, token in enumerate(tokens):
                if idx in index_fields:
                    result[index_fields[idx]] = token
                else:
                    # Preserve unlisted columns so no data is lost
                    result[f"col_{idx}"] = token
            return result

        # Case 3: Header mapping where fields are column names
        if isinstance(self.field_definitions, dict):
            # Positional fallback matching order of field_definitions
            field_names = list(self.field_definitions.values())
            for idx, token in enumerate(tokens):
                if idx < len(field_names):
                    result[field_names[idx]] = token
                else:
                    result[f"col_{idx}"] = token
            return result

        # Default fallback
        for idx, token in enumerate(tokens):
            result[f"col_{idx}"] = token
        return result


class JSONParser(BaseParser):
    """Parser for single-line JSON logs with dotted-path field extraction."""

    def __init__(self, config: MappingConfig):
        super().__init__(config)
        self.field_definitions = self.config.parsing.get("fields", {})

    def parse(self, log_line: str, header_context: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        line = log_line.strip()
        if not line:
            return None

        try:
            data = json.loads(line)
            if not isinstance(data, dict):
                return None
        except (json.JSONDecodeError, ValueError):
            return None

        result: Dict[str, Any] = {}

        # Flatten/extract defined json paths into raw field names
        extracted_paths = set()
        for json_path, target_raw_field in self.field_definitions.items():
            val = get_nested_json_value(data, json_path)
            if val is not None:
                result[target_raw_field] = val
                extracted_paths.add(json_path)

        # Also preserve all top-level keys that weren't covered
        for k, v in data.items():
            if k not in self.field_definitions and k not in extracted_paths:
                # Add to result for unmapped bucket
                result[k] = v

        return result


class KeyValueParser(BaseParser):
    """Parser for key=value or key:value format log lines."""

    KV_REGEX = re.compile(r'(?P<key>[a-zA-Z0-9_\.\-]+)=(?P<val>"[^"]*"|\'[^\']*\'|[^\s]+)')

    def __init__(self, config: MappingConfig):
        super().__init__(config)
        self.field_map = self.config.parsing.get("fields", {})

    def parse(self, log_line: str, header_context: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        line = log_line.strip()
        if not line:
            return None

        matches = self.KV_REGEX.findall(line)
        if not matches:
            return None

        result: Dict[str, Any] = {}
        for key, val in matches:
            # Strip quotes if present
            clean_val = val.strip('"\'')
            target_key = self.field_map.get(key, key)
            result[target_key] = clean_val

        return result


class SyslogParser(BaseParser):
    """Parser for Syslog messages, including Cisco ASA syslog with message families."""

    # Common Cisco ASA message body patterns
    ASA_PATTERNS = [
        # 302013 / Built connection
        (
            re.compile(r'Built\s+(?P<direction>\w+)\s+(?P<raw_protocol>\w+)\s+connection\s+(?P<raw_connection_id>\d+)\s+for\s+(?P<raw_src_zone>[\w\-]+):(?P<raw_src_ip>[0-9\.]+)/(?P<raw_src_port>\d+)(?:\s+\([^\)]+\))?\s+to\s+(?P<raw_dst_zone>[\w\-]+):(?P<raw_dst_ip>[0-9\.]+)/(?P<raw_dst_port>\d+)', re.IGNORECASE),
            {"event_action": "open"}
        ),
        # 302014 / Teardown connection
        (
            re.compile(r'Teardown\s+(?P<raw_protocol>\w+)\s+connection\s+(?P<raw_connection_id>\d+)\s+for\s+(?P<raw_src_zone>[\w\-]+):(?P<raw_src_ip>[0-9\.]+)/(?P<raw_src_port>\d+)\s+to\s+(?P<raw_dst_zone>[\w\-]+):(?P<raw_dst_ip>[0-9\.]+)/(?P<raw_dst_port>\d+)\s+duration\s+(?P<raw_duration>[\d:]+)\s+bytes\s+(?P<raw_bytes>\d+)(?:\s+(?P<raw_end_reason>.*))?', re.IGNORECASE),
            {"event_action": "close"}
        ),
        # 106023 / Deny access-list
        (
            re.compile(r'Deny\s+(?P<raw_protocol>\w+)\s+src\s+(?P<raw_src_zone>[\w\-]+):(?P<raw_src_ip>[0-9\.]+)/(?P<raw_src_port>\d+)\s+dst\s+(?P<raw_dst_zone>[\w\-]+):(?P<raw_dst_ip>[0-9\.]+)/(?P<raw_dst_port>\d+)(?:\s+by\s+access-group\s+"(?P<raw_access_group>[^"]+)")?', re.IGNORECASE),
            {"event_action": "deny"}
        ),
        # 305011 / Built dynamic translation (NAT)
        (
            re.compile(r'Built\s+dynamic\s+(?P<raw_protocol>\w+)\s+translation\s+from\s+(?P<raw_original_src_zone>[\w\-]+):(?P<raw_original_src_ip>[0-9\.]+)/(?P<raw_original_src_port>\d+)\s+to\s+(?P<raw_translated_src_zone>[\w\-]+):(?P<raw_translated_src_ip>[0-9\.]+)/(?P<raw_translated_src_port>\d+)', re.IGNORECASE),
            {"event_action": "translate"}
        ),
    ]

    def __init__(self, config: MappingConfig):
        super().__init__(config)
        parsing = self.config.parsing
        header_config = parsing.get("header", {})
        raw_header_pattern = header_config.get("pattern", "")
        if raw_header_pattern:
            py_pattern = normalize_regex(raw_header_pattern)
            self.header_regex = re.compile(py_pattern)
        else:
            self.header_regex = None

        self.header_fields = header_config.get("fields", {})
        self.body_target = parsing.get("body", {}).get("target", "raw_message")
        self.message_families = self.config.message_families

    def parse(self, log_line: str, header_context: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        line = log_line.strip()
        if not line:
            return None

        result: Dict[str, Any] = {}
        body_text = line

        # 1. Parse header if pattern is configured
        if self.header_regex:
            match = self.header_regex.search(line)
            if match:
                group_dict = match.groupdict()
                for group_name, raw_field in self.header_fields.items():
                    if group_name in group_dict:
                        result[raw_field] = group_dict[group_name]
                body_text = line[match.end():].strip()

        result[self.body_target] = body_text

        # 2. Determine message family and parse body
        msg_id = str(result.get("raw_message_id", ""))
        family_name = None
        for fam_name, fam_def in self.message_families.items():
            msg_ids = [str(mid) for mid in fam_def.get("message_ids", [])]
            if msg_id in msg_ids:
                family_name = fam_name
                break

        if family_name:
            result["message_family"] = family_name

        # 3. Apply ASA body patterns
        for pattern, defaults in self.ASA_PATTERNS:
            b_match = pattern.search(body_text)
            if b_match:
                result.update(defaults)
                for k, v in b_match.groupdict().items():
                    if v is not None:
                        result[k] = v
                break

        return result


class RegexParser(BaseParser):
    """Generic parser utilizing a named-capture-group regular expression."""

    def __init__(self, config: MappingConfig):
        super().__init__(config)
        pattern = self.config.parsing.get("pattern") or self.config.detection.get("pattern", "")
        py_pattern = normalize_regex(pattern)
        self.regex = re.compile(py_pattern)

    def parse(self, log_line: str, header_context: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        line = log_line.strip()
        if not line:
            return None
        match = self.regex.search(line)
        if not match:
            return None
        return dict(match.groupdict())


def get_parser(config: MappingConfig) -> BaseParser:
    """Factory to instantiate the appropriate parser for a MappingConfig."""
    fmt = (config.format or config.parsing.get("format", "")).lower()

    if fmt in ("space_delimited", "csv", "tsv", "delimited"):
        return DelimitedParser(config)
    elif fmt == "json":
        return JSONParser(config)
    elif fmt in ("key_value", "kv"):
        return KeyValueParser(config)
    elif fmt == "syslog":
        return SyslogParser(config)
    elif fmt == "regex":
        return RegexParser(config)
    else:
        # Fallback to Delimited or Regex parser
        if "delimiter" in config.parsing:
            return DelimitedParser(config)
        elif "pattern" in config.parsing or "pattern" in config.detection:
            return RegexParser(config)
        return DelimitedParser(config)

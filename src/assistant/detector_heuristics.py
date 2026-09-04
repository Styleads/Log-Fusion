"""Format and boundary detection heuristics for unknown raw log samples."""

import csv
import io
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class DetectedFormatResult:
    format_type: str  # 'json', 'key_value', 'csv', 'space_delimited', 'syslog'
    delimiter: Optional[str] = None
    has_header: bool = False
    header_columns: Optional[List[str]] = None
    detection_method: str = "regex"
    detection_pattern: Optional[str] = None
    detection_conditions: Optional[List[Dict[str, Any]]] = None
    parsed_samples: List[Dict[str, Any]] = field(default_factory=list)
    raw_lines: List[str] = field(default_factory=list)
    confidence: float = 0.5  # 0.0 to 1.0


class FormatDetector:
    """Infers log format, field delimiters, headers, and detection patterns from raw sample lines."""

    # Regex patterns for format recognition
    KV_PATTERN = re.compile(r'(?P<key>[a-zA-Z0-9_\.\-]+)=(?P<val>"[^"]*"|\'[^\']*\'|[^\s]+)')
    SYSLOG_HEADER_PATTERN = re.compile(
        r'^(?:<\d{1,3}>)?(?P<raw_timestamp>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<raw_host>[^\s:]+)\s+(?:%?(?P<raw_tag>[A-Za-z0-9_\-\.]+)(?:\[\d+\])?:?\s+)?(?P<raw_message>.*)$'
    )
    CISCO_ASA_TAG = re.compile(r'%ASA-\d+-\d+')

    def detect(self, raw_lines: List[str]) -> DetectedFormatResult:
        """Inspect sample lines and return detected format structure and parsed field samples."""
        clean_lines = [line.strip() for line in raw_lines if line and line.strip() and not line.strip().startswith("#")]
        if not clean_lines:
            return DetectedFormatResult(
                format_type="space_delimited",
                delimiter=" ",
                detection_method="regex",
                raw_lines=raw_lines,
                confidence=0.1,
            )

        # 1. Test for JSON
        json_result = self._check_json(clean_lines)
        if json_result:
            return json_result

        # 2. Test for Key-Value format
        kv_result = self._check_key_value(clean_lines)
        if kv_result:
            return kv_result

        # 3. Test for Syslog format
        syslog_result = self._check_syslog(clean_lines)
        if syslog_result:
            return syslog_result

        # 4. Test for Character-Delimited (CSV, Pipe, Tab)
        delimited_result = self._check_delimited(clean_lines)
        if delimited_result:
            return delimited_result

        # 5. Default to Space-Delimited
        return self._check_space_delimited(clean_lines)

    def _check_json(self, lines: List[str]) -> Optional[DetectedFormatResult]:
        """Check if all sample lines are valid JSON objects."""
        all_json = True
        parsed_samples = []

        for line in lines:
            if not (line.startswith("{") and line.endswith("}")):
                all_json = False
                break
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    parsed_samples.append(data)
                else:
                    all_json = False
                    break
            except Exception:
                all_json = False
                break

        if all_json and parsed_samples:
            # Build conditions for detection
            conditions = []
            sample_keys = parsed_samples[0]
            
            # Look for common discriminator fields in JSON logs
            for key in ("event_type", "type", "action", "log_type", "category"):
                if key in sample_keys:
                    val = sample_keys[key]
                    if isinstance(val, (str, int, bool)):
                        conditions.append({"path": key, "equals": str(val)})
                        break

            if not conditions and parsed_samples:
                # Use first available string field that exists across all samples
                first_key = next(iter(sample_keys.keys()), None)
                if first_key:
                    conditions.append({"path": first_key, "exists": True})

            return DetectedFormatResult(
                format_type="json",
                detection_method="json_match",
                detection_conditions=conditions,
                parsed_samples=parsed_samples,
                raw_lines=lines,
                confidence=0.95,
            )
        return None

    def _check_key_value(self, lines: List[str]) -> Optional[DetectedFormatResult]:
        """Check if lines consist primarily of key=value pairs."""
        parsed_samples = []
        kv_match_count = 0

        for line in lines:
            matches = self.KV_PATTERN.findall(line)
            if len(matches) >= 3:
                kv_match_count += 1
                row_dict = {}
                for k, v in matches:
                    row_dict[k] = v.strip('"\'')
                parsed_samples.append(row_dict)

        # If majority of lines have at least 3 key-value pairs
        if kv_match_count > 0 and kv_match_count >= len(lines) * 0.7:
            # Extract common prefix / signature for detection regex
            # Look for a common key across samples, e.g. "type=", "action=", "devname="
            common_keys = set(parsed_samples[0].keys())
            for sample in parsed_samples[1:]:
                common_keys &= set(sample.keys())

            detection_pattern = None
            if common_keys:
                sorted_keys = sorted(list(common_keys))[:2]
                pattern_parts = [re.escape(k) + r'=' for k in sorted_keys]
                detection_pattern = r'.*'.join(pattern_parts)

            if not detection_pattern:
                detection_pattern = r'[a-zA-Z0-9_\.\-]+='

            return DetectedFormatResult(
                format_type="key_value",
                detection_method="regex",
                detection_pattern=detection_pattern,
                parsed_samples=parsed_samples,
                raw_lines=lines,
                confidence=0.88,
            )
        return None

    def _check_syslog(self, lines: List[str]) -> Optional[DetectedFormatResult]:
        """Check if lines match standard RFC syslog structure or specific vendor syslog headers."""
        syslog_matches = 0
        parsed_samples = []

        for line in lines:
            m = self.SYSLOG_HEADER_PATTERN.match(line)
            if m:
                syslog_matches += 1
                parsed_samples.append(m.groupdict())
            elif self.CISCO_ASA_TAG.search(line):
                syslog_matches += 1
                parsed_samples.append({"raw_message": line})

        if syslog_matches >= len(lines) * 0.7:
            # Check for Cisco ASA or general syslog pattern
            first_line = lines[0]
            cisco_m = self.CISCO_ASA_TAG.search(first_line)
            if cisco_m:
                pattern = r'%ASA-\d+-\d+'
            else:
                pattern = r'^(?:<\d+>)?(?:[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T)'

            return DetectedFormatResult(
                format_type="syslog",
                detection_method="regex",
                detection_pattern=pattern,
                parsed_samples=parsed_samples,
                raw_lines=lines,
                confidence=0.85,
            )
        return None

    def _check_delimited(self, lines: List[str]) -> Optional[DetectedFormatResult]:
        """Check for CSV (comma), Tab, Pipe, or Semicolon separated values."""
        candidate_delimiters = [',', '|', ';', '\t']

        for delim in candidate_delimiters:
            counts = []
            parsed_rows = []
            for line in lines:
                try:
                    reader = csv.reader(io.StringIO(line), delimiter=delim, skipinitialspace=True)
                    row = next(reader)
                    counts.append(len(row))
                    parsed_rows.append(row)
                except Exception:
                    pass

            if len(counts) == len(lines) and len(counts) > 0:
                first_count = counts[0]
                # If consistent column count and >= 3 columns
                if first_count >= 3 and all(c == first_count for c in counts):
                    # Check if first line appears to be a header row (all string column names, no numbers/IPs)
                    first_row = parsed_rows[0]
                    looks_like_header = self._is_header_row(first_row)

                    if looks_like_header and len(parsed_rows) > 1:
                        header_cols = [col.strip().lower().replace(" ", "_") for col in first_row]
                        data_rows = parsed_rows[1:]
                        parsed_samples = [dict(zip(header_cols, row)) for row in data_rows]
                        has_header = True
                    else:
                        header_cols = None
                        parsed_samples = [
                            {f"col_{idx}": val for idx, val in enumerate(row)}
                            for row in parsed_rows
                        ]
                        has_header = False

                    # Build regex pattern for detection
                    # Sample first data line to create a regex anchor
                    sample_line = lines[1] if has_header and len(lines) > 1 else lines[0]
                    escaped_delim = re.escape(delim)
                    # Pattern anchor: looks for repeated delimiter
                    detection_pattern = f'^{escaped_delim.join([r"[^" + escaped_delim + r"]+"] * min(3, first_count))}'

                    return DetectedFormatResult(
                        format_type="csv" if delim == "," else "delimited",
                        delimiter=delim,
                        has_header=has_header,
                        header_columns=header_cols,
                        detection_method="regex",
                        detection_pattern=detection_pattern,
                        parsed_samples=parsed_samples,
                        raw_lines=lines,
                        confidence=0.82,
                    )

        return None

    def _check_space_delimited(self, lines: List[str]) -> DetectedFormatResult:
        """Space-delimited fallback where lines are split by whitespace tokens."""
        token_lists = [line.split() for line in lines]
        parsed_samples = []

        for tokens in token_lists:
            row_dict = {f"col_{i}": tok for i, tok in enumerate(tokens)}
            parsed_samples.append(row_dict)

        # Construct a regex pattern based on leading token characteristics
        first_line = lines[0] if lines else ""
        first_tokens = first_line.split()
        
        pattern_parts = []
        for tok in first_tokens[:4]:
            # Date check
            if re.match(r'^\d{4}[-/]\d{2}[-/]\d{2}$', tok):
                pattern_parts.append(r'\d{4}[-/]\d{2}[-/]\d{2}')
            # Time check
            elif re.match(r'^\d{2}:\d{2}:\d{2}(?:\.\d+)?$', tok):
                pattern_parts.append(r'\d{2}:\d{2}:\d{2}(?:\.\d+)?')
            # Epoch timestamp check (e.g. 1756289531.123 or 1756289531)
            elif re.match(r'^\d{10}\.\d{3}$', tok):
                pattern_parts.append(r'\d{10}\.\d{3}')
            elif re.match(r'^\d{10}(?:\.\d+)?$', tok):
                pattern_parts.append(r'\d{10}(?:\.\d+)?')
            # IP check
            elif re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', tok):
                pattern_parts.append(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
            # Compound protocol/result codes (e.g. TCP_MISS/200, TCP_DENIED/403)
            elif re.match(r'^(?:TCP|UDP)_[A-Za-z]+/\d+$', tok):
                pattern_parts.append(r'(?:TCP|UDP)_\w+/\d+')
            elif re.match(r'^[A-Za-z]+_[A-Za-z]+/\d+$', tok):
                pattern_parts.append(r'\w+/\d+')
            # HTTP methods
            elif tok.upper() in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "PATCH", "TRACE"):
                pattern_parts.append(r'(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|PATCH|TRACE)')
            # Action keywords
            elif tok.upper() in ("DROP", "ALLOW", "ACCEPT", "DENY", "BLOCK", "PERMIT", "REJECT"):
                pattern_parts.append(r'(?:DROP|ALLOW|ACCEPT|DENY|BLOCK|PERMIT|REJECT)')
            # Protocol keywords
            elif tok.upper() in ("TCP", "UDP", "ICMP", "ESP", "GRE"):
                pattern_parts.append(r'(?:TCP|UDP|ICMP|ESP|GRE)')
            # Generic positive integer (e.g. duration or port or byte count)
            elif re.match(r'^\d+$', tok):
                pattern_parts.append(r'\d+')
            else:
                pattern_parts.append(re.escape(tok))

        detection_pattern = (r'^' + r'\s+'.join(pattern_parts)) if pattern_parts else r'^\S+\s+\S+'

        # If lines contain multiple consecutive spaces between tokens, use "whitespace" delimiter
        has_variable_whitespace = any(re.search(r'\S\s{2,}\S', line) for line in lines)
        delimiter = "whitespace" if has_variable_whitespace else " "

        return DetectedFormatResult(
            format_type="space_delimited",
            delimiter=delimiter,
            has_header=False,
            header_columns=None,
            detection_method="regex",
            detection_pattern=detection_pattern,
            parsed_samples=parsed_samples,
            raw_lines=lines,
            confidence=0.70,
        )

    def _is_header_row(self, row: List[str]) -> bool:
        """Heuristic to check if a row represents column headers rather than data."""
        if not row:
            return False
        # If all items are text without purely numeric or IP patterns
        for col in row:
            val = col.strip()
            # If matches IP, number, or timestamp, it's a data row
            if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', val):
                return False
            if val.isdigit() and len(val) > 2:
                return False
            if re.match(r'^\d{4}[-/]\d{2}[-/]\d{2}', val):
                return False
        
        # Check if words look like common headers
        header_keywords = {"time", "timestamp", "date", "src", "dst", "source", "dest", "ip", "port", "proto", "action", "rule", "bytes", "user"}
        matched = sum(1 for col in row if any(kw in col.lower() for kw in header_keywords))
        return matched >= 2

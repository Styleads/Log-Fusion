"""Semantic field analyzer identifying OCSF roles and mappings via heuristics."""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from .detector_heuristics import DetectedFormatResult


@dataclass
class SemanticAnalysisResult:
    field_definitions: Dict[str, str]  # parsing field definitions (e.g. index/key -> raw_field_name)
    field_map: Dict[str, str]          # raw_field_name -> dotted OCSF path
    transforms: Dict[str, Any]         # raw_field_name -> transform spec
    classification_rules: List[Dict[str, Any]]
    default_class_uid: int
    default_class_name: str
    timestamp_config: Dict[str, Any]
    static_fields: Dict[str, Any]
    unmapped_policy: Dict[str, Any]
    raw_preservation: Dict[str, Any]
    confidence_score: float
    confidence_label: str             # "high", "medium", "low"
    ambiguous_fields: List[str]       # unclassified fields that can benefit from LLM fallback


class SemanticAnalyzer:
    """Analyzes extracted field values and keys across samples to assign OCSF semantic roles."""

    IPV4_REGEX = re.compile(r'^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)$')
    IPV6_REGEX = re.compile(r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$')
    KNOWN_PROTOCOLS = {"TCP", "UDP", "ICMP", "IGMP", "GRE", "ESP", "AH", "OSPF", "IPV6", "SCTP", "L2TP", "VRRP"}
    ACTION_ALLOW = {"ALLOW", "ACCEPT", "PERMIT", "PASS", "ALLOWED", "PERMITTED"}
    ACTION_DENY = {"DROP", "DENY", "BLOCK", "REJECT", "BLOCKED", "DROPPED", "DENIED", "RESET"}
    ACTION_ALERT = {"ALERT", "DETECT", "SIGNATURE", "DETECTED", "WARNING"}
    HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "PATCH", "TRACE"}
    CONTENT_TYPE_REGEX = re.compile(r'^(?:text|image|application|audio|video|multipart|font)/[a-zA-Z0-9\.\-\+]+(?:\s*;\s*charset=.*)?$')
    RESULT_CODE_REGEX = re.compile(r'^(?:[A-Za-z]+_)?(?:[A-Za-z]+)/\d{3}$')

    def analyze(
        self,
        format_result: DetectedFormatResult,
        source_name: str = "Unknown Device",
        device_type_hint: Optional[str] = None,
    ) -> SemanticAnalysisResult:
        """Analyze sample records and produce complete mapping configurations."""
        samples = format_result.parsed_samples
        if not samples:
            return self._build_empty_result(format_result, source_name, device_type_hint)

        field_definitions: Dict[str, str] = {}
        field_map: Dict[str, str] = {}
        transforms: Dict[str, Any] = {}
        classification_rules: List[Dict[str, Any]] = []
        ambiguous_fields: List[str] = []

        # Aggregate values per key across all sample rows
        all_keys = list(samples[0].keys())
        key_values: Dict[str, List[Any]] = {k: [] for k in all_keys}
        for s in samples:
            for k in all_keys:
                if k in s and s[k] is not None and str(s[k]).strip() != "":
                    key_values[k].append(str(s[k]).strip())

        # Pre-scan: Identify if telemetry exhibits HTTP characteristics
        has_http_indicator = any(
            self._is_http_method(vals, k) or self._is_url(vals, k) or self._is_compound_result_code(vals)
            for k, vals in key_values.items()
        )
        is_http = bool(has_http_indicator or (device_type_hint and "proxy" in device_type_hint.lower()))

        # Locate index of first IP address column if positional
        first_ip_key_idx: Optional[int] = None
        for idx, k in enumerate(all_keys):
            if self._is_ip_address(key_values[k]):
                first_ip_key_idx = idx
                break

        # State trackers for semantic assignments
        found_ips: List[Tuple[str, str, str, int]] = []
        found_ports: List[Tuple[str, str, str]] = []
        action_field: Optional[str] = None
        action_values: Set[str] = set()
        protocol_field: Optional[str] = None
        date_field: Optional[str] = None
        time_field: Optional[str] = None
        iso_time_field: Optional[str] = None
        syslog_time_field: Optional[str] = None
        epoch_time_field: Optional[str] = None
        epoch_has_fractional: bool = False
        result_code_field: Optional[str] = None
        elapsed_ms_field: Optional[str] = None

        # 1. First pass: identify semantic roles for each key
        for idx, key in enumerate(all_keys):
            vals = key_values[key]
            if not vals:
                continue

            clean_key = key.lower().replace("-", "_").replace(" ", "_")

            # Check for Epoch Timestamp (e.g. 1756289531.123 or 1756289531)
            if self._is_epoch_timestamp(vals):
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role="raw_timestamp")
                field_definitions[key] = raw_name
                epoch_time_field = raw_name
                epoch_has_fractional = any("." in v for v in vals)
                continue

            # Check for ISO-8601 Timestamp
            if self._is_iso_timestamp(vals):
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role="raw_timestamp")
                field_definitions[key] = raw_name
                iso_time_field = raw_name
                continue

            # Check for Syslog Timestamp
            if self._is_syslog_timestamp(vals):
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role="raw_timestamp")
                field_definitions[key] = raw_name
                syslog_time_field = raw_name
                continue

            # Check for Date
            if self._is_date(vals):
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role="raw_date")
                field_definitions[key] = raw_name
                date_field = raw_name
                continue

            # Check for Time
            if self._is_time(vals):
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role="raw_time")
                field_definitions[key] = raw_name
                time_field = raw_name
                continue

            # Check for IP Address
            if self._is_ip_address(vals):
                role = "raw_client_ip" if is_http else ("raw_src_ip" if not found_ips else "raw_dest_ip")
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role=role)
                field_definitions[key] = raw_name
                found_ips.append((key, raw_name, clean_key, idx))
                continue

            # Check for Compound Result Code (e.g. TCP_MISS/200, TCP_DENIED/403)
            if self._is_compound_result_code(vals):
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role="raw_result_code")
                field_definitions[key] = raw_name
                result_code_field = raw_name
                transforms[raw_name] = {
                    "type": "split_status",
                    "delimiter": "/",
                    "parts": ["cache_result", "http_status"],
                    "target_status_field": "http_response.code",
                }
                continue

            # Check for HTTP Method (e.g. GET, POST)
            if self._is_http_method(vals, clean_key):
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role="raw_method")
                field_definitions[key] = raw_name
                field_map[raw_name] = "http_request.http_method"
                continue

            # Check for Web URL
            if self._is_url(vals, clean_key):
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role="raw_url")
                field_definitions[key] = raw_name
                field_map[raw_name] = "http_request.url.text"
                continue

            # Check for MIME Content-Type
            if self._is_content_type(vals, clean_key):
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role="raw_content_type")
                field_definitions[key] = raw_name
                field_map[raw_name] = "http_response.content_type"
                continue

            # Check for Elapsed Time in milliseconds (e.g. 215, 142)
            if self._is_elapsed_ms(vals, clean_key, idx, first_ip_key_idx, is_http):
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role="raw_elapsed_ms")
                field_definitions[key] = raw_name
                elapsed_ms_field = raw_name
                transforms[raw_name] = {"type": "cast_int", "target": "duration_ms"}
                continue

            # Check for Byte / Packet Traffic counts
            if self._is_traffic_bytes(clean_key, vals, is_http):
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role="raw_bytes")
                field_definitions[key] = raw_name
                field_map[raw_name] = "traffic.bytes"
                transforms[raw_name] = {"type": "integer"}
                continue

            # Check for Proxy Hierarchy / Peer (e.g. HIER_DIRECT/93.184.216.34)
            if self._is_peer(vals):
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role="raw_peer")
                field_definitions[key] = raw_name
                continue

            # Check for RFC 931 / Ident username (e.g. '-')
            if self._is_rfc931(vals, clean_key):
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role="raw_rfc931")
                field_definitions[key] = raw_name
                continue

            # Check for Port numbers
            if self._is_port(vals, clean_key, idx, first_ip_key_idx, is_http):
                role = "raw_src_port" if not found_ports else "raw_dst_port"
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role=role)
                field_definitions[key] = raw_name
                found_ports.append((key, raw_name, clean_key))
                continue

            # Check for Protocol
            if self._is_protocol(vals, clean_key):
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role="raw_protocol")
                field_definitions[key] = raw_name
                protocol_field = raw_name
                field_map[raw_name] = "connection_info.protocol_name"
                if all(v.isdigit() for v in vals):
                    transforms[raw_name] = {"type": "protocol_num_to_name"}
                else:
                    transforms[raw_name] = {"type": "passthrough_upper"}
                continue

            # Check for Action / Decision
            if self._is_action(vals, clean_key):
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role="raw_action")
                field_definitions[key] = raw_name
                action_field = raw_name
                for v in vals:
                    action_values.add(v.upper())
                continue

            # Check for Firewall Rule or Finding Title
            if any(term in clean_key for term in ("rule", "policy", "acl")):
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role="raw_rule")
                field_definitions[key] = raw_name
                field_map[raw_name] = "firewall_rule.name"
                continue
            if any(term in clean_key for term in ("signature", "threat", "alert_name", "attack", "msg")):
                raw_name = self._generate_raw_field_name(clean_key, key, format_result, role="raw_message")
                field_definitions[key] = raw_name
                field_map[raw_name] = "finding_info.title"
                continue

            # Fallback for unclassified columns
            raw_name = self._generate_raw_field_name(clean_key, key, format_result)
            field_definitions[key] = raw_name
            ambiguous_fields.append(key)

        # 2. Resolve IP Address Roles (Source vs Destination)
        self._resolve_ip_roles(found_ips, field_map, is_http=is_http)

        # 3. Resolve Port Roles (Source vs Destination)
        self._resolve_port_roles(found_ports, field_map, transforms)

        # 4. Resolve Timestamp Configuration
        ts_config, timestamp_verified = self._resolve_timestamp_config(
            iso_time_field, syslog_time_field, date_field, time_field, epoch_time_field, epoch_has_fractional, samples
        )

        # 5. Resolve Classification Rules & OCSF Class
        default_class_uid, default_class_name, classification_rules = self._resolve_classification(
            action_field=action_field,
            action_values=action_values,
            result_code_field=result_code_field,
            device_type_hint=device_type_hint,
            is_http=is_http,
        )

        # 6. Build Static Fields
        vendor_name = source_name.strip()
        product_name = source_name.strip()
        if source_name.lower().strip() in ("squid", "squid proxy", "squid proxy sample"):
            vendor_name = "Squid"
            product_name = "Squid Proxy"

        dev_type = (
            device_type_hint.capitalize()
            if device_type_hint
            else ("Proxy" if is_http else ("Firewall"))
        )

        static_fields = {
            "device.vendor_name": vendor_name,
            "device.type": dev_type,
            "metadata.product.vendor_name": vendor_name,
            "metadata.product.name": product_name,
        }

        # 7. Confidence Scoring
        confidence_score, confidence_label = self._calculate_confidence(
            field_map=field_map,
            ts_config=ts_config,
            action_field=action_field,
            timestamp_verified=timestamp_verified,
            total_fields_count=len(all_keys),
            is_http=is_http,
            has_rules=bool(classification_rules),
        )

        return SemanticAnalysisResult(
            field_definitions=field_definitions,
            field_map=field_map,
            transforms=transforms,
            classification_rules=classification_rules,
            default_class_uid=default_class_uid,
            default_class_name=default_class_name,
            timestamp_config=ts_config,
            static_fields=static_fields,
            unmapped_policy={"action": "bucket", "target": "unmapped"},
            raw_preservation={"enabled": True, "target_field": "raw_data"},
            confidence_score=confidence_score,
            confidence_label=confidence_label,
            ambiguous_fields=ambiguous_fields,
        )

    def _generate_raw_field_name(
        self,
        clean_key: str,
        original_key: str,
        format_result: DetectedFormatResult,
        role: Optional[str] = None,
    ) -> str:
        """Create a consistent raw_field_name (e.g. raw_client_ip, raw_elapsed_ms, col_0)."""
        if format_result.format_type in ("space_delimited", "csv") and not format_result.has_header:
            if role:
                return role
            return f"raw_{clean_key}" if not clean_key.startswith("raw_") else clean_key
        if not clean_key.startswith("raw_"):
            return f"raw_{clean_key}"
        return clean_key

    def _is_epoch_timestamp(self, values: List[str]) -> bool:
        """Check if values match Unix epoch timestamps (seconds or fractional seconds)."""
        valid = 0
        for v in values:
            try:
                val = float(v)
                # Valid epoch range: ~2001 to 2100 (10^9 to 4.1*10^9 seconds)
                if 1_000_000_000 <= val <= 4_102_444_800:
                    valid += 1
            except (ValueError, TypeError):
                pass
        return valid >= max(1, int(len(values) * 0.7))

    def _is_ip_address(self, values: List[str]) -> bool:
        """Check if values represent IPv4 or IPv6 addresses."""
        valid_count = sum(1 for v in values if self.IPV4_REGEX.match(v) or self.IPV6_REGEX.match(v))
        return valid_count >= max(1, int(len(values) * 0.7))

    def _is_port(
        self,
        values: List[str],
        clean_key: str,
        key_index: int,
        first_ip_idx: Optional[int],
        is_http: bool = False,
    ) -> bool:
        """Check if values represent network port numbers in 1-65535, avoiding false positives."""
        if any(term in clean_key for term in ("port", "sport", "dport", "src_port", "dst_port", "pt")):
            valid = sum(1 for v in values if v.isdigit() and 1 <= int(v) <= 65535)
            return valid >= max(1, int(len(values) * 0.7))

        if is_http:
            return False

        if first_ip_idx is not None and key_index < first_ip_idx:
            return False

        valid_ports = []
        for v in values:
            if v.isdigit() and 1 <= int(v) <= 65535:
                valid_ports.append(int(v))

        if len(valid_ports) < max(1, int(len(values) * 0.7)):
            return False

        common_ports = {20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 137, 138, 139, 143, 161, 389, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443}
        return any(p in common_ports or p >= 1024 for p in valid_ports)

    def _is_protocol(self, values: List[str], clean_key: str) -> bool:
        """Check if values or key represent network protocols."""
        if any(term in clean_key for term in ("proto", "protocol", "service")):
            return True
        valid_count = sum(1 for v in values if v.upper() in self.KNOWN_PROTOCOLS)
        return valid_count >= max(1, int(len(values) * 0.7))

    def _is_action(self, values: List[str], clean_key: str) -> bool:
        """Check if values represent security/firewall action."""
        if any(term in clean_key for term in ("action", "act", "disposition", "decision", "event_action")):
            return True
        all_actions = self.ACTION_ALLOW | self.ACTION_DENY | self.ACTION_ALERT
        valid_count = sum(1 for v in values if v.upper() in all_actions)
        return valid_count >= max(1, int(len(values) * 0.5))

    def _is_iso_timestamp(self, values: List[str]) -> bool:
        """Check if values match ISO-8601 timestamps."""
        pattern = re.compile(r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}')
        valid_count = sum(1 for v in values if pattern.match(v))
        return valid_count >= max(1, int(len(values) * 0.7))

    def _is_syslog_timestamp(self, values: List[str]) -> bool:
        """Check if values match BSD/Syslog timestamps (e.g. Aug 27 09:14:02)."""
        pattern = re.compile(r'^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}')
        valid_count = sum(1 for v in values if pattern.match(v))
        return valid_count >= max(1, int(len(values) * 0.7))

    def _is_date(self, values: List[str]) -> bool:
        """Check if values match standalone dates (YYYY-MM-DD or YYYY/MM/DD)."""
        pattern = re.compile(r'^\d{4}[-/]\d{2}[-/]\d{2}$')
        valid_count = sum(1 for v in values if pattern.match(v))
        return valid_count >= max(1, int(len(values) * 0.7))

    def _is_time(self, values: List[str]) -> bool:
        """Check if values match standalone times (HH:MM:SS)."""
        pattern = re.compile(r'^\d{2}:\d{2}:\d{2}(?:\.\d+)?$')
        valid_count = sum(1 for v in values if pattern.match(v))
        return valid_count >= max(1, int(len(values) * 0.7))

    def _is_http_method(self, values: List[str], clean_key: str) -> bool:
        """Check if values represent HTTP request methods."""
        if any(term in clean_key for term in ("method", "http_method", "verb")):
            return True
        valid = sum(1 for v in values if v.upper() in self.HTTP_METHODS)
        return valid >= max(1, int(len(values) * 0.7))

    def _is_url(self, values: List[str], clean_key: str) -> bool:
        """Check if values represent HTTP URLs or path targets."""
        if any(term in clean_key for term in ("url", "uri", "path", "request_url", "req_url")):
            return True
        valid = 0
        for v in values:
            if v.startswith("http://") or v.startswith("https://") or (v.startswith("/") and len(v) > 1 and " " not in v):
                valid += 1
        return valid >= max(1, int(len(values) * 0.7))

    def _is_content_type(self, values: List[str], clean_key: str) -> bool:
        """Check if values represent MIME / Content-Type headers."""
        if any(term in clean_key for term in ("content_type", "mime", "mime_type")):
            return True
        valid = sum(1 for v in values if self.CONTENT_TYPE_REGEX.match(v) or v == "-")
        return valid >= max(1, int(len(values) * 0.7)) and any(self.CONTENT_TYPE_REGEX.match(v) for v in values)

    def _is_compound_result_code(self, values: List[str]) -> bool:
        """Check if values represent compound action/status codes (e.g. TCP_MISS/200, TCP_DENIED/403)."""
        valid = sum(1 for v in values if self.RESULT_CODE_REGEX.match(v))
        return valid >= max(1, int(len(values) * 0.7))

    def _is_elapsed_ms(
        self,
        values: List[str],
        clean_key: str,
        key_index: int,
        first_ip_idx: Optional[int],
        is_http: bool = False,
    ) -> bool:
        """Check if values denote elapsed request time in milliseconds."""
        if any(term in clean_key for term in ("elapsed", "duration", "time_taken", "latency", "ms", "response_time")):
            return all(v.isdigit() for v in values if v)

        if is_http and first_ip_idx is not None and key_index < first_ip_idx:
            return all(v.isdigit() and int(v) >= 0 for v in values if v)

        return False

    def _is_traffic_bytes(self, clean_key: str, values: List[str], is_http: bool = False) -> bool:
        """Check if key or values denote traffic byte count."""
        if any(term in clean_key for term in ("byte", "size", "length", "len", "rcvdbyte", "sentbyte", "bytes_out", "bytes_in")):
            return all(v.isdigit() for v in values if v)

        if is_http and all(v.isdigit() for v in values if v):
            nums = [int(v) for v in values if v]
            if any(n > 500 for n in nums) or (0 in nums and any(n > 0 for n in nums)):
                return True
        return False

    def _is_peer(self, values: List[str]) -> bool:
        """Check if values look like proxy hierarchy/peer specs (e.g. HIER_DIRECT/ip)."""
        valid = sum(1 for v in values if v.startswith("HIER_") or "DIRECT/" in v or "NONE/" in v)
        return valid >= max(1, int(len(values) * 0.7))

    def _is_rfc931(self, values: List[str], clean_key: str) -> bool:
        """Check if values represent RFC 931 / identd username (e.g. standard '-' placeholder)."""
        if any(term in clean_key for term in ("rfc931", "ident", "identd")):
            return True
        return all(v == "-" for v in values)

    def _resolve_ip_roles(
        self,
        found_ips: List[Tuple[str, str, str, int]],
        field_map: Dict[str, str],
        is_http: bool = False,
    ) -> None:
        """Assign source IP vs destination IP based on key naming or positional ordering."""
        if not found_ips:
            return

        assigned = set()
        for key, raw_field, clean_key, idx in found_ips:
            if any(term in clean_key for term in ("src", "source", "saddr", "orig_h", "client")):
                field_map[raw_field] = "src_endpoint.ip"
                assigned.add(raw_field)
            elif any(term in clean_key for term in ("dst", "dest", "destination", "daddr", "resp_h", "server")):
                field_map[raw_field] = "dst_endpoint.ip"
                assigned.add(raw_field)

        remaining = [item for item in found_ips if item[1] not in assigned]
        if len(remaining) >= 2:
            field_map[remaining[0][1]] = "src_endpoint.ip"
            field_map[remaining[1][1]] = "dst_endpoint.ip"
        elif len(remaining) == 1:
            field_map[remaining[0][1]] = "src_endpoint.ip"

    def _resolve_port_roles(
        self,
        found_ports: List[Tuple[str, str, str]],
        field_map: Dict[str, str],
        transforms: Dict[str, Any],
    ) -> None:
        """Assign source port vs destination port based on naming or positional ordering."""
        if not found_ports:
            return

        assigned = set()
        for key, raw_field, clean_key in found_ports:
            transforms[raw_field] = {"type": "integer"}
            if any(term in clean_key for term in ("src", "sport", "s_port", "orig_p", "source")):
                field_map[raw_field] = "src_endpoint.port"
                assigned.add(raw_field)
            elif any(term in clean_key for term in ("dst", "dport", "d_port", "resp_p", "dest", "destination")):
                field_map[raw_field] = "dst_endpoint.port"
                assigned.add(raw_field)

        remaining = [item for item in found_ports if item[1] not in assigned]
        if len(remaining) >= 2:
            field_map[remaining[0][1]] = "src_endpoint.port"
            field_map[remaining[1][1]] = "dst_endpoint.port"
        elif len(remaining) == 1 and "src_endpoint.port" not in field_map.values():
            field_map[remaining[0][1]] = "src_endpoint.port"
        elif len(remaining) == 1:
            field_map[remaining[0][1]] = "dst_endpoint.port"

    def _resolve_timestamp_config(
        self,
        iso_time_field: Optional[str],
        syslog_time_field: Optional[str],
        date_field: Optional[str],
        time_field: Optional[str],
        epoch_time_field: Optional[str],
        epoch_has_fractional: bool,
        samples: List[Dict[str, Any]],
    ) -> Tuple[Dict[str, Any], bool]:
        """Formulate timestamp parsing section and report verification status."""
        if epoch_time_field:
            return {
                "source_field": epoch_time_field,
                "format": "epoch_seconds_fractional" if epoch_has_fractional else "epoch_seconds",
                "timezone": "UTC",
            }, True
        elif iso_time_field:
            return {
                "source_field": iso_time_field,
                "format": "%Y-%m-%dT%H:%M:%S%z",
                "timezone": "UTC",
            }, True
        elif date_field and time_field:
            return {
                "source_field": f"{date_field}+{time_field}",
                "format": "%Y-%m-%d %H:%M:%S",
                "timezone": "UTC",
            }, True
        elif syslog_time_field:
            return {
                "source_field": syslog_time_field,
                "format": "%b %d %H:%M:%S",
                "timezone": "UTC",
            }, True
        elif date_field:
            return {
                "source_field": date_field,
                "format": "%Y-%m-%d",
                "timezone": "UTC",
            }, True

        first_key = next(iter(samples[0].keys()), "")
        return {
            "source_field": f"raw_{first_key}" if first_key else "raw_time",
            "format": "%Y-%m-%d %H:%M:%S",
            "timezone": "UTC",
        }, False

    def _resolve_classification(
        self,
        action_field: Optional[str],
        action_values: Set[str],
        result_code_field: Optional[str],
        device_type_hint: Optional[str],
        is_http: bool = False,
    ) -> Tuple[int, str, List[Dict[str, Any]]]:
        """Build OCSF classification rules and class defaults."""
        rules = []

        is_ids = bool(device_type_hint and "ids" in device_type_hint.lower())
        if is_http:
            default_class_uid = 4002
            default_class_name = "HTTP Activity"
        elif is_ids:
            default_class_uid = 2001
            default_class_name = "Detection Finding"
        else:
            default_class_uid = 4001
            default_class_name = "Network Activity"

        if result_code_field and is_http:
            rules.append({
                "when": {f"{result_code_field}_contains": "DENIED"},
                "class_uid": 4002,
                "activity_id": 6,
                "activity_name": "Deny",
            })
            rules.append({
                "when": {f"{result_code_field}_contains": "HIT"},
                "class_uid": 4002,
                "activity_id": 1,
                "activity_name": "Allow",
            })
            rules.append({
                "when": {f"{result_code_field}_contains": "MISS"},
                "class_uid": 4002,
                "activity_id": 1,
                "activity_name": "Allow",
            })
        elif action_field:
            for val in sorted(list(action_values)):
                if val in self.ACTION_DENY:
                    rules.append({
                        "when": {action_field: val},
                        "class_uid": default_class_uid,
                        "class_name": default_class_name,
                        "activity_id": 6,
                        "activity_name": "Deny",
                    })
                elif val in self.ACTION_ALLOW:
                    rules.append({
                        "when": {action_field: val},
                        "class_uid": default_class_uid,
                        "class_name": default_class_name,
                        "activity_id": 1,
                        "activity_name": "Allow",
                    })
                elif val in self.ACTION_ALERT:
                    rules.append({
                        "when": {action_field: val},
                        "class_uid": 2001,
                        "class_name": "Detection Finding",
                        "activity_id": 1,
                        "activity_name": "Alert",
                    })

        return default_class_uid, default_class_name, rules

    def _calculate_confidence(
        self,
        field_map: Dict[str, str],
        ts_config: Dict[str, Any],
        action_field: Optional[str],
        timestamp_verified: bool,
        total_fields_count: int,
        is_http: bool = False,
        has_rules: bool = False,
    ) -> Tuple[float, str]:
        """Compute principled mapping confidence score and categorical label."""
        # 1. Timestamp Verification (0.0 to 0.25)
        ts_score = 0.25 if timestamp_verified else 0.0

        # 2. Core Schema Role Coverage (0.0 to 0.45)
        mapped_targets = set(field_map.values())
        if is_http:
            core_http = {"src_endpoint.ip", "http_request.http_method", "http_request.url.text"}
            aux_http = {"http_response.content_type", "traffic.bytes", "http_response.code"}
            core_matches = mapped_targets.intersection(core_http)
            aux_matches = mapped_targets.intersection(aux_http)
            core_score = (len(core_matches) / len(core_http)) * 0.35 + (len(aux_matches) / len(aux_http)) * 0.10
        else:
            core_net = {
                "src_endpoint.ip",
                "dst_endpoint.ip",
                "src_endpoint.port",
                "dst_endpoint.port",
                "connection_info.protocol_name",
            }
            core_matches = mapped_targets.intersection(core_net)
            core_score = (len(core_matches) / len(core_net)) * 0.45

        # 3. Action / Classification Disambiguation (0.0 to 0.10)
        action_score = 0.10 if (action_field or has_rules) else 0.0

        # 4. Total Field Mapping Rate (0.0 to 0.20)
        if total_fields_count > 0:
            coverage_ratio = len(field_map) / total_fields_count
            coverage_score = min(0.20, round(coverage_ratio * 0.20, 2))
        else:
            coverage_score = 0.0

        score = round(ts_score + core_score + action_score + coverage_score, 2)
        score = min(1.0, max(0.1, score))

        if score >= 0.75:
            label = "high"
        elif score >= 0.50:
            label = "medium"
        else:
            label = "low"

        return score, label

    def _build_empty_result(
        self,
        format_result: DetectedFormatResult,
        source_name: str,
        device_type_hint: Optional[str],
    ) -> SemanticAnalysisResult:
        """Construct fallback result when no samples could be parsed."""
        return SemanticAnalysisResult(
            field_definitions={},
            field_map={},
            transforms={},
            classification_rules=[],
            default_class_uid=4001,
            default_class_name="Network Activity",
            timestamp_config={"source_field": "raw_time", "format": "%Y-%m-%d %H:%M:%S", "timezone": "UTC"},
            static_fields={"device.vendor_name": source_name, "device.type": device_type_hint or "Firewall"},
            unmapped_policy={"action": "bucket", "target": "unmapped"},
            raw_preservation={"enabled": True, "target_field": "raw_data"},
            confidence_score=0.1,
            confidence_label="low",
            ambiguous_fields=[],
        )

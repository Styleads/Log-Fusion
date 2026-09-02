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

        # State trackers for positional IP and port assignment
        found_ips: List[str] = []
        found_ports: List[str] = []
        action_field: Optional[str] = None
        action_values: Set[str] = set()
        protocol_field: Optional[str] = None
        date_field: Optional[str] = None
        time_field: Optional[str] = None
        iso_time_field: Optional[str] = None
        syslog_time_field: Optional[str] = None

        # 1. First pass: identify semantic roles for each key
        for key in all_keys:
            vals = key_values[key]
            if not vals:
                continue

            clean_key = key.lower().replace("-", "_").replace(" ", "_")
            raw_field_name = self._generate_raw_field_name(clean_key, key, format_result)
            field_definitions[key] = raw_field_name

            # Check for Timestamp / Date / Time
            if self._is_iso_timestamp(vals):
                iso_time_field = raw_field_name
                continue
            elif self._is_syslog_timestamp(vals):
                syslog_time_field = raw_field_name
                continue
            elif self._is_date(vals):
                date_field = raw_field_name
                continue
            elif self._is_time(vals):
                time_field = raw_field_name
                continue

            # Check for IP Address
            if self._is_ip_address(vals):
                found_ips.append((key, raw_field_name, clean_key))
                continue

            # Check for Port
            if self._is_port(vals):
                found_ports.append((key, raw_field_name, clean_key))
                continue

            # Check for Protocol
            if self._is_protocol(vals, clean_key):
                protocol_field = raw_field_name
                field_map[raw_field_name] = "connection_info.protocol_name"
                # If numeric protocol, use protocol_num_to_name
                if all(v.isdigit() for v in vals):
                    transforms[raw_field_name] = {"type": "protocol_num_to_name"}
                else:
                    transforms[raw_field_name] = {"type": "passthrough_upper"}
                continue

            # Check for Action / Decision
            if self._is_action(vals, clean_key):
                action_field = raw_field_name
                for v in vals:
                    action_values.add(v.upper())
                continue

            # Check for Byte / Packet Traffic counts
            if self._is_traffic_bytes(clean_key, vals):
                field_map[raw_field_name] = "traffic.bytes"
                transforms[raw_field_name] = {"type": "integer"}
                continue

            # Check for Firewall Rule or Finding Title
            if any(term in clean_key for term in ("rule", "policy", "acl")):
                field_map[raw_field_name] = "firewall_rule.name"
                continue
            if any(term in clean_key for term in ("signature", "threat", "alert_name", "attack", "msg")):
                field_map[raw_field_name] = "finding_info.title"
                continue

            # If not matched by heuristics, mark as ambiguous
            ambiguous_fields.append(key)

        # 2. Resolve IP Address Roles (Source vs Destination)
        self._resolve_ip_roles(found_ips, field_map)

        # 3. Resolve Port Roles (Source vs Destination)
        self._resolve_port_roles(found_ports, field_map, transforms)

        # 4. Resolve Timestamp Configuration
        ts_config = self._resolve_timestamp_config(
            iso_time_field, syslog_time_field, date_field, time_field, samples
        )

        # 5. Resolve Classification Rules & OCSF Class
        default_class_uid, default_class_name, classification_rules = self._resolve_classification(
            action_field, action_values, device_type_hint
        )

        # 6. Build Static Fields
        vendor_name = source_name.strip()
        product_name = source_name.strip()
        dev_type = device_type_hint.capitalize() if device_type_hint else "Firewall"
        static_fields = {
            "device.vendor_name": vendor_name,
            "device.type": dev_type,
            "metadata.product.vendor_name": vendor_name,
            "metadata.product.name": product_name,
        }

        # 7. Confidence Scoring
        confidence_score, confidence_label = self._calculate_confidence(field_map, ts_config, action_field)

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

    def _generate_raw_field_name(self, clean_key: str, original_key: str, format_result: DetectedFormatResult) -> str:
        """Create a consistent raw_field_name (e.g. raw_src_ip, raw_action, col_0)."""
        if format_result.format_type in ("space_delimited", "csv") and not format_result.has_header:
            return f"raw_{clean_key}" if not clean_key.startswith("raw_") else clean_key
        if not clean_key.startswith("raw_"):
            return f"raw_{clean_key}"
        return clean_key

    def _is_ip_address(self, values: List[str]) -> bool:
        """Check if values represent IPv4 or IPv6 addresses."""
        valid_count = sum(1 for v in values if self.IPV4_REGEX.match(v) or self.IPV6_REGEX.match(v))
        return valid_count >= max(1, int(len(values) * 0.7))

    def _is_port(self, values: List[str]) -> bool:
        """Check if values are integer port numbers in 1-65535."""
        valid_count = 0
        for v in values:
            if v.isdigit():
                port = int(v)
                if 1 <= port <= 65535:
                    valid_count += 1
        return valid_count >= max(1, int(len(values) * 0.7))

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

    def _is_traffic_bytes(self, clean_key: str, values: List[str]) -> bool:
        """Check if key or values denote traffic byte count."""
        if any(term in clean_key for term in ("byte", "size", "length", "len", "rcvdbyte", "sentbyte")):
            return all(v.isdigit() for v in values if v)
        return False

    def _resolve_ip_roles(self, found_ips: List[Tuple[str, str, str]], field_map: Dict[str, str]) -> None:
        """Assign source IP vs destination IP based on key naming or positional ordering."""
        if not found_ips:
            return

        # Check explicit naming first
        assigned = set()
        for key, raw_field, clean_key in found_ips:
            if any(term in clean_key for term in ("src", "source", "saddr", "orig_h", "client")):
                field_map[raw_field] = "src_endpoint.ip"
                assigned.add(raw_field)
            elif any(term in clean_key for term in ("dst", "dest", "destination", "daddr", "resp_h", "server")):
                field_map[raw_field] = "dst_endpoint.ip"
                assigned.add(raw_field)

        # Fallback to positional ordering if not assigned by name
        remaining = [item for item in found_ips if item[1] not in assigned]
        if len(remaining) >= 2:
            field_map[remaining[0][1]] = "src_endpoint.ip"
            field_map[remaining[1][1]] = "dst_endpoint.ip"
        elif len(remaining) == 1 and "src_endpoint.ip" not in field_map.values():
            field_map[remaining[0][1]] = "src_endpoint.ip"
        elif len(remaining) == 1:
            field_map[remaining[0][1]] = "dst_endpoint.ip"

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
        samples: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Formulate timestamp parsing section with source_field, format, and timezone."""
        if iso_time_field:
            return {
                "source_field": iso_time_field,
                "format": "%Y-%m-%dT%H:%M:%S%z",
                "timezone": "UTC",
            }
        elif date_field and time_field:
            return {
                "source_field": f"{date_field}+{time_field}",
                "format": "%Y-%m-%d %H:%M:%S",
                "timezone": "UTC",
            }
        elif syslog_time_field:
            return {
                "source_field": syslog_time_field,
                "format": "%b %d %H:%M:%S",
                "timezone": "UTC",
            }
        elif date_field:
            return {
                "source_field": date_field,
                "format": "%Y-%m-%d",
                "timezone": "UTC",
            }
        
        # Check if first key has a timestamp-like name
        first_key = next(iter(samples[0].keys()), "")
        return {
            "source_field": f"raw_{first_key}" if first_key else "raw_time",
            "format": "%Y-%m-%d %H:%M:%S",
            "timezone": "UTC",
        }

    def _resolve_classification(
        self,
        action_field: Optional[str],
        action_values: Set[str],
        device_type_hint: Optional[str],
    ) -> Tuple[int, str, List[Dict[str, Any]]]:
        """Build OCSF classification rules and class defaults."""
        rules = []

        is_ids = device_type_hint and "ids" in device_type_hint.lower()
        default_class_uid = 2001 if is_ids else 4001
        default_class_name = "Detection Finding" if is_ids else "Network Activity"

        if action_field:
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
    ) -> Tuple[float, str]:
        """Compute heuristic mapping confidence score and categorical label."""
        key_ocsf_targets = {
            "src_endpoint.ip",
            "dst_endpoint.ip",
            "src_endpoint.port",
            "dst_endpoint.port",
            "connection_info.protocol_name",
        }
        mapped_targets = set(field_map.values())
        matched_keys = mapped_targets.intersection(key_ocsf_targets)

        score = 0.2  # base score
        score += (len(matched_keys) / len(key_ocsf_targets)) * 0.5
        if ts_config.get("source_field"):
            score += 0.15
        if action_field:
            score += 0.15

        score = min(1.0, max(0.1, round(score, 2)))

        if score >= 0.75:
            label = "high"
        elif score >= 0.5:
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

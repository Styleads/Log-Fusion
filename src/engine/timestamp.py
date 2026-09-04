"""Event timestamp parsing and ISO-8601 UTC normalization module."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from .config_loader import MappingConfig


class TimestampParser:
    """Parses raw date/time fields and converts them into standardized ISO-8601 UTC strings."""

    def __init__(self, config: MappingConfig):
        self.config = config
        self.ts_config = self.config.timestamp
        self.source_fields = self._parse_source_fields()
        self.format_str = self.ts_config.get("format")
        self.tz_setting = self.ts_config.get("timezone", "UTC").lower()

    def _parse_source_fields(self) -> list[str]:
        source = self.ts_config.get("source_field", "")
        if not source:
            return []
        return [f.strip() for f in source.split("+") if f.strip()]

    def parse_time(self, parsed_fields: Dict[str, Any]) -> Optional[str]:
        """
        Extract timestamp values from parsed fields, parse, and return ISO-8601 UTC string.
        """
        if not self.source_fields:
            # Fallback to standard raw_timestamp or time fields if present
            for fallback in ("raw_timestamp", "timestamp", "time", "raw_time"):
                if fallback in parsed_fields and parsed_fields[fallback]:
                    return self._parse_string_value(str(parsed_fields[fallback]))
            return None

        # Build composite timestamp string from configured source fields
        components = []
        for sf in self.source_fields:
            val = parsed_fields.get(sf)
            if val is not None and val != "-":
                components.append(str(val).strip())

        if not components:
            return None

        raw_time_str = " ".join(components)
        return self._parse_string_value(raw_time_str)

    def _parse_string_value(self, time_str: str) -> Optional[str]:
        """Parse raw time string using configured format or ISO fallback."""
        cleaned_str = time_str.strip()
        if not cleaned_str or cleaned_str == "-":
            return None

        dt: Optional[datetime] = None

        # 1. Try configured format string if present
        if self.format_str:
            fmt_lower = self.format_str.lower()
            if fmt_lower in ("epoch_seconds_fractional", "epoch_seconds", "epoch"):
                try:
                    dt = datetime.fromtimestamp(float(cleaned_str), tz=timezone.utc)
                except (ValueError, OSError):
                    pass
            elif fmt_lower in ("epoch_ms", "epoch_millis", "epoch_milliseconds"):
                try:
                    dt = datetime.fromtimestamp(float(cleaned_str) / 1000.0, tz=timezone.utc)
                except (ValueError, OSError):
                    pass
            else:
                try:
                    # Handle %z timezone offsets like +0000 or -05:00
                    dt = datetime.strptime(cleaned_str, self.format_str)
                except ValueError:
                    pass

        # 2. Try Python fromisoformat (handles ISO-8601 with offset or Z)
        if dt is None:
            try:
                # Handle +0000 or +00:00 format
                iso_str = cleaned_str.replace("Z", "+00:00")
                dt = datetime.fromisoformat(iso_str)
            except ValueError:
                pass

        # 3. Common fallback formats
        if dt is None:
            fallbacks = [
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
                "%b %d %Y %H:%M:%S",
                "%b %d %H:%M:%S %Y",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%fZ",
            ]
            for fmt in fallbacks:
                try:
                    dt = datetime.strptime(cleaned_str, fmt)
                    break
                except ValueError:
                    continue

        # 4. Epoch auto-detection fallback
        if dt is None:
            try:
                val_f = float(cleaned_str)
                if 1_000_000_000 <= val_f <= 4_102_444_800:
                    dt = datetime.fromtimestamp(val_f, tz=timezone.utc)
                elif 1_000_000_000_000 <= val_f <= 4_102_444_800_000:
                    dt = datetime.fromtimestamp(val_f / 1000.0, tz=timezone.utc)
            except (ValueError, OSError):
                pass

        if dt is None:
            # If unable to parse into datetime, return the original string
            return cleaned_str

        # 4. Standardize to UTC and format ISO-8601 string
        if dt.tzinfo is None:
            # Naive datetime: treat as UTC or local based on config
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            # Convert timezone-aware datetime to UTC
            dt = dt.astimezone(timezone.utc)

        # Output format: YYYY-MM-DDTHH:MM:SSZ (or with microseconds if present)
        if dt.microsecond > 0:
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

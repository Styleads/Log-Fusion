"""Main normalization pipeline orchestrating Detect -> Parse -> Classify -> Map -> Transform -> Preserve."""

import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union
from .config_loader import ConfigLoader, MappingConfig
from .detector import LogDetector
from .parsers import BaseParser, get_parser
from .classifier import OCSFClassifier
from .transforms import ValueTransformer
from .timestamp import TimestampParser
from .mapper import NestedMapper, set_nested_value


class NormalizationPipeline:
    """End-to-end log normalization pipeline for the Universal Log Pre-processing Framework."""

    def __init__(self, mappings_dir_or_loader: Optional[Union[str, Path, ConfigLoader]] = None):
        if isinstance(mappings_dir_or_loader, ConfigLoader):
            self.loader = mappings_dir_or_loader
        elif mappings_dir_or_loader:
            self.loader = ConfigLoader(mappings_dir_or_loader)
        else:
            # Default to mappings directory in workspace root
            default_dir = Path(__file__).resolve().parent.parent.parent / "mappings"
            self.loader = ConfigLoader(default_dir)

        self.detector = LogDetector(self.loader)
        self._components_cache: Dict[str, Dict[str, Any]] = {}

    def _get_components(self, config: MappingConfig) -> Dict[str, Any]:
        """Lazy-instantiate and cache engine components for a specific mapping config."""
        key = str(config.file_path or f"{config.vendor}_{config.product}")
        if key not in self._components_cache:
            self._components_cache[key] = {
                "parser": get_parser(config),
                "classifier": OCSFClassifier(config),
                "transformer": ValueTransformer(config),
                "timestamp_parser": TimestampParser(config),
                "mapper": NestedMapper(config),
            }
        return self._components_cache[key]

    def process_line(
        self,
        log_line: str,
        header_context: Optional[List[str]] = None,
        config: Optional[MappingConfig] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Normalize a single log line through the full pipeline:
        Detect -> Parse -> Transform -> Timestamp -> Classify -> Map -> Preserve
        
        Returns:
            Normalized OCSF event dictionary, or None if the line is a header/comment.
        """
        line = log_line.strip()
        if not line:
            return None

        # 1. Detect Config
        active_config = config or self.detector.detect(line, header_context=header_context)
        if not active_config:
            # Unrecognized log format
            return None

        comps = self._get_components(active_config)
        parser: BaseParser = comps["parser"]
        classifier: OCSFClassifier = comps["classifier"]
        transformer: ValueTransformer = comps["transformer"]
        ts_parser: TimestampParser = comps["timestamp_parser"]
        mapper: NestedMapper = comps["mapper"]

        # 2. Parse Line
        parsed_fields = parser.parse(line, header_context=header_context)
        if parsed_fields is None:
            # Comment, header row, or non-event line
            return None

        # 3. Transform Values & Type Cast
        transformed_fields = transformer.transform_all(parsed_fields)

        # 4. Parse & Standardize Timestamp
        event_time = ts_parser.parse_time(parsed_fields)

        # 5. Classify Event
        classification = classifier.classify(parsed_fields)

        # 6. Map to Nested OCSF Structure & Bucket Unmapped Fields
        event = mapper.map_event(
            parsed_fields=parsed_fields,
            transformed_fields=transformed_fields,
            classification=classification,
            event_time=event_time,
        )

        # 7. Preserve Raw Data & Attach Unique Traceability UUID
        event_uid = str(uuid.uuid4())
        set_nested_value(event, "metadata.uid", event_uid)

        raw_pres = active_config.raw_preservation
        if raw_pres.get("enabled", True):
            target_field = raw_pres.get("target_field", "raw_data")
            set_nested_value(event, target_field, line)

        return event

    def process_lines(self, lines: Iterable[str]) -> List[Dict[str, Any]]:
        """Process a stream or list of log lines."""
        events: List[Dict[str, Any]] = []
        header_context: Optional[List[str]] = None

        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue

            # Detect CSV header row (only if not JSON)
            if header_context is None and not line.startswith("{") and ("," in line and '"' in line):
                import csv
                import io
                try:
                    reader = csv.reader(io.StringIO(line))
                    row = next(reader)
                    # Check if row looks like headers (e.g. contains Source IP, Time, Type)
                    if any("time" in col.lower() or "ip" in col.lower() or "type" in col.lower() for col in row):
                        header_context = row
                        continue
                except Exception:
                    pass

            event = self.process_line(line, header_context=header_context)
            if event is not None:
                events.append(event)

        return events

    def process_file(self, file_path: Union[str, Path]) -> List[Dict[str, Any]]:
        """Read and process an entire log file."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Log file not found: {path}")

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return self.process_lines(f)

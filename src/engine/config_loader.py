"""Config Loader for YAML-driven OCSF log mapping definitions."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import yaml


class MappingConfigError(Exception):
    """Raised when a mapping configuration fails to load or validate."""
    pass


class MappingConfig:
    """Encapsulates a single vendor/product mapping configuration."""

    def __init__(self, raw_config: Dict[str, Any], file_path: Optional[Union[str, Path]] = None):
        self.raw_config = raw_config
        self.file_path = Path(file_path) if file_path else None
        self._validate()

    def _validate(self) -> None:
        """Validate required top-level configuration sections."""
        required_sections = [
            "source_identity",
            "detection",
            "parsing",
            "classification",
            "field_map",
        ]
        missing = [s for s in required_sections if s not in self.raw_config]
        if missing:
            path_str = f" in {self.file_path}" if self.file_path else ""
            raise MappingConfigError(
                f"Mapping configuration missing required sections{path_str}: {', '.join(missing)}"
            )

        source_id = self.raw_config.get("source_identity", {})
        if not isinstance(source_id, dict) or not source_id.get("vendor"):
            path_str = f" in {self.file_path}" if self.file_path else ""
            raise MappingConfigError(f"source_identity must contain at least 'vendor'{path_str}")

    @property
    def source_identity(self) -> Dict[str, Any]:
        return self.raw_config.get("source_identity", {})

    @property
    def vendor(self) -> str:
        return self.source_identity.get("vendor", "")

    @property
    def product(self) -> str:
        return self.source_identity.get("product", "")

    @property
    def format(self) -> str:
        return self.source_identity.get("format", "")

    @property
    def version(self) -> str:
        return str(self.source_identity.get("version", ""))

    @property
    def detection(self) -> Dict[str, Any]:
        return self.raw_config.get("detection", {})

    @property
    def detection_method(self) -> str:
        return self.detection.get("method", "")

    @property
    def parsing(self) -> Dict[str, Any]:
        return self.raw_config.get("parsing", {})

    @property
    def message_families(self) -> Dict[str, Any]:
        return self.raw_config.get("message_families", {})

    @property
    def classification(self) -> Dict[str, Any]:
        return self.raw_config.get("classification", {})

    @property
    def default_class_uid(self) -> Optional[int]:
        return self.classification.get("default_class_uid")

    @property
    def default_class_name(self) -> Optional[str]:
        return self.classification.get("default_class_name")

    @property
    def classification_rules(self) -> List[Dict[str, Any]]:
        """Normalize classification rules into a list of rule dictionaries."""
        rules = self.classification.get("rules", [])
        if isinstance(rules, list):
            return rules
        elif isinstance(rules, dict):
            # Convert named rule dictionary: {rule_name: {when: ..., ...}} -> [{name: rule_name, when: ..., ...}]
            normalized = []
            for name, rule in rules.items():
                if isinstance(rule, dict):
                    rule_copy = dict(rule)
                    rule_copy.setdefault("name", name)
                    normalized.append(rule_copy)
            return normalized
        return []

    @property
    def field_map(self) -> Dict[str, str]:
        return self.raw_config.get("field_map", {})

    @property
    def static_fields(self) -> Dict[str, Any]:
        return self.raw_config.get("static_fields", {})

    @property
    def transforms(self) -> Dict[str, Any]:
        return self.raw_config.get("transforms", {})

    @property
    def timestamp(self) -> Dict[str, Any]:
        return self.raw_config.get("timestamp", {})

    @property
    def unmapped_policy(self) -> Dict[str, Any]:
        return self.raw_config.get("unmapped_policy", {"action": "bucket", "target": "unmapped"})

    @property
    def raw_preservation(self) -> Dict[str, Any]:
        return self.raw_config.get("raw_preservation", {"enabled": True, "target_field": "raw_data"})

    def __repr__(self) -> str:
        return f"<MappingConfig vendor='{self.vendor}' product='{self.product}' format='{self.format}'>"


class ConfigLoader:
    """Loads and manages YAML mapping configurations for the engine."""

    def __init__(self, mappings_dir: Optional[Union[str, Path]] = None):
        self.mappings_dir = Path(mappings_dir) if mappings_dir else None
        self.configs: List[MappingConfig] = []
        if self.mappings_dir:
            self.load_directory(self.mappings_dir)

    def load_file(self, file_path: Union[str, Path]) -> MappingConfig:
        """Load a single YAML mapping configuration file."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Mapping configuration file not found: {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f)
        except Exception as e:
            raise MappingConfigError(f"Failed to parse YAML from {path}: {e}") from e

        if not isinstance(content, dict):
            raise MappingConfigError(f"YAML content in {path} must be a dictionary")

        config = MappingConfig(content, file_path=path)
        return config

    def load_directory(self, dir_path: Union[str, Path]) -> List[MappingConfig]:
        """Recursively scan a directory and load all YAML mapping configurations."""
        path = Path(dir_path)
        if not path.is_dir():
            raise NotADirectoryError(f"Mappings directory not found: {path}")

        self.mappings_dir = path
        self.configs = []

        # Find all .yaml and .yml files
        yaml_files = sorted(list(path.glob("**/*.yaml")) + list(path.glob("**/*.yml")))

        for file_path in yaml_files:
            try:
                config = self.load_file(file_path)
                self.configs.append(config)
            except MappingConfigError as e:
                # Log or ignore non-mapping YAML files (or raise if strict)
                print(f"[ConfigLoader] Warning: Skipping non-mapping file {file_path}: {e}")

        return self.configs

    def get_by_source(self, vendor: str, product: Optional[str] = None) -> Optional[MappingConfig]:
        """Find a configuration matching the given vendor and optional product."""
        for cfg in self.configs:
            if cfg.vendor.lower() == vendor.lower():
                if product is None or cfg.product.lower() == product.lower():
                    return cfg
        return None

    def reload(self) -> List[MappingConfig]:
        """Reload all configurations from the configured directory."""
        if not self.mappings_dir:
            raise ValueError("No mappings directory configured for reload")
        return self.load_directory(self.mappings_dir)

    def __len__(self) -> int:
        return len(self.configs)

    def __iter__(self):
        return iter(self.configs)

# Comprehensive Technical Report: Auto-Mapping Assistant

> **Project**: Universal Log Pre-processing Framework (ULPF / Rosetta)  
> **Module**: Auto-Mapping Assistant (`src/assistant/`, `src/app/`, `src/main.py`)  
> **Role / Owner**: Auto-Mapping Assistant & AI Layer Lead  
> **Status**: 100% Completed & Verified (47/47 Tests Passing)

---

## 1. Executive Summary

Onboarding unknown perimeter network device logs traditionally requires a human analyst to manually inspect sample log lines, identify field delimiters and boundaries, map vendor-specific attributes to the standard taxonomy, and hand-author a declarative `mapping.yaml` file. While highly accurate, this process creates an onboarding bottleneck.

The **Auto-Mapping Assistant** eliminates this bottleneck by automatically:
1. Ingesting a small batch of sample log lines (5–20 lines) from an unknown source.
2. Inferring log format (JSON, key-value, delimited/CSV, space-delimited, syslog) and boundary delimiters.
3. Extracting semantic field roles (IPs, ports, protocols, action/decisions, timestamps, traffic metrics) via deterministic regex heuristics with an optional 1-shot local LLM (Ollama) fallback.
4. Generating a standard, fully populated draft `mapping.yaml` matching canonical ULPF schema rules with explicit `status: "draft"` and human review warning headers.
5. Validating the draft against the live normalization engine (`NormalizationPipeline`) to produce side-by-side normalized OCSF JSON documents.
6. Managing draft persistence, folder collision prevention, and the human approval lifecycle (`status: "draft"` → `status: "reviewed"`).

---

## 2. Architecture & Execution Pipeline Flow

```
Unknown Raw Log Samples (5-20 lines) + Source Name + (Optional Device Hint)
                        │
                        ▼
         [ 1. Format Detection Engine ]       ──> JSON / Key-Value / CSV / Space-Delimited / Syslog
                        │
                        ▼
       [ 2. Semantic Analysis & Roles ]       ──> Regex matchers (IP, Port, Protocol, Action, Time)
                        │
                        ▼
      [ 3. Local LLM Fallback (Optional) ]    ──> 1-shot structured Ollama prompt (Graceful offline fallback)
                        │
                        ▼
        [ 4. YAML Config Generator ]          ──> Standard ULPF YAML schema (status: "draft" + review banner)
                        │
                        ▼
       [ 5. Live Pipeline Validation ]        ──> NormalizationPipeline.process_line() validation & preview
                        │
                        ▼
     [ 6. REST API & Lifecycle Management ]   ──> POST /analyze, POST /save, GET /drafts, POST /approve
```

---

## 3. Core Architectural Guarantees & Constraints

1. **Zero Core Engine Mutation**: The core normalization engine (`src/engine/`) remains 100% untouched and completely unaware of the assistant.
2. **Schema Uniformity**: All generated configuration files strictly follow the canonical ULPF YAML schema (`source_identity`, `detection`, `parsing`, `classification`, `field_map`, `static_fields`, `transforms`, `timestamp`, `unmapped_policy`, `raw_preservation`). The engine cannot distinguish between a human-authored config and an approved assistant config.
3. **No Auto-Promotion**: All auto-generated configurations are saved with `source_identity.status: "draft"` and contain an explicit review warning header. A human review action (`approve_draft`) is required to promote the config to production.
4. **Air-Gapped & Offline Ready**: Operates on pure deterministic heuristics and regex pattern engines. The LLM integration is a single 1-shot enhancement that degrades gracefully to the lossless `unmapped` bucket if Ollama is unreachable.
5. **Lossless Preservation & Traceability**: Generated mappings retain complete `raw_data` and unique `metadata.uid` UUIDs.
6. **Collision Protection**: Automatically detects existing reviewed configurations under `mappings/<slug>/` and creates versioned suffixes (e.g. `slug_2`) to prevent accidental overwrites.

---

## 4. Implemented Modules & Directory Structure

```
logflash/
├── mappings/                           # Declarative vendor mapping configurations
│   ├── windows_firewall/
│   ├── CISCO_ASA/
│   ├── Palo_Alto/
│   └── Suricata_IDS/
├── src/
│   ├── __init__.py
│   ├── main.py                         # CLI entrypoint with --auto-map, --save-draft, --pretty
│   ├── app/
│   │   ├── __init__.py
│   │   └── main2.py                    # FastAPI application with Ingestion & Assistant endpoints
│   ├── assistant/                      # Auto-Mapping Assistant Package
│   │   ├── __init__.py                 # Package exports
│   │   ├── detector_heuristics.py      # Format & boundary detection heuristics
│   │   ├── semantic_analyzer.py        # Semantic role extractor & OCSF field mapper
│   │   ├── llm_fallback.py             # 1-shot Ollama fallback client
│   │   ├── generator.py                # Standard YAML configuration generator
│   │   ├── validator.py                # Pipeline validation engine & metrics calculator
│   │   └── service.py                  # AutoMappingAssistant orchestrator & storage manager
│   └── engine/                         # Core parsing & normalization engine (untouched)
│       ├── config_loader.py
│       ├── detector.py
│       ├── parsers.py
│       ├── classifier.py
│       ├── mapper.py
│       ├── transforms.py
│       ├── timestamp.py
│       └── pipeline.py
├── tests/
│   ├── test_auto_mapping_assistant.py  # 13 dedicated assistant unit & integration tests
│   ├── test_classifier.py
│   ├── test_config_loader.py
│   ├── test_detector.py
│   ├── test_mapper.py
│   ├── test_parsers.py
│   ├── test_pipeline.py
│   ├── test_timestamp.py
│   └── test_transforms.py
├── AUTO_MAPPING_ASSISTANT_SPEC.md      # Assistant feature specification
├── PROJECT_BRIEF.md                    # Universal Log Pre-processing Framework brief
├── ENGINE_REPORT.md                    # Core engine report
└── mapping_assistant.md                # This comprehensive assistant report
```

---

## 5. Detailed Component Breakdown

### A. Format & Pattern Detection (`src/assistant/detector_heuristics.py`)
Inspects raw sample lines to determine the log format without requiring manual format declarations:
- **JSON (`json`)**: Detects valid JSON objects, extracts key structures, and infers discriminator conditions (`event_type`, `type`, `action`).
- **Key-Value (`key_value`)**: Matches repeated `key=value` or `key:"value"` patterns via regex (`[a-zA-Z0-9_\.\-]+=(?:"[^"]*"|'[^']*'|\S+)`).
- **Delimited / CSV (`csv`, `delimited`)**: Evaluates candidate delimiters (comma `,`, pipe `|`, tab `\t`, semicolon `;`), verifies column count consistency, and detects presence of header rows.
- **Syslog (`syslog`)**: Recognizes RFC3164/5424 header structures (`<PRI>`, timestamp, host, program tag) and vendor tags (`%ASA-`).
- **Space-Delimited (`space_delimited`)**: Tokenizes on whitespace and constructs anchor regex patterns based on token types (e.g., date, action, protocol).

### B. Semantic Role Analyzer (`src/assistant/semantic_analyzer.py`)
Performs deterministic pattern recognition over extracted token values and keys:
- **IP Addresses**: Matches IPv4 and IPv6 patterns. Assigns first positional IP to `src_endpoint.ip` and second to `dst_endpoint.ip`, or resolves via naming cues (`src`, `dst`, `saddr`, `daddr`, `client`, `server`).
- **Ports (1–65535)**: Matches adjacent integer values or port-named keys (`sport`, `dport`, `srcport`, `dstport`) to `src_endpoint.port` and `dst_endpoint.port`, configuring an `integer` value transform.
- **Protocols**: Identifies keywords (`TCP`, `UDP`, `ICMP`, `ESP`, `GRE`, etc.) and IANA numbers, configuring `passthrough_upper` or `protocol_num_to_name` transforms targeting `connection_info.protocol_name`.
- **Actions & Classification**: Maps `ALLOW`/`ACCEPT`/`PERMIT` to `activity_name: "Allow"` (`activity_id: 1`) and `DROP`/`DENY`/`BLOCK`/`REJECT` to `activity_name: "Deny"` (`activity_id: 6`), formulating classification rules and assigning OCSF `class_uid: 4001` (Network Activity) or `class_uid: 2001` (Detection Finding).
- **Timestamps**: Identifies ISO-8601 strings, composite split date/time fields (`raw_date+raw_time`), or syslog dates, generating format strings and timezone specifications.
- **Confidence Scoring**: Computes a numeric confidence score (0.1–1.0) and categorical rating (`high`, `medium`, `low`) based on key OCSF attributes successfully identified.

### C. 1-Shot LLM Fallback (`src/assistant/llm_fallback.py`)
- Provides a fast, isolated connection to local Ollama (`phi4-mini` / `llama3`).
- Invoked only when heuristics leave fields ambiguous.
- Issues a single structured prompt requesting JSON-formatted field mappings.
- Employs a strict timeout (2.0s) and fails silently to prevent pipeline latency or crashes if Ollama is not running.

### D. YAML Config Generator (`src/assistant/generator.py`)
Generates standard ULPF YAML configurations:
- Prepends mandatory review checklist banner:
  ```yaml
  # ⚠️ AUTO-GENERATED DRAFT — not yet reviewed by a human
  # Generated by: Auto-Mapping Assistant
  # Confidence: <low|medium|high> — see notes below
  # Review checklist:
  #   - Verify field_map targets are semantically correct, not just structurally plausible
  #   - Verify classification rules match real device behavior, not just this sample
  #   - Verify timestamp format/timezone
  #   - Once reviewed, remove this header and move status to "reviewed" in source_identity
  ```
- Formats all 10 canonical sections: `source_identity` (with `status: "draft"`), `detection`, `parsing`, `classification`, `field_map`, `static_fields`, `transforms`, `timestamp`, `unmapped_policy`, `raw_preservation`.

### E. Pipeline Validation Engine (`src/assistant/validator.py`)
- Loads the generated draft YAML into a temporary `MappingConfig`.
- Executes the live `NormalizationPipeline` across all sample log lines.
- Verifies that:
  - Events normalize successfully without unhandled exceptions.
  - Core OCSF attributes (`src_endpoint`, `dst_endpoint`, `connection_info`, `activity_name`, `time`, `raw_data`, `metadata.uid`) are populated.
  - Unmapped fields are losslessly captured in the `unmapped` bucket.
- Calculates mapped vs. unmapped ratios and extracts lineage summaries for preview.

### F. Service & Persistence Manager (`src/assistant/service.py`)
- **`analyze()`**: High-level workflow executing detection, analysis, optional LLM fallback, YAML generation, and pipeline validation.
- **`save_draft()`**: Writes `mappings/<slug>/mapping.yaml` and `mappings/<slug>/samples/synthetic_sample.log`. Implements collision checks to prevent overwriting approved configurations.
- **`list_drafts()`**: Scans `/mappings` for files with `source_identity.status: "draft"`.
- **`approve_draft()`**: Promotes a draft by changing status to `"reviewed"` and replacing the draft warning banner with an approved production header.

---

## 6. Integration Guide & API Reference

### 1. REST API Endpoints (`src/app/main2.py`)

#### `POST /api/v1/assistant/analyze`
Analyze unknown raw log lines and receive a draft YAML and OCSF preview.

**Request**:
```json
{
  "source_name": "SonicWall Firewall",
  "raw_lines": [
    "date=2026-08-27 time=09:14:02 devname=\"fw01\" action=\"deny\" proto=TCP srcip=203.0.113.45 dstip=10.0.4.12 sport=51322 dport=22",
    "date=2026-08-27 time=09:14:05 devname=\"fw01\" action=\"allow\" proto=TCP srcip=192.168.1.10 dstip=10.0.4.12 sport=43211 dport=443"
  ],
  "device_type": "firewall",
  "use_llm": false
}
```

**Response**:
```json
{
  "status": "success",
  "data": {
    "source_name": "SonicWall Firewall",
    "slug": "sonicwall_firewall",
    "detected_format": "key_value",
    "confidence_score": 0.95,
    "confidence_label": "high",
    "yaml_draft": "# ⚠️ AUTO-GENERATED DRAFT ...\nsource_identity:\n  vendor: SonicWall Firewall\n  ...",
    "validation": {
      "valid": true,
      "total_lines": 2,
      "successful_events": 2,
      "mapping_rate": 0.82,
      "field_lineage": {
        "src_endpoint.ip": "203.0.113.45",
        "dst_endpoint.ip": "10.0.4.12",
        "src_endpoint.port": 51322,
        "dst_endpoint.port": 22,
        "connection_info.protocol_name": "TCP",
        "activity_name": "Deny"
      }
    },
    "ocsf_preview": [
      {
        "class_name": "Network Activity",
        "class_uid": 4001,
        "activity_name": "Deny",
        "activity_id": 6,
        "time": "2026-08-27T09:14:02Z",
        "src_endpoint": { "ip": "203.0.113.45", "port": 51322 },
        "dst_endpoint": { "ip": "10.0.4.12", "port": 22 },
        "connection_info": { "protocol_name": "TCP" },
        "metadata": { "uid": "f9464e83-7c19-4a40-9a29-b69004cb6801" },
        "raw_data": "date=2026-08-27 time=09:14:02 devname=\"fw01\" action=\"deny\" proto=TCP srcip=203.0.113.45 dstip=10.0.4.12 sport=51322 dport=22"
      }
    ]
  }
}
```

#### `POST /api/v1/assistant/save`
Save draft YAML and verbatim samples under `mappings/<slug>/`.

**Request**:
```json
{
  "source_name": "SonicWall Firewall",
  "yaml_content": "<YAML_STRING>",
  "raw_lines": ["<RAW_SAMPLE_1>", "<RAW_SAMPLE_2>"]
}
```

#### `GET /api/v1/assistant/drafts`
List all draft mapping configurations pending human review.

#### `POST /api/v1/assistant/approve/{slug}`
Approve an existing draft, flip `status: "reviewed"`, update headers, and hot-reload engine mappings.

---

### 2. CLI Usage (`src/main.py`)

Run the assistant directly from the command line:

```bash
# Analyze a sample file and print draft YAML + OCSF preview:
python -m src.main mappings/windows_firewall/samples/windows_firewall_sample.log --auto-map "Windows Firewall Replica" --pretty

# Analyze and automatically save to mappings/my_new_device/:
python -m src.main sample_logs.txt --auto-map "My New Device" --save-draft --device-type firewall
```

---

### 3. Programmatic Python API

```python
from src.assistant.service import AutoMappingAssistant

assistant = AutoMappingAssistant()

# 1. Analyze sample lines
analysis = assistant.analyze(
    source_name="Custom Edge Gateway",
    raw_lines=["2026-08-27 09:02:11 DROP TCP 45.33.32.156 10.0.0.14 51322 3389"],
    device_type_hint="firewall",
)

# 2. Save draft to disk
save_result = assistant.save_draft(
    source_name="Custom Edge Gateway",
    yaml_content=analysis["yaml_draft"],
    raw_lines=["2026-08-27 09:02:11 DROP TCP 45.33.32.156 10.0.0.14 51322 3389"],
)

# 3. Approve draft after review
assistant.approve_draft(save_result["slug"])
```

---

## 7. Test Suite & Verification Results

### Automated Pytest Suite
Execute all unit and integration tests across the repository:
```bash
python -m pytest tests/ -v
```

**Results (47/47 Tests Passed)**:
```text
tests/test_auto_mapping_assistant.py::test_detect_space_delimited PASSED          [  2%]
tests/test_auto_mapping_assistant.py::test_detect_key_value PASSED                [  4%]
tests/test_auto_mapping_assistant.py::test_detect_json PASSED                     [  6%]
tests/test_auto_mapping_assistant.py::test_detect_csv_with_headers PASSED          [  8%]
tests/test_auto_mapping_assistant.py::test_semantic_analysis_space_delimited PASSED [ 10%]
tests/test_auto_mapping_assistant.py::test_semantic_analysis_key_value PASSED       [ 12%]
tests/test_auto_mapping_assistant.py::test_yaml_generation_structure PASSED        [ 14%]
tests/test_auto_mapping_assistant.py::test_draft_validator_space_delimited_end_to_end PASSED [ 17%]
tests/test_auto_mapping_assistant.py::test_draft_validator_key_value_end_to_end PASSED [ 19%]
tests/test_auto_mapping_assistant.py::test_save_draft_and_approval_flow PASSED     [ 21%]
tests/test_auto_mapping_assistant.py::test_save_draft_collision_protection PASSED  [ 23%]
tests/test_auto_mapping_assistant.py::test_llm_fallback_offline_graceful PASSED    [ 25%]
tests/test_auto_mapping_assistant.py::test_api_endpoints PASSED                   [ 27%]
tests/test_classifier.py::test_classify_windows_firewall_drop PASSED              [ 29%]
tests/test_classifier.py::test_classify_windows_firewall_allow PASSED             [ 31%]
tests/test_classifier.py::test_classify_cisco_asa_connection PASSED               [ 34%]
tests/test_classifier.py::test_classify_cisco_asa_access_denied PASSED            [ 36%]
tests/test_classifier.py::test_classify_suricata_alert PASSED                     [ 38%]
tests/test_config_loader.py::test_load_all_configs PASSED                         [ 40%]
tests/test_config_loader.py::test_windows_firewall_config PASSED                  [ 42%]
tests/test_config_loader.py::test_cisco_asa_config PASSED                         [ 44%]
tests/test_config_loader.py::test_palo_alto_config PASSED                         [ 46%]
tests/test_config_loader.py::test_suricata_config PASSED                          [ 48%]
tests/test_config_loader.py::test_invalid_config_validation PASSED                [ 51%]
tests/test_detector.py::test_detect_windows_firewall PASSED                       [ 53%]
tests/test_detector.py::test_detect_cisco_asa PASSED                              [ 55%]
tests/test_detector.py::test_detect_suricata_eve_json PASSED                      [ 57%]
tests/test_detector.py::test_detect_palo_alto_csv_header PASSED                   [ 59%]
tests/test_mapper.py::test_set_and_get_nested_value PASSED                        [ 61%]
tests/test_mapper.py::test_mapper_windows_firewall PASSED                         [ 63%]
tests/test_parsers.py::test_windows_firewall_delimited_parser PASSED              [ 65%]
tests/test_parsers.py::test_cisco_asa_syslog_parser PASSED                        [ 68%]
tests/test_parsers.py::test_suricata_json_parser PASSED                           [ 70%]
tests/test_parsers.py::test_palo_alto_csv_parser PASSED                           [ 72%]
tests/test_parsers.py::test_key_value_parser PASSED                               [ 74%]
tests/test_pipeline.py::test_windows_firewall_end_to_end PASSED                   [ 76%]
tests/test_pipeline.py::test_cisco_asa_end_to_end PASSED                          [ 78%]
tests/test_pipeline.py::test_palo_alto_end_to_end PASSED                          [ 80%]
tests/test_pipeline.py::test_suricata_end_to_end PASSED                           [ 82%]
tests/test_timestamp.py::test_timestamp_windows_firewall_composite PASSED          [ 85%]
tests/test_timestamp.py::test_timestamp_palo_alto PASSED                          [ 87%]
tests/test_timestamp.py::test_timestamp_cisco_asa PASSED                          [ 89%]
tests/test_timestamp.py::test_timestamp_suricata_iso PASSED                       [ 91%]
tests/test_transforms.py::test_windows_firewall_transforms PASSED                 [ 93%]
tests/test_transforms.py::test_palo_alto_integer_transforms PASSED                [ 95%]
tests/test_transforms.py::test_cisco_asa_duration_transform PASSED                [ 97%]
tests/test_transforms.py::test_protocol_num_and_severity PASSED                   [100%]

======================== 47 passed, 1 warning in 8.01s ========================
```

---

## 8. Summary of Completed Deliverables

| Deliverable | Location | Description |
|---|---|---|
| **Assistant Package** | [`src/assistant/`](file:///c:/Users/Kruthik/Desktop/coding/logflash/src/assistant/) | Modular format detection, semantic analyzer, 1-shot LLM fallback, YAML generator, validator, and service manager. |
| **Backend API** | [`src/app/main2.py`](file:///c:/Users/Kruthik/Desktop/coding/logflash/src/app/main2.py) | Ingest endpoints + full REST API for assistant analysis, draft saving, listing, and approval. |
| **CLI Tool** | [`src/main.py`](file:///c:/Users/Kruthik/Desktop/coding/logflash/src/main.py) | CLI utility supporting `--auto-map`, `--device-type`, `--save-draft`, and `--pretty`. |
| **Unit Test Suite** | [`tests/test_auto_mapping_assistant.py`](file:///c:/Users/Kruthik/Desktop/coding/logflash/tests/test_auto_mapping_assistant.py) | 13 test cases verifying heuristics, YAML validity, pipeline execution, and REST endpoints. |
| **Technical Report** | [`mapping_assistant.md`](file:///c:/Users/Kruthik/Desktop/coding/logflash/mapping_assistant.md) | Architectural documentation and integration guide. |

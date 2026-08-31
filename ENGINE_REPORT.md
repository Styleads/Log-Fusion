# Comprehensive Technical Report: Core Log Pre-processing Engine (Person A)

> **Project**: Universal Log Pre-processing Framework (ULPF / Rosetta)  
> **Module**: Core Pipeline Engine (`src/engine/`)  
> **Author**: Person A (Parsing Engine & Core Pipeline Lead)  
> **Status**: 100% Completed & Verified (34/34 Tests Passing)

---

## 1. Executive Summary

This report documents the design, implementation, and integration protocols for the core log pre-processing and normalization engine. The engine ingests perimeter network device logs in arbitrary formats (CSV, space-delimited, key-value syslog, JSON, regex), automatically detects vendor/product formats using declarative YAML configurations, extracts and transforms fields into the **Open Cybersecurity Schema Framework (OCSF)** nested JSON format, and guarantees lossless raw data preservation with UUID event traceability.

---

## 2. Architecture & Pipeline Execution Flow

The engine implements a zero-code-change architecture: adding support for a new log source requires only adding a new YAML file to `/mappings` without altering any Python code.

```
Raw Log Line
     │
     ▼
[ 1. LogDetector ]       ──> Automatically matches vendor config (Regex / JSON / CSV Header)
     │
     ▼
[ 2. Parser Execution ]  ──> DelimitedParser / JSONParser / KeyValueParser / SyslogParser
     │
     ▼
[ 3. ValueTransformer ]  ──> Categorical lookups, Protocol num->name, type casting, duration
     │
     ▼
[ 4. TimestampParser ]   ──> Composite date/time parsing into standardized ISO-8601 UTC
     │
     ▼
[ 5. OCSFClassifier ]    ──> Evaluates 'when' rules to set OCSF class_uid & activity_id
     │
     ▼
[ 6. NestedMapper ]      ──> Constructs dotted-path nested JSON ("src_endpoint.ip") + static fields
     │
     ▼
[ 7. Raw Preservation ]  ──> Attaches UUIDv4 (metadata.uid) + untouched raw_data + unmapped bucket
     │
     ▼
Normalized OCSF Event (JSON Document)
```

---

## 3. Implemented Modules & Directory Structure

```
logflash/
├── mappings/                           # Declarative vendor mapping configs (Person B)
│   ├── windows_firewall/
│   ├── CISCO_ASA/
│   ├── Palo_Alto/
│   └── Suricata_IDS/
├── src/
│   ├── __init__.py
│   ├── main.py                         # CLI entrypoint for file / stdin processing
│   └── engine/
│       ├── __init__.py
│       ├── config_loader.py            # YAML mapping loader & validator
│       ├── detector.py                 # Format and vendor detector
│       ├── parsers.py                  # Delimited, JSON, KeyValue, Syslog, Regex parsers
│       ├── classifier.py               # OCSF class & activity classifier
│       ├── mapper.py                   # Dotted-path nested JSON dictionary mapper
│       ├── transforms.py               # Value transformations & type casting
│       ├── timestamp.py                # ISO-8601 UTC timestamp parser
│       └── pipeline.py                 # End-to-end normalization pipeline orchestrator
├── tests/                              # Automated test suite (34 tests passing)
│   ├── test_config_loader.py
│   ├── test_detector.py
│   ├── test_parsers.py
│   ├── test_classifier.py
│   ├── test_mapper.py
│   ├── test_transforms.py
│   ├── test_timestamp.py
│   └── test_pipeline.py
├── ACTION_PLAN.md                      # Action plan breakdown
├── ENGINE_REPORT.md                    # This comprehensive report
└── requirements.txt                    # Project dependencies (pyyaml, pytest)
```

---

## 4. How the Engine Works (Step-by-Step)

### Step 1: Config Loading (`src/engine/config_loader.py`)
Scans `/mappings` recursively for `*.yaml` files, loads them into `MappingConfig` models, and normalizes schema sections.

### Step 2: Detection (`src/engine/detector.py`)
Given a raw log line, `LogDetector` evaluates rules:
- `regex`: Regex pattern matching (e.g. `%ASA-\d+-\d{6}:` or `^\d{4}-\d{2}-\d{2}`).
- `json_match`: Verifies JSON format and evaluates path/equals conditions (`event_type == "alert"`).
- `csv_header_and_field`: Evaluates CSV column headers (`Type == "TRAFFIC"`).

### Step 3: Parsing (`src/engine/parsers.py`)
Extracts raw fields into a flat dictionary using the appropriate format parser:
- `DelimitedParser`: Handles index-based or column-name-based CSV/space-delimited lines, ignoring comment prefixes like `#`.
- `JSONParser`: Extracts nested JSON keys via dot notation (`alert.signature_id` → `raw_signature_id`).
- `SyslogParser`: Parses syslog headers (timestamp, severity, message ID) and body message families (Cisco ASA connection, access-control, NAT).
- `KeyValueParser`: Extracts `key=value` or `key:"value"` pairs.

### Step 4: Value Transformations (`src/engine/transforms.py`)
Converts raw string values:
- `lookup`: `"RECEIVE"` → `"Inbound"`, `"SEND"` → `"Outbound"`
- `protocol_num_to_name`: `6` → `"TCP"`, `17` → `"UDP"`, `1` → `"ICMP"`
- `type_cast`: `"51322"` → `51322` (integer), hex `"0x400000"` → `4194304`
- `duration`: `"0:00:44"` → `44` seconds
- `severity_lookup`: Maps scores/levels to OCSF severity strings (`Informational`, `Low`, `Medium`, `High`, `Critical`, `Fatal`).

### Step 5: Timestamp Normalization (`src/engine/timestamp.py`)
Combines single or multi-column date/time fields (`raw_date+raw_time`) and normalizes local timezones into standard ISO-8601 UTC strings (`2026-08-27T09:02:11Z`).

### Step 6: OCSF Classification (`src/engine/classifier.py`)
Evaluates classification rules (`when: { raw_action: "DROP" }`) to set:
- `class_name`: `"Network Activity"` / `"Network Detection"` / `"Authentication"`
- `class_uid`: `4001` / `2001` / `3002`
- `activity_name`: `"Deny"`, `"Allow"`, `"Open"`, `"Close"`, `"Refuse"`
- `activity_id`: `1`, `6`, etc.

### Step 7: Dotted-Path Mapping & Lossless Preservation (`src/engine/mapper.py` & `src/engine/pipeline.py`)
- Maps flat raw attributes to nested OCSF JSON paths (`src_endpoint.ip`, `dst_endpoint.port`, `connection_info.protocol_name`).
- Injects static fields (`device.vendor_name`, `metadata.product.name`).
- Generates unique UUIDv4 (`metadata.uid`) and attaches full untouched original log line (`raw_data`).
- Preserves all unmapped fields in `unmapped` sub-object without data loss.

---

## 5. Integration Guide for Teammates

### For Person B (OCSF Mapping Configs Lead)
- **How to onboard a new vendor log type**: Simply add a new `mapping.yaml` under `/mappings/new_vendor/`.
- **No Python code changes needed**. Ensure your YAML defines: `source_identity`, `detection`, `parsing`, `classification`, `field_map`, `static_fields`, `transforms`, `timestamp`, `unmapped_policy`, `raw_preservation`.

### For Person A / Backend API Developer (FastAPI Ingestion Endpoints)
Import and use `NormalizationPipeline` directly in your FastAPI routes:

```python
from src.engine.pipeline import NormalizationPipeline

# Initialize pipeline (loads all mappings automatically)
pipeline = NormalizationPipeline()

# Ingest single log line (REST / WebSocket endpoint):
@app.post("/api/v1/ingest/line")
def ingest_line(raw_line: str):
    ocsf_event = pipeline.process_line(raw_line)
    if ocsf_event:
        # Pass to storage layer / elasticsearch
        store_event(ocsf_event)
        return {"status": "success", "uid": ocsf_event["metadata"]["uid"]}
    return {"status": "skipped_or_unrecognized"}

# Bulk log file upload endpoint:
@app.post("/api/v1/ingest/file")
def ingest_file(file_path: str):
    ocsf_events = pipeline.process_file(file_path)
    return {"status": "success", "processed_count": len(ocsf_events)}
```

### For Person C (Storage & Data Layer Lead)
- You can consume normalized events as Python dictionaries or NDJSON streams.
- Every normalized event is a valid nested JSON document natively supported by **Elasticsearch**, **OpenSearch**, or **MongoDB**.
- Primary indices/fields for indexing:
  - `metadata.uid` (Primary Key / Document ID)
  - `time` (Timestamp index for time-series aggregation)
  - `class_uid` & `class_name` (OCSF Taxonomy filtering)
  - `src_endpoint.ip` & `dst_endpoint.ip` (Network search)
  - `raw_data` (Full text search / Forensic traceability)

### For Person D (Frontend Dashboard Lead)
The normalized JSON event shape is predictable across all vendors:
- **Stat Cards**: Count events by `class_name`, `activity_name`, or `device.vendor_name`.
- **Event Feed Table**: Display `time`, `device.vendor_name`, `class_name`, `src_endpoint.ip:port`, `dst_endpoint.ip:port`, `activity_name`.
- **Drill-down Modal**: Compare `raw_data` side-by-side with the normalized OCSF JSON.

### For Person E (AI Layer - RAG Chatbot Lead)
- The pipeline attaches `raw_data` and `metadata.uid` to every OCSF event.
- Your LangChain / LangGraph retrieval logic can query the store by `src_endpoint.ip`, `dst_endpoint.ip`, `time`, or `class_name`, and retrieve both structured metrics and the exact untouched `raw_data` for LLM grounding.

### For Person F (Anomaly Detection Lead)
- You can load normalized NDJSON events into pandas DataFrames or process them line-by-line:
```python
import pandas as pd
from src.engine.pipeline import NormalizationPipeline

pipeline = NormalizationPipeline()
events = pipeline.process_file("sample.log")
df = pd.json_normalize(events)

# Groupby source IP and count denied connections:
denied_bursts = df[df['activity_name'] == 'Deny'].groupby('src_endpoint.ip').size()
```

---

## 6. How to Run & Verify

### Running Unit Tests
```bash
python -m pytest tests/
```
Output:
```
34 passed in 1.57s
```

### Running the CLI on Any Raw Log File
```bash
# Pretty-print normalized OCSF JSON to terminal:
python -m src.main mappings/windows_firewall/samples/windows_firewall_sample.log --pretty

# Save normalized output to an NDJSON file:
python -m src.main mappings/palo_alto_panos/samples/PaloAlto_sample.csv -o output.ndjson
```

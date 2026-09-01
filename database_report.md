# Database / Storage & Data Layer Report

## 1. Overview

This component implements the basic **Storage and Data Layer** for the Universal Log Pre-processing Framework (ULPF) / Log-Fusion project.

The current implementation is intentionally standalone. Its purpose is to provide a reliable place to store normalized security events while preserving the original raw event and provenance information. Integration with parsing, normalization, SIEM, analytics, and other components can be performed later.

The storage layer uses:

- **OpenSearch** as the event storage and search engine.
- **FastAPI** as a lightweight REST API between the processing pipeline and OpenSearch.
- **Docker / Docker Compose** for containerized local deployment.

---

## 2. Objectives

The storage layer was designed to support these requirements from the problem statement:

- Preserve raw event information.
- Store normalized/standardized event fields.
- Maintain a unique identifier for each event.
- Maintain traceability and provenance information.
- Support searching and retrieving events.
- Support basic aggregation/statistics.
- Provide a simple interface for future integration with upstream parsers/normalizers.
- Be containerized and suitable for deployment in an isolated/air-gapped environment after required images and dependencies are made available locally.

---

## 3. Architecture

```text
Normalized Event
      |
      v
+-------------------+
|    FastAPI API    |
+-------------------+
      |
      v
+-------------------+
|     OpenSearch    |
|    ulpf-events    |
+-------------------+
      |
      +---- Search
      |
      +---- Retrieve
      |
      +---- Statistics
```

The Docker Compose setup contains two services:

1. **ulpf-opensearch** — OpenSearch 2.19.1.
2. **ulpf-storage-api** — FastAPI application that receives and queries events.

---

## 4. Technologies Used

### OpenSearch

OpenSearch is used as the primary event datastore/search engine. It supports JSON documents, structured filtering, full-text search, IP/date fields, and aggregations.

The primary index is:

```text
ulpf-events
```

### FastAPI

FastAPI provides the REST interface so future ULPF components can send and query events without directly depending on OpenSearch APIs.

### Docker

Docker Compose packages the API and OpenSearch as separate services and makes local deployment reproducible.

---

## 5. Event Storage Model

Each stored event contains:

```text
event_id
normalized_event
raw_event
provenance
ingested_at
```

### `event_id`

A unique identifier used to identify and retrieve an event.

Example:

```json
"event_id": "demo-001"
```

### `normalized_event`

Contains the standardized representation of the event. The current example includes fields such as:

- `class_uid`
- `category_uid`
- `activity_id`
- `severity_id`
- `time`
- `message`
- `src_endpoint`
- `dst_endpoint`
- `device`

The structure is extensible so additional normalized fields can be added as the team's actual event schema evolves.

### `raw_event`

Contains the original source event information. Keeping this alongside the normalized representation supports forensic investigation and traceability.

### `provenance`

Stores information about the source and processing path, such as source, parser, and normalizer version.

### `ingested_at`

Added by the storage API to record when the event entered the storage layer.

---

## 6. API Endpoints

### `GET /health`

Checks whether the storage API can reach OpenSearch.

### `POST /events`

Stores a single event.

### `POST /events/bulk`

Provides bulk ingestion for multiple events, reducing API overhead for future high-volume ingestion.

### `GET /events/{event_id}`

Retrieves a specific event using its event ID.

Example:

```text
GET /events/demo-001
```

### `GET /events/search`

Provides event search/filtering by fields including:

- Keyword
- Severity
- Activity
- Event class
- Source IP
- Destination IP
- Vendor

### `GET /events/stats`

Provides basic aggregations including:

- Total event count
- Severity counts
- Activity counts
- Vendor counts

---

## 7. OpenSearch Mapping

The index uses explicit mappings for important fields while allowing additional fields dynamically.

Important field types include:

- `keyword` for event IDs.
- `date` for timestamps.
- `integer` for classification/severity/activity identifiers.
- `text` for searchable messages.
- `ip` for source and destination IP addresses.
- `object` for nested event structures.

Dynamic fields allow the storage layer to accommodate additional event attributes.

---

## 8. Lossless Storage and Traceability

A key ULPF requirement is avoiding information loss during preprocessing.

The storage design therefore keeps:

```text
Original Raw Event
        +
Normalized Event
        +
Provenance
        +
Event ID
```

within the stored document.

This allows analytics to use normalized fields while preserving the original information for investigation, auditing, and future reprocessing.

---

## 9. Testing Performed

The component was run locally using Docker Desktop with WSL 2.

The following containers were confirmed running:

```text
ulpf-opensearch
ulpf-storage-api
```

OpenSearch was verified through:

```text
http://localhost:9200
```

and returned OpenSearch version:

```text
2.19.1
```

The FastAPI Swagger documentation was verified through:

```text
http://localhost:8000/docs
```

A sample firewall event with:

```text
event_id = demo-001
```

was submitted through `POST /events`.

The event was successfully retrieved using:

```text
GET /events/demo-001
```

The response confirmed retention of:

- Event ID.
- Normalized event.
- Raw event.
- Provenance.
- Ingestion timestamp.

This demonstrates that the basic write-and-retrieve flow between FastAPI and OpenSearch is functioning.

---

## 10. Repository Structure

```text
database/
├── app/
│   ├── __init__.py
│   └── main.py
├── Dockerfile
├── README.md
├── docker-compose.yml
├── index_mapping.json
├── requirements.txt
└── sample_event.json
```

| File | Purpose |
|---|---|
| `app/main.py` | FastAPI application and OpenSearch interaction |
| `app/__init__.py` | Python package initialization |
| `docker-compose.yml` | Defines OpenSearch and storage API services |
| `Dockerfile` | Builds the FastAPI storage container |
| `requirements.txt` | Python dependencies |
| `index_mapping.json` | OpenSearch index settings and mappings |
| `sample_event.json` | Example event for testing |
| `README.md` | Setup and usage documentation |

---

## 11. Current Scope and Limitations

This implementation is a **basic storage/data-layer component**, not the complete ULPF prototype.

Intentionally outside the current scope:

- Source-specific log parsing.
- Vendor-specific normalization.
- Kafka or other message brokers.
- RAG/LLM functionality.
- Embedding/vector search.
- Anomaly detection.
- SIEM frontend/dashboard.
- Production authentication/authorization.
- Production TLS configuration.
- Multi-node OpenSearch clustering.
- Production backup/disaster recovery.
- Enterprise-scale capacity tuning.

These can be integrated later by the relevant project components.

---

## 12. Future Integration

The intended future flow is:

```text
Network / Security Device
          |
          v
   Log Ingestion Layer
          |
          v
 Parser / Normalizer
          |
          v
 Standardized Event
          |
          v
   Storage API
          |
          v
      OpenSearch
          |
     +----+----+
     |         |
     v         v
   SIEM      Analytics
               |
               v
          AI / ML / RAG
```

The current API provides a boundary between event processing and storage, allowing the rest of the system to be connected later.

---

## 13. Conclusion

The implemented storage/data layer provides a simple, containerized OpenSearch-based foundation for ULPF.

It demonstrates:

- Event ingestion.
- Persistent event storage.
- Raw event preservation.
- Normalized event storage.
- Provenance tracking.
- Event retrieval.
- Search/filtering capability.
- Basic aggregation.
- Docker-based deployment.

The component is modular so that the team's parser and normalization components can later send their standardized output directly to the storage API.

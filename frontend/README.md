# Universal Log Pre-processing Framework (ULPF) — Frontend Dashboard

> **Frontend Dashboard**
> OCSF-native normalization pipeline & unified SOC dashboard for perimeter network device logs.

---

## 🌟 Solution Overview

Enterprises collect logs from a vast array of perimeter network devices — firewalls, IDS/IPS sensors, VPN gateways, routers, and proxies/WAFs — each emitting logs in disparate, vendor-specific formats (Syslog, CSV, Key=Value, JSON, XML).

**ULPF (Universal Log Pre-processing Framework)** solves this by standardizing perimeter device logs into the **Open Cybersecurity Schema Framework (OCSF v1.1.0)** while:
1. **Preserving 100% of raw log data** without information loss.
2. **Maintaining cryptographic traceability** via shared UUIDs between raw events and normalized OCSF documents.
3. **Bucketing unmapped vendor attributes** into an `unmapped` dictionary rather than dropping them.
4. **Providing a visually uniform SOC feed** where cards and tables share an identical layout across all vendors (Palo Alto Networks, Suricata IDS, Fortinet FortiOS, Cisco ASA, CheckPoint, Zeek).
5. **Enabling natural-language threat hunting** via a grounded AI/RAG Security Assistant panel.

---

## 🚀 Key Modules Built (Person D Ownership)

### 1. 📊 Unified SOC Dashboard & Event Feed
- **Summary Stat Cards**: Total Events Ingested, Active Perimeter Sources, Deny/Allow Counts & Ratios, Active Detection Findings, Lossless Preservation Rate.
- **Uniform Cross-Vendor Layout**: Every event presents an identical card anatomy regardless of source vendor (Class Badge, Action/Severity, Timestamp, Rule/Signature Name, Source IP:Port $\to$ Destination IP:Port, Protocol, Device & Vendor tag).
- **Multi-Dimensional Filters**: Filter by OCSF Class (`Network Activity 4001`, `Detection Finding 2004`), Vendor, Action (`Deny`, `Allow`, `Create`), Severity (`Critical`, `High`, `Medium`, `Low`), and Free-Text / IP / Port / UUID search.
- **View Toggle**: Switch seamlessly between Card Grid View and Compact Table View.
- **Export to SIEM**: One-click export of normalized views to NDJSON format for Elasticsearch, OpenSearch, or Kafka.

### 2. 🔍 Lossless Forensic Drill-Down & Lineage Modal
- **Side-by-Side Comparison**: Untouched Raw Log string displayed directly alongside the complete Branched OCSF JSON document.
- **Shared Event UUID**: Cryptographic verification badge ensuring 1-to-1 linkage between raw and normalized records.
- **Interactive Field Lineage Table**: Line-by-line traceability showing *Raw Source Field $\to$ Extracted Value $\to$ Target OCSF Path $\to$ Transformation rule*.
- **Unmapped Attributes Inspector**: Visual breakdown of preserved vendor-specific parameters stored in `unmapped`.

### 3. 📈 Visual Telemetry & Analytics (Recharts)
- **Perimeter Velocity Timeline**: Multi-series area chart tracking Allow vs. Deny vs. Detection Findings over time.
- **Top Blocked / Attacking IPs**: Horizontal bar chart highlighting repeat offenders.
- **Protocol Distribution**: Donut chart breaking down TCP, UDP, and ICMP traffic.
- **Vendor Normalization Share**: Distribution pie chart showing multi-vendor ingestion balance.

### 4. ⚡ Interactive Ingestion & Normalization Lab
- **Preset Vendor Samples**: Palo Alto PAN-OS CSV, Suricata EVE JSON, Fortinet FortiOS Key=Value, and Cisco ASA Syslog.
- **Live Normalization Pipeline**: Animates the 6-stage pipeline (*Ingest $\to$ Detect $\to$ Parse $\to$ Classify $\to$ Map $\to$ Preserve*) in real-time.
- **Direct Feed Injection**: Add newly normalized events directly to the live feed and inspect immediate forensic lineage.

### 5. 🤖 Grounded AI Security RAG Assistant
- **Natural Language Threat Hunting**: Grounded queries evaluated over the active normalized OCSF dataset.
- **Pre-built Queries**:
  - *"Any repeated SSH scans from 185.220.101.4?"*
  - *"Show all Deny events across firewalls"*
  - *"What are the active detection findings?"*
  - *"Compare Palo Alto vs Suricata vs Fortinet volumes"*
- **Clickable Citations**: Assistant replies include direct links to event UUIDs that open the full forensic drill-down modal.
- **Dual-Mode Backend**: Communicates with Person E's `/api/chat` endpoint with automatic fallback to an in-browser grounded RAG engine.

### 6. 📑 OCSF Architecture & YAML Mapping Config Explorer
- Interactive viewer for declarative YAML mapping configs (`paloalto-panos.yaml`, `suricata-eve.yaml`, `fortinet-fortios.yaml`, `cisco-asa.yaml`).
- ULPF deliverable satisfaction matrix.

---

## 🛠️ Quickstart & Local Setup

### Prerequisites
- Node.js (v18+)
- npm (v9+)

### Installation & Run

```bash
# Navigate to project directory
cd C:\Users\rajes\.gemini\antigravity\scratch\ulpf-frontend

# Install dependencies
npm install

# Start Vite Development Server
npm run dev
```

The application will be accessible at `http://localhost:3000`.

### Production Build

```bash
npm run build
npm run preview
```

---

## 🔌 Backend Integration (Person A/B/E)

The frontend includes a top-bar **Engine Toggle** that allows switching between:
1. **Standalone High-Fidelity Mock Mode**: Runs client-side normalization and grounded RAG without requiring a backend.
2. **Live Backend Mode (`http://localhost:8000`)**: Connects to FastAPI endpoints:
   - `GET /api/health` — Service health & backend status
   - `GET /api/events` — Retrieve normalized OCSF events
   - `POST /api/ingest` — Ingest raw log line through backend parser
   - `POST /api/chat` — Submit natural language queries to Person E's AI/RAG model

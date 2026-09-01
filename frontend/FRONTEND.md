# Log Fusion Frontend

The Log Fusion frontend is a React dashboard for normalizing and investigating perimeter-device logs using the Open Cybersecurity Schema Framework (OCSF).

## Technology

- React 18 and TypeScript
- Vite
- Tailwind CSS
- Recharts for telemetry visualizations
- Lucide React for icons

## Run locally

Install Node.js 18 or later, then run:

```bash
npm install
npm run dev
```

Vite prints the local application address in the terminal. To create a production build:

```bash
npm run build
npm run preview
```

## Project layout

```text
src/
  components/        Reusable UI, dashboard, ingestion, drill-down, and chat components
  data/              Sample raw logs, mock events, and YAML mapping definitions
  services/          Backend API client, mock OCSF engine, and RAG fallback logic
  types/             TypeScript contracts for events, OCSF, and chat
  App.tsx            Application state and top-level screen composition
  main.tsx           React application entry point
  index.css          Global styles and Tailwind directives
```

## Main capabilities

- Unified event feed for Palo Alto, Suricata, Fortinet, Cisco ASA, Check Point, and Zeek data.
- OCSF-normalized event cards, filtering, analytics, and NDJSON export.
- Raw-log to normalized-event drill-down with field lineage and unmapped-field preservation.
- Interactive ingestion lab for testing vendor log samples.
- Security assistant with a browser-based fallback when the backend is unavailable.

## Backend modes

The app starts in mock mode, so it works without a server. When live mode is enabled, it expects a backend at `http://localhost:8000` with these endpoints:

- `GET /api/health`
- `GET /api/events`
- `POST /api/ingest`
- `POST /api/chat`

The API integration is implemented in `src/services/apiService.ts`.

## Development notes

- Keep event shapes aligned with the contracts in `src/types/ocsf.ts`.
- Add or update test data in `src/data/sampleRawLogs.ts` and `src/data/mockEvents.ts`.
- Reusable visual components belong in `src/components`; avoid putting feature-specific UI directly in `App.tsx` where possible.
- Run `npm run build` before opening a pull request to validate TypeScript and the production bundle.

# 🛡️ LogFusion — VS Code Quickstart Guide

Welcome to the **LogFusion (ULPF)** Frontend project!

This project is built with **React 18**, **Vite**, **Tailwind CSS**, **Recharts**, and **Lucide Icons**.

---

## 🚀 How to Run in VS Code (in 3 Steps)

### Step 1: Open in VS Code
Open VS Code, click **File $\rightarrow$ Open Folder...**, and select this extracted folder.

### Step 2: Install Dependencies
Open the built-in terminal in VS Code (`Ctrl + \`` or `Terminal -> New Terminal`) and run:
```bash
npm install
```

### Step 3: Start Development Server
```bash
npm run dev
```

Open **`http://localhost:3000`** in your browser!

---

## 🔌 Connecting to Backend (Python FastAPI)

The frontend automatically proxies all `/api` requests to **`http://localhost:8000`** (configured in `vite.config.ts`).

### Backend Endpoints Expected by Frontend:
1. `GET /api/health` — Checks backend health (`{ "status": "ok", "version": "1.0.0" }`)
2. `GET /api/events` — Returns normalized OCSF JSON events list
3. `POST /api/ingest` — Ingests raw log payload `{ "raw_log": "..." }` and returns normalized OCSF event
4. `POST /api/chat` — Queries Joi AI Security Assistant `{ "prompt": "...", "context_events": [...] }`

> **Note**: If backend is offline, the frontend automatically falls back to its built-in **Standalone In-Memory Normalization Engine & Grounded RAG** so the entire dashboard stays fully functional!

---

## 📦 Production Build
```bash
npm run build
```
The production bundle will be generated in the `dist/` folder ready for deployment to Vercel, Netlify, or AWS S3.

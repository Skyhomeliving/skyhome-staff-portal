# Sky Home Living — Staff Compliance Portal (v2)

A clean, maintainable rebuild of the staff compliance records system for NHS/CQC/Home Office
requirements. Node + Express + SQLite (Node's built-in driver — no native build), server-rendered.

## Features
- Role-based access (admin / manager / staff); staff see only their own record.
- Full compliance record per staff: identity, **Right to Work + sponsored-worker fields**
  (share code, visa/BRP/passport expiry, CoS), **DBS**, **driving licence**, Care Certificate,
  training matrix with expiries, references, employment history, health/fitness, professional registration.
- **Easy document uploads** (drag & drop) — driving licence, DBS, passport, training certs, etc.
- **Compliance dashboard + alerts**: live RAG status and expiry/renewal tracking.
- Invitations + self-registration, audit log, session auth (bcrypt).

## Run locally
```
npm install
SEED_DEMO=1 ADMIN_SEED_PASSWORD=yourpass npm start   # http://localhost:8080
```

## Environment
- `ADMIN_SEED_PASSWORD` — seeds `admin@skyhomeliving.co.uk` on first boot.
- `DATA_DIR` — data directory (SQLite `data.db` + `uploads/`); mount a Railway volume here.
- `SEED_DEMO=1` — seed synthetic staff (preview only; never in production).
- `PORT` — set by Railway.

## Data compatibility / migration
The schema is a **superset of the legacy portal's** (identical legacy column names), so the
recovered `data.db` upgrades in place on boot (new columns/tables added automatically) and all
existing staff keep their logins. Cutover = copy the recovered `data.db` + `uploads/` onto this
service's volume.

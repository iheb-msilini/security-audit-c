# Securite Audit Template

Production-style starter template for a cloud security audit platform:

- Next.js + Tailwind dashboard frontend
- FastAPI async backend
- PostgreSQL for results
- Celery + Redis for background jobs
- PDF/JSON report generation
- Docker Compose for one-command startup

## Project Structure

```text
securite-audit/
├── backend/
├── frontend/
├── docker-compose.yml
└── README.md
```

## Quick Start

1. Copy environment file:

```bash
cp backend/.env.example backend/.env
```

2. Build and start everything:

```bash
docker compose up --build
```

3. Open:

- Frontend: http://localhost:3001
- Backend docs: http://localhost:8001/docs

## API Highlights

- `GET /health`
- `GET /api/audits`
- `POST /api/audits`
- `POST /api/audits/{audit_id}/trigger`
- `GET /api/connectors`
- `GET /api/findings/{audit_id}`
- `GET /api/dashboard/summary`
- `GET /api/reports/{audit_id}?format=json|pdf`

## Local Backend (without Docker)

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

## Notes

- Cloud connectors use real SDK paths for AWS/Azure/GCP and collect inventory when credentials are available.
- Checks are evaluated from collected inventory; when credentials/permissions are missing, check status is returned as `unknown`.
- For production: add auth/RBAC, migrations, secrets management, and full provider integrations.

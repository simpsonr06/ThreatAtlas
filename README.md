# ThreatAtlas

Unified Cyber Threat Intelligence & Detection Platform.

ThreatAtlas is an educational security-engineering project for collecting, normalizing,
enriching and correlating public threat intelligence with authorized lab telemetry.
An IOC match is not proof of compromise.

## Day 1 scope

- Lightweight FastAPI backend
- SQLite database for local development
- Liveness and readiness endpoints
- Initial automated test
- No Docker, WSL, Redis or PostgreSQL required for this phase

## Requirements

- Windows 11
- Python 3.12
- Git

## Setup (PowerShell)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload
```

Open:
- http://127.0.0.1:8000/health
- http://127.0.0.1:8000/ready
- http://127.0.0.1:8000/docs

Run tests in a second terminal:

```powershell
.\.venv\Scripts\Activate.ps1
pytest -q
```

## Stop

Press Ctrl+C in the API terminal.

## Security notes

- `.env` is ignored by Git; commit `.env.example`, never `.env`.
- Keep the development API bound to localhost.
- Only ingest public feeds and telemetry from systems you own or are authorized to monitor.
- A threat-intelligence match is contextual evidence, not proof of compromise.

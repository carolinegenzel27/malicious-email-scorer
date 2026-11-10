# Malicious Email Scorer

A Gmail Add-on that analyzes the currently opened email and shows a maliciousness
score, a verdict, and a clear explanation of the reasoning behind it.

> 🚧 Work in progress. Full documentation (architecture, design decisions,
> security considerations, setup) will be added here.

## Repository layout

| Path | Contents |
|---|---|
| `addon/` | Gmail Add-on (Google Apps Script + CardService) |
| `backend/` | Analysis backend service (Python + FastAPI) |
| `tools/demo-emails/` | Apps Script that inserts safe sample emails into your own inbox for demos |

## Running the backend locally

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
export API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
.venv/bin/uvicorn app.main:create_app --factory --port 8000
```

## Deploying the add-on

```bash
npm install
npx clasp login
npm run addon:push
```

Then in the Apps Script editor: **Deploy → Test deployments → Gmail → Install**.

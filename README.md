# Malicious Email Scorer

A Gmail Add-on that analyzes the currently opened email and shows a maliciousness
score, a verdict, and a clear explanation of the reasoning behind it.

> 🚧 Work in progress. Full documentation (architecture, design decisions,
> security considerations, setup) will be added here.

## Repository layout

| Path | Contents |
|---|---|
| `addon/` | Gmail Add-on (Google Apps Script + CardService) |
| `backend/` | Analysis backend service (coming soon) |

## Deploying the add-on

```bash
npm install
npx clasp login
npm run addon:push
```

Then in the Apps Script editor: **Deploy → Test deployments → Gmail → Install**.

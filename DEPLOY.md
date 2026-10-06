# Educlawd CRM (PWA + payments) - fresh Railway deployment

Railway project = 2 services:
1. **MySQL** (database)
2. **App** (this folder: Node server that serves the PWA and the /api, stores data in MySQL)

On every start the app creates the 3 tables if missing, and creates the first admin if no admin exists yet.

## 1. Database
- Open your Railway project. If a **MySQL** box is still there, keep it (your tables and admin are in it).
- If it is gone: **+ New -> Database -> Add MySQL**.

## 2. Code on GitHub
Put the **contents** of this folder at the top level of the repo (`server.js` and `package.json` in the repo root). Delete old files.

## 3. Create the app service
**+ New -> GitHub Repo** -> choose the repo. The first deploy will fail or crash until step 4 is done - that is expected.

## 4. Variables (app service -> Variables)
- `MYSQL_URL` = `${{MySQL.MYSQL_URL}}`  (use your database box's exact name, or "Add Reference")
- Only if the database is NEW/empty: `ADMIN_PASSWORD` = a password of 6+ characters (and optionally `ADMIN_USERNAME`, default `educlawdcrm`). Remove `ADMIN_PASSWORD` after the first successful start.

Saving variables redeploys automatically.

## 5. Open it
- **Deployments -> Logs** must show `Educlawd CRM running on port ...`.
- **Settings -> Networking -> Generate Domain**, open it. `/health` shows `{"ok":true}`.
- Sign in. On a phone: "Add to Home Screen" to install.

## Notes
- `railway.json` sets the start command and health check (`/health`).
- Payments are stored as admin-owned records, so sales members never receive them.
- `_headers` and `vercel.json` from the old hosting are not needed.

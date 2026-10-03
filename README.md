# FC Training Academy – Compliance & Learner Records

Multi-user web app for LCL centre LC 447: staff, centre checks, QMS documents, learners, register, off-the-job hours and the EQA audit pack.

- Roles: **Manager** (changes everything directly, manages users, approves requests) and **Admin** (sees everything; every change is sent to the Manager for approval on the Approvals tab).
- Node/Express + PostgreSQL. Uploaded files are stored in the database. Every change is recorded in the Activity log.
- "Offline copy" downloads a ready-to-use offline version (open `FC Compliance.html` in Chrome).

## Environment variables
- `DATABASE_URL` – Postgres connection string
- `SESSION_SECRET` – random string, 32+ characters
- `SETUP_CODE` – one-time code to create the first Manager account (generated and printed in the logs if not set) (only works while no users exist)

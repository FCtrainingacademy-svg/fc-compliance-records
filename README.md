# FC Training Academy – Compliance & Learner Records

Multi-user web app for LCL centre LC 447: staff, centre checks, QMS documents, learners, register, off-the-job hours and the EQA audit pack.

- Roles: **Admin** (everything, including users), **Manager** (everything except users), **Assessor** (learners, register, OTJ hours, evidence uploads; read-only elsewhere).
- Node/Express + PostgreSQL. Uploaded files are stored in the database. Every change is recorded in the Activity log.
- "Offline copy" downloads a ready-to-use offline version (open `FC Compliance.html` in Chrome).

## Environment variables
- `DATABASE_URL` – Postgres connection string
- `SESSION_SECRET` – random string, 32+ characters
- `SETUP_CODE` – one-time code to create the first Admin account (only works while no users exist)

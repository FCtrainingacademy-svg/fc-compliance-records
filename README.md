# FC Training Academy – Compliance & Learner Records

Multi-user web app for LCL centre LC 447: staff, centre checks, QMS documents, learners, register, off-the-job hours and the EQA audit pack.

- Roles: **Manager** (changes everything directly, manages users, approves requests) and **Admin** (sees everything; every change is sent to the Manager for approval on the Approvals tab).
- Node/Express + PostgreSQL. Uploaded files are stored in the database. Every change is recorded in the Activity log.
- "Offline copy" downloads a ready-to-use offline version (open `FC Compliance.html` in Chrome).

## Environment variables
- `DATABASE_URL` – Postgres connection string
- `SESSION_SECRET` – random string, 32+ characters
- `SETUP_CODE` – one-time code to create the first Manager account (generated and printed in the logs if not set) (only works while no users exist)

### Learner portal password reset email
- `SMTP_USER` – mailbox that sends reset emails, e.g. `info@fctrainingacademy.com`
- `SMTP_PASS` – that mailbox's password (or app password)
- `SMTP_HOST` – default `smtp.office365.com`; `SMTP_PORT` – default `587`
- `MAIL_FROM` – optional, default `FC Training Academy <SMTP_USER>`
- `PORTAL_URL` – optional, default `https://learners.fctrainingacademy.com` (used in reset links)

Learners who have not set their own password sign in with their email and the default password `1234`. "Forgot password?" emails a one-time reset link valid for 1 hour. Without `SMTP_USER`/`SMTP_PASS` the forgot-password form tells learners to contact FC.

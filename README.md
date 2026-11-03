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

Learners who have not set their own password sign in with their email and the default password `1234`. After that first sign-in they're asked to choose their own password (any password except 1234). Learners who kept 1234 before are asked to choose a new one at their next sign-in. "Forgot password?" emails a one-time reset link valid for 1 hour. Without `SMTP_USER`/`SMTP_PASS` the forgot-password form tells learners to contact FC.

### Job Desk link (FC Training onsite portfolio jobs)
- `JOBDESK_KEY` – long random string (24+ characters). Set the **same value** as `LMS_KEY` on the Maintenance Job Desk.
- The Job Desk reads active learners (name, phone, email, cohort, mentor) from `GET /api/jobdesk/learners` so it can send them FC Training jobs on WhatsApp.
- When a learner finishes a training job, the Job Desk writes it back with `PUT /api/jobdesk/sitejob/:id`. It shows on the learner's page under **Onsite portfolio jobs**, counted against the 30-job target (boiler and cooker: 5 installs, 5 services, 4 fault finds, 1 pipework each).
- Both calls need the header `x-jobdesk-key`. Without `JOBDESK_KEY` set they're switched off.

## News

Industry news (new standards, Gas Safe Register bulletins, LCL/ACS changes) is kept in the LMS: **Learners → News**. Stories are drafts until the Manager presses **Publish** and saves. Published stories appear:

- on the public page **/news/** (e.g. https://learners.fctrainingacademy.com/news/) — link the website's News menu item here;
- at the top of the learner portal's **This week** tab (latest two);
- as JSON at **/api/news** (open to any site, for embedding on fctrainingacademy.com).

Drafts prepared outside the LMS go in `news/drafts.json` (fields: `id`, `date` YYYY-MM-DD, `tag`, `title`, `summary`, `body`, `source`, `url`). On start-up any story whose `id` the LMS hasn't seen before is added as a draft. Deleted drafts don't come back.

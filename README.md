# Northstar Student Portal

A Flask and SQLite computer institute portal with a public student project gallery, private student dashboards, and role-scoped staff administration. Academic and project records are stored in a relational SQLite database; uploaded files are kept outside the static web directory.

## Features

- Public project showcase with category and text search, anonymous publication, image lightbox, and inline PDF viewing.
- Student ID/username plus password login. Public lookup never confirms whether an account exists.
- Private student dashboard, per-course syllabus progress, normalized test scores, attendance history, and project submission library.
- Admin-created student and teacher accounts, password resets, course assignments, course/syllabus editing, marks, attendance, feedback, and project publication controls.
- Teacher permissions are restricted to assigned courses. Students can read only their own records and cannot edit academic data.
- CSRF checks on POST requests, password hashing, server-side sessions, role checks, file signature checks, upload size limits, SQLite constraints, and administrative audit records.
- Responsive interface with reduced-motion support and empty states.

## Requirements

- Python 3.10 or newer
- Packages in `requirements.txt`

## Local setup

In PowerShell, from this folder:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
flask --app app create-admin
flask --app app run
```

The app creates `instance\portal.sqlite3` and the private `instance\private_uploads\` directory automatically. The first administrator is created interactively; the password is entered without echo and stored only as a password hash. Open the local URL shown by Flask. Students sign in at `/login`; staff sign in at `/admin/login`.

To use a non-default database or upload directory, set `PORTAL_DATABASE` and `PORTAL_UPLOAD_FOLDER`. Set `PORTAL_ATTENDANCE_ALERT_PERCENT` (default `75`) and `PORTAL_ATTENDANCE_ALERT_MIN_SESSIONS` (default `3`) to configure the staff dashboard's academic-attention watchlist. Back up the database and private uploads together.

## Production configuration

Do not expose Flask's development server to the public internet. Configure a production WSGI server such as Waitress behind HTTPS, and set a unique high-entropy `PORTAL_SECRET_KEY` and `PORTAL_ENV=production` before startup. Production mode refuses to start without the secret key and enables secure session cookies. Example:

```powershell
$env:PORTAL_SECRET_KEY = "<generate and store a private random value at least 32 characters long>"
$env:PORTAL_ENV = "production"
waitress-serve --listen=127.0.0.1:8080 app:app
```

Use a persistent, access-controlled disk for both SQLite and private uploads; configure HTTPS termination, backups, monitoring, and operating-system permissions. SQLite is appropriate for a single-instance institute deployment and development, but is not a substitute for PostgreSQL/object storage in a horizontally scaled or high-concurrency deployment. Do not put the `instance\` directory under a public static path or commit it.

## Privacy and behavior notes

- Student IDs and names alone never authorize access. Student records are only shown after password authentication.
- Class sessions begin with enrolled students recorded as absent. Staff can correct each status. Present and absent count toward the rate; leave/excused and cancelled sessions do not.
- Overall and course averages are normalized as total marks earned divided by total marks possible. Test percentages use marks earned divided by that test's maximum.
- Syllabus percentages count completed topics divided by all topics assigned through an active/completed enrollment. A course with no topics has 0% progress.
- New project submissions are private. An administrator must explicitly publish a project. Anonymous display and public downloads are separately controlled.
- JPG/JPEG, PNG, and PDF files are limited to 10 MB per file (up to 10 attachments and 50 MB total per request) and checked against their expected file signature. Student files are served only after server-side authorization.
- The public brand name is currently “Northstar Institute”; customize the shared brand label in `templates/base.html`, `templates/home.html`, and `templates/login.html` for the institute.

## Validation

Run the focused workflow and authorization tests with:

```powershell
python -m unittest discover -s tests -v
```

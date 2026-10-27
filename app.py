import calendar
import hmac
import math
import os
import secrets
import sqlite3
import uuid
from datetime import date, timedelta
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent
ALLOWED_UPLOADS = {
    ".jpg": ("image/jpeg", b"\xff\xd8\xff"),
    ".jpeg": ("image/jpeg", b"\xff\xd8\xff"),
    ".png": ("image/png", b"\x89PNG\r\n\x1a\n"),
    ".pdf": ("application/pdf", b"%PDF-"),
}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_REQUEST_BYTES = 50 * 1024 * 1024
MAX_UPLOAD_COUNT = 10
MAX_PASSWORD_LENGTH = 1024


def create_app(test_config=None):
    if (
        os.environ.get("PORTAL_ENV", "").lower() == "production"
        and len(os.environ.get("PORTAL_SECRET_KEY", "")) < 32
    ):
        raise RuntimeError("PORTAL_SECRET_KEY must be set to at least 32 characters in production.")
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("PORTAL_SECRET_KEY") or secrets.token_hex(32),
        DATABASE=os.environ.get("PORTAL_DATABASE", str(Path(app.instance_path) / "portal.sqlite3")),
        UPLOAD_FOLDER=os.environ.get("PORTAL_UPLOAD_FOLDER", str(Path(app.instance_path) / "private_uploads")),
        MAX_CONTENT_LENGTH=MAX_REQUEST_BYTES,
        ATTENTION_THRESHOLD=float(os.environ.get("PORTAL_ATTENDANCE_ALERT_PERCENT", "75")),
        ATTENTION_MIN_SESSIONS=int(os.environ.get("PORTAL_ATTENDANCE_ALERT_MIN_SESSIONS", "3")),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=(
            os.environ.get("PORTAL_HTTPS", "").lower() == "true"
            or os.environ.get("PORTAL_ENV", "").lower() == "production"
        ),
    )
    if test_config:
        app.config.update(test_config)
    if not 0 <= app.config["ATTENTION_THRESHOLD"] <= 100 or app.config["ATTENTION_MIN_SESSIONS"] < 1:
        raise ValueError("Attendance attention thresholds must be 0-100 percent and at least one session.")

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(app.config["DATABASE"])
    try:
        with connection:
            connection.executescript((BASE_DIR / "schema.sql").read_text(encoding="utf-8"))
            connection.execute("PRAGMA journal_mode = WAL")
    finally:
        connection.close()

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
            g.db.execute("PRAGMA busy_timeout = 5000")
        return g.db

    app.get_db = get_db

    @app.teardown_appcontext
    def close_db(_error=None):
        database = g.pop("db", None)
        if database is not None:
            database.close()

    @app.before_request
    def load_user_and_check_csrf():
        user_id = session.get("user_id")
        g.user = get_db().execute(
            "SELECT id, username, role, active FROM users WHERE id = ?", (user_id,)
        ).fetchone() if user_id else None
        if user_id and (g.user is None or not g.user["active"]):
            session.clear()
            g.user = None
        if request.method == "POST":
            provided = request.form.get("csrf_token", "")
            expected = session.get("csrf_token", "")
            if not provided or not expected or not hmac.compare_digest(provided, expected):
                abort(400, description="Your session token expired. Reload the page and try again.")

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' "
            "https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'"
        )
        return response

    @app.context_processor
    def shared_context():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return {"csrf_token": session["csrf_token"], "current_user": g.get("user")}

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not g.user:
                flash("Sign in to continue.", "info")
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    def roles_required(*roles):
        def decorator(view):
            @wraps(view)
            @login_required
            def wrapped(*args, **kwargs):
                if g.user["role"] not in roles:
                    abort(403)
                return view(*args, **kwargs)
            return wrapped
        return decorator

    def audit(action, entity_type, entity_id=None, details=""):
        if g.user:
            get_db().execute(
                "INSERT INTO audit_logs (actor_id, action, entity_type, entity_id, details) VALUES (?, ?, ?, ?, ?)",
                (g.user["id"], action, entity_type, entity_id, details[:500]),
            )

    def student_for_user(user_id):
        return get_db().execute(
            "SELECT * FROM students WHERE user_id = ? AND archived = 0", (user_id,)
        ).fetchone()

    def course_allowed(course_id):
        if g.user["role"] == "admin":
            return True
        if g.user["role"] != "teacher":
            return False
        return get_db().execute(
            "SELECT 1 FROM teacher_courses WHERE teacher_id = ? AND course_id = ?",
            (g.user["id"], course_id),
        ).fetchone() is not None

    def require_course(course_id):
        if not course_allowed(course_id):
            abort(403)

    def enrollment_for(student_id, course_id):
        return get_db().execute(
            """SELECT 1 FROM enrollments e JOIN students s ON s.id = e.student_id
               JOIN users u ON u.id = s.user_id
               WHERE e.student_id = ? AND e.course_id = ? AND e.status IN ('active', 'completed')
                 AND s.archived = 0 AND u.active = 1""",
            (student_id, course_id),
        ).fetchone() is not None

    def progress_summary(student_id, course_id):
        row = get_db().execute(
            """SELECT COUNT(p.topic_id) AS total,
                      SUM(CASE WHEN p.status = 'completed' THEN 1 ELSE 0 END) AS completed,
                      SUM(CASE WHEN p.status = 'in_progress' THEN 1 ELSE 0 END) AS in_progress
               FROM topic_progress p JOIN topics t ON t.id = p.topic_id
               JOIN modules m ON m.id = t.module_id
               WHERE p.student_id = ? AND m.course_id = ?""",
            (student_id, course_id),
        ).fetchone()
        total = row["total"] or 0
        completed = row["completed"] or 0
        active = row["in_progress"] or 0
        return {
            "total": total,
            "completed": completed,
            "in_progress": active,
            "pending": total - completed - active,
            "percent": round(completed * 100 / total, 1) if total else 0,
        }

    def attendance_summary(student_id, course_id=None):
        condition = " AND cs.course_id = ?" if course_id is not None else ""
        values = (student_id, course_id) if course_id is not None else (student_id,)
        row = get_db().execute(
            """SELECT SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END) AS attended,
                      SUM(CASE WHEN a.status IN ('present', 'absent') THEN 1 ELSE 0 END) AS counted
               FROM attendance a JOIN class_sessions cs ON cs.id = a.session_id
               WHERE a.student_id = ? AND cs.cancelled = 0""" + condition,
            values,
        ).fetchone()
        attended = row["attended"] or 0
        counted = row["counted"] or 0
        return {
            "attended": attended,
            "counted": counted,
            "missed": counted - attended,
            "percent": round(attended * 100 / counted, 1) if counted else 0,
        }

    def result_summary(student_id, course_id=None):
        condition = " AND t.course_id = ?" if course_id is not None else ""
        values = (student_id, course_id) if course_id is not None else (student_id,)
        row = get_db().execute(
            """SELECT COALESCE(SUM(r.marks), 0) AS marks,
                      COALESCE(SUM(t.max_marks), 0) AS possible,
                      COUNT(r.id) AS tests
               FROM test_results r JOIN tests t ON t.id = r.test_id
               WHERE r.student_id = ?""" + condition,
            values,
        ).fetchone()
        return {
            "tests": row["tests"],
            "marks": row["marks"],
            "possible": row["possible"],
            "percent": round(row["marks"] * 100 / row["possible"], 1) if row["possible"] else 0,
        }

    def visible_courses(student_id):
        return get_db().execute(
            """SELECT c.*, e.status AS enrollment_status FROM courses c
               JOIN enrollments e ON e.course_id = c.id
               WHERE e.student_id = ? AND e.status IN ('active', 'completed') AND c.active = 1
               ORDER BY c.title""",
            (student_id,),
        ).fetchall()

    def validate_upload(file_storage):
        original_name = secure_filename(file_storage.filename or "")
        suffix = Path(original_name).suffix.lower()
        if not original_name or suffix not in ALLOWED_UPLOADS:
            raise ValueError("Choose a JPG, JPEG, PNG, or PDF file.")
        file_storage.stream.seek(0, os.SEEK_END)
        size = file_storage.stream.tell()
        file_storage.stream.seek(0)
        if size == 0 or size > MAX_UPLOAD_BYTES:
            raise ValueError("Each upload must be between 1 byte and 10 MB.")
        mime_type, signature = ALLOWED_UPLOADS[suffix]
        if file_storage.stream.read(len(signature)) != signature:
            file_storage.stream.seek(0)
            raise ValueError("The file contents do not match the selected file type.")
        file_storage.stream.seek(0)
        return original_name, suffix, mime_type, size

    def save_attachments(project_id, files):
        saved_paths = []
        database = get_db()
        try:
            selected_files = [uploaded for uploaded in files if uploaded.filename]
            if len(selected_files) > MAX_UPLOAD_COUNT:
                raise ValueError("A project can include up to 10 attachments.")
            for uploaded in selected_files:
                original_name, suffix, mime_type, size = validate_upload(uploaded)
                stored_name = f"{uuid.uuid4().hex}{suffix}"
                target = Path(app.config["UPLOAD_FOLDER"]) / stored_name
                uploaded.save(target)
                saved_paths.append(target)
                database.execute(
                    """INSERT INTO project_attachments
                       (project_id, stored_name, original_name, mime_type, file_size)
                       VALUES (?, ?, ?, ?, ?)""",
                    (project_id, stored_name, original_name, mime_type, size),
                )
            return saved_paths
        except Exception:
            for path in saved_paths:
                path.unlink(missing_ok=True)
            raise

    def render_student_section(section, course_id=None):
        student = student_for_user(g.user["id"])
        if student is None:
            abort(403)
        courses = visible_courses(student["id"])
        selected = next((c for c in courses if c["id"] == course_id), None) if course_id else None
        if course_id and selected is None:
            abort(404)
        if selected is None and courses:
            selected = courses[0]
        return student, courses, selected

    @app.route("/")
    def home():
        database = get_db()
        category = request.args.get("category", "").strip()
        search = request.args.get("q", "").strip()[:100]
        page = max(1, request.args.get("page", 1, type=int))
        filters = ["p.archived = 0"]
        values = []
        if category:
            filters.append("p.category = ?")
            values.append(category)
        if search:
            filters.append("(p.title LIKE ? OR p.description LIKE ? OR c.title LIKE ?)")
            values.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        where_clause = " WHERE " + " AND ".join(filters)
        count = database.execute(
            """SELECT COUNT(*) FROM projects p
               JOIN project_publications pub ON pub.project_id = p.id AND pub.published = 1
               JOIN courses c ON c.id = p.course_id""" + where_clause,
            values,
        ).fetchone()[0]
        page_count = max(1, math.ceil(count / 12))
        page = min(page, page_count)
        sql = """SELECT p.id, p.title, p.description, p.category, p.submitted_at,
                        c.title AS course_title, s.full_name, pub.anonymous, pub.allow_download,
                        a.id AS attachment_id, a.original_name, a.mime_type, a.file_size
                 FROM projects p
                 JOIN project_publications pub ON pub.project_id = p.id AND pub.published = 1
                 JOIN students s ON s.id = p.student_id
                 JOIN courses c ON c.id = p.course_id
                 LEFT JOIN project_attachments a ON a.id =
                   (SELECT MIN(first_file.id) FROM project_attachments first_file WHERE first_file.project_id = p.id)
                 """ + where_clause + " ORDER BY p.submitted_at DESC, p.id DESC LIMIT 12 OFFSET ?"
        projects = database.execute(sql, [*values, (page - 1) * 12]).fetchall()
        project_ids = [project["id"] for project in projects]
        attachments_by_project = {}
        if project_ids:
            placeholders = ",".join("?" for _ in project_ids)
            attachments = database.execute(
                f"""SELECT a.*, p.id AS project_id FROM project_attachments a
                    JOIN projects p ON p.id = a.project_id
                    JOIN project_publications pub ON pub.project_id = p.id AND pub.published = 1
                    WHERE p.id IN ({placeholders}) ORDER BY a.id""",
                project_ids,
            ).fetchall()
            for attachment in attachments:
                attachments_by_project.setdefault(attachment["project_id"], []).append(attachment)
        projects = [
            {**dict(project), "attachments": attachments_by_project.get(project["id"], [])}
            for project in projects
        ]
        categories = database.execute(
            """SELECT DISTINCT p.category FROM projects p
               JOIN project_publications pub ON pub.project_id = p.id AND pub.published = 1
               WHERE p.archived = 0 AND p.category <> '' ORDER BY p.category"""
        ).fetchall()
        project_count = database.execute(
            """SELECT COUNT(*) FROM projects p JOIN project_publications pub ON pub.project_id = p.id
               WHERE pub.published = 1 AND p.archived = 0"""
        ).fetchone()[0]
        return render_template(
            "home.html", projects=projects, project_count=project_count,
            categories=categories, category=category, search=search, page=page,
            page_count=page_count, filtered_count=count,
        )

    @app.post("/student/search")
    def student_search():
        query = request.form.get("student_query", "").strip()[:100]
        if len(query) < 2:
            flash("Enter a Student ID or name to continue.", "error")
        else:
            session["login_identifier_hint"] = query
            flash(
                "For your privacy, enter your password to continue. If multiple students share a name, use your Student ID.",
                "info",
            )
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            identifier = request.form.get("identifier", "").strip()
            password = request.form.get("password", "")
            records = []
            if len(password) <= MAX_PASSWORD_LENGTH:
                records = get_db().execute(
                    """SELECT DISTINCT u.* FROM users u LEFT JOIN students s ON s.user_id = u.id
                       WHERE u.active = 1 AND
                         (u.username = ? COLLATE NOCASE OR s.student_code = ? COLLATE NOCASE
                          OR (u.role = 'student' AND s.full_name = ? COLLATE NOCASE))
                       LIMIT 25""",
                    (identifier, identifier, identifier),
                ).fetchall()
            matches = [
                record for record in records
                if check_password_hash(record["password_hash"], password)
            ]
            if len(matches) == 1:
                record = matches[0]
                session.clear()
                session["user_id"] = record["id"]
                session["csrf_token"] = secrets.token_urlsafe(32)
                flash("Welcome back.", "success")
                if record["role"] == "student":
                    return redirect(url_for("student_dashboard"))
                return redirect(url_for("admin_dashboard"))
            flash("The sign-in details were not recognized. Check them and try again.", "error")
        identifier_hint = session.pop("login_identifier_hint", "")
        return render_template("login.html", admin=False, identifier_hint=identifier_hint)

    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        if request.method == "POST":
            identifier = request.form.get("identifier", "").strip()
            password = request.form.get("password", "")
            record = get_db().execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE AND role IN ('admin', 'teacher')",
                (identifier,),
            ).fetchone()
            if (
                len(password) <= MAX_PASSWORD_LENGTH and record and record["active"]
                and check_password_hash(record["password_hash"], password)
            ):
                session.clear()
                session["user_id"] = record["id"]
                session["csrf_token"] = secrets.token_urlsafe(32)
                return redirect(url_for("admin_dashboard"))
            flash("The sign-in details were not recognized. Check them and try again.", "error")
        return render_template("login.html", admin=True)

    @app.post("/logout")
    @login_required
    def logout():
        session.clear()
        flash("You have been signed out.", "success")
        return redirect(url_for("home"))

    @app.route("/student")
    @roles_required("student")
    def student_dashboard():
        student = student_for_user(g.user["id"])
        if student is None:
            abort(403)
        courses = visible_courses(student["id"])
        course_summaries = [
            (course, progress_summary(student["id"], course["id"])) for course in courses
        ]
        stats = {
            "courses": len(courses),
            "results": result_summary(student["id"]),
            "attendance": attendance_summary(student["id"]),
            "projects": get_db().execute(
                "SELECT COUNT(*) FROM projects WHERE student_id = ? AND archived = 0",
                (student["id"],),
            ).fetchone()[0],
        }
        totals = [summary for _course, summary in course_summaries]
        topic_count = sum(item["total"] for item in totals)
        done_count = sum(item["completed"] for item in totals)
        in_progress_count = sum(item["in_progress"] for item in totals)
        stats["syllabus"] = {
            "total": topic_count, "completed": done_count,
            "in_progress": in_progress_count,
            "pending": topic_count - done_count - in_progress_count,
            "percent": round(done_count * 100 / topic_count, 1) if topic_count else 0,
        }
        recent_results = get_db().execute(
            """SELECT t.name, t.test_date, t.max_marks, t.passing_marks, r.marks, c.title AS course_title
               FROM test_results r JOIN tests t ON t.id = r.test_id JOIN courses c ON c.id = t.course_id
               WHERE r.student_id = ? ORDER BY t.test_date DESC LIMIT 5""",
            (student["id"],),
        ).fetchall()
        announcements = get_db().execute(
            """SELECT p.title, p.feedback, p.submitted_at FROM projects p
               WHERE p.student_id = ? AND p.feedback <> '' AND p.archived = 0
               ORDER BY p.submitted_at DESC LIMIT 3""",
            (student["id"],),
        ).fetchall()
        return render_template(
            "student_dashboard.html", student=student, courses=courses, stats=stats,
            recent_results=recent_results, announcements=announcements,
            course_summaries=course_summaries,
        )

    @app.route("/student/syllabus")
    @roles_required("student")
    def student_syllabus():
        student, courses, selected = render_student_section(
            "syllabus", request.args.get("course", type=int)
        )
        status = request.args.get("status", "all")
        if status not in {"all", "completed", "in_progress", "pending"}:
            status = "all"
        topics = []
        summary = None
        if selected:
            summary = progress_summary(student["id"], selected["id"])
            sql = """SELECT t.id, t.title, m.title AS module_title, p.status, p.completed_at, p.remarks
                     FROM topic_progress p JOIN topics t ON t.id = p.topic_id
                     JOIN modules m ON m.id = t.module_id
                     WHERE p.student_id = ? AND m.course_id = ?"""
            values = [student["id"], selected["id"]]
            if status != "all":
                sql += " AND p.status = ?"
                values.append(status)
            sql += " ORDER BY m.position, t.position, t.id"
            topics = get_db().execute(sql, values).fetchall()
        return render_template(
            "student_syllabus.html", student=student, courses=courses, selected=selected,
            topics=topics, summary=summary, status=status,
        )

    @app.route("/student/results")
    @roles_required("student")
    def student_results():
        student, courses, selected = render_student_section(
            "results", request.args.get("course", type=int)
        )
        results = []
        summary = {"tests": 0, "marks": 0, "possible": 0, "percent": 0}
        if selected:
            summary = result_summary(student["id"], selected["id"])
            results = get_db().execute(
                """SELECT t.name, t.test_date, t.max_marks, t.passing_marks, r.marks, r.feedback
                   FROM test_results r JOIN tests t ON t.id = r.test_id
                   WHERE r.student_id = ? AND t.course_id = ? ORDER BY t.test_date DESC""",
                (student["id"], selected["id"]),
            ).fetchall()
        return render_template(
            "student_results.html", student=student, courses=courses, selected=selected,
            results=results, summary=summary,
        )

    @app.route("/student/attendance")
    @roles_required("student")
    def student_attendance():
        student, courses, selected = render_student_section(
            "attendance", request.args.get("course", type=int)
        )
        summary = attendance_summary(student["id"], selected["id"] if selected else None)
        condition = " AND cs.course_id = ?" if selected else ""
        values = (student["id"], selected["id"]) if selected else (student["id"],)
        records = get_db().execute(
            """SELECT cs.title, cs.session_date, cs.cancelled, a.status, a.remarks,
                      c.title AS course_title
               FROM attendance a JOIN class_sessions cs ON cs.id = a.session_id
               JOIN courses c ON c.id = cs.course_id
               WHERE a.student_id = ?""" + condition + " ORDER BY cs.session_date DESC LIMIT 120",
            values,
        ).fetchall()
        month_value = request.args.get("month", "")
        try:
            month_start = date.fromisoformat(f"{month_value}-01") if len(month_value) == 7 else date.today().replace(day=1)
        except ValueError:
            month_start = date.today().replace(day=1)
        if not 1900 <= month_start.year <= 2100:
            month_start = date.today().replace(day=1)
        if month_start.strftime("%Y-%m") != month_value:
            month_value = month_start.strftime("%Y-%m")
        next_month_start = (month_start.replace(day=28) + timedelta(days=4)).replace(day=1)
        previous_month = (month_start - timedelta(days=1)).strftime("%Y-%m")
        next_month = next_month_start.strftime("%Y-%m")
        day_sql = """SELECT cs.session_date, a.status FROM attendance a
                     JOIN class_sessions cs ON cs.id = a.session_id
                     WHERE a.student_id = ? AND cs.cancelled = 0"""
        day_values = [student["id"]]
        if selected:
            day_sql += " AND cs.course_id = ?"
            day_values.append(selected["id"])
        day_sql += " AND substr(cs.session_date, 1, 7) = ?"
        day_values.append(month_value)
        days = get_db().execute(day_sql, day_values).fetchall()
        calendar_statuses = {}
        for item in days:
            calendar_statuses.setdefault(item["session_date"], []).append(item["status"])
        calendar_weeks = []
        for week in calendar.Calendar(firstweekday=0).monthdatescalendar(month_start.year, month_start.month):
            calendar_weeks.append([
                {
                    "date": day,
                    "in_month": day.month == month_start.month,
                    "statuses": calendar_statuses.get(day.isoformat(), []),
                }
                for day in week
            ])
        monthly = get_db().execute(
            """SELECT substr(cs.session_date, 1, 7) AS month,
                      SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END) AS attended,
                      SUM(CASE WHEN a.status IN ('present', 'absent') THEN 1 ELSE 0 END) AS counted
               FROM attendance a JOIN class_sessions cs ON cs.id = a.session_id
               WHERE a.student_id = ? AND cs.cancelled = 0""" + condition +
            " GROUP BY substr(cs.session_date, 1, 7) ORDER BY month DESC LIMIT 6",
            values,
        ).fetchall()
        return render_template(
            "student_attendance.html", student=student, courses=courses, selected=selected,
            summary=summary, records=records, monthly=monthly, calendar_weeks=calendar_weeks,
            calendar_month=month_start.strftime("%B %Y"), month_value=month_value,
            previous_month=previous_month, next_month=next_month,
        )

    @app.route("/student/projects", methods=["GET", "POST"])
    @roles_required("student")
    def student_projects():
        student = student_for_user(g.user["id"])
        if student is None:
            abort(403)
        database = get_db()
        if request.method == "POST":
            course_id = request.form.get("course_id", type=int)
            title = request.form.get("title", "").strip()
            if not title or not enrollment_for(student["id"], course_id):
                flash("Enter a project title and choose one of your enrolled courses.", "error")
            else:
                try:
                    with database:
                        cursor = database.execute(
                            """INSERT INTO projects (student_id, course_id, title, description, category)
                               VALUES (?, ?, ?, ?, ?)""",
                            (student["id"], course_id, title,
                             request.form.get("description", "").strip()[:2000],
                             request.form.get("category", "").strip()[:100]),
                        )
                        save_attachments(cursor.lastrowid, request.files.getlist("files"))
                        database.execute(
                            "INSERT INTO project_publications (project_id) VALUES (?)", (cursor.lastrowid,)
                        )
                        audit("submitted", "project", cursor.lastrowid, title)
                    flash("Project submitted privately for staff review.", "success")
                    return redirect(url_for("student_projects"))
                except ValueError as error:
                    flash(str(error), "error")
        project_rows = database.execute(
            """SELECT p.*, c.title AS course_title FROM projects p JOIN courses c ON c.id = p.course_id
               WHERE p.student_id = ? AND p.archived = 0 ORDER BY p.submitted_at DESC""",
            (student["id"],),
        ).fetchall()
        attachment_rows = database.execute(
            """SELECT a.*, p.id AS project_id FROM project_attachments a
               JOIN projects p ON p.id = a.project_id
               WHERE p.student_id = ? AND p.archived = 0 ORDER BY a.id""", (student["id"],)
        ).fetchall()
        attachments_by_project = {}
        for attachment in attachment_rows:
            attachments_by_project.setdefault(attachment["project_id"], []).append(attachment)
        projects = [
            {**dict(project), "attachments": attachments_by_project.get(project["id"], [])}
            for project in project_rows
        ]
        courses = visible_courses(student["id"])
        return render_template("student_projects.html", student=student, courses=courses, projects=projects)

    @app.route("/student/courses/<int:course_id>")
    @roles_required("student")
    def student_course(course_id):
        student = student_for_user(g.user["id"])
        if student is None or not enrollment_for(student["id"], course_id):
            abort(404)
        course = get_db().execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
        topics = get_db().execute(
            """SELECT m.title AS module_title, t.title AS topic_title, p.status
               FROM topic_progress p JOIN topics t ON t.id = p.topic_id
               JOIN modules m ON m.id = t.module_id
               WHERE p.student_id = ? AND m.course_id = ? ORDER BY m.position, t.position""",
            (student["id"], course_id),
        ).fetchall()
        return render_template(
            "student_course.html", student=student, courses=visible_courses(student["id"]),
            course=course, summary=progress_summary(student["id"], course_id), topics=topics,
        )

    @app.get("/public/files/<int:attachment_id>")
    def public_file(attachment_id):
        attachment = get_db().execute(
            """SELECT a.*, p.id AS project_id, pub.allow_download FROM project_attachments a
               JOIN projects p ON p.id = a.project_id
               JOIN project_publications pub ON pub.project_id = p.id
               WHERE a.id = ? AND pub.published = 1 AND p.archived = 0""",
            (attachment_id,),
        ).fetchone()
        if attachment is None:
            abort(404)
        as_attachment = request.args.get("download") == "1" and attachment["allow_download"]
        return send_file(
            Path(app.config["UPLOAD_FOLDER"]) / attachment["stored_name"],
            mimetype=attachment["mime_type"], as_attachment=as_attachment,
            download_name=attachment["original_name"], conditional=True,
        )

    @app.get("/private/files/<int:attachment_id>")
    @roles_required("admin", "teacher", "student")
    def private_file(attachment_id):
        attachment = get_db().execute(
            """SELECT a.*, p.student_id, p.course_id, pub.published FROM project_attachments a
               JOIN projects p ON p.id = a.project_id
               LEFT JOIN project_publications pub ON pub.project_id = p.id
               WHERE a.id = ? AND p.archived = 0""",
            (attachment_id,),
        ).fetchone()
        if attachment is None:
            abort(404)
        if g.user["role"] == "student":
            student = student_for_user(g.user["id"])
            if student is None or student["id"] != attachment["student_id"]:
                abort(404)
        elif not course_allowed(attachment["course_id"]) and g.user["role"] != "admin":
            abort(404)
        return send_file(
            Path(app.config["UPLOAD_FOLDER"]) / attachment["stored_name"],
            mimetype=attachment["mime_type"], as_attachment=request.args.get("download") == "1",
            download_name=attachment["original_name"], conditional=True,
        )

    @app.route("/admin")
    @roles_required("admin", "teacher")
    def admin_dashboard():
        database = get_db()
        course_filter = ""
        values = []
        if g.user["role"] == "teacher":
            course_filter = " AND c.id IN (SELECT course_id FROM teacher_courses WHERE teacher_id = ?)"
            values = [g.user["id"]]
        metrics = {
            "students": database.execute(
                """SELECT COUNT(*) FROM students s JOIN users u ON u.id = s.user_id
                   WHERE s.archived = 0 AND u.active = 1"""
            ).fetchone()[0] if g.user["role"] == "admin" else database.execute(
                """SELECT COUNT(DISTINCT e.student_id) FROM enrollments e
                   JOIN students s ON s.id = e.student_id JOIN users u ON u.id = s.user_id
                   JOIN teacher_courses tc ON tc.course_id = e.course_id
                   WHERE tc.teacher_id = ? AND e.status = 'active' AND s.archived = 0 AND u.active = 1""",
                (g.user["id"],),
            ).fetchone()[0],
            "courses": database.execute(
                "SELECT COUNT(*) FROM courses c WHERE c.active = 1" + course_filter, values
            ).fetchone()[0],
            "projects": database.execute(
                """SELECT COUNT(*) FROM projects p JOIN courses c ON c.id = p.course_id""" +
                " WHERE p.archived = 0" + course_filter, values
            ).fetchone()[0],
            "published": database.execute(
                """SELECT COUNT(*) FROM project_publications pub
                   JOIN projects p ON p.id = pub.project_id JOIN courses c ON c.id = p.course_id
                   WHERE pub.published = 1""" +
                (" AND c.id IN (SELECT course_id FROM teacher_courses WHERE teacher_id = ?)" if g.user["role"] == "teacher" else ""),
                (g.user["id"],) if g.user["role"] == "teacher" else (),
            ).fetchone()[0],
        }
        courses = database.execute(
            "SELECT c.* FROM courses c WHERE c.active = 1" + course_filter + " ORDER BY c.title", values
        ).fetchall()
        recent = []
        if g.user["role"] == "admin":
            recent = database.execute(
                """SELECT l.action, l.entity_type, l.details, l.created_at, u.username
                   FROM audit_logs l LEFT JOIN users u ON u.id = l.actor_id
                   ORDER BY l.created_at DESC LIMIT 8"""
            ).fetchall()
        course_scope = ""
        scoped_values = ()
        if g.user["role"] == "teacher":
            course_scope = " AND c.id IN (SELECT course_id FROM teacher_courses WHERE teacher_id = ?)"
            scoped_values = (g.user["id"],)
        recent_tests = database.execute(
            """SELECT s.full_name, s.student_code, t.name AS test_name, t.test_date,
                      r.marks, t.max_marks, c.title AS course_title
               FROM test_results r JOIN students s ON s.id = r.student_id
               JOIN tests t ON t.id = r.test_id JOIN courses c ON c.id = t.course_id
               WHERE 1 = 1""" + course_scope + " ORDER BY t.test_date DESC LIMIT 6",
            scoped_values,
        ).fetchall()
        attendance_scope = ""
        attendance_values = ()
        if g.user["role"] == "teacher":
            attendance_scope = " AND cs.course_id IN (SELECT course_id FROM teacher_courses WHERE teacher_id = ?)"
            attendance_values = (g.user["id"],)
        attendance_totals = database.execute(
            """SELECT SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END) AS attended,
                      COUNT(*) AS counted FROM attendance a
               JOIN class_sessions cs ON cs.id = a.session_id
               WHERE cs.cancelled = 0 AND a.status IN ('present', 'absent')""" + attendance_scope,
            attendance_values,
        ).fetchone()
        overall_attendance = {
            "attended": attendance_totals["attended"] or 0,
            "counted": attendance_totals["counted"] or 0,
        }
        overall_attendance["percent"] = (
            round(overall_attendance["attended"] * 100 / overall_attendance["counted"], 1)
            if overall_attendance["counted"] else 0
        )
        attention_students = database.execute(
            """SELECT s.full_name, s.student_code,
                      SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END) AS attended,
                      COUNT(*) AS counted
               FROM attendance a JOIN students s ON s.id = a.student_id JOIN users u ON u.id = s.user_id
               JOIN class_sessions cs ON cs.id = a.session_id
               WHERE cs.cancelled = 0 AND a.status IN ('present', 'absent')
                 AND s.archived = 0 AND u.active = 1""" + attendance_scope +
            """ GROUP BY s.id
               HAVING COUNT(*) >= ? AND (SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END) * 100.0 / COUNT(*)) < ?
               ORDER BY (SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END) * 1.0 / COUNT(*)) LIMIT 6""",
            (*attendance_values, app.config["ATTENTION_MIN_SESSIONS"], app.config["ATTENTION_THRESHOLD"]),
        ).fetchall()
        return render_template(
            "admin_dashboard.html", metrics=metrics, courses=courses, recent=recent,
            recent_tests=recent_tests, overall_attendance=overall_attendance,
            attention_students=attention_students,
            attention_threshold=app.config["ATTENTION_THRESHOLD"],
        )

    @app.route("/admin/students", methods=["GET", "POST"])
    @roles_required("admin")
    def admin_students():
        database = get_db()
        if request.method == "POST":
            name = request.form.get("full_name", "").strip()
            code = request.form.get("student_code", "").strip()
            password = request.form.get("password", "")
            email = request.form.get("email", "").strip()
            phone = request.form.get("phone", "").strip()
            course_id = request.form.get("course_id", type=int)
            if (
                len(name) < 2 or not code or len(code) > 64
                or len(password) < 10 or len(password) > MAX_PASSWORD_LENGTH
            ):
                flash("Enter a name, unique Student ID, and password of at least 10 characters.", "error")
            elif course_id and not database.execute("SELECT 1 FROM courses WHERE id = ?", (course_id,)).fetchone():
                flash("Choose a valid course.", "error")
            else:
                try:
                    with database:
                        cursor = database.execute(
                            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'student')",
                            (code, generate_password_hash(password)),
                        )
                        student_cursor = database.execute(
                            """INSERT INTO students (user_id, student_code, full_name, email, phone)
                               VALUES (?, ?, ?, ?, ?)""",
                            (cursor.lastrowid, code, name, email or None, phone or None),
                        )
                        if course_id:
                            database.execute(
                                "INSERT INTO enrollments (student_id, course_id) VALUES (?, ?)",
                                (student_cursor.lastrowid, course_id),
                            )
                            topics = database.execute(
                                "SELECT t.id FROM topics t JOIN modules m ON m.id = t.module_id WHERE m.course_id = ?",
                                (course_id,),
                            ).fetchall()
                            database.executemany(
                                """INSERT INTO topic_progress (student_id, topic_id, status)
                                   VALUES (?, ?, 'pending')""",
                                [(student_cursor.lastrowid, topic["id"]) for topic in topics],
                            )
                        audit("created", "student", student_cursor.lastrowid, f"Student ID {code}")
                    flash(f"Student account created. Sign-in ID: {code}", "success")
                except sqlite3.IntegrityError:
                    flash("That Student ID or username is already in use.", "error")
                return redirect(url_for("admin_students"))
        search = request.args.get("q", "").strip()[:100]
        student_sql = """SELECT s.*, u.active FROM students s JOIN users u ON u.id = s.user_id"""
        student_values = []
        if search:
            student_sql += " WHERE s.full_name LIKE ? OR s.student_code LIKE ?"
            student_values.extend([f"%{search}%", f"%{search}%"])
        student_sql += " ORDER BY s.archived, s.full_name"
        students = database.execute(student_sql, student_values).fetchall()
        courses = database.execute("SELECT id, title FROM courses WHERE active = 1 ORDER BY title").fetchall()
        return render_template("admin_students.html", students=students, courses=courses, search=search)

    @app.post("/admin/students/<int:student_id>/update")
    @roles_required("admin")
    def update_student(student_id):
        database = get_db()
        student = database.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
        if student is None:
            abort(404)
        name = request.form.get("full_name", "").strip()
        code = request.form.get("student_code", "").strip()
        password = request.form.get("password", "")
        if (
            len(name) < 2 or len(code) < 1 or len(code) > 64
            or (password and (len(password) < 10 or len(password) > MAX_PASSWORD_LENGTH))
        ):
            flash("Provide a valid name and Student ID. A new password must be at least 10 characters.", "error")
        else:
            try:
                with database:
                    database.execute(
                        """UPDATE students SET full_name = ?, student_code = ?, email = ?, phone = ?
                           WHERE id = ?""",
                        (name, code, request.form.get("email", "").strip() or None,
                         request.form.get("phone", "").strip() or None, student_id),
                    )
                    database.execute(
                        "UPDATE users SET username = ?, password_hash = COALESCE(?, password_hash) WHERE id = ?",
                        (code, generate_password_hash(password) if password else None, student["user_id"]),
                    )
                    audit("updated", "student", student_id, f"Student ID {code}")
                flash("Student profile and access details updated.", "success")
            except sqlite3.IntegrityError:
                database.rollback()
                flash("That Student ID or username is already in use.", "error")
        return redirect(url_for("admin_students"))

    @app.post("/admin/students/<int:student_id>/archive")
    @roles_required("admin")
    def archive_student(student_id):
        database = get_db()
        database.execute("UPDATE students SET archived = 1 WHERE id = ?", (student_id,))
        database.execute(
            "UPDATE users SET active = 0 WHERE id = (SELECT user_id FROM students WHERE id = ?)",
            (student_id,),
        )
        audit("archived", "student", student_id)
        database.commit()
        flash("Student account archived.", "success")
        return redirect(url_for("admin_students"))

    @app.route("/admin/courses", methods=["GET", "POST"])
    @roles_required("admin")
    def admin_courses():
        database = get_db()
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            category = request.form.get("category", "").strip() or "Computer Science"
            if len(title) < 3:
                flash("Course title must contain at least 3 characters.", "error")
            else:
                cursor = database.execute(
                    "INSERT INTO courses (title, category, description) VALUES (?, ?, ?)",
                    (title, category, description),
                )
                audit("created", "course", cursor.lastrowid, title)
                database.commit()
                flash("Course created.", "success")
                return redirect(url_for("admin_courses"))
        courses = database.execute(
            """SELECT c.*, (SELECT COUNT(*) FROM enrollments e WHERE e.course_id = c.id) AS students,
                      (SELECT COUNT(*) FROM topics t JOIN modules m ON m.id = t.module_id WHERE m.course_id = c.id) AS topics
               FROM courses c ORDER BY c.active DESC, c.title"""
        ).fetchall()
        return render_template("admin_courses.html", courses=courses)

    @app.post("/admin/courses/<int:course_id>/toggle")
    @roles_required("admin")
    def toggle_course(course_id):
        database = get_db()
        course = database.execute("SELECT active, title FROM courses WHERE id = ?", (course_id,)).fetchone()
        if course is None:
            abort(404)
        database.execute("UPDATE courses SET active = ? WHERE id = ?", (0 if course["active"] else 1, course_id))
        audit("archived" if course["active"] else "activated", "course", course_id, course["title"])
        database.commit()
        flash("Course status updated.", "success")
        return redirect(url_for("admin_courses"))

    @app.route("/admin/courses/<int:course_id>", methods=["GET", "POST"])
    @roles_required("admin", "teacher")
    def admin_course_detail(course_id):
        require_course(course_id)
        database = get_db()
        course = database.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
        if course is None:
            abort(404)
        if request.method == "POST":
            action = request.form.get("action")
            if action == "course":
                title = request.form.get("course_title", "").strip()
                category = request.form.get("course_category", "").strip() or "Computer Science"
                description = request.form.get("course_description", "").strip()
                if len(title) < 3:
                    flash("Course title must contain at least 3 characters.", "error")
                else:
                    database.execute(
                        "UPDATE courses SET title = ?, category = ?, description = ? WHERE id = ?",
                        (title, category, description, course_id),
                    )
                    audit("updated", "course", course_id, title)
                    database.commit()
                    flash("Course details updated.", "success")
                    return redirect(url_for("admin_course_detail", course_id=course_id))
            elif action in {"module", "topic"}:
                title = request.form.get("title", "").strip()
                if not title:
                    flash("A title is required.", "error")
                elif action == "module":
                    cursor = database.execute(
                        "INSERT INTO modules (course_id, title, position) VALUES (?, ?, ?)",
                        (course_id, title, request.form.get("position", 0, type=int)),
                    )
                    audit("created", "module", cursor.lastrowid, title)
                    database.commit()
                    flash("Module added.", "success")
                    return redirect(url_for("admin_course_detail", course_id=course_id))
                else:
                    module_id = request.form.get("module_id", type=int)
                    if not database.execute(
                        "SELECT 1 FROM modules WHERE id = ? AND course_id = ?", (module_id, course_id)
                    ).fetchone():
                        flash("Choose a module from this course.", "error")
                    else:
                        cursor = database.execute(
                            "INSERT INTO topics (module_id, title, position) VALUES (?, ?, ?)",
                            (module_id, title, request.form.get("position", 0, type=int)),
                        )
                        enrolled_students = database.execute(
                            """SELECT e.student_id FROM enrollments e
                               JOIN students s ON s.id = e.student_id JOIN users u ON u.id = s.user_id
                               WHERE e.course_id = ? AND e.status IN ('active','completed')
                                 AND s.archived = 0 AND u.active = 1""",
                            (course_id,),
                        ).fetchall()
                        database.executemany(
                            "INSERT INTO topic_progress (student_id, topic_id, status) VALUES (?, ?, 'pending')",
                            [(row["student_id"], cursor.lastrowid) for row in enrolled_students],
                        )
                        audit("created", "topic", cursor.lastrowid, title)
                        database.commit()
                        flash("Topic added and assigned to enrolled students.", "success")
                        return redirect(url_for("admin_course_detail", course_id=course_id))
        module_rows = database.execute(
            """SELECT m.*, t.id AS topic_id, t.title AS topic_title
               FROM modules m LEFT JOIN topics t ON t.module_id = m.id
               WHERE m.course_id = ? ORDER BY m.position, m.id, t.position, t.id""",
            (course_id,),
        ).fetchall()
        students = database.execute(
            """SELECT s.id, s.student_code, s.full_name, e.status FROM enrollments e
               JOIN students s ON s.id = e.student_id JOIN users u ON u.id = s.user_id
               WHERE e.course_id = ? AND s.archived = 0 AND u.active = 1
               ORDER BY s.full_name""",
            (course_id,),
        ).fetchall()
        modules = []
        module_map = {}
        for row in module_rows:
            module = module_map.get(row["id"])
            if module is None:
                module = {"id": row["id"], "title": row["title"], "topics": []}
                module_map[row["id"]] = module
                modules.append(module)
            if row["topic_id"] is not None:
                module["topics"].append({
                    "id": row["topic_id"], "title": row["topic_title"], "progress": []
                })
        topic_map = {
            topic["id"]: topic
            for module in modules for topic in module["topics"]
        }
        progress_rows = database.execute(
            """SELECT p.student_id, p.topic_id, p.status, p.remarks FROM topic_progress p
               JOIN topics t ON t.id = p.topic_id JOIN modules m ON m.id = t.module_id
               WHERE m.course_id = ?""", (course_id,)
        ).fetchall()
        progress_map = {
            (row["student_id"], row["topic_id"]): row for row in progress_rows
        }
        for topic in topic_map.values():
            for student in students:
                current = progress_map.get((student["id"], topic["id"]))
                topic["progress"].append({
                    "student": student,
                    "status": current["status"] if current else "pending",
                    "remarks": current["remarks"] if current else "",
                })
        if g.user["role"] == "admin":
            all_students = database.execute(
                """SELECT s.id, s.student_code, s.full_name FROM students s
                   JOIN users u ON u.id = s.user_id
                   WHERE s.archived = 0 AND u.active = 1 AND NOT EXISTS
                     (SELECT 1 FROM enrollments e WHERE e.student_id = s.id AND e.course_id = ?)
                   ORDER BY s.full_name""", (course_id,)
            ).fetchall()
        else:
            all_students = []
        return render_template(
            "admin_course_detail.html", course=course, modules=modules, students=students,
            all_students=all_students,
        )

    @app.post("/admin/courses/<int:course_id>/enrollments/<int:student_id>")
    @roles_required("admin")
    def update_enrollment(course_id, student_id):
        status = request.form.get("status")
        if status not in {"active", "completed", "paused"}:
            abort(400)
        database = get_db()
        cursor = database.execute(
            "UPDATE enrollments SET status = ? WHERE course_id = ? AND student_id = ?",
            (status, course_id, student_id),
        )
        if cursor.rowcount == 0:
            abort(404)
        audit("updated", "enrollment", course_id, f"student={student_id}; status={status}")
        database.commit()
        flash("Enrollment status updated.", "success")
        return redirect(url_for("admin_course_detail", course_id=course_id))

    @app.post("/admin/courses/<int:course_id>/enroll")
    @roles_required("admin")
    def enroll_student(course_id):
        student_id = request.form.get("student_id", type=int)
        database = get_db()
        if not database.execute("SELECT 1 FROM courses WHERE id = ?", (course_id,)).fetchone():
            abort(404)
        if not database.execute(
            "SELECT 1 FROM students WHERE id = ? AND archived = 0", (student_id,)
        ).fetchone():
            flash("Choose an active student.", "error")
        elif enrollment_for(student_id, course_id):
            flash("That student is already enrolled.", "error")
        else:
            try:
                with database:
                    database.execute(
                        "INSERT INTO enrollments (student_id, course_id) VALUES (?, ?)",
                        (student_id, course_id),
                    )
                    topics = database.execute(
                        "SELECT t.id FROM topics t JOIN modules m ON m.id = t.module_id WHERE m.course_id = ?",
                        (course_id,),
                    ).fetchall()
                    database.executemany(
                        "INSERT INTO topic_progress (student_id, topic_id, status) VALUES (?, ?, 'pending')",
                        [(student_id, row["id"]) for row in topics],
                    )
                    audit("enrolled", "course", course_id, f"student {student_id}")
                flash("Student enrolled.", "success")
            except sqlite3.IntegrityError:
                flash("That student is already enrolled.", "error")
        return redirect(url_for("admin_course_detail", course_id=course_id))

    @app.post("/admin/progress/<int:student_id>/<int:topic_id>")
    @roles_required("admin", "teacher")
    def update_topic_progress(student_id, topic_id):
        database = get_db()
        row = database.execute(
            """SELECT m.course_id FROM topics t JOIN modules m ON m.id = t.module_id
               WHERE t.id = ?""", (topic_id,)
        ).fetchone()
        if row is None:
            abort(404)
        require_course(row["course_id"])
        status = request.form.get("status")
        if status not in {"completed", "in_progress", "pending"}:
            abort(400)
        if not enrollment_for(student_id, row["course_id"]):
            abort(400, description="Student is not enrolled in this course.")
        remarks = request.form.get("remarks", "").strip()[:500]
        completed_at = date.today().isoformat() if status == "completed" else None
        database.execute(
            """INSERT INTO topic_progress (student_id, topic_id, status, completed_at, remarks)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(student_id, topic_id) DO UPDATE SET status = excluded.status,
               completed_at = excluded.completed_at, remarks = excluded.remarks,
               updated_at = CURRENT_TIMESTAMP""",
            (student_id, topic_id, status, completed_at, remarks),
        )
        audit("updated", "topic_progress", topic_id, f"student={student_id}; status={status}")
        database.commit()
        flash("Syllabus progress saved.", "success")
        return redirect(url_for("admin_course_detail", course_id=row["course_id"]))

    @app.route("/admin/results", methods=["GET", "POST"])
    @roles_required("admin", "teacher")
    def admin_results():
        database = get_db()
        if request.method == "POST":
            action = request.form.get("action")
            if action == "test":
                course_id = request.form.get("course_id", type=int)
                require_course(course_id)
                name = request.form.get("name", "").strip()
                max_marks = request.form.get("max_marks", type=float)
                passing = request.form.get("passing_marks", type=float)
                test_date = request.form.get("test_date", "")
                try:
                    date.fromisoformat(test_date) if test_date else date.today()
                    date_valid = True
                except ValueError:
                    date_valid = False
                if (
                    not name or max_marks is None or not math.isfinite(max_marks) or max_marks <= 0
                    or (passing is not None and (
                        not math.isfinite(passing) or passing < 0 or passing > max_marks
                    ))
                    or not date_valid
                ):
                    flash("Enter valid test details and a passing mark within the maximum score.", "error")
                else:
                    cursor = database.execute(
                        """INSERT INTO tests (course_id, name, test_date, max_marks, passing_marks)
                           VALUES (?, ?, ?, ?, ?)""",
                        (course_id, name, test_date or date.today().isoformat(), max_marks, passing),
                    )
                    audit("created", "test", cursor.lastrowid, name)
                    database.commit()
                    flash("Test created. Add student marks below.", "success")
                    return redirect(url_for("admin_results"))
            elif action == "result":
                test_id = request.form.get("test_id", type=int)
                student_id = request.form.get("student_id", type=int)
                marks = request.form.get("marks", type=float)
                test = database.execute("SELECT * FROM tests WHERE id = ?", (test_id,)).fetchone()
                if test is None:
                    abort(404)
                require_course(test["course_id"])
                if (
                    marks is None or not math.isfinite(marks) or marks < 0
                    or marks > test["max_marks"] or not enrollment_for(student_id, test["course_id"])
                ):
                    flash("Marks must be within the maximum and the student must be enrolled in this course.", "error")
                else:
                    previous = database.execute(
                        "SELECT marks FROM test_results WHERE test_id = ? AND student_id = ?",
                        (test_id, student_id),
                    ).fetchone()
                    database.execute(
                        """INSERT INTO test_results (test_id, student_id, marks, feedback)
                           VALUES (?, ?, ?, ?)
                           ON CONFLICT(test_id, student_id) DO UPDATE SET marks = excluded.marks,
                           feedback = excluded.feedback, updated_at = CURRENT_TIMESTAMP""",
                        (test_id, student_id, marks, request.form.get("feedback", "").strip()[:500]),
                    )
                    before = previous["marks"] if previous else "new"
                    audit(
                        "saved", "test_result", test_id,
                        f"student={student_id}; previous={before}; current={marks}",
                    )
                    database.commit()
                    flash("Test result saved.", "success")
                    return redirect(url_for("admin_results"))
        if g.user["role"] == "admin":
            courses = database.execute("SELECT * FROM courses WHERE active = 1 ORDER BY title").fetchall()
            tests = database.execute(
                """SELECT t.*, c.title AS course_title FROM tests t JOIN courses c ON c.id = t.course_id
                   ORDER BY t.test_date DESC"""
            ).fetchall()
            results = database.execute(
                """SELECT r.*, s.full_name, s.student_code, t.name AS test_name, t.max_marks,
                          c.title AS course_title FROM test_results r
                   JOIN students s ON s.id = r.student_id JOIN tests t ON t.id = r.test_id
                   JOIN courses c ON c.id = t.course_id ORDER BY t.test_date DESC LIMIT 100"""
            ).fetchall()
        else:
            courses = database.execute(
                """SELECT c.* FROM courses c JOIN teacher_courses tc ON tc.course_id = c.id
                   WHERE tc.teacher_id = ? AND c.active = 1 ORDER BY c.title""", (g.user["id"],)
            ).fetchall()
            tests = database.execute(
                """SELECT t.*, c.title AS course_title FROM tests t JOIN courses c ON c.id = t.course_id
                   JOIN teacher_courses tc ON tc.course_id = c.id WHERE tc.teacher_id = ?
                   ORDER BY t.test_date DESC""", (g.user["id"],)
            ).fetchall()
            results = database.execute(
                """SELECT r.*, s.full_name, s.student_code, t.name AS test_name, t.max_marks,
                          c.title AS course_title FROM test_results r
                   JOIN students s ON s.id = r.student_id JOIN tests t ON t.id = r.test_id
                   JOIN courses c ON c.id = t.course_id JOIN teacher_courses tc ON tc.course_id = c.id
                   WHERE tc.teacher_id = ? ORDER BY t.test_date DESC LIMIT 100""", (g.user["id"],)
            ).fetchall()
        enrollment_sql = """SELECT e.course_id, s.id AS student_id, s.full_name, s.student_code
                            FROM enrollments e JOIN students s ON s.id = e.student_id
                            JOIN users u ON u.id = s.user_id
                            WHERE e.status IN ('active','completed') AND s.archived = 0 AND u.active = 1"""
        enrollment_values = ()
        if g.user["role"] == "teacher":
            enrollment_sql += " AND e.course_id IN (SELECT course_id FROM teacher_courses WHERE teacher_id = ?)"
            enrollment_values = (g.user["id"],)
        enrollments = database.execute(enrollment_sql, enrollment_values).fetchall()
        return render_template(
            "admin_results.html", courses=courses, tests=tests, results=results, enrollments=enrollments
        )

    @app.route("/admin/attendance", methods=["GET", "POST"])
    @roles_required("admin", "teacher")
    def admin_attendance():
        database = get_db()
        if request.method == "POST":
            action = request.form.get("action")
            if action == "session":
                course_id = request.form.get("course_id", type=int)
                require_course(course_id)
                title = request.form.get("title", "").strip()
                session_date = request.form.get("session_date", "")
                try:
                    date.fromisoformat(session_date)
                    date_valid = True
                except ValueError:
                    date_valid = False
                if not title or not date_valid:
                    flash("Enter a session title and date.", "error")
                else:
                    cursor = database.execute(
                        "INSERT INTO class_sessions (course_id, title, session_date) VALUES (?, ?, ?)",
                        (course_id, title, session_date),
                    )
                    students = database.execute(
                        "SELECT student_id FROM enrollments WHERE course_id = ? AND status IN ('active','completed')",
                        (course_id,),
                    ).fetchall()
                    database.executemany(
                        "INSERT INTO attendance (session_id, student_id, status) VALUES (?, ?, 'absent')",
                        [(cursor.lastrowid, row["student_id"]) for row in students],
                    )
                    audit("created", "class_session", cursor.lastrowid, title)
                    database.commit()
                    flash("Class session created with enrolled students marked absent by default.", "success")
                    return redirect(url_for("admin_attendance"))
            elif action == "cancel":
                session_id = request.form.get("session_id", type=int)
                class_session = database.execute(
                    "SELECT * FROM class_sessions WHERE id = ?", (session_id,)
                ).fetchone()
                if class_session is None:
                    abort(404)
                require_course(class_session["course_id"])
                cancelled = int(not class_session["cancelled"])
                database.execute(
                    "UPDATE class_sessions SET cancelled = ? WHERE id = ?",
                    (cancelled, session_id),
                )
                audit("cancelled" if cancelled else "reopened", "class_session", session_id)
                database.commit()
                flash("Class session status updated.", "success")
                return redirect(url_for("admin_attendance"))
            elif action == "attendance":
                session_id = request.form.get("session_id", type=int)
                student_id = request.form.get("student_id", type=int)
                status = request.form.get("status")
                class_session = database.execute(
                    "SELECT * FROM class_sessions WHERE id = ?", (session_id,)
                ).fetchone()
                if class_session is None:
                    abort(404)
                require_course(class_session["course_id"])
                if status not in {"present", "absent", "leave", "excused"} or not enrollment_for(student_id, class_session["course_id"]):
                    flash("Choose an enrolled student and a valid attendance status.", "error")
                else:
                    database.execute(
                        """INSERT INTO attendance (session_id, student_id, status, remarks)
                           VALUES (?, ?, ?, ?) ON CONFLICT(session_id, student_id) DO UPDATE
                           SET status = excluded.status, remarks = excluded.remarks""",
                        (session_id, student_id, status, request.form.get("remarks", "").strip()[:500]),
                    )
                    audit("updated", "attendance", session_id, f"student={student_id}; status={status}")
                    database.commit()
                    flash("Attendance saved.", "success")
                    return redirect(url_for("admin_attendance"))
        if g.user["role"] == "admin":
            courses = database.execute("SELECT * FROM courses WHERE active = 1 ORDER BY title").fetchall()
            sessions = database.execute(
                """SELECT cs.*, c.title AS course_title FROM class_sessions cs
                   JOIN courses c ON c.id = cs.course_id ORDER BY cs.session_date DESC LIMIT 100"""
            ).fetchall()
        else:
            courses = database.execute(
                """SELECT c.* FROM courses c JOIN teacher_courses tc ON tc.course_id = c.id
                   WHERE tc.teacher_id = ? AND c.active = 1 ORDER BY c.title""", (g.user["id"],)
            ).fetchall()
            sessions = database.execute(
                """SELECT cs.*, c.title AS course_title FROM class_sessions cs
                   JOIN courses c ON c.id = cs.course_id JOIN teacher_courses tc ON tc.course_id = c.id
                   WHERE tc.teacher_id = ? ORDER BY cs.session_date DESC LIMIT 100""", (g.user["id"],)
            ).fetchall()
        enrollment_sql = """SELECT e.course_id, s.id AS student_id, s.full_name, s.student_code
                            FROM enrollments e JOIN students s ON s.id = e.student_id
                            JOIN users u ON u.id = s.user_id
                            WHERE e.status IN ('active','completed') AND s.archived = 0 AND u.active = 1"""
        enrollment_values = ()
        if g.user["role"] == "teacher":
            enrollment_sql += " AND e.course_id IN (SELECT course_id FROM teacher_courses WHERE teacher_id = ?)"
            enrollment_values = (g.user["id"],)
        enrollments = database.execute(enrollment_sql, enrollment_values).fetchall()
        return render_template(
            "admin_attendance.html", courses=courses, sessions=sessions, enrollments=enrollments
        )

    @app.route("/admin/projects", methods=["GET", "POST"])
    @roles_required("admin", "teacher")
    def admin_projects():
        database = get_db()
        if request.method == "POST":
            action = request.form.get("action")
            if action == "create":
                student_id = request.form.get("student_id", type=int)
                course_id = request.form.get("course_id", type=int)
                require_course(course_id)
                title = request.form.get("title", "").strip()
                if not title or not enrollment_for(student_id, course_id):
                    flash("Enter a title and select a student enrolled in this course.", "error")
                else:
                    try:
                        with database:
                            cursor = database.execute(
                                """INSERT INTO projects (student_id, course_id, title, description, category)
                                   VALUES (?, ?, ?, ?, ?)""",
                                (student_id, course_id, title,
                                 request.form.get("description", "").strip()[:2000],
                                 request.form.get("category", "").strip()[:100]),
                            )
                            save_attachments(cursor.lastrowid, request.files.getlist("files"))
                            database.execute(
                                "INSERT INTO project_publications (project_id) VALUES (?)", (cursor.lastrowid,)
                            )
                            audit("created", "project", cursor.lastrowid, title)
                        flash("Project saved privately. Approve it below to publish.", "success")
                        return redirect(url_for("admin_projects"))
                    except (ValueError, sqlite3.IntegrityError) as error:
                        flash(str(error) or "The project could not be saved.", "error")
            elif action == "publication":
                if g.user["role"] != "admin":
                    abort(403)
                project_id = request.form.get("project_id", type=int)
                project = database.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
                if project is None:
                    abort(404)
                require_course(project["course_id"])
                published = int(request.form.get("published") == "1")
                anonymous = int(request.form.get("anonymous") == "1")
                allow_download = int(request.form.get("allow_download") == "1")
                database.execute(
                    """UPDATE project_publications SET published = ?, anonymous = ?,
                       allow_download = ?, approved_by = ?, approved_at = CASE WHEN ? = 1
                       THEN CURRENT_TIMESTAMP ELSE NULL END WHERE project_id = ?""",
                    (published, anonymous, allow_download, g.user["id"], published, project_id),
                )
                audit("published" if published else "unpublished", "project", project_id)
                database.commit()
                flash("Publication settings saved.", "success")
                return redirect(url_for("admin_projects"))
            elif action == "feedback":
                project_id = request.form.get("project_id", type=int)
                project = database.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
                if project is None:
                    abort(404)
                require_course(project["course_id"])
                database.execute(
                    "UPDATE projects SET feedback = ? WHERE id = ?",
                    (request.form.get("feedback", "").strip()[:1000], project_id),
                )
                audit("feedback", "project", project_id)
                database.commit()
                flash("Project feedback saved.", "success")
                return redirect(url_for("admin_projects"))
            elif action == "edit":
                project_id = request.form.get("project_id", type=int)
                project = database.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
                if project is None:
                    abort(404)
                require_course(project["course_id"])
                title = request.form.get("title", "").strip()
                if len(title) < 2:
                    flash("Project title must contain at least 2 characters.", "error")
                else:
                    database.execute(
                        "UPDATE projects SET title = ?, description = ?, category = ? WHERE id = ?",
                        (title, request.form.get("description", "").strip()[:2000],
                         request.form.get("category", "").strip()[:100], project_id),
                    )
                    audit("updated", "project", project_id, title)
                    database.commit()
                    flash("Project details updated.", "success")
                    return redirect(url_for("admin_projects"))
        if g.user["role"] == "admin":
            courses = database.execute("SELECT * FROM courses WHERE active = 1 ORDER BY title").fetchall()
            students = database.execute(
                """SELECT s.* FROM students s JOIN users u ON u.id = s.user_id
                   WHERE s.archived = 0 AND u.active = 1 ORDER BY s.full_name"""
            ).fetchall()
            projects = database.execute(
                """SELECT p.*, s.full_name, s.student_code, c.title AS course_title,
                          pub.published, pub.anonymous, pub.allow_download,
                          a.id AS attachment_id, a.original_name, a.mime_type, a.file_size
                   FROM projects p JOIN students s ON s.id = p.student_id
                   JOIN courses c ON c.id = p.course_id
                   JOIN project_publications pub ON pub.project_id = p.id
                   LEFT JOIN project_attachments a ON a.id =
                     (SELECT MIN(first_file.id) FROM project_attachments first_file WHERE first_file.project_id = p.id)
                   WHERE p.archived = 0 ORDER BY p.submitted_at DESC"""
            ).fetchall()
        else:
            courses = database.execute(
                """SELECT c.* FROM courses c JOIN teacher_courses tc ON tc.course_id = c.id
                   WHERE tc.teacher_id = ? AND c.active = 1 ORDER BY c.title""", (g.user["id"],)
            ).fetchall()
            students = database.execute(
                """SELECT DISTINCT s.* FROM students s JOIN users u ON u.id = s.user_id
                   JOIN enrollments e ON e.student_id = s.id
                   JOIN teacher_courses tc ON tc.course_id = e.course_id
                   WHERE tc.teacher_id = ? AND s.archived = 0 AND u.active = 1 ORDER BY s.full_name""", (g.user["id"],)
            ).fetchall()
            projects = database.execute(
                """SELECT p.*, s.full_name, s.student_code, c.title AS course_title,
                          pub.published, pub.anonymous, pub.allow_download,
                          a.id AS attachment_id, a.original_name, a.mime_type, a.file_size
                   FROM projects p JOIN students s ON s.id = p.student_id
                   JOIN courses c ON c.id = p.course_id JOIN teacher_courses tc ON tc.course_id = c.id
                   JOIN project_publications pub ON pub.project_id = p.id
                   LEFT JOIN project_attachments a ON a.id =
                     (SELECT MIN(first_file.id) FROM project_attachments first_file WHERE first_file.project_id = p.id)
                   WHERE tc.teacher_id = ? AND p.archived = 0 ORDER BY p.submitted_at DESC""",
                (g.user["id"],),
            ).fetchall()
        project_ids = [project["id"] for project in projects]
        attachments_by_project = {}
        if project_ids:
            placeholders = ",".join("?" for _ in project_ids)
            attachments = database.execute(
                f"""SELECT a.*, p.id AS project_id FROM project_attachments a
                    JOIN projects p ON p.id = a.project_id
                    WHERE p.id IN ({placeholders}) ORDER BY a.id""",
                project_ids,
            ).fetchall()
            for attachment in attachments:
                attachments_by_project.setdefault(attachment["project_id"], []).append(attachment)
        projects = [
            {**dict(project), "attachments": attachments_by_project.get(project["id"], [])}
            for project in projects
        ]
        return render_template("admin_projects.html", courses=courses, students=students, projects=projects)

    @app.post("/admin/projects/<int:project_id>/archive")
    @roles_required("admin")
    def archive_project(project_id):
        database = get_db()
        project = database.execute(
            "SELECT title FROM projects WHERE id = ?", (project_id,)
        ).fetchone()
        if project is None:
            abort(404)
        database.execute("UPDATE projects SET archived = 1 WHERE id = ?", (project_id,))
        database.execute(
            "UPDATE project_publications SET published = 0, approved_at = NULL WHERE project_id = ?",
            (project_id,),
        )
        audit("archived", "project", project_id, project["title"])
        database.commit()
        flash("Project archived and removed from the public showcase.", "success")
        return redirect(url_for("admin_projects"))

    @app.route("/admin/users", methods=["GET", "POST"])
    @roles_required("admin")
    def admin_users():
        database = get_db()
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            course_ids = request.form.getlist("course_ids", type=int)
            if len(username) < 3 or len(password) < 10 or len(password) > MAX_PASSWORD_LENGTH:
                flash("Enter a username of at least 3 characters and a password of at least 10 characters.", "error")
            else:
                try:
                    cursor = database.execute(
                        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'teacher')",
                        (username, generate_password_hash(password)),
                    )
                    for course_id in course_ids:
                        database.execute(
                            "INSERT INTO teacher_courses (teacher_id, course_id) VALUES (?, ?)",
                            (cursor.lastrowid, course_id),
                        )
                    audit("created", "teacher", cursor.lastrowid, username)
                    database.commit()
                    flash("Teacher account created and course access assigned.", "success")
                    return redirect(url_for("admin_users"))
                except sqlite3.IntegrityError:
                    database.rollback()
                    flash("That username is already in use or a selected course is invalid.", "error")
        user_rows = database.execute(
            """SELECT u.id, u.username, u.role, u.active, group_concat(c.title, ', ') AS courses,
                      group_concat(DISTINCT tc.course_id) AS course_ids
               FROM users u LEFT JOIN teacher_courses tc ON tc.teacher_id = u.id
               LEFT JOIN courses c ON c.id = tc.course_id GROUP BY u.id ORDER BY u.role, u.username"""
        ).fetchall()
        users = [
            {**dict(user), "course_ids": (user["course_ids"] or "").split(",") if user["course_ids"] else []}
            for user in user_rows
        ]
        courses = database.execute("SELECT id, title FROM courses WHERE active = 1 ORDER BY title").fetchall()
        return render_template("admin_users.html", users=users, courses=courses)

    @app.post("/admin/users/<int:user_id>/courses")
    @roles_required("admin")
    def update_teacher_courses(user_id):
        database = get_db()
        teacher = database.execute(
            "SELECT role FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if teacher is None:
            abort(404)
        if teacher["role"] != "teacher":
            abort(400, description="Course assignments are only available for teacher accounts.")
        course_ids = set(request.form.getlist("course_ids", type=int))
        valid_ids = {
            row["id"] for row in database.execute(
                "SELECT id FROM courses WHERE active = 1"
            ).fetchall()
        }
        if not course_ids.issubset(valid_ids):
            flash("One or more selected courses are invalid.", "error")
        else:
            with database:
                database.execute("DELETE FROM teacher_courses WHERE teacher_id = ?", (user_id,))
                database.executemany(
                    "INSERT INTO teacher_courses (teacher_id, course_id) VALUES (?, ?)",
                    [(user_id, course_id) for course_id in sorted(course_ids)],
                )
                audit("updated", "teacher_permissions", user_id, f"courses={sorted(course_ids)}")
            flash("Teacher course permissions updated.", "success")
        return redirect(url_for("admin_users"))

    @app.post("/admin/users/<int:user_id>/password")
    @roles_required("admin")
    def reset_user_password(user_id):
        password = request.form.get("password", "")
        if len(password) < 10 or len(password) > MAX_PASSWORD_LENGTH:
            flash("New passwords must be at least 10 characters.", "error")
            return redirect(url_for("admin_users"))
        database = get_db()
        user = database.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            abort(404)
        database.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(password), user_id),
        )
        audit("password_reset", "user", user_id, f"username={user['username']}")
        database.commit()
        flash("Password reset. Share the new password with the account holder privately.", "success")
        return redirect(url_for("admin_users"))

    @app.post("/admin/users/<int:user_id>/toggle")
    @roles_required("admin")
    def toggle_user(user_id):
        if user_id == g.user["id"]:
            flash("You cannot deactivate your own account.", "error")
        else:
            database = get_db()
            user = database.execute("SELECT role, active FROM users WHERE id = ?", (user_id,)).fetchone()
            if user is None:
                abort(404)
            database.execute("UPDATE users SET active = ? WHERE id = ?", (0 if user["active"] else 1, user_id))
            audit("deactivated" if user["active"] else "activated", "user", user_id)
            database.commit()
            flash("Account status updated.", "success")
        return redirect(url_for("admin_users"))

    @app.errorhandler(413)
    def upload_too_large(_error):
        return render_template("error.html", code=413, message="The request exceeds the 50 MB total upload limit."), 413

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="You don't have permission to view this page."), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="We couldn't find that page or record."), 404

    @app.errorhandler(400)
    def bad_request(error):
        message = getattr(error, "description", None) or "The request could not be processed. Reload the page and try again."
        return render_template("error.html", code=400, message=message), 400

    @app.cli.command("create-admin")
    def create_admin():
        """Create the first administrator account through a secure interactive prompt."""
        import getpass

        username = input("Administrator username: ").strip()
        password = getpass.getpass("Administrator password (min 12 characters): ")
        if len(username) < 3 or len(password) < 12 or len(password) > MAX_PASSWORD_LENGTH:
            raise SystemExit("Username must be at least 3 characters and password at least 12 characters.")
        database = get_db()
        if database.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone():
            raise SystemExit("An administrator already exists.")
        database.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
            (username, generate_password_hash(password)),
        )
        database.commit()
        print("Administrator account created.")

    return app


app = create_app()


if __name__ == "__main__":
    app.run()

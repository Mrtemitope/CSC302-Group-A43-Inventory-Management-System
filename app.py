"""CSC 302 Group A43 Inventory Management System coursework prototype.

Local runs use SQLite; Vercel deployments can connect to Neon PostgreSQL via
DATABASE_URL. This remains a classroom prototype, not an approved production
service for institutional inventory records.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import html
import io
import json
import math
import os
import re
import secrets
import sqlite3
import sys
import threading
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit


APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
DB_PATH = Path(os.environ.get("CSC302_DB_PATH", DATA_DIR / "inventory.db"))
SCHEMA_PATH = APP_DIR / "schema.sql"
HOST = os.environ.get("CSC302_HOST", "127.0.0.1")
PORT = int(os.environ.get("CSC302_PORT", "8000"))
DEFAULT_DEMO_MODE = "0" if os.environ.get("VERCEL") else "1"
DEMO_MODE = os.environ.get("CSC302_DEMO_MODE", DEFAULT_DEMO_MODE).strip().lower() not in {"0", "false", "no"}
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
SESSION_COOKIE = "csc302_session"
PASSWORD_ITERATIONS = 180_000
SESSION_LOCK = threading.Lock()
SESSIONS: dict[str, dict[str, object]] = {}

try:
    import psycopg2
except ImportError:
    psycopg2 = None

DB_ERRORS = (sqlite3.Error,) + ((psycopg2.Error,) if psycopg2 else ())
DB_INTEGRITY_ERRORS = (sqlite3.IntegrityError,) + ((psycopg2.IntegrityError,) if psycopg2 else ())

CATEGORIES = (
    "Stationery and Printing",
    "Computer Accessories",
    "Cleaning Materials",
    "Course Materials",
)
UNITS = ("Each", "Pkt", "Btl", "Ball", "Ream", "Set")
ROLES = {
    "admin": "System Administrator",
    "inventory_officer": "Store / Inventory Officer",
    "procurement_officer": "Procurement Officer",
}


@contextmanager
def connect_db():
    if DATABASE_URL:
        if psycopg2 is None:
            raise RuntimeError("PostgreSQL support requires psycopg2. Install the project requirements.")
        raw_conn = psycopg2.connect(DATABASE_URL, connect_timeout=10, sslmode="require")
        conn = PostgresConnection(raw_conn)
        try:
            yield conn
            raw_conn.commit()
        except Exception:
            raw_conn.rollback()
            raise
        finally:
            raw_conn.close()
        return
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


class HybridRow(dict):
    """PostgreSQL result row that supports both named and numeric indexing."""

    def __init__(self, names: list[str], values: tuple[object, ...]):
        super().__init__(zip(names, values))
        self._values = values

    def __getitem__(self, key: object) -> object:
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)


class PostgresCursor:
    def __init__(self, cursor: object, lastrowid: int | None = None):
        self._cursor = cursor
        self.lastrowid = lastrowid

    def _row(self, values: tuple[object, ...] | None) -> HybridRow | None:
        if values is None:
            return None
        names = [column.name for column in self._cursor.description]
        return HybridRow(names, values)

    def fetchone(self) -> HybridRow | None:
        return self._row(self._cursor.fetchone())

    def fetchall(self) -> list[HybridRow]:
        return [self._row(row) for row in self._cursor.fetchall()]


class PostgresConnection:
    """Small SQLite-shaped adapter for the existing parameterized SQL."""

    _ids = {
        "users": "user_id", "items": "item_id", "stocktake_events": "event_id",
        "stocktake_records": "record_id", "categories": "category_id", "units": "unit_id",
        "suppliers": "supplier_id", "audit_log": "audit_id",
    }

    def __init__(self, connection: object):
        self._connection = connection

    def execute(self, statement: str, params: tuple[object, ...] = ()) -> PostgresCursor:
        query = statement.strip()
        ignore_conflict = bool(re.match(r"INSERT\s+OR\s+IGNORE\s+INTO", query, re.IGNORECASE))
        if ignore_conflict:
            query = re.sub(r"INSERT\s+OR\s+IGNORE\s+INTO", "INSERT INTO", query, count=1, flags=re.IGNORECASE)
        query = re.sub(r"\s+COLLATE\s+NOCASE", "", query, flags=re.IGNORECASE)
        query = re.sub(r"\bLIKE\b", "ILIKE", query, flags=re.IGNORECASE).replace("?", "%s")
        table_match = re.match(r"INSERT\s+INTO\s+([a-z_]+)", query, re.IGNORECASE)
        lastrowid = None
        if ignore_conflict:
            query = query.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
        elif table_match and table_match.group(1).lower() in self._ids:
            query = query.rstrip().rstrip(";") + f" RETURNING {self._ids[table_match.group(1).lower()]}"
        cursor = self._connection.cursor()
        cursor.execute(query, params)
        if table_match and not ignore_conflict and cursor.description:
            returned = cursor.fetchone()
            lastrowid = returned[0] if returned else None
        return PostgresCursor(cursor, lastrowid)

    def executescript(self, script: str) -> None:
        for statement in script.split(";"):
            if statement.strip():
                self.execute(statement)


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, expected_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    _salt, actual = hash_password(password, salt)
    return hmac.compare_digest(actual, expected_hex)


def seed_demo_data(conn: sqlite3.Connection) -> None:
    existing = conn.execute("SELECT user_id FROM users WHERE username = 'admin'").fetchone()
    if os.environ.get("VERCEL"):
        required_passwords = ("CSC302_ADMIN_PASSWORD", "CSC302_OFFICER_PASSWORD", "CSC302_PROCUREMENT_PASSWORD")
        if any(not os.environ.get(name) for name in required_passwords):
            raise RuntimeError("Set unique CSC302 demo passwords in the deployment environment before enabling demo mode.")

    demo_users = (
        ("admin", "System Administrator (Demo)", "admin", os.environ.get("CSC302_ADMIN_PASSWORD", "admin123")),
        ("officer", "Inventory Officer (Demo)", "inventory_officer", os.environ.get("CSC302_OFFICER_PASSWORD", "officer123")),
        ("procurement", "Procurement Officer (Demo)", "procurement_officer", os.environ.get("CSC302_PROCUREMENT_PASSWORD", "procurement123")),
    )
    if not existing:
        for username, display_name, role, password in demo_users:
            salt, digest = hash_password(password)
            conn.execute(
                "INSERT INTO users(username, display_name, role, password_salt, password_hash) VALUES (?, ?, ?, ?, ?)",
                (username, display_name, role, salt, digest),
            )
    elif os.environ.get("VERCEL"):
        # Vercel secrets are write-only. Refresh only the three known demo accounts
        # from the configured secrets so password updates can take effect after a redeploy.
        for username, _display_name, role, password in demo_users:
            account = conn.execute(
                "SELECT role FROM users WHERE username = ?", (username,)
            ).fetchone()
            if account and account["role"] == role:
                salt, digest = hash_password(password)
                conn.execute(
                    "UPDATE users SET password_salt = ?, password_hash = ? WHERE username = ? AND role = ?",
                    (salt, digest, username, role),
                )

    demo_event = conn.execute("SELECT event_id FROM stocktake_events WHERE event_ref = 'DEMO-2026-001'").fetchone()
    if demo_event:
        return

    admin = conn.execute("SELECT user_id, display_name FROM users WHERE username = 'admin'").fetchone()
    if not admin:
        return
    demo_items = (
        ("DEMO-STA-001", "A4 Copier Paper", "Stationery and Printing", "Ream", 0),
        ("DEMO-STA-002", "Blue Ballpoint Pen", "Stationery and Printing", "Each", 0),
        ("DEMO-ACC-001", "USB Optical Mouse", "Computer Accessories", "Each", 0),
        ("DEMO-CLN-001", "Multipurpose Cleaner", "Cleaning Materials", "Btl", 0),
        ("DEMO-CRS-001", "Course Workbook", "Course Materials", "Each", 0),
    )
    ids: dict[str, int] = {}
    for code, name, category_name, unit_name, is_demo in demo_items:
        conn.execute(
            """INSERT OR IGNORE INTO items
               (item_code, item_name, category_id, unit_id, reorder_level, status, is_demo, created_by)
               VALUES (?, ?, (SELECT category_id FROM categories WHERE category_name = ?),
                       (SELECT unit_id FROM units WHERE unit_name = ?), NULL, 'active', ?, ?)""",
            (code, name, category_name, unit_name, is_demo, admin["user_id"]),
        )
        row = conn.execute("SELECT item_id FROM items WHERE item_code = ?", (code,)).fetchone()
        ids[code] = row["item_id"]

    conn.execute(
        """INSERT INTO stocktake_events
           (event_ref, stocktake_date, officer_id, officer_name, location, notes, is_demo)
           VALUES ('DEMO-2026-001', '2026-11-20', ?, ?, 'Morohundiya Store',
                   'Fictional demonstration records only. Not current DLC balances or prices.', 1)""",
        (admin["user_id"], admin["display_name"]),
    )
    event_id = conn.execute("SELECT event_id FROM stocktake_events WHERE event_ref = 'DEMO-2026-001'").fetchone()["event_id"]
    lines = (
        ("DEMO-STA-001", 20, 18, 6500.00, "Demonstration variance for presentation."),
        ("DEMO-STA-002", 50, 50, 350.00, "Demonstration count; no variance."),
        ("DEMO-ACC-001", 12, 9, 5800.00, "Demonstration variance for presentation."),
        ("DEMO-CLN-001", 12, 14, 1500.00, "Demonstration variance for presentation."),
        ("DEMO-CRS-001", 40, 40, 1200.00, "Demonstration count; no variance."),
    )
    for code, bin_balance, physical_qty, unit_price, remarks in lines:
        item = conn.execute(
            """SELECT i.item_id, i.item_code, i.item_name, u.unit_name
               FROM items i JOIN units u ON u.unit_id = i.unit_id WHERE i.item_code = ?""",
            (code,),
        ).fetchone()
        variance = float(physical_qty) - float(bin_balance)
        value = float(physical_qty) * float(unit_price)
        conn.execute(
            """INSERT OR IGNORE INTO stocktake_records
               (event_id, item_id, item_code_at_stocktake, item_name_at_stocktake,
                unit_at_stocktake, bin_card_balance, physical_qty, variance,
                unit_price_at_stocktake, stock_value_found, remarks, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (event_id, item["item_id"], item["item_code"], item["item_name"], item["unit_name"],
             bin_balance, physical_qty, variance, unit_price, value, remarks, admin["user_id"]),
        )


def initialize_database() -> None:
    if not DATABASE_URL:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
    with connect_db() as conn:
        schema_path = APP_DIR / "schema_postgres.sql" if DATABASE_URL else SCHEMA_PATH
        conn.executescript(schema_path.read_text(encoding="utf-8"))
        for category in CATEGORIES:
            conn.execute("INSERT OR IGNORE INTO categories(category_name) VALUES (?)", (category,))
        for unit in UNITS:
            conn.execute("INSERT OR IGNORE INTO units(unit_name) VALUES (?)", (unit,))
        if DEMO_MODE:
            seed_demo_data(conn)


def esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def fmt_qty(value: object) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "—"
    return f"{number:,.2f}".rstrip("0").rstrip(".")


def fmt_money(value: object) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = 0.0
    return f"₦{number:,.2f}"


def role_label(role: str) -> str:
    return ROLES.get(role, role.replace("_", " ").title())


def field(name: str, label: str, value: object = "", kind: str = "text", required: bool = False,
          attrs: str = "", help_text: str = "") -> str:
    req = " required" if required else ""
    element = f'<input id="{esc(name)}" name="{esc(name)}" type="{esc(kind)}" value="{esc(value)}"{req}{attrs}>'
    helper = f'<span class="hint">{esc(help_text)}</span>' if help_text else ""
    return f'<div class="field"><label for="{esc(name)}">{esc(label)}</label>{element}{helper}</div>'


def select_field(name: str, label: str, options: list[tuple[object, object]], selected: object = "",
                 required: bool = True, allow_blank: bool = False) -> str:
    req = " required" if required else ""
    blank = '<option value="">Select one</option>' if allow_blank else ""
    option_html = []
    for value, label_text in options:
        is_selected = " selected" if str(value) == str(selected) else ""
        option_html.append(f'<option value="{esc(value)}"{is_selected}>{esc(label_text)}</option>')
    return (f'<div class="field"><label for="{esc(name)}">{esc(label)}</label>'
            f'<select id="{esc(name)}" name="{esc(name)}"{req}>{blank}{"".join(option_html)}</select></div>')


def csrf_input(session: dict[str, object] | None) -> str:
    token = session.get("csrf", "") if session else ""
    return f'<input type="hidden" name="csrf" value="{esc(token)}">'


def demo_banner() -> str:
    return (
        '<section class="demo-banner" role="note"><span aria-hidden="true">ⓘ</span>'
        '<div><strong>Demonstration data</strong><p>All DEMO items, counts, prices and variances in this prototype are fictional examples for presentation. '
        'They are not current Morohundiya Store balances and were not copied from the December 2019 form.</p></div></section>'
    )


def notice_block(notice: str | None = None, error: str | None = None) -> str:
    if error:
        return f'<div class="flash error" role="alert">{esc(error)}</div>'
    if notice:
        return f'<div class="flash" role="status">{esc(notice)}</div>'
    return ""


def layout(handler: "InventoryHandler", title: str, content: str, active: str = "",
           notice: str | None = None, error: str | None = None, login: bool = False) -> str:
    user = handler.user
    show_demo = demo_data_exists()
    banner = demo_banner() if show_demo and not login else ""
    if login:
        return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} | CSC302 Inventory System</title><link rel="stylesheet" href="/static/styles.css"></head><body>
<main class="login-screen"><section class="login-card"><a class="brand" href="/login"><span class="brand-mark">A43</span><span><span class="brand-title">Inventory Management System</span><br><span class="brand-subtitle">CSC 302 · University of Ibadan DLC</span></span></a>
{notice_block(notice, error)}{content}</section></main></body></html>'''
    nav = [
        ("/", "Dashboard", "dashboard"),
        ("/items", "Items", "items"),
        ("/stocktakes", "Stocktakes", "stocktakes"),
        ("/reports", "Reports", "reports"),
    ]
    if user and user["role"] == "admin":
        nav.extend([("/settings", "Settings", "settings"), ("/users", "Users", "users"), ("/audit", "Audit log", "audit")])
    links = "".join(f'<a class="{"active" if key == active else ""}" href="{href}">{label}</a>' for href, label, key in nav)
    session = handler.session
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} | CSC302 Inventory System</title><link rel="stylesheet" href="/static/styles.css"></head><body>
<header class="topbar"><a class="brand" href="/"><span class="brand-mark">A43</span><span><span class="brand-title">Inventory Management System</span><br><span class="brand-subtitle">Morohundiya Store · CSC 302</span></span></a>
<nav class="nav" aria-label="Main navigation">{links}</nav><div class="top-user"><span>{esc(user['display_name'])}<br><small>{esc(role_label(user['role']))}</small></span><form method="post" action="/logout">{csrf_input(session)}<button class="logout" type="submit">Sign out</button></form></div></header>
<main class="wrap">{banner}{notice_block(notice, error)}{content}<footer class="footer">CSC 302 Group A43 · Inventory Management System prototype · {"Hosted PostgreSQL" if DATABASE_URL else "Local SQLite"}</footer></main></body></html>'''


def demo_data_exists() -> bool:
    try:
        with connect_db() as conn:
            return bool(conn.execute("SELECT 1 FROM items WHERE is_demo = 1 LIMIT 1").fetchone())
    except DB_ERRORS:
        return DEMO_MODE


def audit(conn: sqlite3.Connection, actor: sqlite3.Row | None, action: str, entity: str,
          entity_id: object = "", details: str = "") -> None:
    actor_name = actor["display_name"] if actor else "System setup"
    actor_id = actor["user_id"] if actor else None
    conn.execute(
        "INSERT INTO audit_log(actor_id, actor_name, action, entity, entity_id, details) VALUES (?, ?, ?, ?, ?, ?)",
        (actor_id, actor_name, action, entity, str(entity_id), details[:500]),
    )


def latest_count_query() -> str:
    return """SELECT i.item_id, i.item_code, i.item_name, i.reorder_level, i.status,
                     c.category_name, u.unit_name, r.physical_qty, r.stock_value_found,
                     e.stocktake_date, e.event_ref, e.is_demo
              FROM items i
              JOIN categories c ON c.category_id = i.category_id
              JOIN units u ON u.unit_id = i.unit_id
              LEFT JOIN stocktake_records r ON r.record_id = (
                SELECT r2.record_id FROM stocktake_records r2
                JOIN stocktake_events e2 ON e2.event_id = r2.event_id
                WHERE r2.item_id = i.item_id
                ORDER BY e2.stocktake_date DESC, e2.event_id DESC LIMIT 1
              )
              LEFT JOIN stocktake_events e ON e.event_id = r.event_id"""


class InventoryHandler(BaseHTTPRequestHandler):
    server_version = "CSC302Inventory/1.0"
    user: sqlite3.Row | None = None
    session: dict[str, object] | None = None
    session_id: str | None = None
    pending_cookie: str | None = None

    def log_message(self, format_string: str, *args: object) -> None:
        sys.stdout.write("[%s] %s\n" % (self.log_date_time_string(), format_string % args))

    def do_GET(self) -> None:
        self.dispatch("GET")

    def do_POST(self) -> None:
        self.dispatch("POST")

    def read_form(self) -> dict[str, str]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length > 1_000_000:
            raise ValueError("The submitted form is too large.")
        raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        parsed = parse_qs(raw, keep_blank_values=True)
        return {key: values[-1] for key, values in parsed.items()}

    def cookie_session(self) -> dict[str, object] | None:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            return None
        morsel = cookie.get(SESSION_COOKIE)
        sid = morsel.value if morsel else ""
        if not sid:
            return None
        if DATABASE_URL:
            with connect_db() as conn:
                row = conn.execute(
                    "SELECT user_id, csrf_token FROM web_sessions WHERE session_id = ? AND expires_at > ?",
                    (sid, datetime.now(timezone.utc).isoformat(timespec="seconds")),
                ).fetchone()
            session = {"user_id": row["user_id"], "csrf": row["csrf_token"]} if row else None
        else:
            with SESSION_LOCK:
                session = SESSIONS.get(sid)
        if not session:
            return None
        self.session_id = sid
        self.session = session
        return session

    def new_session(self, user_id: int | None = None) -> None:
        sid = secrets.token_urlsafe(32)
        session: dict[str, object] = {"user_id": user_id, "csrf": secrets.token_urlsafe(32)}
        if DATABASE_URL:
            expires_at = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat(timespec="seconds")
            with connect_db() as conn:
                conn.execute("DELETE FROM web_sessions WHERE expires_at < ?", (datetime.now(timezone.utc).isoformat(timespec="seconds"),))
                conn.execute("INSERT INTO web_sessions(session_id, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
                              (sid, user_id, session["csrf"], expires_at))
        else:
            with SESSION_LOCK:
                SESSIONS[sid] = session
        self.session_id = sid
        self.session = session
        secure = "; Secure" if os.environ.get("VERCEL") else ""
        self.pending_cookie = f"{SESSION_COOKIE}={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800{secure}"

    def remove_session(self) -> None:
        if not self.session_id:
            return
        if DATABASE_URL:
            with connect_db() as conn:
                conn.execute("DELETE FROM web_sessions WHERE session_id = ?", (self.session_id,))
        else:
            with SESSION_LOCK:
                SESSIONS.pop(self.session_id, None)

    def current_user(self) -> sqlite3.Row | None:
        session = self.cookie_session()
        if not session or not session.get("user_id"):
            return None
        with connect_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE user_id = ? AND is_active = 1", (session["user_id"],)).fetchone()
        return user

    def dispatch(self, method: str) -> None:
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        original_path = query.pop("__csc302_path", [None])[0]
        path = unquote(original_path or parsed.path)
        self.user = self.current_user()
        self.pending_cookie = None
        try:
            if path.startswith("/static/") and method == "GET":
                self.serve_static(path)
                return
            if path == "/login":
                self.login_route(method, query)
                return
            if path == "/setup":
                self.setup_route(method)
                return
            if path == "/logout" and method == "POST":
                self.logout_route()
                return
            if self.user is None:
                with connect_db() as conn:
                    count = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
                self.redirect("/setup" if count == 0 else "/login")
                return
            self.session = self.cookie_session()
            self.route_authenticated(method, path, query)
        except (ValueError,) + DB_ERRORS as exc:
            self.respond_error(str(exc) if isinstance(exc, ValueError) else "The request could not be completed. Check the submitted values and try again.", 400)
        except Exception as exc:
            sys.stderr.write(f"Request error at {path}: {exc}\n")
            self.respond_error("Something went wrong while loading this page. Please return to the dashboard and try again.", 500)

    def send_html(self, content: str, status: int = 200) -> None:
        body = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:")
        if self.pending_cookie:
            self.send_header("Set-Cookie", self.pending_cookie)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location: str, status: int = 303) -> None:
        self.send_response(status)
        self.send_header("Location", location)
        if self.pending_cookie:
            self.send_header("Set-Cookie", self.pending_cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def respond_error(self, message: str, status: int = 400) -> None:
        content = '<div class="page-head"><div><p class="eyebrow">Request notice</p><h1>We could not complete that action</h1></div></div>'
        content += f'<section class="panel"><p>{esc(message)}</p><a class="button secondary" href="/">Return to dashboard</a></section>'
        if self.user is None:
            target = "/setup" if self.path.startswith("/setup") else "/login"
            content = f'<h1>Request notice</h1><p>Review the message above, then reload the form.</p><a class="button secondary" href="{target}">Reload form</a>'
            self.send_html(layout(self, "Request notice", content, error=message, login=True), status)
            return
        self.send_html(layout(self, "Request notice", content, error=message), status)

    def serve_static(self, path: str) -> None:
        relative = path.removeprefix("/static/")
        if relative != "styles.css":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        file_path = APP_DIR / "static" / relative
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/css; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def valid_csrf(self, form: dict[str, str]) -> bool:
        token = str(self.session.get("csrf", "")) if self.session else ""
        return bool(token and form.get("csrf") and hmac.compare_digest(token, form["csrf"]))

    def need_csrf(self, form: dict[str, str]) -> bool:
        if self.valid_csrf(form):
            return True
        self.respond_error("This form expired or could not be verified. Reload the page and try again.", 403)
        return False

    def role_allowed(self, *roles: str) -> bool:
        return bool(self.user and self.user["role"] in roles)

    def forbidden(self) -> None:
        content = '<div class="page-head"><div><p class="eyebrow">Access control</p><h1>This action is not available to your role</h1><p class="subtitle">Ask a system administrator to update your access if you need this function.</p></div></div>'
        self.send_html(layout(self, "Access control", content), 403)

    def login_route(self, method: str, query: dict[str, list[str]]) -> None:
        if self.user:
            self.redirect("/")
            return
        if method == "POST":
            form = self.read_form()
            session = self.cookie_session()
            self.session = session
            if not self.valid_csrf(form):
                self.login_page(error="Reload the sign-in page and try again.")
                return
            username = form.get("username", "").strip()
            password = form.get("password", "")
            with connect_db() as conn:
                user = conn.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?) AND is_active = 1", (username,)).fetchone()
            if not user or not verify_password(password, user["password_salt"], user["password_hash"]):
                self.login_page(error="The username or password is incorrect.", form=form)
                return
            self.remove_session()
            self.new_session(user["user_id"])
            self.redirect("/", 303)
            return
        if self.session is None:
            self.new_session(None)
        self.login_page(notice=query.get("notice", [None])[0])

    def login_page(self, error: str | None = None, notice: str | None = None,
                   form: dict[str, str] | None = None) -> None:
        form = form or {}
        demo_accounts = """<aside class="demo-credentials"><strong>Demo sign-in accounts</strong><br>
Administrator: <code>admin</code> / <code>admin123</code><br>
Inventory officer: <code>officer</code> / <code>officer123</code><br>
Procurement officer: <code>procurement</code> / <code>procurement123</code></aside>""" if DEMO_MODE else ""
        if os.environ.get("VERCEL") and DEMO_MODE:
            demo_accounts = """<aside class="demo-credentials"><strong>Demonstration dataset</strong><br>
Sample inventory is fictional and provided for the CSC 302 project walkthrough.</aside>"""
        content = f'''<h1>Sign in to your workspace</h1><p class="intro">Record item details, conduct stocktakes and review inventory reports for the Morohundiya Store.</p>
<form method="post" action="/login">{csrf_input(self.session)}{field("username", "Username", form.get("username", ""), required=True)}{field("password", "Password", kind="password", required=True)}
<button type="submit" style="width:100%">Sign in</button></form>{demo_accounts}<p class="hint" style="margin-top:18px">This is a CSC 302 coursework prototype. Use the demo accounts for presentation only.</p>'''
        self.send_html(layout(self, "Sign in", content, notice=notice, error=error, login=True))

    def setup_route(self, method: str) -> None:
        with connect_db() as conn:
            user_count = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        if user_count:
            self.redirect("/login")
            return
        if method == "POST":
            form = self.read_form()
            self.session = self.cookie_session()
            if not self.need_csrf(form):
                return
            username = form.get("username", "").strip()
            display_name = form.get("display_name", "").strip()
            password = form.get("password", "")
            confirm = form.get("confirm_password", "")
            if not re.fullmatch(r"[A-Za-z0-9._-]{3,40}", username):
                self.setup_page("Choose a username using 3–40 letters, numbers, dots, underscores or hyphens.", form)
                return
            if len(display_name) < 2 or len(display_name) > 120:
                self.setup_page("Enter the administrator's full name.", form)
                return
            if len(password) < 8:
                self.setup_page("Choose a password with at least 8 characters.", form)
                return
            if password != confirm:
                self.setup_page("The passwords do not match.", form)
                return
            salt, digest = hash_password(password)
            with connect_db() as conn:
                if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
                    self.redirect("/login")
                    return
                cur = conn.execute("INSERT INTO users(username, display_name, role, password_salt, password_hash) VALUES (?, ?, 'admin', ?, ?)",
                                   (username, display_name, salt, digest))
                audit(conn, None, "created", "user", cur.lastrowid, f"Initial administrator {username}")
            self.new_session(cur.lastrowid)
            self.redirect("/", 303)
            return
        if self.session is None:
            self.new_session(None)
        self.setup_page()

    def setup_page(self, error: str | None = None, form: dict[str, str] | None = None) -> None:
        form = form or {}
        content = f'''<p class="eyebrow">First-time setup</p><h1>Create the administrator account</h1><p class="intro">This local database has no users yet. Create the first administrator to configure the system.</p>
<form method="post" action="/setup">{csrf_input(self.session)}{field("display_name", "Full name", form.get("display_name", ""), required=True)}{field("username", "Username", form.get("username", "admin"), required=True, attrs=' minlength="3" maxlength="40"')}{field("password", "Password", kind="password", required=True, attrs=' minlength="8"')}{field("confirm_password", "Confirm password", kind="password", required=True)}<button type="submit" style="width:100%">Create administrator</button></form>'''
        self.send_html(layout(self, "First-time setup", content, error=error, login=True))

    def logout_route(self) -> None:
        form = self.read_form()
        self.session = self.cookie_session()
        if not self.need_csrf(form):
            return
        self.remove_session()
        secure = "; Secure" if os.environ.get("VERCEL") else ""
        self.pending_cookie = f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}"
        self.redirect("/login?notice=You+have+signed+out")

    def route_authenticated(self, method: str, path: str, query: dict[str, list[str]]) -> None:
        notice = query.get("notice", [None])[0]
        if path == "/" and method == "GET":
            self.dashboard(notice)
        elif path == "/items" and method == "GET":
            self.items_page(query, notice)
        elif path == "/items/new" and method == "GET":
            self.item_form_page()
        elif path == "/items/new" and method == "POST":
            self.create_item()
        elif path == "/stocktakes" and method == "GET":
            self.stocktakes_page(notice)
        elif path == "/stocktakes/new" and method == "POST":
            self.create_stocktake()
        elif path == "/reports" and method == "GET":
            self.reports_page(query, notice)
        elif path == "/reports.csv" and method == "GET":
            self.reports_csv(query)
        elif path == "/settings" and method == "GET":
            self.settings_page(notice)
        elif path == "/settings" and method == "POST":
            self.settings_post()
        elif path == "/users" and method == "GET":
            self.users_page(notice)
        elif path == "/users" and method == "POST":
            self.users_post()
        elif path == "/audit" and method == "GET":
            self.audit_page()
        elif path == "/backup" and method == "GET":
            self.backup_database()
        else:
            item_edit = re.fullmatch(r"/items/(\d+)/edit", path)
            item_save = re.fullmatch(r"/items/(\d+)/edit", path)
            item_reorder = re.fullmatch(r"/items/(\d+)/reorder", path)
            stocktake = re.fullmatch(r"/stocktakes/(\d+)", path)
            if item_edit and method == "GET":
                self.item_form_page(int(item_edit.group(1)))
            elif item_save and method == "POST":
                self.update_item(int(item_save.group(1)))
            elif item_reorder and method == "POST":
                self.update_reorder_level(int(item_reorder.group(1)))
            elif stocktake and method == "GET":
                self.stocktake_detail(int(stocktake.group(1)), notice)
            elif stocktake and method == "POST":
                self.add_stocktake_record(int(stocktake.group(1)))
            else:
                self.send_error(HTTPStatus.NOT_FOUND)

    def page_head(self, eyebrow: str, title: str, subtitle: str = "", actions: str = "") -> str:
        sub = f'<p class="subtitle">{esc(subtitle)}</p>' if subtitle else ""
        return f'<div class="page-head"><div><p class="eyebrow">{esc(eyebrow)}</p><h1>{esc(title)}</h1>{sub}</div>{actions}</div>'

    def dashboard(self, notice: str | None = None) -> None:
        with connect_db() as conn:
            metrics = {
                "items": conn.execute("SELECT COUNT(*) FROM items WHERE status = 'active'").fetchone()[0],
                "events": conn.execute("SELECT COUNT(*) FROM stocktake_events").fetchone()[0],
                "variance": conn.execute("SELECT COUNT(*) FROM stocktake_records WHERE variance <> 0").fetchone()[0],
                "value": conn.execute("SELECT COALESCE(SUM(stock_value_found), 0) FROM stocktake_records r WHERE r.event_id = (SELECT event_id FROM stocktake_events ORDER BY stocktake_date DESC, event_id DESC LIMIT 1)").fetchone()[0],
            }
            recent = conn.execute(
                """SELECT e.event_id, e.event_ref, e.stocktake_date, e.officer_name, e.is_demo,
                          COUNT(r.record_id) AS line_count,
                          SUM(CASE WHEN r.variance <> 0 THEN 1 ELSE 0 END) AS variance_count
                   FROM stocktake_events e LEFT JOIN stocktake_records r ON r.event_id = e.event_id
                   GROUP BY e.event_id ORDER BY e.stocktake_date DESC, e.event_id DESC LIMIT 5"""
            ).fetchall()
            low = conn.execute(latest_count_query() + " WHERE i.status = 'active' AND i.reorder_level IS NOT NULL AND r.physical_qty IS NOT NULL AND r.physical_qty <= i.reorder_level ORDER BY i.item_name LIMIT 6").fetchall()
            unconfigured = conn.execute("SELECT COUNT(*) FROM items WHERE status = 'active' AND reorder_level IS NULL").fetchone()[0]
        metric_cards = (
            ("Active items", metrics["items"], "Items in the register"),
            ("Stocktake events", metrics["events"], "Historical counts saved"),
            ("Variance lines", metrics["variance"], "Records for review"),
            ("Latest event value", fmt_money(metrics["value"]), "Historical snapshot value"),
        )
        cards = "".join(f'<article class="metric"><div class="metric-label">{label}</div><div class="metric-value">{value}</div><div class="metric-foot">{foot}</div></article>' for label, value, foot in metric_cards)
        if recent:
            recent_rows = "".join(
                f'<tr><td><a href="/stocktakes/{row["event_id"]}"><strong>{esc(row["event_ref"])}</strong></a>{" <span class=\"badge demo\">DEMO</span>" if row["is_demo"] else ""}</td>'
                f'<td>{esc(row["stocktake_date"])}</td><td>{esc(row["officer_name"])}</td>'
                f'<td>{row["line_count"]}</td><td><span class="badge {"warn" if row["variance_count"] else "good"}">{row["variance_count"] or 0} to review</span></td></tr>'
                for row in recent
            )
            event_content = f'<div class="table-wrap"><table><thead><tr><th>Event</th><th>Date</th><th>Officer</th><th>Lines</th><th>Review</th></tr></thead><tbody>{recent_rows}</tbody></table></div>'
        else:
            event_content = '<div class="empty"><strong>No stocktake events yet</strong>Create an event when you are ready to record a physical count.</div>'
        if low:
            low_content = "".join(
                f'<div class="review-row"><div><strong>{esc(row["item_name"])}</strong><p>{esc(row["item_code"])} · {fmt_qty(row["physical_qty"])} {esc(row["unit_name"])} on latest count</p></div><span class="badge warn">At or below {fmt_qty(row["reorder_level"])}</span></div>'
                for row in low
            )
        else:
            low_content = '<div class="empty"><strong>No low-stock items flagged</strong>Only authorized reorder levels are used. Set a level after it has been approved.</div>'
        if unconfigured:
            low_content += f'<p class="hint" style="margin-top:13px">{unconfigured} active item(s) do not have an authorized reorder level.</p>'
        actions = '<div class="actions"><a class="button" href="/stocktakes">Open stocktakes</a><a class="button secondary" href="/items">View item register</a></div>'
        content = self.page_head("Inventory overview", "Good day, " + self.user["display_name"].split("(")[0].strip(),
                                 "A clear view of item records, recent stocktakes and review items.", actions)
        content += f'<section class="grid metrics">{cards}</section>'
        content += f'<section class="grid content-grid"><article class="panel"><div class="panel-head"><div><h2>Recent stocktakes</h2><p>Historical event snapshots for Morohundiya Store</p></div><a href="/stocktakes">View all</a></div>{event_content}</article>'
        content += f'<article class="panel"><div class="panel-head"><div><h2>Reorder review</h2><p>Uses configured thresholds and the latest recorded physical count</p></div></div>{low_content}</article></section>'
        self.send_html(layout(self, "Dashboard", content, "dashboard", notice=notice))

    def items_page(self, query: dict[str, list[str]], notice: str | None = None) -> None:
        search = query.get("q", [""])[0].strip()
        status = query.get("status", ["active"])[0]
        where = []
        params: list[object] = []
        if status in {"active", "inactive"}:
            where.append("i.status = ?")
            params.append(status)
        if search:
            where.append("(i.item_code LIKE ? OR i.item_name LIKE ? OR c.category_name LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like])
        sql = """SELECT i.*, c.category_name, u.unit_name, s.supplier_name
                 FROM items i JOIN categories c ON c.category_id = i.category_id
                 JOIN units u ON u.unit_id = i.unit_id LEFT JOIN suppliers s ON s.supplier_id = i.supplier_id"""
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY i.status, i.item_code COLLATE NOCASE"
        with connect_db() as conn:
            rows = conn.execute(sql, params).fetchall()
        can_manage = self.role_allowed("admin", "inventory_officer")
        can_reorder = self.role_allowed("admin", "procurement_officer")
        action = '<a class="button" href="/items/new">Add item</a>' if can_manage else ""
        content = self.page_head("Master data", "Item register", "Search and maintain the approved item list, categories, units and optional suppliers.", action)
        search_options = "".join(f'<option value="{value}"{" selected" if status == value else ""}>{label}</option>' for value, label in (("active", "Active"), ("inactive", "Inactive"), ("all", "All statuses")))
        content += f'''<section class="panel"><div class="toolbar"><form method="get" action="/items"><input type="search" name="q" placeholder="Search code, item or category" value="{esc(search)}" aria-label="Search items"><select name="status" aria-label="Item status">{search_options}</select><button type="submit">Search</button></form></div>'''
        if rows:
            body = []
            for row in rows:
                reorder = fmt_qty(row["reorder_level"]) if row["reorder_level"] is not None else "Not configured"
                if can_reorder and row["status"] == "active":
                    reorder = f'''<form class="inline-form" method="post" action="/items/{row['item_id']}/reorder">{csrf_input(self.session)}<input type="number" min="0" step="0.01" name="reorder_level" value="{esc(row['reorder_level'] if row['reorder_level'] is not None else '')}" aria-label="Reorder level for {esc(row['item_name'])}" placeholder="Unset"><button class="button small secondary" type="submit">Save</button></form>'''
                edit = f'<a class="button small secondary" href="/items/{row["item_id"]}/edit">Edit</a>' if can_manage else ""
                demo = ' <span class="badge demo">DEMO</span>' if row["is_demo"] else ""
                body.append(f'''<tr><td><strong>{esc(row['item_code'])}</strong>{demo}<span class="subcell">{esc(row['item_name'])}</span></td>
<td>{esc(row['category_name'])}</td><td>{esc(row['unit_name'])}</td><td>{esc(row['supplier_name'] or '—')}</td><td>{reorder}</td>
<td><span class="badge {'good' if row['status']=='active' else ''}">{esc(row['status'].title())}</span></td><td>{edit}</td></tr>''')
            content += '<div class="table-wrap"><table><thead><tr><th>Item</th><th>Category</th><th>Unit</th><th>Supplier</th><th>Reorder level</th><th>Status</th><th></th></tr></thead><tbody>' + "".join(body) + '</tbody></table></div>'
        else:
            content += '<div class="empty"><strong>No items found</strong>Add an item or adjust the search filters.</div>'
        content += '</section>'
        self.send_html(layout(self, "Item register", content, "items", notice=notice))

    def item_form_page(self, item_id: int | None = None, error: str | None = None,
                       form: dict[str, str] | None = None) -> None:
        if not self.role_allowed("admin", "inventory_officer"):
            self.forbidden()
            return
        form = form or {}
        with connect_db() as conn:
            item = conn.execute("SELECT * FROM items WHERE item_id = ?", (item_id,)).fetchone() if item_id else None
            categories = conn.execute("SELECT category_id, category_name FROM categories ORDER BY category_name").fetchall()
            units = conn.execute("SELECT unit_id, unit_name FROM units ORDER BY unit_name").fetchall()
            suppliers = conn.execute("SELECT supplier_id, supplier_name FROM suppliers ORDER BY supplier_name").fetchall()
        if item_id and not item:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        vals = dict(form)
        if item:
            for key in ("item_code", "item_name", "category_id", "unit_id", "supplier_id", "reorder_level", "status"):
                vals.setdefault(key, "" if item[key] is None else str(item[key]))
        title = "Edit item" if item else "Add an item"
        content = self.page_head("Item details", title, "Register stable item information. Reorder levels should be entered only after an authorized officer approves them.")
        content += '<section class="panel"><form method="post" action="' + (f"/items/{item_id}/edit" if item else "/items/new") + '"><div class="form-grid">'
        content += field("item_code", "Item code", vals.get("item_code", ""), required=True, attrs=' maxlength="40"', help_text="Codes must be unique.")
        content += field("item_name", "Description of goods", vals.get("item_name", ""), required=True, attrs=' maxlength="160"')
        cat_options = [(row["category_id"], row["category_name"]) for row in categories]
        unit_options = [(row["unit_id"], row["unit_name"]) for row in units]
        supplier_options = [(row["supplier_id"], row["supplier_name"]) for row in suppliers]
        content += select_field("category_id", "Category", cat_options, vals.get("category_id", ""))
        content += select_field("unit_id", "Unit of measure", unit_options, vals.get("unit_id", ""))
        content += select_field("supplier_id", "Supplier (optional)", supplier_options, vals.get("supplier_id", ""), required=False, allow_blank=True)
        content += field("reorder_level", "Authorized reorder level (optional)", vals.get("reorder_level", ""), "number", False, ' min="0" step="0.01"', "Leave blank until a threshold has been approved.")
        if item:
            status_options = [("active", "Active"), ("inactive", "Inactive")]
            content += select_field("status", "Record status", status_options, vals.get("status", "active"))
        content += '</div>' + csrf_input(self.session) + '<div class="form-actions"><button type="submit">Save item</button><a class="button secondary" href="/items">Cancel</a></div></form></section>'
        self.send_html(layout(self, title, content, "items", error=error))

    def _validate_item(self, form: dict[str, str], old_id: int | None = None) -> tuple[dict[str, object] | None, str | None]:
        code = form.get("item_code", "").strip()
        name = form.get("item_name", "").strip()
        if not code or len(code) > 40:
            return None, "Enter an item code of 1–40 characters."
        if not name or len(name) > 160:
            return None, "Enter a description of 1–160 characters."
        try:
            category_id = int(form.get("category_id", ""))
            unit_id = int(form.get("unit_id", ""))
        except ValueError:
            return None, "Choose an existing category and unit."
        supplier_value = form.get("supplier_id", "").strip()
        supplier_id = None
        if supplier_value:
            try:
                supplier_id = int(supplier_value)
            except ValueError:
                return None, "Choose a valid supplier or leave the field blank."
        reorder_raw = form.get("reorder_level", "").strip()
        reorder: float | None = None
        if reorder_raw:
            try:
                reorder = float(reorder_raw)
            except ValueError:
                return None, "Reorder level must be a number or left blank."
            if not math.isfinite(reorder) or reorder < 0:
                return None, "Reorder level must be zero or greater."
        status = form.get("status", "active") if old_id else "active"
        if status not in {"active", "inactive"}:
            return None, "Choose a valid record status."
        with connect_db() as conn:
            if not conn.execute("SELECT 1 FROM categories WHERE category_id = ?", (category_id,)).fetchone():
                return None, "The selected category is unavailable."
            if not conn.execute("SELECT 1 FROM units WHERE unit_id = ?", (unit_id,)).fetchone():
                return None, "The selected unit is unavailable."
            if supplier_id and not conn.execute("SELECT 1 FROM suppliers WHERE supplier_id = ?", (supplier_id,)).fetchone():
                return None, "The selected supplier is unavailable."
            duplicate = conn.execute("SELECT item_id FROM items WHERE LOWER(item_code) = LOWER(?) AND item_id <> COALESCE(?, -1)", (code, old_id)).fetchone()
            if duplicate:
                return None, "That item code is already in use. Choose a unique code."
        return {"code": code, "name": name, "category_id": category_id, "unit_id": unit_id,
                "supplier_id": supplier_id, "reorder": reorder, "status": status}, None

    def create_item(self) -> None:
        if not self.role_allowed("admin", "inventory_officer"):
            self.forbidden()
            return
        form = self.read_form()
        if not self.need_csrf(form):
            return
        data, error = self._validate_item(form)
        if error:
            self.item_form_page(error=error, form=form)
            return
        with connect_db() as conn:
            cur = conn.execute(
                """INSERT INTO items(item_code, item_name, category_id, unit_id, supplier_id, reorder_level, status, is_demo, created_by, updated_by)
                   VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)""",
                (data["code"], data["name"], data["category_id"], data["unit_id"], data["supplier_id"], data["reorder"], int(DEMO_MODE), self.user["user_id"], self.user["user_id"]),
            )
            audit(conn, self.user, "created", "item", cur.lastrowid, f"{data['code']} — {data['name']}")
        self.redirect("/items?notice=Item+saved")

    def update_item(self, item_id: int) -> None:
        if not self.role_allowed("admin", "inventory_officer"):
            self.forbidden()
            return
        form = self.read_form()
        if not self.need_csrf(form):
            return
        data, error = self._validate_item(form, item_id)
        if error:
            self.item_form_page(item_id, error, form)
            return
        with connect_db() as conn:
            old = conn.execute("SELECT item_code, item_name, is_demo FROM items WHERE item_id = ?", (item_id,)).fetchone()
            if not old:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            conn.execute(
                """UPDATE items SET item_code=?, item_name=?, category_id=?, unit_id=?, supplier_id=?, reorder_level=?, status=?, updated_by=?, updated_at=CURRENT_TIMESTAMP WHERE item_id=?""",
                (data["code"], data["name"], data["category_id"], data["unit_id"], data["supplier_id"], data["reorder"], data["status"], self.user["user_id"], item_id),
            )
            audit(conn, self.user, "updated", "item", item_id, f"{old['item_code']} → {data['code']}; {old['item_name']} → {data['name']}")
        self.redirect("/items?notice=Item+updated")

    def update_reorder_level(self, item_id: int) -> None:
        if not self.role_allowed("admin", "procurement_officer"):
            self.forbidden()
            return
        form = self.read_form()
        if not self.need_csrf(form):
            return
        raw = form.get("reorder_level", "").strip()
        value: float | None = None
        if raw:
            try:
                value = float(raw)
            except ValueError:
                self.redirect("/items?notice=Enter+a+valid+reorder+level")
                return
            if not math.isfinite(value) or value < 0:
                self.redirect("/items?notice=Reorder+level+must+be+zero+or+greater")
                return
        with connect_db() as conn:
            row = conn.execute("SELECT item_code FROM items WHERE item_id = ?", (item_id,)).fetchone()
            if not row:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            conn.execute("UPDATE items SET reorder_level=?, updated_by=?, updated_at=CURRENT_TIMESTAMP WHERE item_id=?", (value, self.user["user_id"], item_id))
            audit(conn, self.user, "updated reorder level", "item", item_id, f"{row['item_code']}: {value if value is not None else 'unset'}")
        self.redirect("/items?notice=Reorder+level+saved")

    def stocktakes_page(self, notice: str | None = None) -> None:
        can_create = self.role_allowed("admin", "inventory_officer")
        create_form = ""
        if can_create:
            create_form = f'''<section class="panel" style="margin-bottom:18px"><div class="panel-head"><div><h2>Start a stocktake</h2><p>Creates a dated event for the Morohundiya Store.</p></div></div>
<form method="post" action="/stocktakes/new" class="form-grid">{csrf_input(self.session)}{field("stocktake_date", "Stocktake date", date.today().isoformat(), "date", True)}
<div class="field"><label for="location">Location</label><input id="location" value="Morohundiya Store" readonly><span class="hint">All four confirmed categories are recorded at this store.</span></div>
<div class="field span-2"><label for="notes">Event note (optional)</label><textarea id="notes" name="notes" maxlength="300" placeholder="Purpose or context for this count"></textarea></div><div class="span-2 form-actions"><button type="submit">Create stocktake event</button></div></form></section>'''
        with connect_db() as conn:
            rows = conn.execute(
                """SELECT e.*, COUNT(r.record_id) AS line_count,
                          SUM(CASE WHEN r.variance <> 0 THEN 1 ELSE 0 END) AS variance_count,
                          COALESCE(SUM(r.stock_value_found), 0) AS total_value
                   FROM stocktake_events e LEFT JOIN stocktake_records r ON r.event_id = e.event_id
                   GROUP BY e.event_id ORDER BY e.stocktake_date DESC, e.event_id DESC"""
            ).fetchall()
        if rows:
            trs = "".join(
                f'<tr><td><a href="/stocktakes/{row["event_id"]}"><strong>{esc(row["event_ref"])}</strong></a>{" <span class=\"badge demo\">DEMO</span>" if row["is_demo"] else ""}<span class="subcell">{esc(row["location"])}</span></td>'
                f'<td>{esc(row["stocktake_date"])}</td><td>{esc(row["officer_name"])}</td><td>{row["line_count"]}</td>'
                f'<td>{row["variance_count"] or 0}</td><td class="currency">{fmt_money(row["total_value"])}</td></tr>' for row in rows
            )
            table = f'<div class="table-wrap"><table><thead><tr><th>Event</th><th>Date</th><th>Responsible officer</th><th>Counted items</th><th>Variance lines</th><th>Value found</th></tr></thead><tbody>{trs}</tbody></table></div>'
        else:
            table = '<div class="empty"><strong>No stocktake history yet</strong>Create an event, then add one record for each item counted.</div>'
        content = self.page_head("Physical counts", "Stocktake events", "Each event preserves the values entered for that count, including the price and item description at the time.") + create_form
        content += f'<section class="panel"><div class="panel-head"><div><h2>Stocktake history</h2><p>Open an event to add or review counted items.</p></div></div>{table}</section>'
        self.send_html(layout(self, "Stocktakes", content, "stocktakes", notice=notice))

    def create_stocktake(self) -> None:
        if not self.role_allowed("admin", "inventory_officer"):
            self.forbidden()
            return
        form = self.read_form()
        if not self.need_csrf(form):
            return
        stocktake_date = form.get("stocktake_date", "").strip()
        notes = form.get("notes", "").strip()
        try:
            date.fromisoformat(stocktake_date)
        except ValueError:
            self.redirect("/stocktakes?notice=Choose+a+valid+stocktake+date")
            return
        if len(notes) > 300:
            self.redirect("/stocktakes?notice=Event+notes+must+be+300+characters+or+less")
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        ref = f"ST-{stamp}-{datetime.now().microsecond:06d}"
        with connect_db() as conn:
            cur = conn.execute(
                """INSERT INTO stocktake_events(event_ref, stocktake_date, officer_id, officer_name, location, notes, is_demo)
                   VALUES (?, ?, ?, ?, 'Morohundiya Store', ?, ?)""",
                (ref, stocktake_date, self.user["user_id"], self.user["display_name"], notes or None, int(DEMO_MODE)),
            )
            audit(conn, self.user, "created", "stocktake event", cur.lastrowid, f"{ref} on {stocktake_date}")
        self.redirect(f"/stocktakes/{cur.lastrowid}?notice=Stocktake+event+created")

    def stocktake_detail(self, event_id: int, notice: str | None = None, error: str | None = None) -> None:
        with connect_db() as conn:
            event = conn.execute("SELECT * FROM stocktake_events WHERE event_id = ?", (event_id,)).fetchone()
            if not event:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            records = conn.execute("SELECT * FROM stocktake_records WHERE event_id = ? ORDER BY item_code_at_stocktake", (event_id,)).fetchall()
            items = conn.execute(
                """SELECT i.item_id, i.item_code, i.item_name, u.unit_name FROM items i
                   JOIN units u ON u.unit_id = i.unit_id WHERE i.status = 'active'
                   AND i.item_id NOT IN (SELECT item_id FROM stocktake_records WHERE event_id = ?) ORDER BY i.item_code""",
                (event_id,),
            ).fetchall()
        can_add = self.role_allowed("admin", "inventory_officer")
        event_demo = ' <span class="badge demo">DEMO ONLY</span>' if event["is_demo"] else ""
        content = self.page_head("Stocktake detail", event["event_ref"] + (" · DEMO" if event["is_demo"] else ""),
                                 f"{event['location']} · {event['stocktake_date']} · Responsible officer: {event['officer_name']}",
                                 '<a class="button secondary" href="/reports?type=stocktake">Open reports</a>')
        content += f'<section class="panel" style="margin-bottom:18px"><div class="panel-head"><div><h2>Event information{event_demo}</h2><p>{esc(event["notes"] or "No event note recorded.")}</p></div><span class="badge">{len(records)} line(s)</span></div>'
        if event["is_demo"]:
            content += '<p class="note">This event and its counts are fictional demonstration records. Do not report them as actual DLC stock balances.</p>'
        if records:
            trs = "".join(
                f'<tr><td><strong>{esc(row["item_code_at_stocktake"])}</strong><span class="subcell">{esc(row["item_name_at_stocktake"])}</span></td>'
                f'<td>{esc(row["unit_at_stocktake"])}</td><td>{fmt_qty(row["bin_card_balance"])}</td><td>{fmt_qty(row["physical_qty"])}</td>'
                f'<td><span class="badge {"good" if row["variance"] == 0 else "warn"}">{"0" if row["variance"] == 0 else ("+" if row["variance"] > 0 else "") + fmt_qty(row["variance"])}</span></td>'
                f'<td>{fmt_money(row["unit_price_at_stocktake"])}</td><td>{fmt_money(row["stock_value_found"])}</td><td>{esc(row["remarks"] or "—")}</td></tr>' for row in records
            )
            content += '<div class="table-wrap"><table><thead><tr><th>Item</th><th>Unit</th><th>Bin card</th><th>Physical</th><th>Variance</th><th>Unit price</th><th>Value found</th><th>Remarks</th></tr></thead><tbody>' + trs + '</tbody></table></div>'
            total_value = sum(float(row["stock_value_found"]) for row in records)
            variance_lines = sum(1 for row in records if float(row["variance"]) != 0)
            content += f'<p class="hint" style="margin-top:14px">{variance_lines} line(s) require review · Total value found: <strong>{fmt_money(total_value)}</strong></p>'
        else:
            content += '<div class="empty"><strong>No item counts recorded</strong>Select an item and enter the bin-card balance, physical count and price.</div>'
        content += '</section>'
        if can_add:
            if items:
                options = [(row["item_id"], f'{row["item_code"]} · {row["item_name"]} ({row["unit_name"]})') for row in items]
                form_content = '<section class="panel"><div class="panel-head"><div><h2>Add a counted item</h2><p>One line per item in an event. Values are stored as a historical snapshot.</p></div></div>'
                form_content += f'<form method="post" action="/stocktakes/{event_id}"><div class="form-grid">{csrf_input(self.session)}{select_field("item_id", "Item", options)}'
                form_content += field("bin_card_balance", "Bin card balance", "", "number", True, ' min="0" step="0.01"')
                form_content += field("physical_qty", "Physical quantity", "", "number", True, ' min="0" step="0.01"')
                form_content += field("unit_price", "Unit price at stocktake (₦)", "", "number", True, ' min="0" step="0.01"')
                form_content += '<div class="calc-preview span-2"><div class="preview-box"><span>Variance preview</span><strong id="variance-preview">—</strong></div><div class="preview-box"><span>Value found preview</span><strong id="value-preview">—</strong></div></div>'
                form_content += '<div class="field span-2"><label for="remarks">Remarks</label><textarea id="remarks" name="remarks" maxlength="300" placeholder="Optional note for this item"></textarea></div></div>'
                form_content += '<div class="form-actions"><button type="submit">Save stocktake record</button><a class="button secondary" href="/stocktakes">Back to events</a></div></form>'
                form_content += '''<script>
const binInput=document.getElementById('bin_card_balance'), physicalInput=document.getElementById('physical_qty'), priceInput=document.getElementById('unit_price');
function preview(){const b=parseFloat(binInput.value),p=parseFloat(physicalInput.value),u=parseFloat(priceInput.value);document.getElementById('variance-preview').textContent=Number.isFinite(b)&&Number.isFinite(p)?((p-b>0?'+':'')+(p-b).toLocaleString(undefined,{maximumFractionDigits:2})):'—';document.getElementById('value-preview').textContent=Number.isFinite(p)&&Number.isFinite(u)?'₦'+(p*u).toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2}):'—';}
[binInput,physicalInput,priceInput].forEach(el=>el.addEventListener('input',preview));
</script></section>'''
            else:
                form_content = '<section class="panel"><div class="empty"><strong>No eligible items</strong>Create or activate an item before entering a count.</div></section>'
            content += form_content
        self.send_html(layout(self, "Stocktake detail", content, "stocktakes", notice=notice, error=error))

    def add_stocktake_record(self, event_id: int) -> None:
        if not self.role_allowed("admin", "inventory_officer"):
            self.forbidden()
            return
        form = self.read_form()
        if not self.need_csrf(form):
            return
        try:
            item_id = int(form.get("item_id", ""))
        except ValueError:
            self.stocktake_detail(event_id, error="Select an item from the register.")
            return
        def number(name: str, label: str) -> float | None:
            raw = form.get(name, "").strip()
            try:
                value = float(raw)
            except ValueError:
                raise ValueError(f"{label} must be a number.")
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{label} must be zero or greater.")
            return round(value, 2)
        try:
            bin_balance = number("bin_card_balance", "Bin card balance")
            physical = number("physical_qty", "Physical quantity")
            unit_price = number("unit_price", "Unit price")
        except ValueError as exc:
            self.stocktake_detail(event_id, error=str(exc))
            return
        remarks = form.get("remarks", "").strip()
        if len(remarks) > 300:
            self.stocktake_detail(event_id, error="Remarks must be 300 characters or less.")
            return
        with connect_db() as conn:
            event = conn.execute("SELECT * FROM stocktake_events WHERE event_id = ?", (event_id,)).fetchone()
            item = conn.execute(
                """SELECT i.item_id, i.item_code, i.item_name, i.status, u.unit_name FROM items i
                   JOIN units u ON u.unit_id = i.unit_id WHERE i.item_id = ?""", (item_id,)
            ).fetchone()
            if not event or not item or item["status"] != "active":
                self.stocktake_detail(event_id, error="Choose an active item and an existing stocktake event.")
                return
            if conn.execute("SELECT 1 FROM stocktake_records WHERE event_id = ? AND item_id = ?", (event_id, item_id)).fetchone():
                self.stocktake_detail(event_id, error="This item already has a record in this event.")
                return
            variance = round(physical - bin_balance, 2)
            stock_value = round(physical * unit_price, 2)
            cur = conn.execute(
                """INSERT INTO stocktake_records
                   (event_id, item_id, item_code_at_stocktake, item_name_at_stocktake, unit_at_stocktake,
                    bin_card_balance, physical_qty, variance, unit_price_at_stocktake, stock_value_found,
                    remarks, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (event_id, item_id, item["item_code"], item["item_name"], item["unit_name"], bin_balance,
                 physical, variance, unit_price, stock_value, remarks or None, self.user["user_id"]),
            )
            audit(conn, self.user, "created", "stocktake record", cur.lastrowid,
                  f"{event['event_ref']} · {item['item_code']} · variance {fmt_qty(variance)} · value {fmt_money(stock_value)}")
        self.redirect(f"/stocktakes/{event_id}?notice=Stocktake+record+saved")

    def report_data(self, report_type: str) -> tuple[list[str], list[list[object]], str]:
        with connect_db() as conn:
            if report_type == "items":
                rows = conn.execute(
                    """SELECT i.item_code, i.item_name, c.category_name, u.unit_name, s.supplier_name,
                              i.reorder_level, i.status, CASE WHEN i.is_demo=1 THEN 'DEMO' ELSE '' END AS demo
                       FROM items i JOIN categories c ON c.category_id=i.category_id JOIN units u ON u.unit_id=i.unit_id
                       LEFT JOIN suppliers s ON s.supplier_id=i.supplier_id ORDER BY i.item_code"""
                ).fetchall()
                headers = ["Item code", "Description", "Category", "Unit", "Supplier", "Authorized reorder level", "Status", "Data type"]
                data = [[r["item_code"], r["item_name"], r["category_name"], r["unit_name"], r["supplier_name"] or "",
                         "Not configured" if r["reorder_level"] is None else fmt_qty(r["reorder_level"]), r["status"], r["demo"]] for r in rows]
                note = "Item register and optional approved reorder thresholds."
            elif report_type == "stocktake":
                rows = conn.execute(
                    """SELECT e.event_ref, e.stocktake_date, e.location, e.officer_name,
                              r.item_code_at_stocktake, r.item_name_at_stocktake, r.unit_at_stocktake,
                              r.bin_card_balance, r.physical_qty, r.variance, r.unit_price_at_stocktake,
                              r.stock_value_found, r.remarks, CASE WHEN e.is_demo=1 THEN 'DEMO' ELSE '' END AS demo
                       FROM stocktake_events e JOIN stocktake_records r ON r.event_id=e.event_id
                       ORDER BY e.stocktake_date DESC, e.event_id DESC, r.item_code_at_stocktake"""
                ).fetchall()
                headers = ["Event", "Date", "Location", "Officer", "Item code", "Description", "Unit", "Bin card balance", "Physical quantity", "Variance", "Unit price", "Value found", "Remarks", "Data type"]
                data = [[r[k] for k in ("event_ref", "stocktake_date", "location", "officer_name", "item_code_at_stocktake", "item_name_at_stocktake", "unit_at_stocktake", "bin_card_balance", "physical_qty", "variance", "unit_price_at_stocktake", "stock_value_found", "remarks", "demo")] for r in rows]
                note = "All counts are retained under their event; historical values do not change when item details are updated."
            elif report_type in {"variance", "valuation"}:
                condition = "WHERE r.variance <> 0" if report_type == "variance" else ""
                rows = conn.execute(
                    f"""SELECT e.event_ref, e.stocktake_date, e.location, e.officer_name,
                               r.item_code_at_stocktake, r.item_name_at_stocktake, r.unit_at_stocktake,
                               r.bin_card_balance, r.physical_qty, r.variance, r.unit_price_at_stocktake,
                               r.stock_value_found, r.remarks, CASE WHEN e.is_demo=1 THEN 'DEMO' ELSE '' END AS demo
                        FROM stocktake_events e JOIN stocktake_records r ON r.event_id=e.event_id {condition}
                        ORDER BY e.stocktake_date DESC, e.event_id DESC, r.item_code_at_stocktake"""
                ).fetchall()
                headers = ["Event", "Date", "Location", "Officer", "Item code", "Description", "Unit", "Bin card balance", "Physical quantity", "Variance", "Unit price", "Value found", "Remarks", "Data type"]
                data = [[r[k] for k in ("event_ref", "stocktake_date", "location", "officer_name", "item_code_at_stocktake", "item_name_at_stocktake", "unit_at_stocktake", "bin_card_balance", "physical_qty", "variance", "unit_price_at_stocktake", "stock_value_found", "remarks", "demo")] for r in rows]
                note = "Variance = physical quantity − bin card balance." if report_type == "variance" else "Value found = physical quantity × unit price recorded for that stocktake line."
            elif report_type == "reorder":
                rows = conn.execute(latest_count_query() + " WHERE i.status='active' AND i.reorder_level IS NOT NULL ORDER BY i.item_name").fetchall()
                headers = ["Item code", "Description", "Category", "Unit", "Approved reorder level", "Latest physical quantity", "Latest stocktake date", "Review status", "Data type"]
                data = []
                for r in rows:
                    if r["physical_qty"] is None:
                        status = "No stocktake recorded"
                        latest_qty = "Not counted"
                    elif float(r["physical_qty"]) <= float(r["reorder_level"]):
                        status = "Review for replenishment"
                        latest_qty = fmt_qty(r["physical_qty"])
                    else:
                        status = "Above threshold"
                        latest_qty = fmt_qty(r["physical_qty"])
                    data.append([r["item_code"], r["item_name"], r["category_name"], r["unit_name"], fmt_qty(r["reorder_level"]), latest_qty, r["stocktake_date"] or "", status, "DEMO" if r["is_demo"] else ""])
                note = "Only items with an entered threshold appear here. The system does not create a default reorder quantity."
            else:
                raise ValueError("Choose a valid report type.")
        return headers, data, note

    def reports_page(self, query: dict[str, list[str]], notice: str | None = None) -> None:
        report_type = query.get("type", ["stocktake"])[0]
        titles = {"stocktake": "Stocktake summary", "variance": "Variance report", "valuation": "Stock valuation", "items": "Item register", "reorder": "Low-stock review"}
        if report_type not in titles:
            report_type = "stocktake"
        headers, rows, note = self.report_data(report_type)
        buttons = "".join(f'<a class="button {"" if key == report_type else "secondary"} small" href="/reports?type={key}">{label}</a>' for key, label in (("stocktake", "Stocktake"), ("variance", "Variance"), ("valuation", "Valuation"), ("items", "Items"), ("reorder", "Reorder review")))
        content = self.page_head("Inventory reporting", titles[report_type], "Review and export recorded inventory information. Reports use the values stored for each event.", f'<a class="button" href="/reports.csv?type={report_type}">Download CSV</a>')
        content += f'<section class="panel"><div class="toolbar">{buttons}<button class="button secondary small" type="button" onclick="window.print()">Print</button></div><p class="note">{esc(note)}</p>'
        if rows:
            trs = []
            for row in rows:
                cells = []
                for index, value in enumerate(row):
                    if headers[index] in {"Unit price", "Value found"}:
                        value = fmt_money(value)
                    elif headers[index] in {"Bin card balance", "Physical quantity", "Variance", "Approved reorder level", "Latest physical quantity"} and str(value) != "Not counted":
                        value = fmt_qty(value)
                    cells.append(f"<td>{esc(value if value is not None else '—')}</td>")
                trs.append("<tr>" + "".join(cells) + "</tr>")
            head_html = "".join(f"<th>{esc(column)}</th>" for column in headers)
            content += f'<div class="table-wrap"><table><thead><tr>{head_html}</tr></thead><tbody>{"".join(trs)}</tbody></table></div>'
        else:
            content += '<div class="empty" style="margin-top:15px"><strong>No records to show</strong>Records will appear here after the related items or stocktakes are saved.</div>'
        content += '</section>'
        self.send_html(layout(self, titles[report_type], content, "reports", notice=notice))

    def reports_csv(self, query: dict[str, list[str]]) -> None:
        report_type = query.get("type", ["stocktake"])[0]
        headers, rows, _note = self.report_data(report_type)
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(headers)
        for row in rows:
            writer.writerow([safe_csv_cell(value) for value in row])
        data = ("\ufeff" + output.getvalue()).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="CSC302_{report_type}_report.csv"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def settings_page(self, notice: str | None = None, error: str | None = None) -> None:
        if not self.role_allowed("admin"):
            self.forbidden()
            return
        with connect_db() as conn:
            categories = conn.execute("SELECT c.category_id, c.category_name, COUNT(i.item_id) AS item_count FROM categories c LEFT JOIN items i ON i.category_id=c.category_id GROUP BY c.category_id ORDER BY c.category_name").fetchall()
            units = conn.execute("SELECT u.unit_id, u.unit_name, COUNT(i.item_id) AS item_count FROM units u LEFT JOIN items i ON i.unit_id=u.unit_id GROUP BY u.unit_id ORDER BY u.unit_name").fetchall()
            suppliers = conn.execute("SELECT s.supplier_id, s.supplier_name, s.phone, s.email, COUNT(i.item_id) AS item_count FROM suppliers s LEFT JOIN items i ON i.supplier_id=s.supplier_id GROUP BY s.supplier_id ORDER BY s.supplier_name").fetchall()
        cat_list = "".join(f'<div class="review-row"><strong>{esc(r["category_name"])}</strong><span class="badge">{r["item_count"]} item(s)</span></div>' for r in categories)
        unit_list = "".join(f'<div class="review-row"><strong>{esc(r["unit_name"])}</strong><span class="badge">{r["item_count"]} item(s)</span></div>' for r in units)
        supp_list = "".join(f'<div class="review-row"><div><strong>{esc(r["supplier_name"])}</strong><p>{esc(r["phone"] or "No phone")}{" · " + esc(r["email"]) if r["email"] else ""}</p></div><span class="badge">{r["item_count"]} item(s)</span></div>' for r in suppliers) or '<p class="hint">No suppliers recorded. Supplier details are optional.</p>'
        content = self.page_head("System configuration", "Reference data and backup", "Maintain categories and units as records. Reorder levels remain optional until authorized.")
        content += f'''<section class="grid content-grid"><article class="panel"><div class="panel-head"><div><h2>Categories</h2><p>Four categories are confirmed for the project.</p></div></div><div class="stack">{cat_list}</div>
<form method="post" action="/settings" style="margin-top:17px">{csrf_input(self.session)}<input type="hidden" name="action" value="add_category">{field("category_name", "Add category", "", required=True, attrs=' maxlength="80"')}<button class="button small" type="submit">Add category</button></form></article>
<article class="panel"><div class="panel-head"><div><h2>Units of measure</h2><p>Initial values match the supplied stocktake form and can be extended.</p></div></div><div class="stack">{unit_list}</div>
<form method="post" action="/settings" style="margin-top:17px">{csrf_input(self.session)}<input type="hidden" name="action" value="add_unit">{field("unit_name", "Add unit", "", required=True, attrs=' maxlength="40"')}<button class="button small" type="submit">Add unit</button></form></article></section>
<section class="panel" style="margin-top:18px"><div class="panel-head"><div><h2>Suppliers</h2><p>Keep supplier details only where the Unit chooses to maintain them.</p></div></div><div class="stack">{supp_list}</div>
<form method="post" action="/settings" class="form-grid" style="margin-top:17px">{csrf_input(self.session)}<input type="hidden" name="action" value="add_supplier">{field("supplier_name", "Supplier name", "", required=True, attrs=' maxlength="120"')}{field("phone", "Phone (optional)", "", attrs=' maxlength="30"')}{field("email", "Email (optional)", "", "email", attrs=' maxlength="160"')}<div class="span-2"><button class="button small" type="submit">Add supplier</button></div></form></section>
<section class="panel" style="margin-top:18px"><div class="panel-head"><div><h2>Database backup</h2><p>Download a copy of the local SQLite database for controlled safekeeping.</p></div><a class="button secondary" href="/backup">Download database backup</a></div><p class="hint">Keep backup files in an approved location and test restoration before operational use.</p></section>'''
        self.send_html(layout(self, "System settings", content, "settings", notice=notice, error=error))

    def settings_post(self) -> None:
        if not self.role_allowed("admin"):
            self.forbidden()
            return
        form = self.read_form()
        if not self.need_csrf(form):
            return
        action = form.get("action", "")
        with connect_db() as conn:
            try:
                if action == "add_category":
                    name = form.get("category_name", "").strip()
                    if not name or len(name) > 80:
                        raise ValueError("Enter a category name of 1–80 characters.")
                    cur = conn.execute("INSERT INTO categories(category_name) VALUES (?)", (name,))
                    audit(conn, self.user, "created", "category", cur.lastrowid, name)
                elif action == "add_unit":
                    name = form.get("unit_name", "").strip()
                    if not name or len(name) > 40:
                        raise ValueError("Enter a unit name of 1–40 characters.")
                    cur = conn.execute("INSERT INTO units(unit_name) VALUES (?)", (name,))
                    audit(conn, self.user, "created", "unit", cur.lastrowid, name)
                elif action == "add_supplier":
                    name = form.get("supplier_name", "").strip()
                    phone = form.get("phone", "").strip()
                    email = form.get("email", "").strip()
                    if not name or len(name) > 120:
                        raise ValueError("Enter a supplier name of 1–120 characters.")
                    if email and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                        raise ValueError("Enter a valid supplier email address.")
                    cur = conn.execute("INSERT INTO suppliers(supplier_name, phone, email) VALUES (?, ?, ?)", (name, phone or None, email or None))
                    audit(conn, self.user, "created", "supplier", cur.lastrowid, name)
                else:
                    raise ValueError("Choose a valid reference-data action.")
            except DB_INTEGRITY_ERRORS:
                raise ValueError("A record with that name already exists.")
        self.redirect("/settings?notice=Reference+data+saved")

    def users_page(self, notice: str | None = None, error: str | None = None) -> None:
        if not self.role_allowed("admin"):
            self.forbidden()
            return
        with connect_db() as conn:
            rows = conn.execute("SELECT user_id, username, display_name, role, is_active, created_at FROM users ORDER BY display_name").fetchall()
        trs = []
        for row in rows:
            action = ""
            if row["user_id"] != self.user["user_id"]:
                verb = "Deactivate" if row["is_active"] else "Reactivate"
                action = f'''<div class="actions"><form method="post" action="/users">{csrf_input(self.session)}<input type="hidden" name="action" value="toggle"><input type="hidden" name="user_id" value="{row["user_id"]}"><button type="submit" class="button small secondary">{verb}</button></form>
<form class="inline-form" method="post" action="/users">{csrf_input(self.session)}<input type="hidden" name="action" value="reset_password"><input type="hidden" name="user_id" value="{row["user_id"]}"><input type="password" name="new_password" minlength="8" placeholder="New password" aria-label="Set a new password for {esc(row["username"])}" required><button type="submit" class="button small secondary">Reset</button></form></div>'''
            trs.append(f'<tr><td><strong>{esc(row["display_name"])}</strong><span class="subcell">{esc(row["username"])}</span></td><td>{esc(role_label(row["role"]))}</td><td><span class="badge {"good" if row["is_active"] else ""}">{"Active" if row["is_active"] else "Inactive"}</span></td><td>{esc(row["created_at"][:10])}</td><td>{action}</td></tr>')
        role_options = [(role, label) for role, label in ROLES.items()]
        content = self.page_head("Access control", "User accounts", "Create accounts for the three proposed roles. These role names describe the prototype and do not confirm formal University job titles.")
        content += f'''<section class="grid content-grid"><article class="panel"><div class="panel-head"><div><h2>Accounts</h2><p>Inactive accounts cannot sign in.</p></div></div><div class="table-wrap"><table><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Created</th><th></th></tr></thead><tbody>{"".join(trs)}</tbody></table></div></article>
<article class="panel"><div class="panel-head"><div><h2>Create an account</h2><p>Use a unique username and a password with at least eight characters.</p></div></div><form method="post" action="/users">{csrf_input(self.session)}<input type="hidden" name="action" value="create">{field("display_name", "Full name", "", required=True, attrs=' maxlength="120"')}{field("username", "Username", "", required=True, attrs=' minlength="3" maxlength="40"')}{select_field("role", "Role", role_options)}{field("password", "Temporary password", "", "password", True, ' minlength="8"')}<button type="submit">Create user</button></form></article></section>'''
        self.send_html(layout(self, "User accounts", content, "users", notice=notice, error=error))

    def users_post(self) -> None:
        if not self.role_allowed("admin"):
            self.forbidden()
            return
        form = self.read_form()
        if not self.need_csrf(form):
            return
        action = form.get("action", "")
        with connect_db() as conn:
            if action == "create":
                username = form.get("username", "").strip()
                display_name = form.get("display_name", "").strip()
                role = form.get("role", "")
                password = form.get("password", "")
                if not re.fullmatch(r"[A-Za-z0-9._-]{3,40}", username):
                    raise ValueError("Choose a username using 3–40 letters, numbers, dots, underscores or hyphens.")
                if not display_name or len(display_name) > 120:
                    raise ValueError("Enter a full name of 1–120 characters.")
                if role not in ROLES:
                    raise ValueError("Choose one of the three available roles.")
                if len(password) < 8:
                    raise ValueError("Choose a temporary password with at least 8 characters.")
                salt, digest = hash_password(password)
                try:
                    cur = conn.execute("INSERT INTO users(username, display_name, role, password_salt, password_hash) VALUES (?, ?, ?, ?, ?)",
                                       (username, display_name, role, salt, digest))
                except DB_INTEGRITY_ERRORS:
                    raise ValueError("That username is already in use.")
                audit(conn, self.user, "created", "user", cur.lastrowid, f"{username} ({role})")
            elif action == "toggle":
                try:
                    target_id = int(form.get("user_id", ""))
                except ValueError:
                    raise ValueError("Choose an account to update.")
                if target_id == self.user["user_id"]:
                    raise ValueError("You cannot deactivate your own account.")
                target = conn.execute("SELECT username, is_active FROM users WHERE user_id=?", (target_id,)).fetchone()
                if not target:
                    raise ValueError("That account could not be found.")
                new_state = 0 if target["is_active"] else 1
                conn.execute("UPDATE users SET is_active=?, updated_at=CURRENT_TIMESTAMP WHERE user_id=?", (new_state, target_id))
                audit(conn, self.user, "reactivated" if new_state else "deactivated", "user", target_id, target["username"])
            elif action == "reset_password":
                try:
                    target_id = int(form.get("user_id", ""))
                except ValueError:
                    raise ValueError("Choose an account to update.")
                password = form.get("new_password", "")
                if len(password) < 8:
                    raise ValueError("Choose a new password with at least 8 characters.")
                target = conn.execute("SELECT username FROM users WHERE user_id=?", (target_id,)).fetchone()
                if not target:
                    raise ValueError("That account could not be found.")
                salt, digest = hash_password(password)
                conn.execute("UPDATE users SET password_salt=?, password_hash=?, updated_at=CURRENT_TIMESTAMP WHERE user_id=?", (salt, digest, target_id))
                audit(conn, self.user, "reset password", "user", target_id, target["username"])
            else:
                raise ValueError("Choose a valid account action.")
        self.redirect("/users?notice=User+account+updated")

    def audit_page(self) -> None:
        if not self.role_allowed("admin"):
            self.forbidden()
            return
        with connect_db() as conn:
            rows = conn.execute("SELECT * FROM audit_log ORDER BY audit_id DESC LIMIT 150").fetchall()
        if rows:
            trs = "".join(f'<tr><td>{esc(r["created_at"])}</td><td>{esc(r["actor_name"])}</td><td>{esc(r["action"])}</td><td>{esc(r["entity"])}</td><td>{esc(r["entity_id"] or "—")}</td><td>{esc(r["details"] or "—")}</td></tr>' for r in rows)
            table = f'<div class="table-wrap"><table><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Record type</th><th>ID</th><th>Details</th></tr></thead><tbody>{trs}</tbody></table></div>'
        else:
            table = '<div class="empty"><strong>No audit entries yet</strong>Important record changes will appear here.</div>'
        content = self.page_head("System oversight", "Audit log", "Recent account, reference-data, item and stocktake changes are recorded for review.")
        content += f'<section class="panel">{table}</section>'
        self.send_html(layout(self, "Audit log", content, "audit"))

    def backup_database(self) -> None:
        if not self.role_allowed("admin"):
            self.forbidden()
            return
        if DATABASE_URL:
            content = self.page_head("Database backup", "Cloud backup", "Database backups and restore points are managed from the Neon project console.")
            content += '<section class="panel"><p>Use the Neon project’s Backup &amp; Restore page to review available restore points. This prototype does not export a cloud database dump from the public application.</p></section>'
            self.send_html(layout(self, "Cloud backup", content, "audit"))
            return
        memory = sqlite3.connect(":memory:")
        with connect_db() as source:
            source.backup(memory)
        data = memory.serialize()
        memory.close()
        filename = f"CSC302_Group_A43_inventory_backup_{date.today().isoformat()}.sqlite3"
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.sqlite3")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def safe_csv_cell(value: object) -> object:
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def run() -> None:
    initialize_database()
    server = ThreadingHTTPServer((HOST, PORT), InventoryHandler)
    print(f"CSC302 Group A43 Inventory System running at http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop the local server.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down the local server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    run()


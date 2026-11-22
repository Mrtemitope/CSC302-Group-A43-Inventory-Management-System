# Inventory Management System Prototype

This browser-based prototype implements the first release described in the Group A43 CSC 302 design report. It runs locally with SQLite and can use Neon PostgreSQL when deployed as Vercel Python functions.

## Start it

On Windows, double-click `run_demo.bat`. Or open a terminal in this folder and run:

```powershell
python app.py
```

Then visit [http://127.0.0.1:8000](http://127.0.0.1:8000). The database is created at `data/inventory.db` on first run and keeps saved records between restarts.

## Included functions

- Secure sign-in with the proposed administrator, inventory officer and procurement officer roles.
- Item creation, search, editing and deactivation, with unique item codes and category, unit and optional supplier references.
- Extensible category and unit lists. The four confirmed categories and the six units named in the supplied form are seeded.
- Stocktake events fixed to Morohundiya Store, with one count record per item per event.
- Separate bin-card and physical quantities, non-negative numeric validation, live calculation preview, stored variance and value found.
- Historical snapshots of item code, description, unit, unit price and stock value.
- Authorized reorder-level entry and a review list based on the latest physical count. No default threshold is invented.
- Item, stocktake, variance, valuation and low-stock reports, with CSV download and print support.
- Audit history and a downloadable SQLite backup.

## Demo access

| Role | Username | Password |
| --- | --- | --- |
| System Administrator | `admin` | `admin123` |
| Store / Inventory Officer | `officer` | `officer123` |
| Procurement Officer | `procurement` | `procurement123` |

The default run includes fictional `DEMO` items and one `DEMO` stocktake so the group can show reports and variance calculations without presenting invented data as current institutional stock. In demo mode, new items and stocktake events are also marked as demonstration records.

## Clean database without demo records

In PowerShell, choose a new database path before starting the application:

```powershell
$env:CSC302_DEMO_MODE = "0"
$env:CSC302_DB_PATH = "C:\path\to\a\new\inventory.db"
python app.py
```

The first-time page creates the initial administrator. Keep the application on `127.0.0.1` for the classroom prototype. Do not use the demo accounts or this local server for real institutional records.

## Run the automated checks

From this folder, run:

```powershell
python -m unittest discover -s tests -v
```

The checks use a temporary database. They cover the officer sign-in flow, item creation, stocktake entry, variance/value calculations, report output and duplicate item-code validation.

## Files

- `app.py` — request handling, access control, validation, calculations and reports.
- `schema.sql` — relational tables, foreign keys, uniqueness rules and indexes.
- `static/styles.css` — responsive user interface styling.
- `run_demo.bat` — Windows launch shortcut.
- `data/` — created automatically at runtime; do not include local database files in a public repository or submission ZIP unless the group intends to share the demo data.

## Hosted deployment

The Vercel adapter is in `api/index.py`. Set `DATABASE_URL` to the Neon pooled PostgreSQL connection string. The first serverless start creates the PostgreSQL schema and seeds fictional demo records. Set these Vercel environment variables before the first deployment:

- `DATABASE_URL` — Neon pooled PostgreSQL connection string; keep it out of Git.
- `CSC302_DEMO_MODE=1` — enables the fictional sample dataset.
- `CSC302_ADMIN_PASSWORD`, `CSC302_OFFICER_PASSWORD`, `CSC302_PROCUREMENT_PASSWORD` — three unique passwords for the demo roles. The public sign-in page never displays these values.

The application stores sessions in PostgreSQL when `DATABASE_URL` is set, so sign-in survives different serverless function instances. PostgreSQL backups and restore points are managed in the Neon console. The downloadable SQLite backup is available only when running locally.

For local PostgreSQL development, copy `.env.example` to `.env` and fill in local values, then start `python app.py`. When `DATABASE_URL` is absent, the application uses the local SQLite database and the documented classroom demo accounts.

Vercel project settings should use this repository root as the project root. `vercel.json` routes the browser pages through the Python handler while static CSS is served from `static/`.


"""Vercel serverless adapter for the coursework HTTP application."""

from __future__ import annotations

import sys
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

import app as inventory_app  # noqa: E402

inventory_app.initialize_database()


class handler(inventory_app.InventoryHandler):
    """Reuse the same routes with Vercel's Python HTTP handler interface."""



import http.cookiejar
import re
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from pathlib import Path

import app


class InventoryFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        app.DATA_DIR = Path(self.temp.name)
        app.DB_PATH = app.DATA_DIR / "test_inventory.db"
        app.DEMO_MODE = True
        with app.SESSION_LOCK:
            app.SESSIONS.clear()
        app.initialize_database()
        self.server = app.ThreadingHTTPServer(("127.0.0.1", 0), app.InventoryHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, path, data=None):
        request = urllib.request.Request(self.base + path, data=data)
        with self.opener.open(request, timeout=5) as response:
            return response.status, response.read().decode("utf-8")

    def csrf(self, page):
        match = re.search(r'name="csrf" value="([^"]+)"', page)
        self.assertIsNotNone(match, "A CSRF token should be present on signed-in forms.")
        return match.group(1)

    def sign_in_as_officer(self):
        _, page = self.request("/login")
        token = self.csrf(page)
        payload = urllib.parse.urlencode({"csrf": token, "username": "officer", "password": "officer123"}).encode()
        _, dashboard = self.request("/login", payload)
        self.assertIn("Inventory overview", dashboard)
        return dashboard

    def test_officer_can_create_item_and_save_calculated_stocktake(self):
        dashboard = self.sign_in_as_officer()
        token = self.csrf(dashboard)
        with app.connect_db() as conn:
            category_id = conn.execute("SELECT category_id FROM categories WHERE category_name='Stationery and Printing'").fetchone()[0]
            unit_id = conn.execute("SELECT unit_id FROM units WHERE unit_name='Each'").fetchone()[0]

        item_form = urllib.parse.urlencode({
            "csrf": token,
            "item_code": "TEST-001",
            "item_name": "Automated flow test item",
            "category_id": category_id,
            "unit_id": unit_id,
            "supplier_id": "",
            "reorder_level": "",
        }).encode()
        _, items_page = self.request("/items/new", item_form)
        self.assertIn("Item saved", items_page)
        self.assertIn("TEST-001", items_page)

        token = self.csrf(items_page)
        event_form = urllib.parse.urlencode({"csrf": token, "stocktake_date": "2026-11-21", "notes": "Automated flow test"}).encode()
        _, event_page = self.request("/stocktakes/new", event_form)
        event_match = re.search(r'action="/stocktakes/(\d+)"', event_page)
        self.assertIsNotNone(event_match)
        event_id = event_match.group(1)

        _, detail = self.request(f"/stocktakes/{event_id}")
        token = self.csrf(detail)
        with app.connect_db() as conn:
            item_id = conn.execute("SELECT item_id FROM items WHERE item_code='TEST-001'").fetchone()[0]
        record_form = urllib.parse.urlencode({
            "csrf": token,
            "item_id": item_id,
            "bin_card_balance": "12",
            "physical_qty": "10",
            "unit_price": "250",
            "remarks": "Automated flow test",
        }).encode()
        _, detail = self.request(f"/stocktakes/{event_id}", record_form)
        self.assertIn("-2", detail)
        self.assertIn("₦2,500.00", detail)

        _, report = self.request("/reports?type=variance")
        self.assertIn("TEST-001", report)
        self.assertIn("-2", report)

    def test_duplicate_item_code_is_rejected(self):
        dashboard = self.sign_in_as_officer()
        token = self.csrf(dashboard)
        with app.connect_db() as conn:
            category_id = conn.execute("SELECT category_id FROM categories LIMIT 1").fetchone()[0]
            unit_id = conn.execute("SELECT unit_id FROM units LIMIT 1").fetchone()[0]
        payload = urllib.parse.urlencode({
            "csrf": token,
            "item_code": "DEMO-STA-001",
            "item_name": "Duplicate code attempt",
            "category_id": category_id,
            "unit_id": unit_id,
            "supplier_id": "",
            "reorder_level": "",
        }).encode()
        _, page = self.request("/items/new", payload)
        self.assertIn("already in use", page)


if __name__ == "__main__":
    unittest.main()


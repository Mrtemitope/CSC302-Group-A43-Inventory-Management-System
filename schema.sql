PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS categories (
    category_id INTEGER PRIMARY KEY,
    category_name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS units (
    unit_id INTEGER PRIMARY KEY,
    unit_name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS suppliers (
    supplier_id INTEGER PRIMARY KEY,
    supplier_name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    phone TEXT,
    email TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'inventory_officer', 'procurement_officer')),
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS items (
    item_id INTEGER PRIMARY KEY,
    item_code TEXT NOT NULL UNIQUE COLLATE NOCASE,
    item_name TEXT NOT NULL,
    category_id INTEGER NOT NULL REFERENCES categories(category_id),
    unit_id INTEGER NOT NULL REFERENCES units(unit_id),
    supplier_id INTEGER REFERENCES suppliers(supplier_id) ON DELETE SET NULL,
    reorder_level REAL CHECK (reorder_level IS NULL OR reorder_level >= 0),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    is_demo INTEGER NOT NULL DEFAULT 0 CHECK (is_demo IN (0, 1)),
    created_by INTEGER REFERENCES users(user_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by INTEGER REFERENCES users(user_id),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS stocktake_events (
    event_id INTEGER PRIMARY KEY,
    event_ref TEXT NOT NULL UNIQUE COLLATE NOCASE,
    stocktake_date TEXT NOT NULL,
    officer_id INTEGER REFERENCES users(user_id),
    officer_name TEXT NOT NULL,
    location TEXT NOT NULL DEFAULT 'Morohundiya Store',
    notes TEXT,
    is_demo INTEGER NOT NULL DEFAULT 0 CHECK (is_demo IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS stocktake_records (
    record_id INTEGER PRIMARY KEY,
    event_id INTEGER NOT NULL REFERENCES stocktake_events(event_id) ON DELETE CASCADE,
    item_id INTEGER NOT NULL REFERENCES items(item_id),
    item_code_at_stocktake TEXT NOT NULL,
    item_name_at_stocktake TEXT NOT NULL,
    unit_at_stocktake TEXT NOT NULL,
    bin_card_balance REAL NOT NULL CHECK (bin_card_balance >= 0),
    physical_qty REAL NOT NULL CHECK (physical_qty >= 0),
    variance REAL NOT NULL,
    unit_price_at_stocktake REAL NOT NULL CHECK (unit_price_at_stocktake >= 0),
    stock_value_found REAL NOT NULL CHECK (stock_value_found >= 0),
    remarks TEXT,
    created_by INTEGER REFERENCES users(user_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (event_id, item_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id INTEGER PRIMARY KEY,
    actor_id INTEGER REFERENCES users(user_id),
    actor_name TEXT NOT NULL,
    action TEXT NOT NULL,
    entity TEXT NOT NULL,
    entity_id TEXT,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_items_category ON items(category_id);
CREATE INDEX IF NOT EXISTS idx_items_status ON items(status);
CREATE INDEX IF NOT EXISTS idx_stocktake_event_date ON stocktake_events(stocktake_date);
CREATE INDEX IF NOT EXISTS idx_stocktake_record_item ON stocktake_records(item_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);


import sqlite3
import os

DB_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'dns_threat_monitor.db')

TABLES = [
    "dns_logs",
    "alerts",
    "alert_history",
    "threat_cache",
    "dns_log_ips",
    "threat_feeds",
    "rules",
    "alert_rules",
]


def print_separator(char="=", width=70):
    print(char * width)


def inspect(limit=10):
    if not os.path.exists(DB_FILE):
        print(f"Database file not found: {DB_FILE}")
        return

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    print_separator()
    print(f"DATABASE: {DB_FILE}")
    print_separator()

    for table in TABLES:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]

            print(f"\nTABLE: {table}  ({count} rows)")
            print_separator("-")

            if count == 0:
                print("  (empty)")
                continue

            cursor.execute(f"SELECT * FROM {table} LIMIT {limit}")
            rows = cursor.fetchall()
            cols = rows[0].keys()

            col_widths = {col: max(len(col), max(len(str(row[col])) for row in rows)) for col in cols}
            col_widths = {col: min(w, 40) for col, w in col_widths.items()}

            header = "  " + "  ".join(col.ljust(col_widths[col]) for col in cols)
            print(header)
            print("  " + "  ".join("-" * col_widths[col] for col in cols))

            for row in rows:
                line = "  " + "  ".join(str(row[col])[:col_widths[col]].ljust(col_widths[col]) for col in cols)
                print(line)

            if count > limit:
                print(f"  ... and {count - limit} more rows (showing first {limit})")

        except sqlite3.Error as e:
            print(f"  Error reading {table}: {e}")

    print_separator()
    conn.close()


if __name__ == "__main__":
    inspect()

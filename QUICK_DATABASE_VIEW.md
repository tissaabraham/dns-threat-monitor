# Quick Commands to View Database Structure

## Option 1: Run the Inspector Script (RECOMMENDED) ⭐

**The script is located in the `database/` subfolder**

### Method A: Navigate to database folder first
```powershell
cd "C:\Users\Tissa Abraham\MyGitRepo\dns-threat-monitor\database"
python inspect_db.py
```

### Method B: Run directly with full path (No cd needed) ✅ EASIEST
```powershell
python "C:\Users\Tissa Abraham\MyGitRepo\dns-threat-monitor\database\inspect_db.py"
```

⚠️ **Important Notes:**
- Use **quotes** around the path because of spaces in "Tissa Abraham"
- The script is in the **`database/`** subfolder (not root)
- Use the **full path** to `database/inspect_db.py`

This will show:
- ✅ All tables with row counts
- ✅ Columns, types, and constraints
- ✅ Indexes and foreign keys
- ✅ Database statistics

---

## Option 2: Run Python One-Liner

```powershell
cd "C:\Users\Tissa Abraham\MyGitRepo\dns-threat-monitor"
python -c "
import sqlite3
conn = sqlite3.connect('dns_threat_monitor.db')
cursor = conn.cursor()
cursor.execute(\"SELECT name FROM sqlite_master WHERE type='table'\")
for table in cursor.fetchall():
    print(f'\\nTable: {table[0]}')
    cursor.execute(f'PRAGMA table_info({table[0]})')
    for col in cursor.fetchall():
        print(f'  {col[1]}: {col[2]}')
conn.close()
"
```

⚠️ **Note:** Use **quotes** around the path because of spaces in "Tissa Abraham"

---

## Option 3: Use SQLite Command Line

```powershell
cd "C:\Users\Tissa Abraham\MyGitRepo\dns-threat-monitor"

# If SQLite3 is installed:
sqlite3 dns_threat_monitor.db

# Then in SQLite prompt:
# .schema              # Shows all tables
# .tables              # Lists all tables
# PRAGMA table_info(dns_logs);  # Shows columns for specific table
# .quit                # Exit
```

⚠️ **Note:** Use **quotes** around the path because of spaces in "Tissa Abraham"

---

## Option 4: Python Interactive Shell

```powershell
cd "C:\Users\Tissa Abraham\MyGitRepo\dns-threat-monitor"
python

# Inside Python:
import sqlite3
conn = sqlite3.connect('dns_threat_monitor.db')
cursor = conn.cursor()

# View all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
print(cursor.fetchall())

# View schema for dns_logs
cursor.execute("PRAGMA table_info(dns_logs)")
print(cursor.fetchall())

# View row counts
cursor.execute("SELECT COUNT(*) FROM dns_logs")
print(f"dns_logs rows: {cursor.fetchone()[0]}")

conn.close()
```

⚠️ **Note:** Use **quotes** around the path because of spaces in "Tissa Abraham"

---

## Option 5: Visual Database Browser

Download **DB Browser for SQLite**: https://sqlitebrowser.org/

Then:
1. Open DB Browser
2. File → Open Database
3. Navigate to: `C:\Users\Tissa Abraham\MyGitRepo\dns-threat-monitor\dns_threat_monitor.db`
4. View all tables graphically with column details

---

## Database Tables Overview

Your database has 4 main tables:

### 1. dns_logs
- Stores all DNS queries captured from network
- Fields: timestamp, source_ip, domain, query_type, response_code, resolved_ips, threat_score
- Indexed on: timestamp, domain

### 2. alerts
- Stores alerts generated when threats detected
- Fields: dns_log_id, timestamp, source_ip, domain, severity, threat_score, rules_triggered, status
- Foreign key to dns_logs
- Indexed on: timestamp, status

### 3. alert_history
- Tracks all status changes of alerts
- Fields: alert_id, old_status, new_status, timestamp, notes
- Foreign key to alerts
- Indexed on: timestamp

### 4. threat_cache
- Caches known malicious domains
- Fields: domain, source, threat_type, last_updated
- Indexed on: domain (UNIQUE)

---

---

## Run Inspector Now

### 🚀 **COPY AND PASTE THIS COMMAND (Fastest Way):**

```powershell
python "C:\Users\Tissa Abraham\MyGitRepo\dns-threat-monitor\database\inspect_db.py"
```

This will give you a complete, formatted report of your entire database structure!

---

## ⚠️ Important Notes

### File Location
The `inspect_db.py` script is in the **`database/`** subfolder:
```
dns-threat-monitor/
├── database/
│   ├── inspect_db.py          ← HERE
│   ├── database.py
│   └── ...
└── ...
```

**Do NOT** look for it in the root directory!

### Path with Spaces
Since your username "Tissa Abraham" contains a space:

```powershell
# ❌ WRONG - Will fail with "No such file or directory"
python "C:\Users\Tissa Abraham\MyGitRepo\dns-threat-monitor\inspect_db.py"

# ✅ CORRECT - Include database/ folder in path
python "C:\Users\Tissa Abraham\MyGitRepo\dns-threat-monitor\database\inspect_db.py"

# ❌ WRONG - No quotes (won't work due to space)
cd C:\Users\Tissa Abraham\MyGitRepo\dns-threat-monitor

# ✅ CORRECT - With quotes
cd "C:\Users\Tissa Abraham\MyGitRepo\dns-threat-monitor"
```

---

## Summary

✅ **Always use:**
1. **Full path** with `database/` folder included
2. **Quotes** around paths with spaces
3. **Exact filename** `inspect_db.py`

```powershell
python "C:\Users\Tissa Abraham\MyGitRepo\dns-threat-monitor\database\inspect_db.py"
```


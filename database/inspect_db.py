#!/usr/bin/env python3
"""
DNS Threat Monitor - Database Schema Inspector
===============================================

This script displays the complete database structure including:
- All tables with row counts
- Column definitions and types
- Indexes and foreign keys
- Database statistics
- Sample data (optional)

Usage:
    python inspect_db.py              # Show complete schema
    python inspect_db.py --stats-only # Show only statistics
    python inspect_db.py --sample     # Show schema + sample data
"""

import sqlite3
import os
import sys
from datetime import datetime

class DatabaseInspector:
    def __init__(self, db_path):
        self.db_path = db_path
        if not os.path.exists(db_path):
            print(f"Error: Database file not found at {db_path}")
            sys.exit(1)
        
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
    
    def print_header(self, title, width=100):
        """Print a formatted section header"""
        print("\n" + "=" * width)
        print(f"  {title}".ljust(width - 2))
        print("=" * width)
    
    def print_subheader(self, title, width=100):
        """Print a formatted subsection header"""
        print("\n" + "-" * width)
        print(f"  {title}")
        print("-" * width)
    
    def show_statistics(self):
        """Display database statistics"""
        self.print_header("DATABASE STATISTICS")
        
        # Database file info
        file_size = os.path.getsize(self.db_path)
        created_time = os.path.getctime(self.db_path)
        modified_time = os.path.getmtime(self.db_path)
        
        print(f"\n  📁 File Information:")
        print(f"     Path:     {self.db_path}")
        print(f"     Size:     {file_size:,} bytes ({file_size/1024:.2f} KB)")
        print(f"     Created:  {datetime.fromtimestamp(created_time).strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"     Modified: {datetime.fromtimestamp(modified_time).strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Get all tables and row counts
        self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in self.cursor.fetchall()]
        
        total_rows = 0
        print(f"\n  📊 Table Statistics:")
        print(f"     Total Tables: {len(tables)}")
        
        table_stats = []
        for table in tables:
            self.cursor.execute(f"SELECT COUNT(*) FROM {table};")
            count = self.cursor.fetchone()[0]
            total_rows += count
            table_stats.append((table, count))
        
        print(f"     Total Rows:   {total_rows:,}\n")
        
        # Display table breakdown
        for table_name, row_count in table_stats:
            status = "✅" if row_count > 0 else "⏸️"
            print(f"     {status} {table_name:<30} {row_count:>8,} rows")
        
        # Get index count
        self.cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%';")
        index_count = self.cursor.fetchone()[0]
        print(f"\n  🔍 Indexes:")
        print(f"     Total:  {index_count}")
    
    def show_tables(self):
        """Display all tables"""
        self.print_header("TABLES OVERVIEW")
        
        self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in self.cursor.fetchall()]
        
        print(f"\nFound {len(tables)} table(s):\n")
        for i, table in enumerate(tables, 1):
            self.cursor.execute(f"SELECT COUNT(*) FROM {table};")
            count = self.cursor.fetchone()[0]
            print(f"  {i}. {table:<30} ({count:>6,} rows)")
    
    def show_table_schema(self, table_name):
        """Display schema for a specific table"""
        self.print_subheader(f"TABLE: {table_name.upper()}")
        
        # Get columns
        self.cursor.execute(f"PRAGMA table_info({table_name});")
        columns = self.cursor.fetchall()
        
        print(f"\nColumns ({len(columns)}):\n")
        print(f"  {'#':<3} {'Column':<20} {'Type':<15} {'NotNull':<8} {'Default':<12} {'PK':<3}")
        print("  " + "-" * 90)
        
        for col in columns:
            col_id, name, col_type, not_null, default, pk = col
            not_null_str = "✓" if not_null else "✗"
            pk_str = "✓" if pk else "✗"
            default_str = str(default) if default else "-"
            print(f"  {col_id:<3} {name:<20} {col_type:<15} {not_null_str:<8} {default_str:<12} {pk_str:<3}")
        
        # Get indexes for this table
        self.cursor.execute(f"PRAGMA index_list({table_name});")
        indexes = self.cursor.fetchall()
        
        if indexes:
            print(f"\nIndexes ({len(indexes)}):\n")
            for idx in indexes:
                idx_seq, idx_name, unique = idx[:3]
                unique_str = "UNIQUE" if unique else "normal"
                print(f"  • {idx_name:<40} ({unique_str})")
        
        # Get foreign keys
        self.cursor.execute(f"PRAGMA foreign_key_list({table_name});")
        fks = self.cursor.fetchall()
        
        if fks:
            print(f"\nForeign Keys ({len(fks)}):\n")
            for fk in fks:
                _, seq, ref_table, from_col, to_col, on_delete, on_update, match = fk
                print(f"  • {from_col:<20} → {ref_table}({to_col})")
        
        # Get row count
        self.cursor.execute(f"SELECT COUNT(*) FROM {table_name};")
        row_count = self.cursor.fetchone()[0]
        
        status = "✅" if row_count > 0 else "⏸️"
        print(f"\nRow Count: {status} {row_count:,}")
    
    def show_all_schemas(self):
        """Display schema for all tables"""
        self.print_header("DETAILED TABLE SCHEMAS")
        
        self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in self.cursor.fetchall()]
        
        for table in tables:
            self.show_table_schema(table)
    
    def show_indexes(self):
        """Display all indexes"""
        self.print_header("INDEXES")
        
        self.cursor.execute("""
            SELECT name, tbl_name FROM sqlite_master 
            WHERE type='index' AND name NOT LIKE 'sqlite_%'
            ORDER BY tbl_name, name
        """)
        indexes = self.cursor.fetchall()
        
        if indexes:
            print(f"\nFound {len(indexes)} index(es):\n")
            current_table = None
            for idx_name, tbl_name in indexes:
                if tbl_name != current_table:
                    print(f"\n  Table: {tbl_name}")
                    current_table = tbl_name
                print(f"    • {idx_name}")
        else:
            print("\nNo indexes found")
    
    def show_foreign_keys(self):
        """Display all foreign keys"""
        self.print_header("FOREIGN KEY RELATIONSHIPS")
        
        self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in self.cursor.fetchall()]
        
        found_any = False
        for table in tables:
            self.cursor.execute(f"PRAGMA foreign_key_list({table});")
            fks = self.cursor.fetchall()
            
            if fks:
                if not found_any:
                    found_any = True
                print(f"\n  Table: {table}")
                for fk in fks:
                    _, _, ref_table, from_col, to_col, on_delete, on_update, match = fk
                    print(f"    • {from_col} → {ref_table}({to_col})")
        
        if not found_any:
            print("\nNo foreign keys found")
    
    def show_sample_data(self, limit=3):
        """Display sample data from each table"""
        self.print_header("SAMPLE DATA FROM EACH TABLE")
        
        self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in self.cursor.fetchall()]
        
        for table in tables:
            self.print_subheader(f"Sample from {table} (limit {limit})")
            
            self.cursor.execute(f"SELECT COUNT(*) FROM {table};")
            total = self.cursor.fetchone()[0]
            
            if total == 0:
                print(f"\n  No data in this table")
                continue
            
            # Get column names and data
            self.cursor.row_factory = sqlite3.Row
            self.cursor.execute(f"SELECT * FROM {table} LIMIT {limit}")
            rows = self.cursor.fetchall()
            
            if rows:
                rows_cursor = self.cursor.execute(f"SELECT * FROM {table} LIMIT {limit}")
                columns = [description[0] for description in rows_cursor.description]
                
                print(f"\n  Columns: {', '.join(columns)}\n")
                for i, row in enumerate(rows, 1):
                    print(f"  Row {i}:")
                    for col, val in zip(columns, row):
                        # Truncate long values
                        val_str = str(val)
                        if len(val_str) > 50:
                            val_str = val_str[:47] + "..."
                        print(f"    {col:<20} = {val_str}")
                    print()
    
    def show_sql_statements(self):
        """Display original CREATE TABLE statements"""
        self.print_header("ORIGINAL CREATE TABLE STATEMENTS")
        
        self.cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND sql IS NOT NULL;")
        tables = self.cursor.fetchall()
        
        for table_name, sql in tables:
            print(f"\n{sql}\n")
    
    def show_complete_report(self):
        """Display complete database report"""
        print(f"\n\n{'='*100}")
        print(f"{'DNS THREAT MONITOR - DATABASE INSPECTOR':^100}")
        print(f"{'Generated: ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^100}")
        print(f"{'='*100}")
        
        self.show_statistics()
        self.show_tables()
        self.show_all_schemas()
        self.show_indexes()
        self.show_foreign_keys()
        self.show_sql_statements()
        
        print(f"\n{'='*100}")
        print(f"{'Report Complete':^100}")
        print(f"{'='*100}\n")
    
    def close(self):
        """Close database connection"""
        self.conn.close()


def main():
    # Get database path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(script_dir, '..', 'dns_threat_monitor.db')
    db_path = os.path.normpath(db_path)
    
    # Check for command line arguments
    show_sample = '--sample' in sys.argv
    stats_only = '--stats-only' in sys.argv
    
    # Create inspector
    inspector = DatabaseInspector(db_path)
    
    # Display appropriate report
    if stats_only:
        inspector.show_statistics()
    elif show_sample:
        inspector.show_complete_report()
        inspector.show_sample_data(limit=5)
    else:
        inspector.show_complete_report()
    
    inspector.close()


if __name__ == "__main__":
    main()


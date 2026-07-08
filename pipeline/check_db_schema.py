import sqlite3
import os

DB_FILE = os.path.join(os.path.dirname(__file__), 'daily-data', 'scams.db')

def check_schema():
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"Tables in {DB_FILE}: {tables}")

        for table_name in tables:
            table_name = table_name[0]
            print(f"\nSchema for table: {table_name}")
            cursor.execute(f"PRAGMA table_info({table_name});")
            schema = cursor.fetchall()
            for col in schema:
                print(f"  Name: {col[1]}, Type: {col[2]}, NotNull: {bool(col[3])}, PK: {bool(col[5])}")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    check_schema()

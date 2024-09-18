import sqlite3

def view_database(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Query the users table
    cursor.execute("SELECT * FROM users")
    rows = cursor.fetchall()
    
    print("ID | Username | Password | MFA Secret")
    print("-" * 40)
    for row in rows:
        print(f"{row[0]} | {row[1]} | {row[2]} | {row[3]}")
    
    conn.close()

if __name__ == "__main__":
    view_database('mfa.db')

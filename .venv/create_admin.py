import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("complaints.db")
cursor = conn.cursor()

username = "admin"
password = generate_password_hash("admin123")

cursor.execute(
    "INSERT OR IGNORE INTO admins (username, password) VALUES (?, ?)",
    (username, password)
)

conn.commit()
conn.close()

print("Admin created: admin / admin123")

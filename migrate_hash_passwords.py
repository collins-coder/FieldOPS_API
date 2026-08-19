import MySQLdb
from werkzeug.security import generate_password_hash
from config import Config
 
 
def is_already_hashed(password_value):
    if not password_value:
        return False
 
    return password_value.startswith("pbkdf2:") or password_value.startswith("scrypt:")
 
 
def main():
    connection = MySQLdb.connect(
        host=Config.MYSQL_HOST,
        user=Config.MYSQL_USER,
        passwd=Config.MYSQL_PASSWORD,
        db=Config.MYSQL_DB
    )
 
    cursor = connection.cursor()
 
    try:
        cursor.execute("SELECT id, username, password FROM users")
        rows = cursor.fetchall()
 
        hashed_count = 0
        skipped_count = 0
 
        for user_id, username, password in rows:
 
            if is_already_hashed(password):
                skipped_count += 1
                continue
 
            new_hash = generate_password_hash(password)
 
            cursor.execute(
                "UPDATE users SET password = %s WHERE id = %s",
                (new_hash, user_id)
            )
 
            hashed_count += 1
            print(f"Hashed password for user '{username}' (id={user_id})")
 
        connection.commit()
 
        print("\nDone.")
        print(f"  Hashed:  {hashed_count}")
        print(f"  Skipped (already hashed): {skipped_count}")
        print(f"  Total rows: {len(rows)}")
 
    finally:
        cursor.close()
        connection.close()
 
 
if __name__ == "__main__":
    main()
 
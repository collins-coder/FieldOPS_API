from flask_mysqldb import MySQL

def save_log(mysql, action, payload, response, status, details):
    cur = mysql.connection.cursor()

    cur.execute("""
        INSERT INTO integration_logs
        (action, payload, response, status, details)
        VALUES (%s, %s, %s, %s, %s)
    """, (
        action,
        str(payload),
        str(response),
        status,
        details
    ))

    mysql.connection.commit()
    cur.close()

def get_failed_logs(mysql):
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT id, payload
        FROM integration_logs
        WHERE status = 'FAILED'
        AND retry_count < 3
    """)

    rows = cur.fetchall()
    cur.close()

    return rows

    
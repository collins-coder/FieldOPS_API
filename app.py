from flask import Flask, request, jsonify, send_file
from flask_mysqldb import MySQL
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)
from config import Config
from flask import request, send_file
import io
from datetime import datetime
import pandas as pd


# =====================================================
# APP SETUP
# =====================================================

app = Flask(__name__)
CORS(app)

app.config.from_object(Config)
app.config["JWT_SECRET_KEY"] = "fieldops_super_secret_key"

mysql = MySQL(app)
jwt = JWTManager(app)

# =====================================================
# SAFE USER FETCH FROM JWT (FIXED CORE ISSUE)
# =====================================================

def get_current_user():
    identity = get_jwt_identity()

    # identity is user_id (string or int)
    user_id = identity

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT id, username, role
        FROM users
        WHERE id = %s
    """, (user_id,))

    user = cur.fetchone()
    cur.close()

    if not user:
        return None

    return {
        "id": user[0],
        "username": user[1],
        "role": user[2]
    }

# =====================================================
# HOME
# =====================================================

@app.route("/")
def home():
    return "FieldOPS Running Successfully"

# =====================================================
# LOGIN
# =====================================================

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT id, username, role
        FROM users
        WHERE username = %s
        AND password = %s
        AND status = 'Active'
    """, (username, password))

    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({"message": "Invalid username or password"}), 401

    access_token = create_access_token(identity=str(user[0]))

    return jsonify({
        "message": "Login successful",
        "access_token": access_token,
        "username": user[1],
        "role": user[2]
    })

# =====================================================
# USERS MODULE
# =====================================================

@app.route("/admin/users", methods=["GET"])
@jwt_required()
def get_users():
    current_user = get_current_user()

    if not current_user or current_user["role"] not in ["admin", "developer"]:
        return jsonify({"message": "Access denied"}), 403

    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT id, username, email, role, status, created_at
        FROM users
        ORDER BY created_at DESC
    """)

    rows = cur.fetchall()
    cur.close()

    users = []
    for r in rows:
        users.append({
            "id": r[0],
            "username": r[1],
            "email": r[2],
            "role": r[3],
            "status": r[4],
            "created_at": str(r[5])
        })

    return jsonify(users)

@app.route("/admin/users", methods=["POST"])
@jwt_required()
def create_user():
    current_user = get_current_user()

    if not current_user or current_user["role"] not in ["admin", "developer"]:
        return jsonify({"message": "Access denied"}), 403

    data = request.get_json()

    cur = mysql.connection.cursor()

    cur.execute("""
        INSERT INTO users (username, email, password, role, status)
        VALUES (%s, %s, %s, %s, %s)
    """, (
        data["username"],
        data.get("email"),
        data["password"],
        data["role"],
        data.get("status", "Active")
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "User created successfully"})

@app.route("/admin/users/<int:user_id>", methods=["PUT"])
@jwt_required()
def update_user(user_id):
    current_user = get_current_user()

    if not current_user or current_user["role"] not in ["admin", "developer"]:
        return jsonify({"message": "Access denied"}), 403

    data = request.get_json()

    cur = mysql.connection.cursor()

    cur.execute("""
        UPDATE users
        SET username=%s, email=%s, role=%s, status=%s
        WHERE id=%s
    """, (
        data["username"],
        data.get("email"),
        data["role"],
        data["status"],
        user_id
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "User updated successfully"})

@app.route("/admin/users/<int:user_id>/status", methods=["PATCH"])
@jwt_required()
def toggle_user_status(user_id):
    current_user = get_current_user()

    if not current_user or current_user["role"] not in ["admin", "developer"]:
        return jsonify({"message": "Access denied"}), 403

    data = request.get_json()

    cur = mysql.connection.cursor()

    cur.execute("""
        UPDATE users
        SET status=%s
        WHERE id=%s
    """, (data["status"], user_id))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Status updated"})

@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    current_user = get_current_user()

    if not current_user or current_user["role"] != "admin":
        return jsonify({"message": "Access denied"}), 403

    cur = mysql.connection.cursor()

    cur.execute("DELETE FROM users WHERE id=%s", (user_id,))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "User deleted"})

# =====================================================
# CUSTOMERS MODULE
# =====================================================

@app.route("/customers", methods=["GET"])
@jwt_required()
def get_customers():
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT id, customer_code, customer_name, phone, email,
               location, route, credit_limit, status, created_by, created_at
        FROM customers
        ORDER BY created_at DESC
    """)

    rows = cur.fetchall()
    cur.close()

    customers = [{
        "id": r[0],
        "customer_code": r[1],
        "customer_name": r[2],
        "phone": r[3],
        "email": r[4],
        "location": r[5],
        "route": r[6],
        "credit_limit": float(r[7]) if r[7] else 0,
        "status": r[8],
        "created_by": r[9],
        "created_at": str(r[10])
    } for r in rows]

    return jsonify(customers)

@app.route("/customers", methods=["POST"])
@jwt_required()
def create_customer():
    data = request.get_json()
    current_user = get_current_user()

    cur = mysql.connection.cursor()

    cur.execute("""
        INSERT INTO customers
        (customer_code, customer_name, phone, email, location,
         route, credit_limit, status, created_by)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        data["customer_code"],
        data["customer_name"],
        data.get("phone"),
        data.get("email"),
        data.get("location"),
        data.get("route"),
        data.get("credit_limit", 0),
        data.get("status", "Active"),
        current_user["username"]
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Customer created successfully"})

@app.route("/customers/<int:customer_id>", methods=["PUT"])
@jwt_required()
def update_customer(customer_id):
    data = request.get_json()

    cur = mysql.connection.cursor()

    cur.execute("""
        UPDATE customers
        SET customer_name=%s, phone=%s, email=%s,
            location=%s, route=%s, credit_limit=%s, status=%s
        WHERE id=%s
    """, (
        data["customer_name"],
        data["phone"],
        data["email"],
        data["location"],
        data["route"],
        data["credit_limit"],
        data["status"],
        customer_id
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Customer updated"})

@app.route("/customers/<int:customer_id>", methods=["DELETE"])
@jwt_required()
def delete_customer(customer_id):
    cur = mysql.connection.cursor()

    cur.execute("DELETE FROM customers WHERE id=%s", (customer_id,))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Customer deleted"})

@app.route("/items", methods=["GET"])
@jwt_required()
def get_items():
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT id, item_code, name, category, price, stock, status, created_at
        FROM items
        ORDER BY created_at DESC
    """)

    rows = cur.fetchall()
    cur.close()

    items = [{
        "id": r[0],
        "item_code": r[1],
        "name": r[2],
        "category": r[3],
        "price": float(r[4]),
        "stock": r[5],
        "status": r[6],
        "created_at": str(r[7])
    } for r in rows]

    return jsonify(items)

@app.route("/items", methods=["POST"])
@jwt_required()
def create_item():
    data = request.get_json()

    cur = mysql.connection.cursor()

    cur.execute("""
        INSERT INTO items (item_code, name, category, price, stock, status)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        data["item_code"],
        data["name"],
        data.get("category"),
        data.get("price", 0),
        data.get("stock", 0),
        data.get("status", "Active")
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Item created successfully"})

@app.route("/items/<int:item_id>", methods=["PUT"])
@jwt_required()
def update_item(item_id):
    data = request.get_json()

    cur = mysql.connection.cursor()

    cur.execute("""
        UPDATE items
        SET item_code=%s,
            name=%s,
            category=%s,
            price=%s,
            stock=%s,
            status=%s
        WHERE id=%s
    """, (
        data["item_code"],
        data["name"],
        data.get("category"),
        data.get("price"),
        data.get("stock"),
        data.get("status"),
        item_id
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Item updated"})

@app.route("/items/<int:item_id>", methods=["DELETE"])
@jwt_required()
def delete_item(item_id):
    cur = mysql.connection.cursor()

    cur.execute("DELETE FROM items WHERE id=%s", (item_id,))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Item deleted"})



# =====================================================
# INVOICES
# =====================================================

@app.route("/admin/invoices", methods=["GET"])
@jwt_required()
def get_invoices():
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT id, invoice_number, customer_name,
               invoice_amount, due_date, status, created_at
        FROM invoices
        ORDER BY created_at DESC
    """)

    rows = cur.fetchall()
    cur.close()

    return jsonify([{
        "id": r[0],
        "invoice_number": r[1],
        "customer_name": r[2],
        "invoice_amount": float(r[3]),
        "due_date": str(r[4]),
        "status": r[5],
        "created_at": str(r[6])
    } for r in rows])

@app.route("/create-invoice", methods=["POST"])
@jwt_required()
def create_invoice():
    data = request.get_json()

    cur = mysql.connection.cursor()

    cur.execute("""
        INSERT INTO invoices
        (invoice_number, customer_name, sales_order_id,
         invoice_amount, due_date, status)
        VALUES (%s,%s,%s,%s,%s,%s)
    """, (
        data["invoice_number"],
        data["customer_name"],
        data["sales_order_id"],
        data["invoice_amount"],
        data["due_date"],
        "Pending"
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Invoice created"})

# =====================================================
# PAYMENTS
# =====================================================

@app.route("/admin/payments", methods=["GET"])
@jwt_required()
def get_payments():
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT id, payment_reference, invoice_id,
               amount_paid, payment_method, payment_date,
               status, created_at
        FROM payments
        ORDER BY created_at DESC
    """)

    rows = cur.fetchall()
    cur.close()

    return jsonify([{
        "id": r[0],
        "payment_reference": r[1],
        "invoice_id": r[2],
        "amount_paid": float(r[3]),
        "payment_method": r[4],
        "payment_date": str(r[5]),
        "status": r[6],
        "created_at": str(r[7])
    } for r in rows])

# =====================================================
# LOGS
# =====================================================

@app.route("/admin/logs", methods=["GET"])
@jwt_required()
def get_logs():
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT id, action, payload, response,
               status, retry_count, created_at
        FROM integration_logs
        ORDER BY created_at DESC
    """)

    rows = cur.fetchall()
    cur.close()

    return jsonify([{
        "id": r[0],
        "action": r[1],
        "payload": r[2],
        "response": r[3],
        "status": r[4],
        "retry_count": r[5],
        "created_at": str(r[6])
    } for r in rows])

@app.route('/timesheet', methods=['GET'])
def get_timesheet():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = """
        SELECT user, date, start_time, end_time, status, logged_hours
        FROM timesheet
        WHERE 1=1
    """
    params = []

    if start_date:
        query += " AND date >= %s"
        params.append(start_date)

    if end_date:
        query += " AND date <= %s"
        params.append(end_date)

    query += " ORDER BY date DESC"

    cur = mysql.connection.cursor()
    cur.execute(query, params)
    rows = cur.fetchall()
    cur.close()
    data = [
        {
            "user": r[0],
            "date": r[1].strftime("%Y-%m-%d") if r[1] else None,
            "start_time": str(r[2]) if r[2] else None,
            "end_time": str(r[3]) if r[3] else None,
            "status": r[4],
            "logged_hours": float(r[5]) if r[5] else 0
        }
        for r in rows
    ]

    return jsonify(data)

@app.route('/timesheet/export', methods=['GET'])
def export_timesheet():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = """
        SELECT user, date, start_time, end_time, status, logged_hours
        FROM timesheet
        WHERE 1=1
    """
    params = []

    if start_date:
        query += " AND date >= %s"
        params.append(start_date)

    if end_date:
        query += " AND date <= %s"
        params.append(end_date)

    cur = mysql.connection.cursor()
    cur.execute(query, params)
    rows = cur.fetchall()
    cur.close()

    df = pd.DataFrame([
        {
            "User": r[0],
            "Date": r[1],
            "Start Time": r[2],
            "End Time": r[3],
            "Status": r[4],
            "Logged Hours": r[5]
        }
        for r in rows
    ])

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Timesheet")

    output.seek(0)

    return send_file(
        output,
        download_name="timesheet.xlsx",
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

@app.route("/trips", methods=["GET"])
def get_trips():
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT 
            t.id,
            t.trip_name,
            t.sales_rep_id,
            u.username AS sales_rep_name,
            t.region_id,
            r.name AS region_name,
            t.schedule_type,
            t.monthly_date,
            t.visit_all_customers,
            t.created_at
        FROM trips t
        LEFT JOIN users u ON u.id = t.sales_rep_id
        LEFT JOIN regions r ON r.id = t.region_id
        ORDER BY t.id DESC
    """)

    trips = cur.fetchall()

    result = []

    for t in trips:
        trip_id = t[0]

        # customers from existing relation table (NOW WITH NAMES)
        cur.execute("""
            SELECT c.id, c.customer_name
            FROM trip_customers tc
            JOIN customers c ON c.id = tc.customer_id
            WHERE tc.trip_id = %s
        """, (trip_id,))

        customers = [
            {
                "id": c[0],
                "name": c[1]
            }
            for c in cur.fetchall()
        ]

        result.append({
            "id": trip_id,
            "trip_name": t[1],
            "sales_rep_id": t[2],
            "sales_rep_name": t[3],
            "region_id": t[4],
            "region_name": t[5],
            "schedule_type": t[6],
            "monthly_date": t[7],
            "visit_all_customers": bool(t[8]),
            "customers": customers,
            "created_at": t[9]
        })

    cur.close()
    return jsonify(result)

@app.route('/trips', methods=['POST'])
def create_trip():
    data = request.json

    cur = mysql.connection.cursor()

    # 1. insert trip
    cur.execute("""
        INSERT INTO trips (
            trip_name,
            sales_rep_id,
            region_id,
            schedule_type,
            monthly_date,
            visit_all_customers
        )
        VALUES (%s,%s,%s,%s,%s,%s)
    """, (
        data.get("trip_name"),
        data.get("sales_rep_id"),
        data.get("region_id"),
        data.get("schedule_type"),
        data.get("monthly_date"),
        data.get("visit_all_customers", 0)
    ))

    trip_id = cur.lastrowid

    # 2. weekly schedule
    if data.get("schedule_type") == "weekly":
        for day in data.get("weekly_days", []):
            cur.execute("""
                INSERT INTO trip_weekly_schedule (trip_id, day_of_week)
                VALUES (%s, %s)
            """, (trip_id, day))

    # 3. customers (multi-select support)
    if not data.get("visit_all_customers", 0):
        for cust in data.get("customers", []):
            cur.execute("""
                INSERT INTO trip_customers (trip_id, customer_id)
                VALUES (%s, %s)
            """, (trip_id, cust))

    mysql.connection.commit()
    cur.close()

    return jsonify({
        "message": "Trip created successfully",
        "trip_id": trip_id
    }), 201

# =====================================================
# UPDATE TRIP
# =====================================================

@app.route("/trips/<int:trip_id>", methods=["PUT"])
def update_trip(trip_id):

    data = request.json

    cur = mysql.connection.cursor()

    # ================= UPDATE MAIN TRIP =================

    cur.execute("""
        UPDATE trips
        SET
            trip_name = %s,
            sales_rep_id = %s,
            region_id = %s,
            schedule_type = %s,
            monthly_date = %s,
            visit_all_customers = %s,
            status = %s
        WHERE id = %s
    """, (
        data.get("trip_name"),
        data.get("sales_rep_id"),
        data.get("region_id"),
        data.get("schedule_type"),
        data.get("monthly_date"),
        data.get("visit_all_customers", 0),
        data.get("status", "Active"),
        trip_id
    ))

    # ================= REMOVE OLD CUSTOMERS =================

    cur.execute("""
        DELETE FROM trip_customers
        WHERE trip_id = %s
    """, (trip_id,))

    # ================= ADD NEW CUSTOMERS =================

    if not data.get("visit_all_customers", 0):

        for cust in data.get("customers", []):

            cur.execute("""
                INSERT INTO trip_customers (trip_id, customer_id)
                VALUES (%s, %s)
            """, (trip_id, cust))

    mysql.connection.commit()
    cur.close()

    return jsonify({
        "message": "Trip updated successfully"
    }), 200


# =====================================================
# UPDATE TRIP STATUS
# =====================================================

@app.route("/trips/<int:trip_id>/status", methods=["PATCH"])
def update_trip_status(trip_id):

    data = request.json

    cur = mysql.connection.cursor()

    cur.execute("""
        UPDATE trips
        SET status = %s
        WHERE id = %s
    """, (
        data.get("status"),
        trip_id
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({
        "message": "Trip status updated"
    }), 200


# =====================================================
# DELETE TRIP
# =====================================================

@app.route("/trips/<int:trip_id>", methods=["DELETE"])
def delete_trip(trip_id):

    cur = mysql.connection.cursor()

    try:

        # ================= DELETE CHILD RECORDS FIRST =================

        cur.execute("""
            DELETE FROM trip_customers
            WHERE trip_id = %s
        """, (trip_id,))

        cur.execute("""
            DELETE FROM trip_weekly_schedule
            WHERE trip_id = %s
        """, (trip_id,))

        # ================= DELETE MAIN TRIP =================

        cur.execute("""
            DELETE FROM trips
            WHERE id = %s
        """, (trip_id,))

        mysql.connection.commit()

        return jsonify({
            "message": "Trip deleted successfully"
        }), 200

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": str(e)
        }), 500

    finally:

        cur.close()



@app.route('/visits', methods=['GET'])
def get_visits():
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    query = """
        SELECT 
            user,
            customer,
            route_name,
            time_in,
            time_out,
            duration,
            comment,
            status,
            visit_date
        FROM visits
        WHERE 1=1
    """

    params = []

    if start_date:
        query += " AND visit_date >= %s"
        params.append(start_date)

    if end_date:
        query += " AND visit_date <= %s"
        params.append(end_date)

    query += " ORDER BY visit_date DESC"

    cur = mysql.connection.cursor()
    cur.execute(query, params)
    rows = cur.fetchall()
    cur.close()

    data = [
        {
            "user": r[0],
            "customer": r[1],
            "route_name": r[2],
            "time_in": str(r[3]) if r[3] else None,
            "time_out": str(r[4]) if r[4] else None,
            "duration": r[5],
            "comment": r[6],
            "status": r[7],
            "visit_date": r[8].strftime("%Y-%m-%d") if r[8] else None
        }
        for r in rows
    ]

    return jsonify(data)

@app.route('/visits/export', methods=['GET'])
def export_visits():
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    query = """
        SELECT 
            user,
            customer,
            route_name,
            time_in,
            time_out,
            duration,
            comment,
            status,
            visit_date
        FROM visits
        WHERE 1=1
    """

    params = []

    if start_date:
        query += " AND visit_date >= %s"
        params.append(start_date)

    if end_date:
        query += " AND visit_date <= %s"
        params.append(end_date)

    cur = mysql.connection.cursor()
    cur.execute(query, params)
    rows = cur.fetchall()
    cur.close()

    df = pd.DataFrame([
        {
            "User": r[0],
            "Customer": r[1],
            "Route Name": r[2],
            "Time In": r[3],
            "Time Out": r[4],
            "Duration": r[5],
            "Comment": r[6],
            "Status": r[7],
            "Visit Date": r[8]
        }
        for r in rows
    ])

    output = io.BytesIO()

    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Visits")

    output.seek(0)

    return send_file(
        output,
        download_name="visits.xlsx",
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

@app.route("/api/price-lists", methods=["GET"])
def get_price_lists():
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT id, code, name, currency, status, created_at, updated_at
        FROM price_lists
    """)

    rows = cur.fetchall()
    cur.close()

    data = []

    for r in rows:
        data.append({
            "id": r[0],
            "code": r[1],
            "name": r[2],
            "currency": r[3],
            "status": r[4],
            "created_at": r[5],
            "updated_at": r[6]
        })

    return jsonify(data)

@app.route("/api/price-lists", methods=["POST"])
def create_price_list():
    data = request.json

    cur = mysql.connection.cursor()

    cur.execute("""
        INSERT INTO price_lists (code, name, currency, status)
        VALUES (%s, %s, %s, %s)
    """, (
        data["code"],
        data["name"],
        data["currency"],
        data.get("status", "Active")
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Created"}), 201

@app.route("/api/price-lists/<int:id>", methods=["PUT"])
def update_price_list(id):
    data = request.json

    cur = mysql.connection.cursor()

    cur.execute("""
        UPDATE price_lists
        SET code=%s,
            name=%s,
            currency=%s,
            status=%s
        WHERE id=%s
    """, (
        data.get("code"),
        data.get("name"),
        data.get("currency"),
        data.get("status"),
        id
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Updated"}), 200

@app.route("/api/price-lists/<int:id>", methods=["DELETE"])
def delete_price_list(id):
    cur = mysql.connection.cursor()

    cur.execute("DELETE FROM price_lists WHERE id=%s", (id,))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Deleted"}), 200

@app.route("/api/taxes", methods=["GET"])
def get_taxes():
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT
            id,
            code,
            name,
            type,
            compound,
            exempt,
            status,
            created_at,
            updated_at
        FROM taxes
        ORDER BY id DESC
    """)

    rows = cur.fetchall()
    cur.close()

    # FIX: convert tuple rows to proper JSON objects
    result = []

    for row in rows:
        result.append({
            "id": row[0],
            "code": row[1],
            "name": row[2],
            "type": row[3],
            "compound": row[4],
            "exempt": row[5],
            "status": row[6],
            "created_at": row[7],
            "updated_at": row[8]
        })

    return jsonify(result)


@app.route("/api/taxes/<int:id>", methods=["GET"])
def get_tax(id):
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT
            id,
            code,
            name,
            type,
            compound,
            exempt,
            status,
            created_at,
            updated_at
        FROM taxes
        WHERE id=%s
    """, (id,))

    row = cur.fetchone()
    cur.close()

    if not row:
        return jsonify({"message": "Tax not found"}), 404

    # FIX: convert single tuple to object
    result = {
        "id": row[0],
        "code": row[1],
        "name": row[2],
        "type": row[3],
        "compound": row[4],
        "exempt": row[5],
        "status": row[6],
        "created_at": row[7],
        "updated_at": row[8]
    }

    return jsonify(result)

@app.route("/api/taxes", methods=["POST"])
def create_tax():
    data = request.json
    cur = mysql.connection.cursor()

    cur.execute("""
        INSERT INTO taxes
        (code, name, type, compound, exempt, status)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        data["code"],
        data["name"],
        data["type"],
        data.get("compound", 0),
        data.get("exempt", 0),
        data.get("status", "Active")
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Tax created successfully"})

@app.route("/api/taxes/<int:id>", methods=["PUT"])
def update_tax(id):
    data = request.json
    cur = mysql.connection.cursor()

    cur.execute("""
        UPDATE taxes
        SET
            code=%s,
            name=%s,
            type=%s,
            compound=%s,
            exempt=%s,
            status=%s,
            updated_at=NOW()
        WHERE id=%s
    """, (
        data["code"],
        data["name"],
        data["type"],
        data.get("compound", 0),
        data.get("exempt", 0),
        data["status"],
        id
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Tax updated successfully"})

@app.route("/api/taxes/<int:id>", methods=["DELETE"])
def delete_tax(id):
    cur = mysql.connection.cursor()

    cur.execute("DELETE FROM taxes WHERE id=%s", (id,))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Tax deleted successfully"})

@app.route("/api/currencies", methods=["GET"])
def get_currencies():
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT
            id,
            code,
            name,
            status,
            created_at,
            updated_at
        FROM currencies
        ORDER BY id DESC
    """)

    rows = cur.fetchall()
    cur.close()

    # FIX: convert tuple rows to proper JSON objects
    result = []

    for row in rows:
        result.append({
            "id": row[0],
            "code": row[1],
            "name": row[2],
            "status": row[3],
            "created_at": row[4],
            "updated_at": row[5]
        })

    return jsonify(result)


@app.route("/api/currencies/<int:id>", methods=["GET"])
def get_currency(id):
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT
            id,
            code,
            name,
            status,
            created_at,
            updated_at
        FROM currencies
        WHERE id=%s
    """, (id,))

    row = cur.fetchone()
    cur.close()

    if not row:
        return jsonify({"message": "Currency not found"}), 404

    # FIX: convert single tuple to object
    result = {
        "id": row[0],
        "code": row[1],
        "name": row[2],
        "status": row[3],
        "created_at": row[4],
        "updated_at": row[5]
    }

    return jsonify(result)

@app.route("/api/currencies", methods=["POST"])
def create_currency():
    data = request.json
    cur = mysql.connection.cursor()

    cur.execute("""
        INSERT INTO currencies (code, name, status)
        VALUES (%s, %s, %s)
    """, (
        data["code"],
        data["name"],
        data.get("status", "Active")
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Currency created successfully"})

@app.route("/api/currencies/<int:id>", methods=["PUT"])
def update_currency(id):
    data = request.json
    cur = mysql.connection.cursor()

    cur.execute("""
        UPDATE currencies
        SET
            code=%s,
            name=%s,
            status=%s,
            updated_at=NOW()
        WHERE id=%s
    """, (
        data["code"],
        data["name"],
        data["status"],
        id
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Currency updated successfully"})

@app.route("/api/currencies/<int:id>", methods=["DELETE"])
def delete_currency(id):
    cur = mysql.connection.cursor()

    cur.execute("DELETE FROM currencies WHERE id=%s", (id,))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Currency deleted successfully"})

@app.route("/api/payment-terms", methods=["GET"])
def get_payment_terms():
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT
            id,
            code,
            name,
            days,
            status,
            created_at,
            updated_at
        FROM payment_terms
        ORDER BY id DESC
    """)

    rows = cur.fetchall()
    cur.close()

    # FIX: convert tuple rows to proper JSON objects
    result = []

    for row in rows:
        result.append({
            "id": row[0],
            "code": row[1],
            "name": row[2],
            "days": row[3],
            "status": row[4],
            "created_at": row[5],
            "updated_at": row[6]
        })

    return jsonify(result)


@app.route("/api/payment-terms/<int:id>", methods=["GET"])
def get_payment_term(id):
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT
            id,
            code,
            name,
            days,
            status,
            created_at,
            updated_at
        FROM payment_terms
        WHERE id=%s
    """, (id,))

    row = cur.fetchone()
    cur.close()

    if not row:
        return jsonify({"message": "Payment term not found"}), 404

    # FIX: convert single tuple to object
    result = {
        "id": row[0],
        "code": row[1],
        "name": row[2],
        "days": row[3],
        "status": row[4],
        "created_at": row[5],
        "updated_at": row[6]
    }

    return jsonify(result)

@app.route("/api/payment-terms", methods=["POST"])
def create_payment_term():
    data = request.json
    cur = mysql.connection.cursor()

    cur.execute("""
        INSERT INTO payment_terms (code, name, days, status)
        VALUES (%s, %s, %s, %s)
    """, (
        data["code"],
        data["name"],
        data["days"],
        data["status"]
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Payment term created successfully"})

@app.route("/api/payment-terms/<int:id>", methods=["PUT"])
def update_payment_term(id):
    data = request.json
    cur = mysql.connection.cursor()

    cur.execute("""
        UPDATE payment_terms
        SET
            code=%s,
            name=%s,
            days=%s,
            status=%s,
            updated_at=NOW()
        WHERE id=%s
    """, (
        data["code"],
        data["name"],
        data["days"],
        data["status"],
        id
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Payment term updated successfully"})

@app.route("/api/payment-terms/<int:id>", methods=["DELETE"])
def delete_payment_term(id):
    cur = mysql.connection.cursor()

    cur.execute("DELETE FROM payment_terms WHERE id=%s", (id,))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Payment term deleted successfully"})

@app.route("/api/warehouses", methods=["GET"])
def get_warehouses():
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT
            id,
            code,
            name,
            type,
            status,
            in_stock,
            committed,
            available,
            created_at,
            updated_at
        FROM warehouses
        ORDER BY id DESC
    """)

    rows = cur.fetchall()
    cur.close()

    # FIX: convert tuple rows to proper JSON objects
    result = []

    for row in rows:
        result.append({
            "id": row[0],
            "code": row[1],
            "name": row[2],
            "type": row[3],
            "status": row[4],
            "in_stock": row[5],
            "committed": row[6],
            "available": row[7],
            "created_at": row[8],
            "updated_at": row[9]
        })

    return jsonify(result)


@app.route("/api/warehouses/<int:id>", methods=["GET"])
def get_warehouse(id):
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT
            id,
            code,
            name,
            type,
            status,
            in_stock,
            committed,
            available,
            created_at,
            updated_at
        FROM warehouses
        WHERE id=%s
    """, (id,))

    row = cur.fetchone()
    cur.close()

    if not row:
        return jsonify({"message": "Warehouse not found"}), 404

    # FIX: convert single tuple to object
    result = {
        "id": row[0],
        "code": row[1],
        "name": row[2],
        "type": row[3],
        "status": row[4],
        "in_stock": row[5],
        "committed": row[6],
        "available": row[7],
        "created_at": row[8],
        "updated_at": row[9]
    }

    return jsonify(result)

@app.route("/api/warehouses", methods=["POST"])
def create_warehouse():
    data = request.json
    cur = mysql.connection.cursor()

    cur.execute("""
        INSERT INTO warehouses (
            code,
            name,
            type,
            status,
            in_stock,
            committed,
            available
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (
        data["code"],
        data["name"],
        data.get("type", ""),
        data.get("status", "Active"),
        data.get("in_stock", 0),
        data.get("committed", 0),
        data.get("available", 0)
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Warehouse created successfully"})


@app.route("/api/warehouses/<int:id>", methods=["PUT"])
def update_warehouse(id):
    data = request.json
    cur = mysql.connection.cursor()

    cur.execute("""
        UPDATE warehouses
        SET
            code=%s,
            name=%s,
            type=%s,
            status=%s,
            in_stock=%s,
            committed=%s,
            available=%s,
            updated_at=NOW()
        WHERE id=%s
    """, (
        data["code"],
        data["name"],
        data.get("type", ""),
        data.get("status", "Active"),
        data.get("in_stock", 0),
        data.get("committed", 0),
        data.get("available", 0),
        id
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Warehouse updated successfully"})

@app.route("/api/warehouses/<int:id>", methods=["DELETE"])
def delete_warehouse(id):
    cur = mysql.connection.cursor()

    cur.execute("DELETE FROM warehouses WHERE id=%s", (id,))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Warehouse deleted successfully"})

@app.route("/api/countries", methods=["GET"])
def get_countries():
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT
            id,
            code,
            name,
            status,
            created_at,
            updated_at
        FROM countries
        ORDER BY id DESC
    """)

    rows = cur.fetchall()
    cur.close()

    # FIX: convert tuple rows to proper JSON objects
    result = []

    for row in rows:
        result.append({
            "id": row[0],
            "code": row[1],
            "name": row[2],
            "status": row[3],
            "created_at": row[4],
            "updated_at": row[5]
        })

    return jsonify(result)


@app.route("/api/countries/<int:id>", methods=["GET"])
def get_country(id):
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT
            id,
            code,
            name,
            status,
            created_at,
            updated_at
        FROM countries
        WHERE id=%s
    """, (id,))

    row = cur.fetchone()
    cur.close()

    if not row:
        return jsonify({"message": "Country not found"}), 404

    # FIX: convert single tuple to object
    result = {
        "id": row[0],
        "code": row[1],
        "name": row[2],
        "status": row[3],
        "created_at": row[4],
        "updated_at": row[5]
    }

    return jsonify(result)

@app.route("/api/countries", methods=["POST"])
def create_country():
    data = request.json
    cur = mysql.connection.cursor()

    cur.execute("""
        INSERT INTO countries (code, name, status)
        VALUES (%s, %s, %s)
    """, (
        data["code"],
        data["name"],
        data.get("status", "Active")
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Country created successfully"})

@app.route("/api/countries/<int:id>", methods=["PUT"])
def update_country(id):
    data = request.json
    cur = mysql.connection.cursor()

    cur.execute("""
        UPDATE countries
        SET
            code=%s,
            name=%s,
            status=%s,
            updated_at=NOW()
        WHERE id=%s
    """, (
        data["code"],
        data["name"],
        data["status"],
        id
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Country updated successfully"})

@app.route("/api/countries/<int:id>", methods=["DELETE"])
def delete_country(id):
    cur = mysql.connection.cursor()

    cur.execute("DELETE FROM countries WHERE id=%s", (id,))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Country deleted successfully"})


from MySQLdb.cursors import DictCursor
@app.route("/api/regions", methods=["GET"])
def get_regions():
    cur = mysql.connection.cursor(DictCursor)

    cur.execute("""
        SELECT
            r.id,
            r.code,
            r.name,
            r.country_id,
            c.name AS country_name,
            r.status,
            r.created_at,
            r.updated_at
        FROM regions r
        LEFT JOIN countries c ON c.id = r.country_id
        ORDER BY r.id DESC
    """)

    rows = cur.fetchall()
    cur.close()

    return jsonify(rows), 200

@app.route("/api/regions/<int:id>", methods=["GET"])
def get_region(id):
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT
            r.id,
            r.code,
            r.name,
            r.country_id,
            c.name AS country_name,
            r.status,
            r.created_at,
            r.updated_at
        FROM regions r
        LEFT JOIN countries c ON c.id = r.country_id
        WHERE r.id=%s
    """, (id,))

    row = cur.fetchone()
    cur.close()

    if not row:
        return jsonify({"message": "Region not found"}), 404

    return jsonify(row), 200

@app.route("/api/regions", methods=["POST"])
def create_region():
    data = request.json
    cur = mysql.connection.cursor()

    cur.execute("""
        INSERT INTO regions (code, name, country_id, status)
        VALUES (%s, %s, %s, %s)
    """, (
        data["code"],
        data["name"],
        data["country_id"],
        data.get("status", "Active")
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Region created successfully"}), 201

@app.route("/api/regions/<int:id>", methods=["PUT"])
def update_region(id):
    data = request.json
    cur = mysql.connection.cursor()

    cur.execute("""
        UPDATE regions
        SET code=%s,
            name=%s,
            country_id=%s,
            status=%s,
            updated_at=NOW()
        WHERE id=%s
    """, (
        data["code"],
        data["name"],
        data["country_id"],
        data["status"],
        id
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Region updated successfully"}), 200


@app.route("/api/regions/<int:id>", methods=["DELETE"])
def delete_region(id):
    cur = mysql.connection.cursor()

    cur.execute("DELETE FROM regions WHERE id=%s", (id,))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Region deleted successfully"}), 200
    

from MySQLdb.cursors import DictCursor
@app.route("/api/routes", methods=["GET"])
def get_routes():
    cur = mysql.connection.cursor(DictCursor)

    cur.execute("""
        SELECT
            r.id,
            r.route_name,
            r.region_id,
            rg.name AS region_name,
            r.country_id,
            c.name AS country_name,
            r.status,
            r.created_at,
            r.updated_at
        FROM routes r
        LEFT JOIN regions rg ON rg.id = r.region_id
        LEFT JOIN countries c ON c.id = r.country_id
        ORDER BY r.id DESC
    """)

    rows = cur.fetchall()
    cur.close()

    return jsonify(rows), 200


@app.route("/api/routes/<int:id>", methods=["GET"])
def get_route(id):
    cur = mysql.connection.cursor(DictCursor)

    cur.execute("""
        SELECT
            r.id,
            r.route_name,
            r.region_id,
            rg.name AS region_name,
            r.country_id,
            c.name AS country_name,
            r.status,
            r.created_at,
            r.updated_at
        FROM routes r
        LEFT JOIN regions rg ON rg.id = r.region_id
        LEFT JOIN countries c ON c.id = r.country_id
        WHERE r.id=%s
    """, (id,))

    row = cur.fetchone()
    cur.close()

    if not row:
        return jsonify({"message": "Route not found"}), 404

    return jsonify(row), 200


@app.route("/api/routes", methods=["POST"])
def create_route():
    data = request.json
    cur = mysql.connection.cursor()

    cur.execute("""
        INSERT INTO routes (route_name, region_id, country_id, status)
        VALUES (%s, %s, %s, %s)
    """, (
        data["route_name"],
        data["region_id"],
        data["country_id"],
        data.get("status", "Active")
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Route created successfully"}), 201


@app.route("/api/routes/<int:id>", methods=["PUT"])
def update_route(id):
    data = request.json
    cur = mysql.connection.cursor()

    cur.execute("""
        UPDATE routes
        SET
            route_name=%s,
            region_id=%s,
            country_id=%s,
            status=%s,
            updated_at=NOW()
        WHERE id=%s
    """, (
        data["route_name"],
        data["region_id"],
        data["country_id"],
        data["status"],
        id
    ))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Route updated successfully"}), 200


@app.route("/api/routes/<int:id>", methods=["DELETE"])
def delete_route(id):
    cur = mysql.connection.cursor()

    cur.execute("DELETE FROM routes WHERE id=%s", (id,))

    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Route deleted successfully"}), 200

# =====================================================
# SALES REPS DROPDOWN
# =====================================================

@app.route("/sales-reps", methods=["GET"])
def sales_reps_dropdown():

    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT id, username
        FROM users
        WHERE role = 'sales_rep'
        AND status = 'Active'
        ORDER BY username ASC
    """)

    rows = cur.fetchall()
    cur.close()

    data = []

    for row in rows:
        data.append({
            "id": row[0],
            "username": row[1]
        })

    return jsonify(data), 200


# =====================================================
# REGIONS DROPDOWN
# =====================================================

@app.route("/regions", methods=["GET"])
def regions_dropdown():

    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT id, name
        FROM regions
        WHERE status = 'Active'
        ORDER BY name ASC
    """)

    rows = cur.fetchall()
    cur.close()

    data = []

    for row in rows:
        data.append({
            "id": row[0],
            "name": row[1]
        })

    return jsonify(data), 200


@app.route("/api/reports/sales-summary", methods=["GET"])
def sales_summary():
    cur = mysql.connection.cursor(mysql.cursors.DictCursor)

    cur.execute("""
        SELECT
            COUNT(DISTINCT c.id) AS total_customers,
            COUNT(DISTINCT i.id) AS total_invoices,
            COALESCE(SUM(i.invoice_amount), 0) AS total_invoice_value,
            COALESCE(SUM(p.amount_paid), 0) AS total_paid
        FROM customers c
        LEFT JOIN invoices i ON i.customer_id = c.id
        LEFT JOIN payments p ON p.invoice_id = i.id
    """)

    row = cur.fetchone()
    cur.close()

    return jsonify(row), 200

@app.route("/api/reports/monthly-sales", methods=["GET"])
def monthly_sales():
    cur = mysql.connection.cursor(mysql.cursors.DictCursor)

    cur.execute("""
        SELECT
            DATE_FORMAT(i.created_at, '%Y-%m') AS month,
            SUM(i.invoice_amount) AS total_sales
        FROM invoices i
        GROUP BY month
        ORDER BY month ASC
    """)

    rows = cur.fetchall()
    cur.close()

    return jsonify(rows), 200

@app.route("/api/reports/route-performance", methods=["GET"])
def route_performance():
    cur = mysql.connection.cursor(mysql.cursors.DictCursor)

    cur.execute("""
        SELECT
            r.route_name,
            COUNT(i.id) AS invoices,
            COALESCE(SUM(i.invoice_amount), 0) AS total_sales
        FROM routes r
        LEFT JOIN invoices i ON i.route_id = r.id
        GROUP BY r.id
        ORDER BY total_sales DESC
    """)

    rows = cur.fetchall()
    cur.close()

    return jsonify(rows), 200

@app.route("/api/reports/sales-rep-performance", methods=["GET"])
def sales_rep_performance():
    cur = mysql.connection.cursor(mysql.cursors.DictCursor)

    cur.execute("""
        SELECT
            u.name AS sales_rep,
            COUNT(i.id) AS invoices,
            COALESCE(SUM(i.invoice_amount), 0) AS total_sales
        FROM users u
        LEFT JOIN invoices i ON i.created_by = u.id
        GROUP BY u.id
        ORDER BY total_sales DESC
    """)

    rows = cur.fetchall()
    cur.close()

    return jsonify(rows), 200

@app.route("/api/reports/collection-rate", methods=["GET"])
def collection_rate():
    cur = mysql.connection.cursor(mysql.cursors.DictCursor)

    cur.execute("""
        SELECT
            COALESCE(SUM(i.invoice_amount), 0) AS billed,
            COALESCE(SUM(p.amount_paid), 0) AS collected,
            CASE 
                WHEN SUM(i.invoice_amount) = 0 THEN 0
                ELSE (SUM(p.amount_paid) / SUM(i.invoice_amount)) * 100
            END AS rate
        FROM invoices i
        LEFT JOIN payments p ON p.invoice_id = i.id
    """)

    row = cur.fetchone()
    cur.close()

    return jsonify(row), 200




@app.route("/admin/export-logs", methods=["GET"])
@jwt_required()
def export_logs():
    print("HEADERS:", request.headers)
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT
            id,
            action,
            payload,
            response,
            status,
            retry_count,
            created_at
        FROM integration_logs
        ORDER BY created_at DESC
    """)

    rows = cur.fetchall()
    cur.close()

    data = []

    for row in rows:
        data.append([
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            row[5],
            str(row[6])
        ])

    df = pd.DataFrame(data, columns=[
        "ID",
        "Action",
        "Payload",
        "Response",
        "Status",
        "Retry Count",
        "Created At"
    ])

    file_name = "integration_logs.xlsx"
    df.to_excel(file_name, index=False)

    return send_file(
        file_name,
        as_attachment=True
    )


# =====================================================
# RUN
# =====================================================

if __name__ == "__main__":
    app.run(debug=True)
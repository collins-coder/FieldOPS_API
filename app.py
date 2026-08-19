from flask import Flask, request, jsonify, send_file
from flask_mysqldb import MySQL
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)
from MySQLdb.cursors import DictCursor
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config

import io
import json
import pandas as pd
from datetime import datetime, date, timedelta


# ============================================================
# APP CONFIGURATION
# ============================================================

app = Flask(__name__)
app.config.from_object(Config)
app.config["JWT_SECRET_KEY"] = "fieldops_super_secret_key"

CORS(app)

mysql = MySQL(app)
jwt = JWTManager(app)


# ============================================================
# HELPERS
# ============================================================

def get_current_user():
    identity = get_jwt_identity()

    cur = mysql.connection.cursor()

    try:
        cur.execute("""
            SELECT
                id,
                username,
                role,
                email,
                status
            FROM users
            WHERE id = %s
        """, (identity,))

        user = cur.fetchone()

        if not user:
            return None

        return {
            "id": user[0],
            "username": user[1],
            "role": user[2],
            "email": user[3],
            "status": user[4]
        }

    finally:
        cur.close()


def admin_or_developer():
    user = get_current_user()

    if not user:
        return None, jsonify({
            "message": "User not found"
        }), 401

    if user["status"] != "Active":
        return None, jsonify({
            "message": "User account is inactive"
        }), 403

    if user["role"] not in ["admin", "developer"]:
        return None, jsonify({
            "message": "Access denied"
        }), 403

    return user, None, None


def create_system_log(
    action,
    status="SUCCESS",
    payload=None,
    response=None,
    retry_count=0
):
    """
    Record an application/system integration event.

    Never pass passwords, JWT tokens, or other sensitive
    credentials in payload or response.
    """

    cur = None

    try:
        cur = mysql.connection.cursor()

        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload, default=str)

        if isinstance(response, (dict, list)):
            response = json.dumps(response, default=str)

        cur.execute("""
            INSERT INTO integration_logs
            (
                action,
                payload,
                response,
                status,
                retry_count
            )
            VALUES (%s, %s, %s, %s, %s)
        """, (
            action,
            payload,
            response,
            status,
            retry_count
        ))

        mysql.connection.commit()

    except Exception as log_error:
        print("System logging error:", log_error)

        try:
            mysql.connection.rollback()
        except Exception:
            pass

    finally:
        if cur:
            cur.close()


def get_date_range():
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    return start_date, end_date


# ------------------------------------------------------------
# Mobile workflow helpers (timesheet / visits / sales orders)
# ------------------------------------------------------------

ALLOWED_VISIT_CHECKOUT_REASONS = [
    "Complete Visit",
    "Shop Closed",
    "Money Collection",
    "Customer Not Available",
    "Other"
]


def _to_seconds(value):
    if value is None:
        return None

    if isinstance(value, timedelta):
        return value.total_seconds()

    return (
        value.hour * 3600
        + value.minute * 60
        + value.second
    )


def format_duration(start_time, end_time):
    start_seconds = _to_seconds(start_time)
    end_seconds = _to_seconds(end_time)

    if start_seconds is None or end_seconds is None:
        return "0m"

    total_seconds = end_seconds - start_seconds

    if total_seconds < 0:
        return "0m"

    hours = int(total_seconds // 3600)
    minutes = int((total_seconds % 3600) // 60)

    if hours > 0:
        return f"{hours}h {minutes}m"

    return f"{minutes}m"


def hours_between(start_time, end_time):
    start_seconds = _to_seconds(start_time)
    end_seconds = _to_seconds(end_time)

    if start_seconds is None or end_seconds is None:
        return 0.0

    total_seconds = end_seconds - start_seconds

    if total_seconds < 0:
        return 0.0

    return round(total_seconds / 3600, 2)


def export_dataframe(df, filename, sheet_name="Report"):
    output = io.BytesIO()

    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(
            writer,
            index=False,
            sheet_name=sheet_name
        )

    output.seek(0)

    return send_file(
        output,
        download_name=filename,
        as_attachment=True,
        mimetype=(
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet"
        )
    )


# ============================================================
# HOME
# ============================================================

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "application": "FieldOPS API",
        "status": "running",
        "message": "FieldOPS API Running Successfully"
    })


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["POST"])
def login():

    data = request.get_json() or {}

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({
            "message": "Username and password are required"
        }), 400

    cur = mysql.connection.cursor()

    try:
        cur.execute("""
            SELECT
                id,
                username,
                role,
                email,
                status,
                password
            FROM users
            WHERE username = %s
            AND status = 'Active'
        """, (
            username,
        ))

        user = cur.fetchone()

    finally:
        cur.close()

    if not user or not check_password_hash(user[5], password):

        create_system_log(
            action="LOGIN_FAILED",
            status="FAILED",
            payload={
                "username": username
            },
            response={
                "message": "Invalid username or password"
            }
        )

        return jsonify({
            "message": "Invalid username or password"
        }), 401

    access_token = create_access_token(
        identity=str(user[0])
    )

    create_system_log(
        action="LOGIN_SUCCESS",
        status="SUCCESS",
        payload={
            "username": user[1],
            "user_id": user[0]
        },
        response={
            "message": "Login successful"
        }
    )

    return jsonify({
        "message": "Login successful",
        "access_token": access_token,
        "username": user[1],
        "role": user[2],
        "email": user[3]
    })


# ============================================================
# USERS
# ============================================================

@app.route("/admin/users", methods=["GET"])
@jwt_required()
def get_users():

    _, error, status = admin_or_developer()

    if error:
        return error, status

    cur = mysql.connection.cursor()

    try:
        cur.execute("""
            SELECT
                id,
                username,
                email,
                role,
                status,
                created_at
            FROM users
            ORDER BY created_at DESC
        """)

        rows = cur.fetchall()

    finally:
        cur.close()

    result = []

    for r in rows:
        result.append({
            "id": r[0],
            "username": r[1],
            "email": r[2],
            "role": r[3],
            "status": r[4],
            "created_at": str(r[5]) if r[5] else None
        })

    return jsonify(result)


@app.route("/admin/users/<int:user_id>", methods=["GET"])
@jwt_required()
def get_user(user_id):

    _, error, status = admin_or_developer()

    if error:
        return error, status

    cur = mysql.connection.cursor()

    try:
        cur.execute("""
            SELECT
                id,
                username,
                email,
                role,
                status,
                created_at
            FROM users
            WHERE id = %s
        """, (user_id,))

        row = cur.fetchone()

    finally:
        cur.close()

    if not row:
        return jsonify({
            "message": "User not found"
        }), 404

    return jsonify({
        "id": row[0],
        "username": row[1],
        "email": row[2],
        "role": row[3],
        "status": row[4],
        "created_at": str(row[5]) if row[5] else None
    })


@app.route("/admin/users", methods=["POST"])
@jwt_required()
def create_user():

    current_user, error, status = admin_or_developer()

    if error:
        return error, status

    data = request.get_json() or {}

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    role = data.get("role")
    user_status = data.get("status", "Active")

    if not username or not password or not role:
        return jsonify({
            "message": "Username, password and role are required"
        }), 400

    if len(password) < 6:
        return jsonify({
            "message": "Password must be at least 6 characters"
        }), 400

    hashed_password = generate_password_hash(password)

    cur = mysql.connection.cursor()

    try:
        cur.execute("""
            INSERT INTO users
            (
                username,
                email,
                password,
                role,
                status
            )
            VALUES (%s, %s, %s, %s, %s)
        """, (
            username,
            email,
            hashed_password,
            role,
            user_status
        ))

        new_user_id = cur.lastrowid

        mysql.connection.commit()

        create_system_log(
            action="USER_CREATED",
            status="SUCCESS",
            payload={
                "created_user_id": new_user_id,
                "username": username,
                "role": role,
                "created_by": current_user["username"]
            },
            response={
                "message": "User created successfully"
            }
        )

        return jsonify({
            "message": "User created successfully"
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        create_system_log(
            action="USER_CREATED",
            status="FAILED",
            payload={
                "username": username,
                "role": role,
                "created_by": current_user["username"]
            },
            response={
                "message": str(e)
            }
        )

        return jsonify({
            "message": "Failed to create user"
        }), 500

    finally:
        cur.close()


@app.route("/admin/users/<int:user_id>", methods=["PUT"])
@jwt_required()
def update_user(user_id):

    current_user, error, status = admin_or_developer()

    if error:
        return error, status

    data = request.get_json() or {}

    username = data.get("username")
    email = data.get("email")
    role = data.get("role")
    user_status = data.get("status")

    if not username or not role or not user_status:
        return jsonify({
            "message": "Username, role and status are required"
        }), 400

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            UPDATE users
            SET
                username=%s,
                email=%s,
                role=%s,
                status=%s
            WHERE id=%s
        """, (
            username,
            email,
            role,
            user_status,
            user_id
        ))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "User not found"
            }), 404

        mysql.connection.commit()

        create_system_log(
            action="USER_UPDATED",
            status="SUCCESS",
            payload={
                "user_id": user_id,
                "username": username,
                "role": role,
                "status": user_status,
                "updated_by": current_user["username"]
            },
            response={
                "message": "User updated successfully"
            }
        )

        return jsonify({
            "message": "User updated successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        create_system_log(
            action="USER_UPDATED",
            status="FAILED",
            payload={
                "user_id": user_id,
                "updated_by": current_user["username"]
            },
            response={
                "message": str(e)
            }
        )

        return jsonify({
            "message": "Failed to update user"
        }), 500

    finally:
        cur.close()


@app.route("/admin/users/<int:user_id>/status", methods=["PATCH"])
@jwt_required()
def toggle_user_status(user_id):

    current_user, error, status = admin_or_developer()

    if error:
        return error, status

    data = request.get_json() or {}

    new_status = data.get("status")

    if new_status not in ["Active", "Inactive"]:
        return jsonify({
            "message": "Invalid status"
        }), 400

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            UPDATE users
            SET status=%s
            WHERE id=%s
        """, (
            new_status,
            user_id
        ))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "User not found"
            }), 404

        mysql.connection.commit()

        create_system_log(
            action="USER_STATUS_CHANGED",
            status="SUCCESS",
            payload={
                "user_id": user_id,
                "new_status": new_status,
                "changed_by": current_user["username"]
            },
            response={
                "message": "Status updated"
            }
        )

        return jsonify({
            "message": "Status updated"
        })

    except Exception as e:

        mysql.connection.rollback()

        create_system_log(
            action="USER_STATUS_CHANGED",
            status="FAILED",
            payload={
                "user_id": user_id,
                "changed_by": current_user["username"]
            },
            response={
                "message": str(e)
            }
        )

        return jsonify({
            "message": "Failed to update status"
        }), 500

    finally:
        cur.close()


@app.route("/admin/users/<int:user_id>/reset-password", methods=["PATCH"])
@jwt_required()
def reset_user_password(user_id):

    current_user, error, status = admin_or_developer()

    if error:
        return error, status

    data = request.get_json() or {}

    new_password = data.get("password")

    if not new_password or len(new_password) < 6:
        return jsonify({
            "message": "Password must be at least 6 characters"
        }), 400

    hashed_password = generate_password_hash(new_password)

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            UPDATE users
            SET password=%s
            WHERE id=%s
        """, (
            hashed_password,
            user_id
        ))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "User not found"
            }), 404

        mysql.connection.commit()

        create_system_log(
            action="USER_PASSWORD_RESET",
            status="SUCCESS",
            payload={
                "user_id": user_id,
                "reset_by": current_user["username"]
            },
            response={
                "message": "Password reset"
            }
        )

        return jsonify({
            "message": "Password reset successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        create_system_log(
            action="USER_PASSWORD_RESET",
            status="FAILED",
            payload={
                "user_id": user_id,
                "reset_by": current_user["username"]
            },
            response={
                "message": str(e)
            }
        )

        return jsonify({
            "message": "Failed to reset password"
        }), 500

    finally:
        cur.close()


@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):

    current_user, error, status = admin_or_developer()

    if error:
        return error, status

    if current_user["role"] != "admin":
        return jsonify({
            "message": "Only administrators can delete users"
        }), 403

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            SELECT username
            FROM users
            WHERE id=%s
        """, (user_id,))

        target_user = cur.fetchone()

        if not target_user:
            return jsonify({
                "message": "User not found"
            }), 404

        target_username = target_user[0]

        cur.execute("""
            DELETE FROM users
            WHERE id=%s
        """, (user_id,))

        mysql.connection.commit()

        create_system_log(
            action="USER_DELETED",
            status="SUCCESS",
            payload={
                "user_id": user_id,
                "username": target_username,
                "deleted_by": current_user["username"]
            },
            response={
                "message": "User deleted"
            }
        )

        return jsonify({
            "message": "User deleted"
        })

    except Exception as e:

        mysql.connection.rollback()

        create_system_log(
            action="USER_DELETED",
            status="FAILED",
            payload={
                "user_id": user_id,
                "deleted_by": current_user["username"]
            },
            response={
                "message": str(e)
            }
        )

        return jsonify({
            "message": "Failed to delete user"
        }), 500

    finally:
        cur.close()


# ============================================================
# CUSTOMERS
# ============================================================

@app.route("/customers", methods=["GET"])
@jwt_required()
def get_customers():

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            SELECT
                c.id,
                c.customer_code,
                c.customer_name,
                c.phone,
                c.email,
                c.location,
                c.route,
                c.credit_limit,
                c.status,
                c.created_by,
                c.created_at,
                c.price_list_id,
                pl.name AS price_list_name,
                c.payment_terms_id,
                pt.name AS payment_terms_name
            FROM customers c
            LEFT JOIN price_lists pl ON pl.id = c.price_list_id
            LEFT JOIN payment_terms pt ON pt.id = c.payment_terms_id
            ORDER BY c.created_at DESC
        """)

        rows = cur.fetchall()

    finally:
        cur.close()

    result = []

    for r in rows:
        result.append({
            "id": r[0],
            "customer_code": r[1],
            "customer_name": r[2],
            "phone": r[3],
            "email": r[4],
            "location": r[5],
            "route": r[6],
            "credit_limit": float(r[7] or 0),
            "status": r[8],
            "created_by": r[9],
            "created_at": str(r[10]) if r[10] else None,
            "price_list_id": r[11],
            "price_list_name": r[12],
            "payment_terms_id": r[13],
            "payment_terms_name": r[14]
        })

    return jsonify(result)


@app.route("/customers/export", methods=["GET"])
@jwt_required()
def export_customers():
    # NEW - direct customers export (previously only available via the
    # /api/reports/customers/export report endpoint).

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute("""
            SELECT
                customer_code AS `Customer Code`,
                customer_name AS `Customer Name`,
                phone AS `Phone`,
                email AS `Email`,
                location AS `Location`,
                route AS `Route`,
                credit_limit AS `Credit Limit`,
                status AS `Status`,
                created_by AS `Created By`,
                created_at AS `Created At`
            FROM customers
            ORDER BY created_at DESC
        """)

        rows = cur.fetchall()

    finally:
        cur.close()

    df = pd.DataFrame(rows)

    return export_dataframe(
        df,
        "customers.xlsx",
        "Customers"
    )


@app.route("/customers", methods=["POST"])
@jwt_required()
def create_customer():

    data = request.get_json() or {}
    current_user = get_current_user()

    if not current_user:
        return jsonify({
            "message": "User not found"
        }), 401

    required_fields = [
        "customer_code",
        "customer_name"
    ]

    missing = [
        field for field in required_fields
        if not data.get(field)
    ]

    if missing:
        return jsonify({
            "message": "Required fields are missing",
            "fields": missing
        }), 400

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            INSERT INTO customers
            (
                customer_code,
                customer_name,
                phone,
                email,
                location,
                route,
                credit_limit,
                status,
                price_list_id,
                payment_terms_id,
                created_by
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            data["customer_code"],
            data["customer_name"],
            data.get("phone"),
            data.get("email"),
            data.get("location"),
            data.get("route"),
            data.get("credit_limit", 0),
            data.get("status", "Active"),
            data.get("price_list_id") or None,
            data.get("payment_terms_id") or None,
            current_user["username"]
        ))

        customer_id = cur.lastrowid

        mysql.connection.commit()

        return jsonify({
            "message": "Customer created successfully",
            "customer_id": customer_id
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to create customer",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/customers/<int:customer_id>", methods=["PUT"])
@jwt_required()
def update_customer(customer_id):

    data = request.get_json() or {}

    if not data.get("customer_name"):
        return jsonify({
            "message": "Customer name is required"
        }), 400

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            UPDATE customers
            SET
                customer_name=%s,
                phone=%s,
                email=%s,
                location=%s,
                route=%s,
                credit_limit=%s,
                status=%s,
                price_list_id=%s,
                payment_terms_id=%s
            WHERE id=%s
        """, (
            data["customer_name"],
            data.get("phone"),
            data.get("email"),
            data.get("location"),
            data.get("route"),
            data.get("credit_limit", 0),
            data.get("status", "Active"),
            data.get("price_list_id") or None,
            data.get("payment_terms_id") or None,
            customer_id
        ))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Customer not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Customer updated"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to update customer",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/customers/<int:customer_id>", methods=["DELETE"])
@jwt_required()
def delete_customer(customer_id):

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            DELETE FROM customers
            WHERE id=%s
        """, (customer_id,))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Customer not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Customer deleted"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to delete customer",
            "error": str(e)
        }), 500

    finally:
        cur.close()


# ============================================================
# ITEMS
# ============================================================

@app.route("/items", methods=["GET"])
@jwt_required()
def get_items():

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            SELECT
                id,
                item_code,
                name,
                category,
                unit,
                price,
                stock,
                status,
                created_at
            FROM items
            ORDER BY created_at DESC
        """)

        rows = cur.fetchall()

    finally:
        cur.close()

    result = []

    for r in rows:
        result.append({
            "id": r[0],
            "item_code": r[1],
            "name": r[2],
            "category": r[3],
            "unit": r[4],
            "price": float(r[5] or 0),
            "stock": r[6] or 0,
            "status": r[7],
            "created_at": str(r[8]) if r[8] else None
        })

    return jsonify(result)


@app.route("/items/export", methods=["GET"])
@jwt_required()
def export_items():
    # NEW - didn't exist before.

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute("""
            SELECT
                item_code AS `Item Code`,
                name AS `Name`,
                category AS `Category`,
                unit AS `Unit`,
                price AS `Price`,
                stock AS `Stock`,
                status AS `Status`,
                created_at AS `Created At`
            FROM items
            ORDER BY created_at DESC
        """)

        rows = cur.fetchall()

    finally:
        cur.close()

    df = pd.DataFrame(rows)

    return export_dataframe(
        df,
        "items.xlsx",
        "Items"
    )


@app.route("/items", methods=["POST"])
@jwt_required()
def create_item():
    # FIXED/CHANGED: item_code is now generated server-side from the
    # new row's id (same pattern already used for order_number,
    # dispatch_code) instead of being typed by hand - guarantees no
    # duplicate is possible, and the frontend no longer needs to send
    # it at all.

    data = request.get_json() or {}

    if not data.get("name"):
        return jsonify({
            "message": "Item name is required"
        }), 400

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            INSERT INTO items
            (
                item_code,
                name,
                category,
                unit,
                price,
                stock,
                status
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (
            "PENDING",
            data["name"],
            data.get("category"),
            data.get("unit", "PCS"),
            data.get("price", 0),
            data.get("stock", 0),
            data.get("status", "Active")
        ))

        item_id = cur.lastrowid

        item_code = f"ITEM-{str(item_id).zfill(6)}"

        cur.execute("""
            UPDATE items
            SET item_code = %s
            WHERE id = %s
        """, (item_code, item_id))

        mysql.connection.commit()

        return jsonify({
            "message": "Item created successfully",
            "item_id": item_id,
            "item_code": item_code
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to create item",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/items/<int:item_id>", methods=["PUT"])
@jwt_required()
def update_item(item_id):
    # item_code intentionally not editable here - it's the permanent
    # identifier assigned at creation.

    data = request.get_json() or {}

    if not data.get("name"):
        return jsonify({
            "message": "Item name is required"
        }), 400

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            UPDATE items
            SET
                name=%s,
                category=%s,
                unit=%s,
                price=%s,
                stock=%s,
                status=%s
            WHERE id=%s
        """, (
            data["name"],
            data.get("category"),
            data.get("unit", "PCS"),
            data.get("price", 0),
            data.get("stock", 0),
            data.get("status", "Active"),
            item_id
        ))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Item not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Item updated"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to update item",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/items/<int:item_id>", methods=["DELETE"])
@jwt_required()
def delete_item(item_id):

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            DELETE FROM items
            WHERE id=%s
        """, (item_id,))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Item not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Item deleted"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to delete item",
            "error": str(e)
        }), 500

    finally:
        cur.close()


# ============================================================
# SALES ORDERS
# ============================================================

@app.route("/admin/sales-orders", methods=["GET"])
@jwt_required()
def get_sales_orders():

    start_date, end_date = get_date_range()

    query = """
        SELECT
            so.id,
            so.order_number,
            so.customer_id,
            c.customer_code,
            c.customer_name,
            so.order_date,
            so.due_date,
            so.total_amount,
            so.status,
            so.doc_status,
            so.sync_status,
            so.created_by
        FROM sales_orders so
        LEFT JOIN customers c
            ON c.id = so.customer_id
        WHERE 1=1
    """

    params = []

    if start_date:
        query += " AND DATE(so.order_date) >= %s"
        params.append(start_date)

    if end_date:
        query += " AND DATE(so.order_date) <= %s"
        params.append(end_date)

    query += """
        ORDER BY
            so.order_date DESC,
            so.id DESC
    """

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute(query, params)
        rows = cur.fetchall()

    finally:
        cur.close()

    return jsonify(rows)


@app.route("/admin/sales-orders", methods=["POST"])
@jwt_required()
def create_sales_order():
    """
    Creates a sales order with one or more line items. Used by the
    mobile app while a sales rep is checked in to a customer visit.
    """

    current_user = get_current_user()

    if not current_user:
        return jsonify({
            "message": "User not found"
        }), 401

    data = request.get_json() or {}

    customer_id = data.get("customer_id")
    items = data.get("items") or []

    if not customer_id:
        return jsonify({
            "message": "Customer is required"
        }), 400

    if not isinstance(items, list) or len(items) == 0:
        return jsonify({
            "message": "At least one item is required"
        }), 400

    line_items = []
    subtotal = 0
    discount_total = 0

    for raw_item in items:

        item_id = raw_item.get("item_id")
        quantity = raw_item.get("quantity")
        unit_price = raw_item.get("unit_price")

        if not item_id or not quantity or unit_price is None:
            return jsonify({
                "message": (
                    "Each item requires item_id, quantity "
                    "and unit_price"
                )
            }), 400

        quantity = float(quantity)
        unit_price = float(unit_price)
        discount = float(raw_item.get("discount", 0) or 0)

        line_total = (quantity * unit_price) - discount

        subtotal += quantity * unit_price
        discount_total += discount

        line_items.append({
            "item_id": item_id,
            "unit": raw_item.get("unit"),
            "quantity": quantity,
            "unit_price": unit_price,
            "discount": discount,
            "total": line_total
        })

    grand_total = subtotal - discount_total

    cur = mysql.connection.cursor()

    try:
        cur.execute("""
            INSERT INTO sales_orders
            (
                order_number,
                customer_id,
                order_date,
                due_date,
                warehouse_id,
                price_list_id,
                currency_id,
                total_amount,
                subtotal,
                discount_total,
                status,
                sync_status,
                created_by
            )
            VALUES (
                %s, %s, CURDATE(), %s, %s, %s, %s,
                %s, %s, %s, 'Pending', 'Not Synced', %s
            )
        """, (
            f"PENDING-{current_user['id']}-{customer_id}",
            customer_id,
            data.get("due_date"),
            data.get("warehouse_id"),
            data.get("price_list_id"),
            data.get("currency_id"),
            grand_total,
            subtotal,
            discount_total,
            current_user["username"]
        ))

        order_id = cur.lastrowid

        order_number = f"SO{str(order_id).zfill(6)}"

        cur.execute("""
            UPDATE sales_orders
            SET order_number = %s
            WHERE id = %s
        """, (order_number, order_id))

        for line in line_items:

            cur.execute("""
                SELECT item_code, name
                FROM items
                WHERE id = %s
            """, (line["item_id"],))

            item_row = cur.fetchone()

            item_code = item_row[0] if item_row else None
            item_name = item_row[1] if item_row else None

            cur.execute("""
                INSERT INTO order_items
                (
                    sales_order_id,
                    item_id,
                    item_code,
                    item_name,
                    quantity,
                    unit,
                    unit_price,
                    discount,
                    total
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                order_id,
                line["item_id"],
                item_code,
                item_name,
                line["quantity"],
                line["unit"],
                line["unit_price"],
                line["discount"],
                line["total"]
            ))

        mysql.connection.commit()

        create_system_log(
            action="SALES_ORDER_CREATED",
            status="SUCCESS",
            payload={
                "order_id": order_id,
                "order_number": order_number,
                "customer_id": customer_id,
                "created_by": current_user["username"],
                "grand_total": grand_total
            },
            response={
                "message": "Sales order created"
            }
        )

        return jsonify({
            "message": "Sales order created successfully",
            "id": order_id,
            "order_number": order_number,
            "total_amount": grand_total
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        create_system_log(
            action="SALES_ORDER_CREATED",
            status="FAILED",
            payload={
                "customer_id": customer_id,
                "created_by": current_user["username"]
            },
            response={
                "message": str(e)
            }
        )

        return jsonify({
            "message": "Failed to create sales order",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/admin/sales-orders/<int:order_id>", methods=["GET"])
@jwt_required()
def get_sales_order_detail(order_id):
    """
    Full order detail matching the order confirmation screen:
    customer info, order metadata, line items, and totals.
    """

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute("""
            SELECT
                so.id,
                so.order_number,
                so.order_date,
                so.due_date,
                so.total_amount,
                so.subtotal,
                so.discount_total,
                so.status,
                so.doc_status,
                so.closed_by_type,
                so.closed_by_id,
                so.sync_status,
                so.sap_doc_number,
                so.created_by,
                so.created_at,
                c.id AS customer_id,
                c.customer_code,
                c.customer_name,
                c.phone AS customer_phone,
                c.email AS customer_email,
                c.location AS customer_location,
                w.name AS warehouse_name,
                pl.name AS price_list_name,
                cur.code AS currency_code
            FROM sales_orders so
            LEFT JOIN customers c ON c.id = so.customer_id
            LEFT JOIN warehouses w ON w.id = so.warehouse_id
            LEFT JOIN price_lists pl ON pl.id = so.price_list_id
            LEFT JOIN currencies cur ON cur.id = so.currency_id
            WHERE so.id = %s
        """, (order_id,))

        order = cur.fetchone()

        if not order:
            return jsonify({
                "message": "Sales order not found"
            }), 404

        # Resolve a human-readable pointer to whatever closed this
        # order (SAP B1 shows this as the linked target document).
        closed_by_number = None

        if order["closed_by_type"] == "invoice" and order["closed_by_id"]:
            cur.execute(
                "SELECT invoice_number FROM invoices WHERE id = %s",
                (order["closed_by_id"],)
            )
            row = cur.fetchone()
            closed_by_number = row["invoice_number"] if row else None

        elif order["closed_by_type"] == "delivery" and order["closed_by_id"]:
            cur.execute(
                "SELECT dispatch_code FROM deliveries WHERE id = %s",
                (order["closed_by_id"],)
            )
            row = cur.fetchone()
            closed_by_number = row["dispatch_code"] if row else None

        order["closed_by_number"] = closed_by_number

        cur.execute("""
            SELECT
                id,
                item_id,
                item_code,
                item_name,
                quantity,
                unit,
                unit_price,
                discount,
                total
            FROM order_items
            WHERE sales_order_id = %s
            ORDER BY id ASC
        """, (order_id,))

        items = cur.fetchall()

    finally:
        cur.close()

    order["items"] = items

    return jsonify(order)


@app.route("/admin/sales-orders/<int:order_id>/status", methods=["PATCH"])
@jwt_required()
def update_sales_order_status(order_id):

    current_user = get_current_user()

    if not current_user:
        return jsonify({
            "message": "User not found"
        }), 401

    data = request.get_json() or {}

    new_status = data.get("status")

    allowed_statuses = ["Pending", "Approved", "Cancelled"]

    if new_status not in allowed_statuses:
        return jsonify({
            "message": "Invalid status",
            "allowed_statuses": allowed_statuses
        }), 400

    cur = mysql.connection.cursor()

    try:
        cur.execute("""
            UPDATE sales_orders
            SET
                status = %s,
                approved_by = %s
            WHERE id = %s
        """, (
            new_status,
            current_user["username"] if new_status == "Approved" else None,
            order_id
        ))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Sales order not found"
            }), 404

        mysql.connection.commit()

        create_system_log(
            action="SALES_ORDER_STATUS_CHANGED",
            status="SUCCESS",
            payload={
                "order_id": order_id,
                "new_status": new_status,
                "changed_by": current_user["username"]
            },
            response={
                "message": "Status updated"
            }
        )

        return jsonify({
            "message": "Sales order status updated"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to update sales order status",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/admin/sales-orders/export", methods=["GET"])
@jwt_required()
def export_sales_orders():

    start_date, end_date = get_date_range()

    query = """
        SELECT
            so.order_number AS `Order Number`,
            c.customer_code AS `Customer Code`,
            c.customer_name AS `Customer Name`,
            c.phone AS `Phone`,
            so.order_date AS `Order Date`,
            so.total_amount AS `Total Amount`
        FROM sales_orders so
        LEFT JOIN customers c
            ON c.id = so.customer_id
        WHERE 1=1
    """

    params = []

    if start_date:
        query += " AND DATE(so.order_date) >= %s"
        params.append(start_date)

    if end_date:
        query += " AND DATE(so.order_date) <= %s"
        params.append(end_date)

    query += " ORDER BY so.order_date DESC"

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute(query, params)
        rows = cur.fetchall()

    finally:
        cur.close()

    df = pd.DataFrame(rows)

    return export_dataframe(
        df,
        "sales_orders.xlsx",
        "Sales Orders"
    )


# ============================================================
# INVOICES
# ============================================================

@app.route("/admin/invoices", methods=["GET"])
@jwt_required()
def get_invoices():
    # FIXED: removed the broken "LEFT JOIN customers c ON c.id =
    # i.customer_id" - invoices has no customer_id column. Uses
    # i.customer_name directly (already stored at creation time).

    start_date, end_date = get_date_range()

    query = """
        SELECT
            i.id,
            i.invoice_number,
            i.customer_name,
            i.sales_order_id,
            i.invoice_amount,
            i.due_date,
            i.status,
            i.doc_status,
            i.created_at
        FROM invoices i
        WHERE 1=1
    """

    params = []

    if start_date:
        query += " AND DATE(i.created_at) >= %s"
        params.append(start_date)

    if end_date:
        query += " AND DATE(i.created_at) <= %s"
        params.append(end_date)

    query += " ORDER BY i.created_at DESC"

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute(query, params)
        rows = cur.fetchall()

    finally:
        cur.close()

    return jsonify(rows)


@app.route("/create-invoice", methods=["POST"])
@jwt_required()
def create_invoice():
    # FIXED: required + inserted "customer_id" before, a column
    # invoices doesn't have. Uses customer_name instead, which the
    # table actually stores and which the frontend already sends.

    data = request.get_json() or {}

    required_fields = [
        "invoice_number",
        "customer_name",
        "due_date"
    ]

    missing = [
        field for field in required_fields
        if not data.get(field)
    ]

    if missing:
        return jsonify({
            "message": "Required fields are missing",
            "fields": missing
        }), 400

    cur = mysql.connection.cursor()

    try:
        sales_order_id = data.get("sales_order_id")

        # SAP B1-style document flow: a sales order can only be
        # copied to ONE invoice. If it's already Closed (already has
        # an invoice or delivery against it), refuse rather than
        # silently allowing a duplicate invoice against the same order.
        if sales_order_id:
            cur.execute("""
                SELECT doc_status FROM sales_orders WHERE id = %s
            """, (sales_order_id,))

            so_row = cur.fetchone()

            if not so_row:
                return jsonify({
                    "message": "Sales order not found"
                }), 404

            if so_row[0] == "Closed":
                return jsonify({
                    "message": (
                        "This sales order is already Closed (an "
                        "invoice or delivery already exists against "
                        "it). Cancel that document first if you need "
                        "to re-copy this order."
                    )
                }), 409

        cur.execute("""
            INSERT INTO invoices
            (
                invoice_number,
                customer_name,
                sales_order_id,
                invoice_amount,
                due_date,
                status,
                doc_status
            )
            VALUES (%s,%s,%s,%s,%s,%s,'Open')
        """, (
            data["invoice_number"],
            data["customer_name"],
            sales_order_id,
            data.get("invoice_amount", 0),
            data["due_date"],
            data.get("status", "Pending")
        ))

        invoice_id = cur.lastrowid

        # Close the base sales order, same as SAP B1's "Copy To"
        # closing the source document once it's been used.
        if sales_order_id:
            cur.execute("""
                UPDATE sales_orders
                SET doc_status = 'Closed',
                    closed_by_type = 'invoice',
                    closed_by_id = %s
                WHERE id = %s
            """, (invoice_id, sales_order_id))

        mysql.connection.commit()

        return jsonify({
            "message": "Invoice created successfully",
            "invoice_id": invoice_id
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to create invoice",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/create-invoice/<int:invoice_id>/cancel", methods=["PATCH"])
@jwt_required()
def cancel_invoice(invoice_id):
    """
    SAP B1-style cancel: marks the invoice Cancelled and re-opens
    whatever sales order it was closing, so that order becomes
    available to copy-to again. Doesn't delete the invoice — it stays
    visible with a Cancelled status, same as SAP B1 keeps a document
    trail rather than erasing it.
    """

    cur = mysql.connection.cursor()

    try:
        cur.execute("""
            SELECT sales_order_id, status
            FROM invoices
            WHERE id = %s
        """, (invoice_id,))

        row = cur.fetchone()

        if not row:
            return jsonify({"message": "Invoice not found"}), 404

        sales_order_id, current_status = row

        if current_status == "Cancelled":
            return jsonify({"message": "Invoice is already cancelled"}), 400

        cur.execute("""
            UPDATE invoices
            SET status = 'Cancelled', doc_status = 'Closed'
            WHERE id = %s
        """, (invoice_id,))

        # Re-open the base sales order, but only if THIS invoice is
        # actually what closed it (it may have already been closed by
        # a delivery instead, in which case leave it alone).
        if sales_order_id:
            cur.execute("""
                UPDATE sales_orders
                SET doc_status = 'Open',
                    closed_by_type = NULL,
                    closed_by_id = NULL
                WHERE id = %s
                AND closed_by_type = 'invoice'
                AND closed_by_id = %s
            """, (sales_order_id, invoice_id))

        mysql.connection.commit()

        create_system_log(
            action="INVOICE_CANCELLED",
            status="SUCCESS",
            payload={"invoice_id": invoice_id},
            response={"message": "Invoice cancelled, base order re-opened"}
        )

        return jsonify({
            "message": "Invoice cancelled and base sales order re-opened"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to cancel invoice",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/admin/invoices/export", methods=["GET"])
@jwt_required()
def export_invoices():
    # FIXED: same broken join as get_invoices, removed.

    start_date, end_date = get_date_range()

    query = """
        SELECT
            i.invoice_number AS `Invoice Number`,
            i.customer_name AS `Customer Name`,
            i.invoice_amount AS `Invoice Amount`,
            i.due_date AS `Due Date`,
            i.status AS `Status`,
            i.created_at AS `Created At`
        FROM invoices i
        WHERE 1=1
    """

    params = []

    if start_date:
        query += " AND DATE(i.created_at) >= %s"
        params.append(start_date)

    if end_date:
        query += " AND DATE(i.created_at) <= %s"
        params.append(end_date)

    query += " ORDER BY i.created_at DESC"

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute(query, params)
        rows = cur.fetchall()

    finally:
        cur.close()

    df = pd.DataFrame(rows)

    return export_dataframe(
        df,
        "invoices.xlsx",
        "Invoices"
    )


# ============================================================
# ============================================================
# DRIVERS  (new master data — add as a new section, e.g. after
# WAREHOUSES)
# ============================================================

@app.route("/api/drivers", methods=["GET"])
@jwt_required()
def get_drivers():

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute("""
            SELECT
                id,
                driver_code,
                driver_name,
                phone,
                vehicle_details,
                status,
                created_at,
                updated_at
            FROM drivers
            ORDER BY id DESC
        """)

        rows = cur.fetchall()

    finally:
        cur.close()

    return jsonify(rows)


@app.route("/api/drivers", methods=["POST"])
@jwt_required()
def create_driver():

    data = request.get_json() or {}

    if not data.get("driver_name"):
        return jsonify({
            "message": "Driver name is required"
        }), 400

    cur = mysql.connection.cursor()

    try:
        cur.execute("""
            INSERT INTO drivers
            (
                driver_code,
                driver_name,
                phone,
                vehicle_details,
                status
            )
            VALUES (%s,%s,%s,%s,%s)
        """, (
            "PENDING",
            data["driver_name"],
            data.get("phone"),
            data.get("vehicle_details"),
            data.get("status", "Active")
        ))

        driver_id = cur.lastrowid

        driver_code = f"DRV{str(driver_id).zfill(4)}"

        cur.execute("""
            UPDATE drivers
            SET driver_code = %s
            WHERE id = %s
        """, (driver_code, driver_id))

        mysql.connection.commit()

        return jsonify({
            "message": "Driver created successfully",
            "id": driver_id,
            "driver_code": driver_code
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to create driver",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/api/drivers/<int:id>", methods=["PUT"])
@jwt_required()
def update_driver(id):

    data = request.get_json() or {}

    cur = mysql.connection.cursor()

    try:
        cur.execute("""
            UPDATE drivers
            SET
                driver_name=%s,
                phone=%s,
                vehicle_details=%s,
                status=%s,
                updated_at=NOW()
            WHERE id=%s
        """, (
            data.get("driver_name"),
            data.get("phone"),
            data.get("vehicle_details"),
            data.get("status", "Active"),
            id
        ))

        if cur.rowcount == 0:
            mysql.connection.rollback()
            return jsonify({"message": "Driver not found"}), 404

        mysql.connection.commit()

        return jsonify({"message": "Driver updated successfully"})

    except Exception as e:
        mysql.connection.rollback()
        return jsonify({
            "message": "Failed to update driver",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/api/drivers/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_driver(id):

    cur = mysql.connection.cursor()

    try:
        cur.execute("DELETE FROM drivers WHERE id=%s", (id,))

        if cur.rowcount == 0:
            mysql.connection.rollback()
            return jsonify({"message": "Driver not found"}), 404

        mysql.connection.commit()

        return jsonify({"message": "Driver deleted successfully"})

    except Exception as e:
        mysql.connection.rollback()
        return jsonify({
            "message": "Failed to delete driver",
            "error": str(e)
        }), 500

    finally:
        cur.close()


# ============================================================
# DELIVERIES — REPLACE get_deliveries, create_delivery.
# ADD get_delivery_detail as a brand-new route.
# ============================================================

@app.route("/deliveries", methods=["GET"])
@jwt_required()
def get_deliveries():
    # List view stays lightweight - full pick list / all references
    # are fetched via get_delivery_detail when the user clicks View,
    # not loaded here for every row.

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute("""
            SELECT
                d.id,
                d.dispatch_code,
                d.customer_name,
                d.agent,
                d.driver_id,
                dr.driver_name,
                dr.vehicle_details,
                d.delivery_date,
                d.status,
                d.return_status,
                d.return_reason,
                d.created_by,
                d.created_at,
                (SELECT COUNT(*) FROM delivery_references dref
                    WHERE dref.delivery_id = d.id) AS reference_count,
                (SELECT COUNT(*) FROM delivery_items di
                    WHERE di.delivery_id = d.id) AS item_count
            FROM deliveries d
            LEFT JOIN drivers dr ON dr.id = d.driver_id
            ORDER BY d.created_at DESC
        """)

        rows = cur.fetchall()

    finally:
        cur.close()

    return jsonify(rows)


@app.route("/deliveries/<int:delivery_id>", methods=["GET"])
@jwt_required()
def get_delivery_detail(delivery_id):
    """
    Full delivery detail for the View screen: every order/invoice
    picked, the full pick list with quantities, and computed totals.
    """

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute("""
            SELECT
                d.id,
                d.dispatch_code,
                d.customer_name,
                d.agent,
                d.driver_id,
                dr.driver_name,
                dr.vehicle_details,
                dr.phone AS driver_phone,
                d.delivery_date,
                d.status,
                d.return_status,
                d.return_reason,
                d.created_by,
                d.created_at
            FROM deliveries d
            LEFT JOIN drivers dr ON dr.id = d.driver_id
            WHERE d.id = %s
        """, (delivery_id,))

        delivery = cur.fetchone()

        if not delivery:
            return jsonify({"message": "Delivery not found"}), 404

        cur.execute("""
            SELECT
                id,
                reference_type,
                reference_id,
                order_number,
                customer_name
            FROM delivery_references
            WHERE delivery_id = %s
        """, (delivery_id,))

        references = cur.fetchall()

        cur.execute("""
            SELECT
                id,
                item_id,
                item_code,
                item_name,
                quantity,
                unit
            FROM delivery_items
            WHERE delivery_id = %s
        """, (delivery_id,))

        items = cur.fetchall()

    finally:
        cur.close()

    delivery["references"] = references
    delivery["items"] = items
    delivery["total_references"] = len(references)
    delivery["total_line_items"] = len(items)
    delivery["total_quantity"] = sum(
        float(i["quantity"] or 0) for i in items
    )

    return jsonify(delivery)


@app.route("/deliveries", methods=["POST"])
@jwt_required()
def create_delivery():
    """
    Creates a delivery against one or more sales orders / invoices.
    Unlike the old single-reference version:
      - references is a LIST — pick one or many orders/invoices in
        one delivery run.
      - Items are NOT typed by hand — they're pulled automatically
        from each referenced order's line items (order_items).
        Invoices don't carry their own line items in this schema, so
        for an invoice reference we resolve it to its sales_order_id
        first and pull that order's items.
      - agent is resolved automatically from the first reference's
        order (created_by) — not sent by the client.
      - return_status/return_reason are intentionally NOT accepted
        here; they default to "No Return" and can only be set later
        via PUT /deliveries/<id> (the return option shows up after
        creation, not during).

    Expected body:
    {
        "references": [
            {"reference_type": "sales_order", "reference_id": 12},
            {"reference_type": "invoice", "reference_id": 7}
        ],
        "driver_id": 3,
        "delivery_date": "2026-08-15"
    }
    """

    current_user = get_current_user()

    if not current_user:
        return jsonify({"message": "User not found"}), 401

    data = request.get_json() or {}

    references = data.get("references") or []

    if not isinstance(references, list) or len(references) == 0:
        return jsonify({
            "message": "At least one sales order or invoice must be selected"
        }), 400

    if not data.get("driver_id"):
        return jsonify({"message": "Driver is required"}), 400

    cur = mysql.connection.cursor()

    try:
        resolved_refs = []
        pick_list = []
        agent = None
        primary_customer_name = None

        for ref in references:

            ref_type = ref.get("reference_type")
            ref_id = ref.get("reference_id")

            if ref_type not in ("sales_order", "invoice"):
                return jsonify({
                    "message": (
                        "Each reference_type must be 'sales_order' "
                        "or 'invoice'"
                    )
                }), 400

            if ref_type == "sales_order":

                cur.execute("""
                    SELECT
                        so.order_number,
                        so.created_by,
                        c.customer_name,
                        so.doc_status
                    FROM sales_orders so
                    LEFT JOIN customers c ON c.id = so.customer_id
                    WHERE so.id = %s
                """, (ref_id,))

                row = cur.fetchone()

                if not row:
                    return jsonify({
                        "message": f"Sales order {ref_id} not found"
                    }), 404

                order_number, created_by, customer_name, so_doc_status = row

                if so_doc_status == "Closed":
                    return jsonify({
                        "message": (
                            f"Sales order {order_number} is already "
                            "Closed and can't be copied again."
                        )
                    }), 409

                sales_order_id_for_items = ref_id

            else:  # invoice

                cur.execute("""
                    SELECT
                        i.invoice_number,
                        i.customer_name,
                        i.sales_order_id,
                        i.doc_status
                    FROM invoices i
                    WHERE i.id = %s
                """, (ref_id,))

                row = cur.fetchone()

                if not row:
                    return jsonify({
                        "message": f"Invoice {ref_id} not found"
                    }), 404

                order_number, customer_name, linked_order_id, inv_doc_status = row

                if inv_doc_status == "Closed":
                    return jsonify({
                        "message": (
                            f"Invoice {order_number} is already "
                            "Closed and can't be copied again."
                        )
                    }), 409

                sales_order_id_for_items = linked_order_id
                created_by = None

                if linked_order_id:
                    cur.execute("""
                        SELECT created_by
                        FROM sales_orders
                        WHERE id = %s
                    """, (linked_order_id,))
                    order_row = cur.fetchone()
                    created_by = order_row[0] if order_row else None

            if agent is None:
                agent = created_by
            if primary_customer_name is None:
                primary_customer_name = customer_name

            resolved_refs.append({
                "reference_type": ref_type,
                "reference_id": ref_id,
                "order_number": order_number,
                "customer_name": customer_name
            })

            # Pull the pick list for this reference's linked order.
            if sales_order_id_for_items:
                cur.execute("""
                    SELECT item_id, item_code, item_name, quantity, unit
                    FROM order_items
                    WHERE sales_order_id = %s
                """, (sales_order_id_for_items,))

                for line in cur.fetchall():
                    pick_list.append({
                        "item_id": line[0],
                        "item_code": line[1],
                        "item_name": line[2],
                        "quantity": line[3],
                        "unit": line[4]
                    })

        # Create the delivery header with a placeholder dispatch_code.
        cur.execute("""
            INSERT INTO deliveries
            (
                dispatch_code,
                reference_type,
                sales_order_id,
                invoice_id,
                order_number,
                customer_name,
                agent,
                driver_id,
                delivery_date,
                status,
                return_status,
                created_by
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
        """, (
            "PENDING",
            resolved_refs[0]["reference_type"],
            resolved_refs[0]["reference_id"] if resolved_refs[0]["reference_type"] == "sales_order" else None,
            resolved_refs[0]["reference_id"] if resolved_refs[0]["reference_type"] == "invoice" else None,
            resolved_refs[0]["order_number"],
            primary_customer_name,
            agent,
            data["driver_id"],
            data.get("delivery_date"),
            data.get("status", "Not Started"),
            "No Return",   # return can only be set later, via PUT
            current_user["username"]
        ))

        delivery_id = cur.lastrowid

        dispatch_code = f"DISP{str(delivery_id).zfill(6)}"

        cur.execute("""
            UPDATE deliveries
            SET dispatch_code = %s
            WHERE id = %s
        """, (dispatch_code, delivery_id))

        # Save every reference (not just the first one).
        for ref in resolved_refs:
            cur.execute("""
                INSERT INTO delivery_references
                (
                    delivery_id,
                    reference_type,
                    reference_id,
                    order_number,
                    customer_name
                )
                VALUES (%s,%s,%s,%s,%s)
            """, (
                delivery_id,
                ref["reference_type"],
                ref["reference_id"],
                ref["order_number"],
                ref["customer_name"]
            ))

        # Save the auto-pulled pick list.
        for line in pick_list:
            cur.execute("""
                INSERT INTO delivery_items
                (
                    delivery_id,
                    item_id,
                    item_code,
                    item_name,
                    quantity,
                    unit
                )
                VALUES (%s,%s,%s,%s,%s,%s)
            """, (
                delivery_id,
                line["item_id"],
                line["item_code"],
                line["item_name"],
                line["quantity"],
                line["unit"]
            ))

        # Close every referenced sales order / invoice, same as
        # create_invoice does — a document can only be "copied to"
        # a delivery once. Delete this delivery later and these all
        # re-open (see delete_delivery below).
        for ref in resolved_refs:
            table = "sales_orders" if ref["reference_type"] == "sales_order" else "invoices"
            cur.execute(f"""
                UPDATE {table}
                SET doc_status = 'Closed',
                    closed_by_type = 'delivery',
                    closed_by_id = %s
                WHERE id = %s
            """, (delivery_id, ref["reference_id"]))

        mysql.connection.commit()

        create_system_log(
            action="DELIVERY_CREATED",
            status="SUCCESS",
            payload={
                "delivery_id": delivery_id,
                "dispatch_code": dispatch_code,
                "reference_count": len(resolved_refs),
                "item_count": len(pick_list),
                "created_by": current_user["username"]
            },
            response={"message": "Delivery created"}
        )

        return jsonify({
            "message": "Delivery created successfully",
            "id": delivery_id,
            "dispatch_code": dispatch_code,
            "reference_count": len(resolved_refs),
            "item_count": len(pick_list)
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to create delivery",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/deliveries/<int:delivery_id>", methods=["PUT"])
@jwt_required()
def update_delivery(delivery_id):
    """
    Updates the logistics side of a delivery (driver, date, status,
    and — now that the delivery already exists — the return fields).
    References and the pick list are intentionally not editable here;
    create a new delivery if it was linked to the wrong order(s).
    """

    data = request.get_json() or {}

    cur = mysql.connection.cursor()

    try:
        cur.execute("""
            UPDATE deliveries
            SET
                driver_id = %s,
                delivery_date = %s,
                status = %s,
                return_status = %s,
                return_reason = %s
            WHERE id = %s
        """, (
            data.get("driver_id"),
            data.get("delivery_date"),
            data.get("status", "Not Started"),
            data.get("return_status", "No Return"),
            data.get("return_reason"),
            delivery_id
        ))

        if cur.rowcount == 0:
            mysql.connection.rollback()
            return jsonify({"message": "Delivery not found"}), 404

        mysql.connection.commit()

        return jsonify({"message": "Delivery updated successfully"})

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to update delivery",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/deliveries/export", methods=["GET"])
@jwt_required()
def export_deliveries():
    # Was missing entirely — added for parity with the export
    # buttons on Sales Orders / Invoices / Payments / Items / Customers.

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute("""
            SELECT
                d.dispatch_code AS `Dispatch Code`,
                d.customer_name AS `Customer`,
                d.agent AS `Agent`,
                dr.driver_name AS `Driver`,
                dr.vehicle_details AS `Vehicle`,
                d.delivery_date AS `Delivery Date`,
                d.status AS `Status`,
                d.return_status AS `Return Status`,
                d.created_by AS `Created By`,
                d.created_at AS `Created At`
            FROM deliveries d
            LEFT JOIN drivers dr ON dr.id = d.driver_id
            ORDER BY d.created_at DESC
        """)

        rows = cur.fetchall()

    finally:
        cur.close()

    df = pd.DataFrame(rows)

    return export_dataframe(
        df,
        "deliveries.xlsx",
        "Deliveries"
    )


# ============================================================
# DELIVERIES — delete (kept from the original single-reference
# version; still works fine against the new schema since it just
# removes the deliveries row, and delivery_references/delivery_items
# cascade-delete via their FOREIGN KEY ... ON DELETE CASCADE).
# ============================================================

@app.route("/deliveries/<int:delivery_id>", methods=["DELETE"])
@jwt_required()
def delete_delivery(delivery_id):

    cur = mysql.connection.cursor()

    try:
        # Re-open whatever sales orders/invoices this delivery had
        # closed, BEFORE deleting it (delivery_references cascade-
        # deletes with the parent row, so we need this list first).
        cur.execute("""
            SELECT reference_type, reference_id
            FROM delivery_references
            WHERE delivery_id = %s
        """, (delivery_id,))

        refs = cur.fetchall()

        cur.execute("""
            DELETE FROM deliveries
            WHERE id = %s
        """, (delivery_id,))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Delivery not found"
            }), 404

        for ref_type, ref_id in refs:
            table = "sales_orders" if ref_type == "sales_order" else "invoices"
            cur.execute(f"""
                UPDATE {table}
                SET doc_status = 'Open',
                    closed_by_type = NULL,
                    closed_by_id = NULL
                WHERE id = %s
                AND closed_by_type = 'delivery'
                AND closed_by_id = %s
            """, (ref_id, delivery_id))

        mysql.connection.commit()

        return jsonify({
            "message": "Delivery deleted successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to delete delivery",
            "error": str(e)
        }), 500

    finally:
        cur.close()




# ============================================================
# PAYMENTS
# ============================================================

@app.route("/admin/payments", methods=["GET"])
@jwt_required()
def get_payments():
    # FIXED: same broken customer_id join as get_invoices, removed -
    # uses i.customer_name from the (valid) invoices join instead.

    start_date, end_date = get_date_range()

    query = """
        SELECT
            p.id,
            p.payment_reference,
            p.invoice_id,
            i.invoice_number,
            i.customer_name,
            p.amount_paid,
            p.payment_method,
            p.payment_date,
            p.status,
            p.created_at
        FROM payments p
        LEFT JOIN invoices i
            ON i.id = p.invoice_id
        WHERE 1=1
    """

    params = []

    if start_date:
        query += " AND DATE(p.payment_date) >= %s"
        params.append(start_date)

    if end_date:
        query += " AND DATE(p.payment_date) <= %s"
        params.append(end_date)

    query += """
        ORDER BY
            p.payment_date DESC,
            p.id DESC
    """

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute(query, params)
        rows = cur.fetchall()

    finally:
        cur.close()

    return jsonify(rows)


@app.route("/create-payment", methods=["POST"])
@jwt_required()
def create_payment():
    """
    NEW route (didn't exist before - confirmed by scanning app.py for
    "create_payment" and finding nothing, which is why saving a
    payment always failed even though listing them worked).

    Two things added per request:

    1. payment_reference is generated server-side from the new row's
       id (same pattern as order_number/dispatch_code/item_code) -
       PAY-000123 - so a duplicate is structurally impossible. The
       frontend no longer needs to send one.

    2. Partial payment support: rejects an amount that would exceed
       the invoice's remaining balance, and auto-updates the
       invoice's status to Pending / Partial / Paid based on the
       running total across all payments against it.
    """

    data = request.get_json() or {}

    required_fields = [
        "invoice_id",
        "amount_paid",
        "payment_method",
        "payment_date"
    ]

    missing = [
        field for field in required_fields
        if not data.get(field)
    ]

    if missing:
        return jsonify({
            "message": "Required fields are missing",
            "fields": missing
        }), 400

    invoice_id = data["invoice_id"]

    try:
        amount_paid = float(data["amount_paid"])
    except (TypeError, ValueError):
        return jsonify({
            "message": "amount_paid must be a number"
        }), 400

    if amount_paid <= 0:
        return jsonify({
            "message": "Amount paid must be greater than zero"
        }), 400

    cur = mysql.connection.cursor()

    try:
        cur.execute("""
            SELECT invoice_amount
            FROM invoices
            WHERE id = %s
        """, (invoice_id,))

        invoice_row = cur.fetchone()

        if not invoice_row:
            return jsonify({
                "message": "Invoice not found"
            }), 404

        invoice_amount = float(invoice_row[0] or 0)

        cur.execute("""
            SELECT COALESCE(SUM(amount_paid), 0)
            FROM payments
            WHERE invoice_id = %s
        """, (invoice_id,))

        already_paid = float(cur.fetchone()[0] or 0)

        remaining = invoice_amount - already_paid

        if amount_paid > remaining + 0.01:
            return jsonify({
                "message": (
                    f"Amount exceeds the remaining balance of "
                    f"{remaining:.2f} on this invoice"
                )
            }), 400

        cur.execute("""
            INSERT INTO payments
            (
                payment_reference,
                invoice_id,
                amount_paid,
                payment_method,
                payment_date,
                status
            )
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (
            "PENDING",
            invoice_id,
            amount_paid,
            data["payment_method"],
            data["payment_date"],
            "Completed"
        ))

        payment_id = cur.lastrowid

        payment_reference = f"PAY-{str(payment_id).zfill(6)}"

        cur.execute("""
            UPDATE payments
            SET payment_reference = %s
            WHERE id = %s
        """, (payment_reference, payment_id))

        new_total_paid = already_paid + amount_paid

        if new_total_paid >= invoice_amount - 0.01:
            new_invoice_status = "Paid"
        elif new_total_paid > 0:
            new_invoice_status = "Partial"
        else:
            new_invoice_status = "Pending"

        cur.execute("""
            UPDATE invoices
            SET status = %s
            WHERE id = %s
        """, (new_invoice_status, invoice_id))

        mysql.connection.commit()

        create_system_log(
            action="PAYMENT_CREATED",
            status="SUCCESS",
            payload={
                "payment_id": payment_id,
                "payment_reference": payment_reference,
                "invoice_id": invoice_id,
                "amount_paid": amount_paid
            },
            response={
                "message": "Payment created",
                "invoice_status": new_invoice_status
            }
        )

        return jsonify({
            "message": "Payment created successfully",
            "payment_id": payment_id,
            "payment_reference": payment_reference,
            "invoice_status": new_invoice_status,
            "remaining_balance": round(invoice_amount - new_total_paid, 2)
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        create_system_log(
            action="PAYMENT_CREATED",
            status="FAILED",
            payload={
                "invoice_id": data.get("invoice_id")
            },
            response={
                "message": str(e)
            }
        )

        return jsonify({
            "message": "Failed to create payment",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/admin/payments/export", methods=["GET"])
@jwt_required()
def export_payments():
    # FIXED: same broken join as get_payments, removed.

    start_date, end_date = get_date_range()

    query = """
        SELECT
            p.payment_reference AS `Payment Reference`,
            i.invoice_number AS `Invoice Number`,
            i.customer_name AS `Customer Name`,
            p.amount_paid AS `Amount Paid`,
            p.payment_method AS `Payment Method`,
            p.payment_date AS `Payment Date`,
            p.status AS `Status`
        FROM payments p
        LEFT JOIN invoices i
            ON i.id = p.invoice_id
        WHERE 1=1
    """

    params = []

    if start_date:
        query += " AND DATE(p.payment_date) >= %s"
        params.append(start_date)

    if end_date:
        query += " AND DATE(p.payment_date) <= %s"
        params.append(end_date)

    query += " ORDER BY p.payment_date DESC"

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute(query, params)
        rows = cur.fetchall()

    finally:
        cur.close()

    df = pd.DataFrame(rows)

    return export_dataframe(
        df,
        "payments.xlsx",
        "Payments"
    )


# ============================================================
# CUSTOMER REPORT
# ============================================================

@app.route("/api/reports/customers", methods=["GET"])
@jwt_required()
def customer_report():

    start_date, end_date = get_date_range()

    query = """
        SELECT
            c.id,
            c.customer_code,
            c.customer_name,
            c.phone,
            c.email,
            c.location,
            c.route,
            c.credit_limit,
            c.status,
            c.created_by,
            c.created_at
        FROM customers c
        WHERE 1=1
    """

    params = []

    if start_date:
        query += " AND DATE(c.created_at) >= %s"
        params.append(start_date)

    if end_date:
        query += " AND DATE(c.created_at) <= %s"
        params.append(end_date)

    query += " ORDER BY c.created_at DESC"

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute(query, params)
        rows = cur.fetchall()

    finally:
        cur.close()

    return jsonify(rows)


@app.route("/api/reports/customers/export", methods=["GET"])
@jwt_required()
def export_customer_report():

    start_date, end_date = get_date_range()

    query = """
        SELECT
            c.customer_code AS `Customer Code`,
            c.customer_name AS `Customer Name`,
            c.phone AS `Phone`,
            c.email AS `Email`,
            c.location AS `Location`,
            c.route AS `Route`,
            c.credit_limit AS `Credit Limit`,
            c.status AS `Status`,
            c.created_by AS `Created By`,
            c.created_at AS `Created At`
        FROM customers c
        WHERE 1=1
    """

    params = []

    if start_date:
        query += " AND DATE(c.created_at) >= %s"
        params.append(start_date)

    if end_date:
        query += " AND DATE(c.created_at) <= %s"
        params.append(end_date)

    query += " ORDER BY c.created_at DESC"

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute(query, params)
        rows = cur.fetchall()

    finally:
        cur.close()

    df = pd.DataFrame(rows)

    return export_dataframe(
        df,
        "customers.xlsx",
        "Customers"
    )


# ============================================================
# REPORT SUMMARY
# ============================================================

@app.route("/api/reports/summary", methods=["GET"])
@jwt_required()
def report_summary():

    start_date, end_date = get_date_range()

    customer_query = """
        SELECT
            COUNT(*) AS total_customers
        FROM customers
        WHERE 1=1
    """

    invoice_query = """
        SELECT
            COUNT(*) AS total_invoices,
            COALESCE(SUM(invoice_amount), 0) AS invoice_value
        FROM invoices
        WHERE 1=1
    """

    payment_query = """
        SELECT
            COUNT(*) AS total_payments,
            COALESCE(SUM(amount_paid), 0) AS paid_amount
        FROM payments
        WHERE 1=1
    """

    sales_order_query = """
        SELECT
            COUNT(*) AS total_orders,
            COALESCE(SUM(total_amount), 0) AS order_value
        FROM sales_orders
        WHERE 1=1
    """

    customer_params = []
    invoice_params = []
    payment_params = []
    sales_order_params = []

    if start_date:

        customer_query += " AND DATE(created_at) >= %s"
        invoice_query += " AND DATE(created_at) >= %s"
        payment_query += " AND DATE(payment_date) >= %s"
        sales_order_query += " AND DATE(order_date) >= %s"

        customer_params.append(start_date)
        invoice_params.append(start_date)
        payment_params.append(start_date)
        sales_order_params.append(start_date)

    if end_date:

        customer_query += " AND DATE(created_at) <= %s"
        invoice_query += " AND DATE(created_at) <= %s"
        payment_query += " AND DATE(payment_date) <= %s"
        sales_order_query += " AND DATE(order_date) <= %s"

        customer_params.append(end_date)
        invoice_params.append(end_date)
        payment_params.append(end_date)
        sales_order_params.append(end_date)

    cur = mysql.connection.cursor(DictCursor)

    try:

        cur.execute(
            customer_query,
            customer_params
        )
        customers = cur.fetchone()

        cur.execute(
            invoice_query,
            invoice_params
        )
        invoices = cur.fetchone()

        cur.execute(
            payment_query,
            payment_params
        )
        payments = cur.fetchone()

        cur.execute(
            sales_order_query,
            sales_order_params
        )
        sales_orders = cur.fetchone()

    finally:
        cur.close()

    invoice_value = float(
        invoices["invoice_value"] or 0
    )

    paid_amount = float(
        payments["paid_amount"] or 0
    )

    collection_rate = (
        (paid_amount / invoice_value) * 100
        if invoice_value > 0
        else 0
    )

    return jsonify({
        "total_customers": customers["total_customers"],
        "total_orders": sales_orders["total_orders"],
        "order_value": float(
            sales_orders["order_value"] or 0
        ),
        "total_invoices": invoices["total_invoices"],
        "invoice_value": invoice_value,
        "total_payments": payments["total_payments"],
        "paid_amount": paid_amount,
        "collection_rate": round(
            collection_rate,
            2
        )
    })


# ============================================================
# MONTHLY SALES REPORT
# ============================================================

@app.route("/api/reports/monthly-sales", methods=["GET"])
@jwt_required()
def monthly_sales():

    start_date, end_date = get_date_range()

    query = """
        SELECT
            DATE_FORMAT(
                i.created_at,
                '%Y-%m'
            ) AS month,
            COUNT(i.id) AS invoices,
            COALESCE(
                SUM(i.invoice_amount),
                0
            ) AS total_sales
        FROM invoices i
        WHERE 1=1
    """

    params = []

    if start_date:
        query += " AND DATE(i.created_at) >= %s"
        params.append(start_date)

    if end_date:
        query += " AND DATE(i.created_at) <= %s"
        params.append(end_date)

    query += """
        GROUP BY DATE_FORMAT(
            i.created_at,
            '%Y-%m'
        )
        ORDER BY month ASC
    """

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute(query, params)
        rows = cur.fetchall()

    finally:
        cur.close()

    return jsonify(rows)


# ============================================================
# ROUTE PERFORMANCE
# ============================================================

@app.route("/api/reports/route-performance", methods=["GET"])
@jwt_required()
def route_performance():

    start_date, end_date = get_date_range()

    query = """
        SELECT
            r.route_name,
            COUNT(i.id) AS invoices,
            COALESCE(
                SUM(i.invoice_amount),
                0
            ) AS total_sales
        FROM routes r
        LEFT JOIN invoices i
            ON i.route_id = r.id
    """

    params = []
    conditions = []

    if start_date:
        conditions.append(
            "DATE(i.created_at) >= %s"
        )
        params.append(start_date)

    if end_date:
        conditions.append(
            "DATE(i.created_at) <= %s"
        )
        params.append(end_date)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += """
        GROUP BY
            r.id,
            r.route_name
        ORDER BY total_sales DESC
    """

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute(query, params)
        rows = cur.fetchall()

    finally:
        cur.close()

    return jsonify(rows)


# ============================================================
# SALES REP PERFORMANCE
# ============================================================

@app.route("/api/reports/sales-rep-performance", methods=["GET"])
@jwt_required()
def sales_rep_performance():

    start_date, end_date = get_date_range()

    query = """
        SELECT
            u.username AS sales_rep,
            COUNT(i.id) AS invoices,
            COALESCE(
                SUM(i.invoice_amount),
                0
            ) AS total_sales
        FROM users u
        LEFT JOIN invoices i
            ON i.created_by = u.id
    """

    params = []

    conditions = [
        "u.role = 'sales_rep'"
    ]

    if start_date:
        conditions.append(
            "DATE(i.created_at) >= %s"
        )
        params.append(start_date)

    if end_date:
        conditions.append(
            "DATE(i.created_at) <= %s"
        )
        params.append(end_date)

    query += """
        WHERE
    """ + " AND ".join(conditions)

    query += """
        GROUP BY
            u.id,
            u.username
        ORDER BY total_sales DESC
    """

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute(query, params)
        rows = cur.fetchall()

    finally:
        cur.close()

    return jsonify(rows)


# ============================================================
# COLLECTION RATE
# ============================================================

@app.route("/api/reports/collection-rate", methods=["GET"])
@jwt_required()
def collection_rate():

    start_date, end_date = get_date_range()

    invoice_query = """
        SELECT
            COALESCE(
                SUM(i.invoice_amount),
                0
            ) AS billed
        FROM invoices i
        WHERE 1=1
    """

    payment_query = """
        SELECT
            COALESCE(
                SUM(p.amount_paid),
                0
            ) AS collected
        FROM payments p
        INNER JOIN invoices i
            ON i.id = p.invoice_id
        WHERE 1=1
    """

    invoice_params = []
    payment_params = []

    if start_date:

        invoice_query += """
            AND DATE(i.created_at) >= %s
        """

        payment_query += """
            AND DATE(i.created_at) >= %s
        """

        invoice_params.append(start_date)
        payment_params.append(start_date)

    if end_date:

        invoice_query += """
            AND DATE(i.created_at) <= %s
        """

        payment_query += """
            AND DATE(i.created_at) <= %s
        """

        invoice_params.append(end_date)
        payment_params.append(end_date)

    cur = mysql.connection.cursor(DictCursor)

    try:

        cur.execute(
            invoice_query,
            invoice_params
        )
        invoice_row = cur.fetchone()

        cur.execute(
            payment_query,
            payment_params
        )
        payment_row = cur.fetchone()

    finally:
        cur.close()

    billed = float(
        invoice_row["billed"] or 0
    )

    collected = float(
        payment_row["collected"] or 0
    )

    rate = (
        (collected / billed) * 100
        if billed > 0
        else 0
    )

    return jsonify({
        "billed": billed,
        "collected": collected,
        "rate": round(rate, 2)
    })


# ============================================================
# TIMESHEET
# ============================================================

@app.route("/timesheet", methods=["GET"])
@jwt_required()
def get_timesheet():

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    query = """
        SELECT
            id,
            user,
            date,
            start_time,
            end_time,
            status,
            logged_hours
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

    try:
        cur.execute(query, params)
        rows = cur.fetchall()

    finally:
        cur.close()

    result = []

    for r in rows:
        result.append({
            "id": r[0],
            "user": r[1],
            "date": (
                r[2].strftime("%Y-%m-%d")
                if r[2] else None
            ),
            "start_time": (
                str(r[3])
                if r[3]
                else None
            ),
            "end_time": (
                str(r[4])
                if r[4]
                else None
            ),
            "status": r[5],
            "logged_hours": float(
                r[6] or 0
            )
        })

    return jsonify(result)


@app.route("/timesheet/current", methods=["GET"])
@jwt_required()
def get_current_timesheet():

    current_user = get_current_user()

    if not current_user:
        return jsonify({
            "message": "User not found"
        }), 401

    cur = mysql.connection.cursor()

    try:
        cur.execute("""
            SELECT
                id,
                user,
                date,
                start_time,
                end_time,
                status,
                logged_hours
            FROM timesheet
            WHERE user = %s
            AND date = CURDATE()
            AND status = 'Active'
            ORDER BY id DESC
            LIMIT 1
        """, (current_user["username"],))

        row = cur.fetchone()

    finally:
        cur.close()

    if not row:
        return jsonify(None)

    return jsonify({
        "id": row[0],
        "user": row[1],
        "date": row[2].strftime("%Y-%m-%d") if row[2] else None,
        "start_time": str(row[3]) if row[3] else None,
        "end_time": str(row[4]) if row[4] else None,
        "status": row[5],
        "logged_hours": float(row[6] or 0)
    })


@app.route("/timesheet/start-day", methods=["POST"])
@jwt_required()
def start_day():

    current_user = get_current_user()

    if not current_user:
        return jsonify({
            "message": "User not found"
        }), 401

    cur = mysql.connection.cursor()

    try:
        cur.execute("""
            SELECT id
            FROM timesheet
            WHERE user = %s
            AND date = CURDATE()
            AND status = 'Active'
        """, (current_user["username"],))

        existing = cur.fetchone()

        if existing:
            return jsonify({
                "message": "You have already started your day"
            }), 400

        cur.execute("""
            INSERT INTO timesheet
            (
                user,
                date,
                start_time,
                status
            )
            VALUES (%s, CURDATE(), CURTIME(), 'Active')
        """, (current_user["username"],))

        new_id = cur.lastrowid

        mysql.connection.commit()

        create_system_log(
            action="TIMESHEET_DAY_STARTED",
            status="SUCCESS",
            payload={
                "user": current_user["username"]
            },
            response={
                "timesheet_id": new_id
            }
        )

        return jsonify({
            "message": "Day started",
            "id": new_id
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to start day",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/timesheet/<int:timesheet_id>/end-day", methods=["PATCH"])
@jwt_required()
def end_day(timesheet_id):

    current_user = get_current_user()

    if not current_user:
        return jsonify({
            "message": "User not found"
        }), 401

    cur = mysql.connection.cursor()

    try:
        cur.execute("""
            SELECT
                id,
                user,
                start_time,
                status
            FROM timesheet
            WHERE id = %s
        """, (timesheet_id,))

        row = cur.fetchone()

        if not row:
            return jsonify({
                "message": "Timesheet entry not found"
            }), 404

        if row[1] != current_user["username"]:
            return jsonify({
                "message": "This timesheet entry does not belong to you"
            }), 403

        if row[3] != "Active":
            return jsonify({
                "message": "This day has already been ended"
            }), 400

        cur.execute("""
            SELECT id
            FROM visits
            WHERE user = %s
            AND visit_date = CURDATE()
            AND status = 'In Progress'
        """, (current_user["username"],))

        open_visit = cur.fetchone()

        if open_visit:
            return jsonify({
                "message": (
                    "Please check out of your current visit "
                    "before ending the day"
                )
            }), 400

        cur.execute("""
            SELECT start_time
            FROM timesheet
            WHERE id = %s
        """, (timesheet_id,))

        start_row = cur.fetchone()
        start_time = start_row[0]

        cur.execute("SELECT CURTIME()")
        end_time = cur.fetchone()[0]

        logged_hours = hours_between(start_time, end_time)

        cur.execute("""
            UPDATE timesheet
            SET
                end_time = %s,
                status = 'Completed',
                logged_hours = %s
            WHERE id = %s
        """, (
            end_time,
            logged_hours,
            timesheet_id
        ))

        mysql.connection.commit()

        create_system_log(
            action="TIMESHEET_DAY_ENDED",
            status="SUCCESS",
            payload={
                "user": current_user["username"],
                "timesheet_id": timesheet_id
            },
            response={
                "logged_hours": logged_hours
            }
        )

        return jsonify({
            "message": "Day ended",
            "logged_hours": logged_hours
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to end day",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/timesheet/export", methods=["GET"])
@jwt_required()
def export_timesheet():

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    query = """
        SELECT
            user AS `User`,
            date AS `Date`,
            start_time AS `Start Time`,
            end_time AS `End Time`,
            status AS `Status`,
            logged_hours AS `Logged Hours`
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

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute(query, params)
        rows = cur.fetchall()

    finally:
        cur.close()

    df = pd.DataFrame(rows)

    return export_dataframe(
        df,
        "timesheet.xlsx",
        "Timesheet"
    )


# ============================================================
# VISITS
# ============================================================

@app.route("/visits", methods=["GET"])
@jwt_required()
def get_visits():

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    query = """
        SELECT
            id,
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

    try:
        cur.execute(query, params)
        rows = cur.fetchall()

    finally:
        cur.close()

    result = []

    for r in rows:
        result.append({
            "id": r[0],
            "user": r[1],
            "customer": r[2],
            "route_name": r[3],
            "time_in": (
                str(r[4])
                if r[4]
                else None
            ),
            "time_out": (
                str(r[5])
                if r[5]
                else None
            ),
            "duration": r[6],
            "comment": r[7],
            "status": r[8],
            "visit_date": (
                r[9].strftime("%Y-%m-%d")
                if r[9]
                else None
            )
        })

    return jsonify(result)


@app.route("/visits/current", methods=["GET"])
@jwt_required()
def get_current_visit():

    current_user = get_current_user()

    if not current_user:
        return jsonify({
            "message": "User not found"
        }), 401

    cur = mysql.connection.cursor()

    try:
        cur.execute("""
            SELECT
                id,
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
            WHERE user = %s
            AND visit_date = CURDATE()
            AND status = 'In Progress'
            ORDER BY id DESC
            LIMIT 1
        """, (current_user["username"],))

        row = cur.fetchone()

    finally:
        cur.close()

    if not row:
        return jsonify(None)

    return jsonify({
        "id": row[0],
        "user": row[1],
        "customer": row[2],
        "route_name": row[3],
        "time_in": str(row[4]) if row[4] else None,
        "time_out": str(row[5]) if row[5] else None,
        "duration": row[6],
        "comment": row[7],
        "status": row[8],
        "visit_date": row[9].strftime("%Y-%m-%d") if row[9] else None
    })


@app.route("/visits/check-in", methods=["POST"])
@jwt_required()
def check_in_visit():

    current_user = get_current_user()

    if not current_user:
        return jsonify({
            "message": "User not found"
        }), 401

    data = request.get_json() or {}

    customer = data.get("customer")
    route_name = data.get("route_name")

    if not customer:
        return jsonify({
            "message": "Customer is required"
        }), 400

    cur = mysql.connection.cursor()

    try:
        cur.execute("""
            SELECT id
            FROM timesheet
            WHERE user = %s
            AND date = CURDATE()
            AND status = 'Active'
        """, (current_user["username"],))

        active_day = cur.fetchone()

        if not active_day:
            return jsonify({
                "message": "Please start your day before checking in"
            }), 400

        cur.execute("""
            SELECT id
            FROM visits
            WHERE user = %s
            AND visit_date = CURDATE()
            AND status = 'In Progress'
        """, (current_user["username"],))

        open_visit = cur.fetchone()

        if open_visit:
            return jsonify({
                "message": (
                    "You are already checked in to a visit. "
                    "Please check out first."
                )
            }), 400

        cur.execute("""
            INSERT INTO visits
            (
                user,
                customer,
                route_name,
                time_in,
                visit_date,
                status
            )
            VALUES (%s, %s, %s, CURTIME(), CURDATE(), 'In Progress')
        """, (
            current_user["username"],
            customer,
            route_name
        ))

        new_id = cur.lastrowid

        mysql.connection.commit()

        create_system_log(
            action="VISIT_CHECKED_IN",
            status="SUCCESS",
            payload={
                "user": current_user["username"],
                "customer": customer
            },
            response={
                "visit_id": new_id
            }
        )

        return jsonify({
            "message": "Checked in",
            "id": new_id
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to check in",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/visits/<int:visit_id>/check-out", methods=["PATCH"])
@jwt_required()
def check_out_visit(visit_id):

    current_user = get_current_user()

    if not current_user:
        return jsonify({
            "message": "User not found"
        }), 401

    data = request.get_json() or {}

    reason = data.get("reason")
    comment = data.get("comment")

    if reason not in ALLOWED_VISIT_CHECKOUT_REASONS:
        return jsonify({
            "message": "Invalid checkout reason",
            "allowed_reasons": ALLOWED_VISIT_CHECKOUT_REASONS
        }), 400

    cur = mysql.connection.cursor()

    try:
        cur.execute("""
            SELECT
                id,
                user,
                time_in,
                status
            FROM visits
            WHERE id = %s
        """, (visit_id,))

        row = cur.fetchone()

        if not row:
            return jsonify({
                "message": "Visit not found"
            }), 404

        if row[1] != current_user["username"]:
            return jsonify({
                "message": "This visit does not belong to you"
            }), 403

        if row[3] != "In Progress":
            return jsonify({
                "message": "This visit has already been checked out"
            }), 400

        time_in = row[2]

        cur.execute("SELECT CURTIME()")
        time_out = cur.fetchone()[0]

        duration_str = format_duration(time_in, time_out)

        cur.execute("""
            UPDATE visits
            SET
                time_out = %s,
                duration = %s,
                status = %s,
                comment = %s
            WHERE id = %s
        """, (
            time_out,
            duration_str,
            reason,
            comment,
            visit_id
        ))

        mysql.connection.commit()

        create_system_log(
            action="VISIT_CHECKED_OUT",
            status="SUCCESS",
            payload={
                "user": current_user["username"],
                "visit_id": visit_id,
                "reason": reason
            },
            response={
                "duration": duration_str
            }
        )

        return jsonify({
            "message": "Checked out",
            "duration": duration_str,
            "status": reason
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to check out",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/visits/export", methods=["GET"])
@jwt_required()
def export_visits():

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    query = """
        SELECT
            user AS `User`,
            customer AS `Customer`,
            route_name AS `Route Name`,
            time_in AS `Time In`,
            time_out AS `Time Out`,
            duration AS `Duration`,
            comment AS `Comment`,
            status AS `Status`,
            visit_date AS `Visit Date`
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

    cur = mysql.connection.cursor(DictCursor)

    try:
        cur.execute(query, params)
        rows = cur.fetchall()

    finally:
        cur.close()

    df = pd.DataFrame(rows)

    return export_dataframe(
        df,
        "visits.xlsx",
        "Visits"
    )


# ============================================================
# TRIPS
# ============================================================

@app.route("/trips", methods=["GET"])
@jwt_required()
def get_trips():

    cur = mysql.connection.cursor()

    try:

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
                t.status,
                t.created_at
            FROM trips t
            LEFT JOIN users u
                ON u.id = t.sales_rep_id
            LEFT JOIN regions r
                ON r.id = t.region_id
            ORDER BY t.id DESC
        """)

        trips = cur.fetchall()

        result = []

        for t in trips:

            trip_id = t[0]

            cur.execute("""
                SELECT
                    c.id,
                    c.customer_name
                FROM trip_customers tc
                JOIN customers c
                    ON c.id = tc.customer_id
                WHERE tc.trip_id = %s
            """, (trip_id,))

            customer_rows = cur.fetchall()

            customers = [
                {
                    "id": c[0],
                    "name": c[1]
                }
                for c in customer_rows
            ]

            cur.execute("""
                SELECT day_of_week
                FROM trip_weekly_schedule
                WHERE trip_id=%s
                ORDER BY day_of_week
            """, (trip_id,))

            weekly_rows = cur.fetchall()

            weekly_days = [
                row[0]
                for row in weekly_rows
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
                "status": t[9],
                "customers": customers,
                "weekly_days": weekly_days,
                "created_at": (
                    str(t[10])
                    if t[10]
                    else None
                )
            })

        return jsonify(result)

    finally:
        cur.close()


@app.route("/trips", methods=["POST"])
@jwt_required()
def create_trip():

    data = request.get_json() or {}

    if not data.get("trip_name"):
        return jsonify({
            "message": "Trip name is required"
        }), 400

    if not data.get("sales_rep_id"):
        return jsonify({
            "message": "Sales representative is required"
        }), 400

    if not data.get("region_id"):
        return jsonify({
            "message": "Region is required"
        }), 400

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            INSERT INTO trips
            (
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

        if data.get("schedule_type") == "weekly":

            for day in data.get("weekly_days", []):

                cur.execute("""
                    INSERT INTO trip_weekly_schedule
                    (
                        trip_id,
                        day_of_week
                    )
                    VALUES (%s,%s)
                """, (
                    trip_id,
                    day
                ))

        if not data.get("visit_all_customers", 0):

            for customer_id in data.get("customers", []):

                cur.execute("""
                    INSERT INTO trip_customers
                    (
                        trip_id,
                        customer_id
                    )
                    VALUES (%s,%s)
                """, (
                    trip_id,
                    customer_id
                ))

        mysql.connection.commit()

        return jsonify({
            "message": "Trip created successfully",
            "trip_id": trip_id
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to create trip",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/trips/<int:trip_id>", methods=["PUT"])
@jwt_required()
def update_trip(trip_id):

    data = request.get_json() or {}

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            UPDATE trips
            SET
                trip_name=%s,
                sales_rep_id=%s,
                region_id=%s,
                schedule_type=%s,
                monthly_date=%s,
                visit_all_customers=%s,
                status=%s
            WHERE id=%s
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

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Trip not found"
            }), 404

        cur.execute("""
            DELETE FROM trip_customers
            WHERE trip_id=%s
        """, (trip_id,))

        if not data.get("visit_all_customers", 0):

            for customer_id in data.get("customers", []):

                cur.execute("""
                    INSERT INTO trip_customers
                    (
                        trip_id,
                        customer_id
                    )
                    VALUES (%s,%s)
                """, (
                    trip_id,
                    customer_id
                ))

        cur.execute("""
            DELETE FROM trip_weekly_schedule
            WHERE trip_id=%s
        """, (trip_id,))

        if data.get("schedule_type") == "weekly":

            for day in data.get("weekly_days", []):

                cur.execute("""
                    INSERT INTO trip_weekly_schedule
                    (
                        trip_id,
                        day_of_week
                    )
                    VALUES (%s,%s)
                """, (
                    trip_id,
                    day
                ))

        mysql.connection.commit()

        return jsonify({
            "message": "Trip updated successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to update trip",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/trips/<int:trip_id>/status", methods=["PATCH"])
@jwt_required()
def update_trip_status(trip_id):

    data = request.get_json() or {}

    new_status = data.get("status")

    if new_status not in [
        "Active",
        "Inactive"
    ]:
        return jsonify({
            "message": "Invalid status"
        }), 400

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            UPDATE trips
            SET status=%s
            WHERE id=%s
        """, (
            new_status,
            trip_id
        ))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Trip not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Trip status updated"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to update trip status",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/trips/<int:trip_id>", methods=["DELETE"])
@jwt_required()
def delete_trip(trip_id):

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            SELECT id
            FROM trips
            WHERE id=%s
        """, (trip_id,))

        trip = cur.fetchone()

        if not trip:
            return jsonify({
                "message": "Trip not found"
            }), 404

        cur.execute("""
            DELETE FROM trip_customers
            WHERE trip_id=%s
        """, (trip_id,))

        cur.execute("""
            DELETE FROM trip_weekly_schedule
            WHERE trip_id=%s
        """, (trip_id,))

        cur.execute("""
            DELETE FROM trips
            WHERE id=%s
        """, (trip_id,))

        mysql.connection.commit()

        return jsonify({
            "message": "Trip deleted successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to delete trip",
            "error": str(e)
        }), 500

    finally:
        cur.close()


# ============================================================
# PRICE LISTS
# ============================================================

@app.route("/api/price-lists", methods=["GET"])
@jwt_required()
def get_price_lists():

    cur = mysql.connection.cursor(DictCursor)

    try:

        cur.execute("""
            SELECT
                id,
                code,
                name,
                currency,
                status,
                created_at,
                updated_at
            FROM price_lists
            ORDER BY id DESC
        """)

        rows = cur.fetchall()

    finally:
        cur.close()

    return jsonify(rows)


@app.route("/api/price-lists", methods=["POST"])
@jwt_required()
def create_price_list():

    data = request.get_json() or {}

    if not data.get("code") or not data.get("name"):
        return jsonify({
            "message": "Code and name are required"
        }), 400

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            INSERT INTO price_lists
            (
                code,
                name,
                currency,
                status
            )
            VALUES (%s,%s,%s,%s)
        """, (
            data["code"],
            data["name"],
            data["currency"],
            data.get("status", "Active")
        ))

        new_id = cur.lastrowid

        mysql.connection.commit()

        return jsonify({
            "message": "Created",
            "id": new_id
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to create price list",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/api/price-lists/<int:id>", methods=["PUT"])
@jwt_required()
def update_price_list(id):

    data = request.get_json() or {}

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            UPDATE price_lists
            SET
                code=%s,
                name=%s,
                currency=%s,
                status=%s,
                updated_at=NOW()
            WHERE id=%s
        """, (
            data.get("code"),
            data.get("name"),
            data.get("currency"),
            data.get("status", "Active"),
            id
        ))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Price list not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Updated"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to update price list",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/api/price-lists/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_price_list(id):

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            DELETE FROM price_lists
            WHERE id=%s
        """, (id,))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Price list not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Deleted"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to delete price list",
            "error": str(e)
        }), 500

    finally:
        cur.close()


# ============================================================
# TAXES
# ============================================================

@app.route("/api/taxes", methods=["GET"])
@jwt_required()
def get_taxes():

    cur = mysql.connection.cursor(DictCursor)

    try:

        cur.execute("""
            SELECT
                id,
                code,
                name,
                type,
                rate,
                compound,
                exempt,
                status,
                created_at,
                updated_at
            FROM taxes
            ORDER BY id DESC
        """)

        rows = cur.fetchall()

    finally:
        cur.close()

    return jsonify(rows)


@app.route("/api/taxes/<int:id>", methods=["GET"])
@jwt_required()
def get_tax(id):

    cur = mysql.connection.cursor(DictCursor)

    try:

        cur.execute("""
            SELECT
                id,
                code,
                name,
                type,
                rate,
                compound,
                exempt,
                status,
                created_at,
                updated_at
            FROM taxes
            WHERE id=%s
        """, (id,))

        row = cur.fetchone()

    finally:
        cur.close()

    if not row:
        return jsonify({
            "message": "Tax not found"
        }), 404

    return jsonify(row)


@app.route("/api/taxes", methods=["POST"])
@jwt_required()
def create_tax():
    # NOTE: "rate" column added to the SELECTs above and to this
    # INSERT/UPDATE below - it was missing from the original queries
    # entirely, which is the real reason the Taxes page never showed
    # or saved a rate (not a frontend bug - the column just wasn't
    # being read or written on the backend).

    data = request.get_json() or {}

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            INSERT INTO taxes
            (
                code,
                name,
                type,
                rate,
                compound,
                exempt,
                status
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (
            data["code"],
            data["name"],
            data["type"],
            data.get("rate", 0),
            data.get("compound", 0),
            data.get("exempt", 0),
            data.get("status", "Active")
        ))

        new_id = cur.lastrowid

        mysql.connection.commit()

        return jsonify({
            "message": "Tax created successfully",
            "id": new_id
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to create tax",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/api/taxes/<int:id>", methods=["PUT"])
@jwt_required()
def update_tax(id):

    data = request.get_json() or {}

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            UPDATE taxes
            SET
                code=%s,
                name=%s,
                type=%s,
                rate=%s,
                compound=%s,
                exempt=%s,
                status=%s,
                updated_at=NOW()
            WHERE id=%s
        """, (
            data["code"],
            data["name"],
            data["type"],
            data.get("rate", 0),
            data.get("compound", 0),
            data.get("exempt", 0),
            data.get("status", "Active"),
            id
        ))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Tax not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Tax updated successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to update tax",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/api/taxes/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_tax(id):

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            DELETE FROM taxes
            WHERE id=%s
        """, (id,))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Tax not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Tax deleted successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to delete tax",
            "error": str(e)
        }), 500

    finally:
        cur.close()


# ============================================================
# CURRENCIES
# ============================================================

@app.route("/api/currencies", methods=["GET"])
@jwt_required()
def get_currencies():

    cur = mysql.connection.cursor(DictCursor)

    try:

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

    finally:
        cur.close()

    return jsonify(rows)


@app.route("/api/currencies/<int:id>", methods=["GET"])
@jwt_required()
def get_currency(id):

    cur = mysql.connection.cursor(DictCursor)

    try:

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

    finally:
        cur.close()

    if not row:
        return jsonify({
            "message": "Currency not found"
        }), 404

    return jsonify(row)


@app.route("/api/currencies", methods=["POST"])
@jwt_required()
def create_currency():

    data = request.get_json() or {}

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            INSERT INTO currencies
            (
                code,
                name,
                status
            )
            VALUES (%s,%s,%s)
        """, (
            data["code"],
            data["name"],
            data.get("status", "Active")
        ))

        new_id = cur.lastrowid

        mysql.connection.commit()

        return jsonify({
            "message": "Currency created successfully",
            "id": new_id
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to create currency",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/api/currencies/<int:id>", methods=["PUT"])
@jwt_required()
def update_currency(id):

    data = request.get_json() or {}

    cur = mysql.connection.cursor()

    try:

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
            data.get("status", "Active"),
            id
        ))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Currency not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Currency updated successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to update currency",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/api/currencies/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_currency(id):

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            DELETE FROM currencies
            WHERE id=%s
        """, (id,))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Currency not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Currency deleted successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to delete currency",
            "error": str(e)
        }), 500

    finally:
        cur.close()


# ============================================================
# PAYMENT TERMS
# ============================================================

@app.route("/api/payment-terms", methods=["GET"])
@jwt_required()
def get_payment_terms():

    cur = mysql.connection.cursor(DictCursor)

    try:

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

    finally:
        cur.close()

    return jsonify(rows)


@app.route("/api/payment-terms/<int:id>", methods=["GET"])
@jwt_required()
def get_payment_term(id):

    cur = mysql.connection.cursor(DictCursor)

    try:

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

    finally:
        cur.close()

    if not row:
        return jsonify({
            "message": "Payment term not found"
        }), 404

    return jsonify(row)


@app.route("/api/payment-terms", methods=["POST"])
@jwt_required()
def create_payment_term():

    data = request.get_json() or {}

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            INSERT INTO payment_terms
            (
                code,
                name,
                days,
                status
            )
            VALUES (%s,%s,%s,%s)
        """, (
            data["code"],
            data["name"],
            data["days"],
            data.get("status", "Active")
        ))

        new_id = cur.lastrowid

        mysql.connection.commit()

        return jsonify({
            "message": "Payment term created successfully",
            "id": new_id
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to create payment term",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/api/payment-terms/<int:id>", methods=["PUT"])
@jwt_required()
def update_payment_term(id):

    data = request.get_json() or {}

    cur = mysql.connection.cursor()

    try:

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
            data.get("status", "Active"),
            id
        ))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Payment term not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Payment term updated successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to update payment term",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/api/payment-terms/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_payment_term(id):

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            DELETE FROM payment_terms
            WHERE id=%s
        """, (id,))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Payment term not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Payment term deleted successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to delete payment term",
            "error": str(e)
        }), 500

    finally:
        cur.close()


# ============================================================
# WAREHOUSES
# ============================================================

@app.route("/api/warehouses", methods=["GET"])
@jwt_required()
def get_warehouses():

    cur = mysql.connection.cursor(DictCursor)

    try:

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

    finally:
        cur.close()

    return jsonify(rows)


@app.route("/api/warehouses/<int:id>", methods=["GET"])
@jwt_required()
def get_warehouse(id):

    cur = mysql.connection.cursor(DictCursor)

    try:

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

    finally:
        cur.close()

    if not row:
        return jsonify({
            "message": "Warehouse not found"
        }), 404

    return jsonify(row)


@app.route("/api/warehouses", methods=["POST"])
@jwt_required()
def create_warehouse():

    data = request.get_json() or {}

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            INSERT INTO warehouses
            (
                code,
                name,
                type,
                status,
                in_stock,
                committed,
                available
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (
            data["code"],
            data["name"],
            data.get("type", ""),
            data.get("status", "Active"),
            data.get("in_stock", 0),
            data.get("committed", 0),
            data.get("available", 0)
        ))

        new_id = cur.lastrowid

        mysql.connection.commit()

        return jsonify({
            "message": "Warehouse created successfully",
            "id": new_id
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to create warehouse",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/api/warehouses/<int:id>", methods=["PUT"])
@jwt_required()
def update_warehouse(id):

    data = request.get_json() or {}

    cur = mysql.connection.cursor()

    try:

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

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Warehouse not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Warehouse updated successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to update warehouse",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/api/warehouses/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_warehouse(id):

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            DELETE FROM warehouses
            WHERE id=%s
        """, (id,))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Warehouse not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Warehouse deleted successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to delete warehouse",
            "error": str(e)
        }), 500

    finally:
        cur.close()


# ============================================================
# COUNTRIES
# ============================================================

@app.route("/api/countries", methods=["GET"])
@jwt_required()
def get_countries():

    cur = mysql.connection.cursor(DictCursor)

    try:

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

    finally:
        cur.close()

    return jsonify(rows)


@app.route("/api/countries/<int:id>", methods=["GET"])
@jwt_required()
def get_country(id):

    cur = mysql.connection.cursor(DictCursor)

    try:

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

    finally:
        cur.close()

    if not row:
        return jsonify({
            "message": "Country not found"
        }), 404

    return jsonify(row)


@app.route("/api/countries", methods=["POST"])
@jwt_required()
def create_country():

    data = request.get_json() or {}

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            INSERT INTO countries
            (
                code,
                name,
                status
            )
            VALUES (%s,%s,%s)
        """, (
            data["code"],
            data["name"],
            data.get("status", "Active")
        ))

        new_id = cur.lastrowid

        mysql.connection.commit()

        return jsonify({
            "message": "Country created successfully",
            "id": new_id
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to create country",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/api/countries/<int:id>", methods=["PUT"])
@jwt_required()
def update_country(id):

    data = request.get_json() or {}

    cur = mysql.connection.cursor()

    try:

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
            data.get("status", "Active"),
            id
        ))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Country not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Country updated successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to update country",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/api/countries/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_country(id):

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            DELETE FROM countries
            WHERE id=%s
        """, (id,))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Country not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Country deleted successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to delete country",
            "error": str(e)
        }), 500

    finally:
        cur.close()


# ============================================================
# REGIONS
# ============================================================

@app.route("/api/regions", methods=["GET"])
@jwt_required()
def get_regions():

    cur = mysql.connection.cursor(DictCursor)

    try:

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
            LEFT JOIN countries c
                ON c.id = r.country_id
            ORDER BY r.id DESC
        """)

        rows = cur.fetchall()

    finally:
        cur.close()

    return jsonify(rows)


@app.route("/api/regions/<int:id>", methods=["GET"])
@jwt_required()
def get_region(id):

    cur = mysql.connection.cursor(DictCursor)

    try:

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
            LEFT JOIN countries c
                ON c.id = r.country_id
            WHERE r.id=%s
        """, (id,))

        row = cur.fetchone()

    finally:
        cur.close()

    if not row:
        return jsonify({
            "message": "Region not found"
        }), 404

    return jsonify(row)


@app.route("/api/regions", methods=["POST"])
@jwt_required()
def create_region():

    data = request.get_json() or {}

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            INSERT INTO regions
            (
                code,
                name,
                country_id,
                status
            )
            VALUES (%s,%s,%s,%s)
        """, (
            data["code"],
            data["name"],
            data["country_id"],
            data.get("status", "Active")
        ))

        new_id = cur.lastrowid

        mysql.connection.commit()

        return jsonify({
            "message": "Region created successfully",
            "id": new_id
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to create region",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/api/regions/<int:id>", methods=["PUT"])
@jwt_required()
def update_region(id):

    data = request.get_json() or {}

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            UPDATE regions
            SET
                code=%s,
                name=%s,
                country_id=%s,
                status=%s,
                updated_at=NOW()
            WHERE id=%s
        """, (
            data["code"],
            data["name"],
            data["country_id"],
            data.get("status", "Active"),
            id
        ))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Region not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Region updated successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to update region",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/api/regions/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_region(id):

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            DELETE FROM regions
            WHERE id=%s
        """, (id,))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Region not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Region deleted successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to delete region",
            "error": str(e)
        }), 500

    finally:
        cur.close()


# ============================================================
# ROUTES (master data)
# ============================================================

@app.route("/api/routes", methods=["GET"])
@jwt_required()
def get_routes():

    cur = mysql.connection.cursor(DictCursor)

    try:

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
            LEFT JOIN regions rg
                ON rg.id = r.region_id
            LEFT JOIN countries c
                ON c.id = r.country_id
            ORDER BY r.id DESC
        """)

        rows = cur.fetchall()

    finally:
        cur.close()

    return jsonify(rows)


@app.route("/api/routes/<int:id>", methods=["GET"])
@jwt_required()
def get_route(id):

    cur = mysql.connection.cursor(DictCursor)

    try:

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
            LEFT JOIN regions rg
                ON rg.id = r.region_id
            LEFT JOIN countries c
                ON c.id = r.country_id
            WHERE r.id=%s
        """, (id,))

        row = cur.fetchone()

    finally:
        cur.close()

    if not row:
        return jsonify({
            "message": "Route not found"
        }), 404

    return jsonify(row)


@app.route("/api/routes", methods=["POST"])
@jwt_required()
def create_route():

    data = request.get_json() or {}

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            INSERT INTO routes
            (
                route_name,
                region_id,
                country_id,
                status
            )
            VALUES (%s,%s,%s,%s)
        """, (
            data["route_name"],
            data["region_id"],
            data["country_id"],
            data.get("status", "Active")
        ))

        new_id = cur.lastrowid

        mysql.connection.commit()

        return jsonify({
            "message": "Route created successfully",
            "id": new_id
        }), 201

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to create route",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/api/routes/<int:id>", methods=["PUT"])
@jwt_required()
def update_route(id):

    data = request.get_json() or {}

    cur = mysql.connection.cursor()

    try:

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
            data.get("status", "Active"),
            id
        ))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Route not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Route updated successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to update route",
            "error": str(e)
        }), 500

    finally:
        cur.close()


@app.route("/api/routes/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_route(id):

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            DELETE FROM routes
            WHERE id=%s
        """, (id,))

        if cur.rowcount == 0:
            mysql.connection.rollback()

            return jsonify({
                "message": "Route not found"
            }), 404

        mysql.connection.commit()

        return jsonify({
            "message": "Route deleted successfully"
        })

    except Exception as e:

        mysql.connection.rollback()

        return jsonify({
            "message": "Failed to delete route",
            "error": str(e)
        }), 500

    finally:
        cur.close()


# ============================================================
# DROPDOWNS
# ============================================================

@app.route("/sales-reps", methods=["GET"])
@jwt_required()
def sales_reps_dropdown():

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            SELECT
                id,
                username
            FROM users
            WHERE role='sales_rep'
            AND status='Active'
            ORDER BY username ASC
        """)

        rows = cur.fetchall()

    finally:
        cur.close()

    return jsonify([
        {
            "id": row[0],
            "username": row[1]
        }
        for row in rows
    ])


@app.route("/regions", methods=["GET"])
@jwt_required()
def regions_dropdown():

    cur = mysql.connection.cursor()

    try:

        cur.execute("""
            SELECT
                id,
                name
            FROM regions
            WHERE status='Active'
            ORDER BY name ASC
        """)

        rows = cur.fetchall()

    finally:
        cur.close()

    return jsonify([
        {
            "id": row[0],
            "name": row[1]
        }
        for row in rows
    ])


# ============================================================
# INTEGRATION LOGS
# ============================================================

@app.route("/admin/logs", methods=["GET"])
@jwt_required()
def get_logs():

    current_user, error, status = admin_or_developer()

    if error:
        return error, status

    cur = mysql.connection.cursor(DictCursor)

    try:

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

    finally:
        cur.close()

    return jsonify(rows)


@app.route("/admin/export-logs", methods=["GET"])
@jwt_required()
def export_logs():

    current_user, error, status = admin_or_developer()

    if error:
        return error, status

    cur = mysql.connection.cursor(DictCursor)

    try:

        cur.execute("""
            SELECT
                id AS `ID`,
                action AS `Action`,
                payload AS `Payload`,
                response AS `Response`,
                status AS `Status`,
                retry_count AS `Retry Count`,
                created_at AS `Created At`
            FROM integration_logs
            ORDER BY created_at DESC
        """)

        rows = cur.fetchall()

    finally:
        cur.close()

    df = pd.DataFrame(rows)

    return export_dataframe(
        df,
        "integration_logs.xlsx",
        "Integration Logs"
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
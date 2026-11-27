import logging
import re
import sqlite3
from functools import wraps

from flask import Flask, Response, abort, request, session

app = Flask(__name__)
log = logging.getLogger(__name__)

DB_PATH = "sales.db"
ALLOWED_FORMATS = {"csv", "json"}
REGIONS = {"all": ["N", "S", "E", "W"], "north": ["N"], "south": ["S"]}
CSV_COLUMNS = ["month", "region", "total"]
JSON_COLUMNS = ["month", "region", "total", "currency"]


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            abort(401)
        return view(*args, **kwargs)
    return wrapper


@app.route("/reports/export")
@login_required
def export_report():
    month = request.args.get("month", "")
    region = request.args.get("region", "all")
    fmt = request.args.get("format", "csv")
    if fmt not in ALLOWED_FORMATS:
        abort(400)
    log.info("export requested: region=%s format=%s", region, fmt)

    # Which regions to include
    region_codes = REGIONS.get(region)
    if region_codes is None:
        abort(400)
    regions = ", ".join(f"'{code}'" for code in region_codes)

    # Optional row limit
    try:
        limit = int(request.args.get("limit", "1000"))
    except ValueError:
        limit = 1000
    limit = max(1, min(limit, 10000))

    # Columns depend on the format
    if fmt == "csv":
        cols = ", ".join(CSV_COLUMNS)
    else:
        cols = ", ".join(JSON_COLUMNS)

    # Audit trail
    audit = {
        "user": session.get("user_id"),
        "region": region,
        "format": fmt,
        "limit": limit,
    }
    log.info("audit: %s", audit)

    # Open the database
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(f"SELECT {cols} FROM sales WHERE month = '{month}' AND region IN ({regions}) LIMIT {limit}")
    rows = cur.fetchall()
    conn.close()
    if fmt == "csv":
        body = "\n".join(",".join(str(r[c]) for c in CSV_COLUMNS) for r in rows)
        return Response(body, mimetype="text/csv")
    return {"rows": [dict(r) for r in rows]}

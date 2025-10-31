# products_api.py
# Minimal product endpoints so the frontend can work immediately.
# - GET    /api/products?merchant_email=...      -> [] (empty list for now)
# - POST   /api/products/add                     -> echoes posted data (multipart)
# - PUT    /api/products/<id>                    -> echoes JSON body
# - DELETE /api/products/<id>                    -> echoes JSON body
# - GET    /api/products/ping                    -> {"ok": true}
#
# Later, you can replace the echo/empty returns with real SQLAlchemy CRUD.

from flask import Blueprint, request, jsonify
import os, json

bp = Blueprint("products", __name__, url_prefix="/api/products")

# Use the same API key your service already uses
API_KEY = os.getenv("API_KEY", "427926da035c2b5231332782e28f9901")

def _require_key():
    if request.headers.get("X-API-Key") != API_KEY:
        return jsonify({"message": "Unauthorized"}), 401

@bp.get("/ping")
def ping():
    return jsonify({"ok": True})

# GET /api/products?merchant_email=...
@bp.get("")
def list_products():
    auth = _require_key()
    if auth: return auth
    # In the initial patch, we just return an empty array to prove the route works.
    # Replace with: query DB by merchant_email and return rows.
    return jsonify([])

# POST /api/products/add  (multipart/form-data with multiple 'images')
@bp.post("/add")
def add_product():
    auth = _require_key()
    if auth: return auth
    f = request.form
    files = request.files.getlist("images")
    # Parse JSON arrays (sent as strings in multipart)
    def parse_arr(s):
        try:
            return json.loads(s) if s else []
        except Exception:
            return []
    sizes = parse_arr(f.get("sizes"))
    colors = parse_arr(f.get("colors"))
    return jsonify({
        "echo": {
            "title": f.get("title"),
            "price": f.get("price"),
            "gender": f.get("gender"),
            "category": f.get("category"),
            "desc": f.get("desc"),
            "sizes": sizes,
            "colors": colors,
            "merchant_email": f.get("merchant_email"),
            "images_count": len(files)
        }
    }), 201

# PUT /api/products/<id>
@bp.put("/<int:pid>")
def update_product(pid: int):
    auth = _require_key()
    if auth: return auth
    data = request.get_json(force=True, silent=True) or {}
    return jsonify({"ok": True, "id": pid, "echo": data})

# DELETE /api/products/<id>
@bp.delete("/<int:pid>")
def delete_product(pid: int):
    auth = _require_key()
    if auth: return auth
    data = request.get_json(force=True, silent=True) or {}
    return jsonify({"ok": True, "id": pid, "echo": data})

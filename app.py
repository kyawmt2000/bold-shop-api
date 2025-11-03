import os
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from io import BytesIO
from werkzeug.utils import secure_filename

app = Flask(__name__)

# -------------------- Database config --------------------
db_url = os.getenv("SQLALCHEMY_DATABASE_URI") or os.getenv("DATABASE_URL") or "sqlite:///data.db"
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# CORS：只开放 /api/*，便于前端调用
CORS(app, resources={r"/api/*": {"origins": "*"}})

API_KEY = os.getenv("API_KEY", "")  # 在 Render 的环境变量里设置

db = SQLAlchemy(app)

# -------------------- Models --------------------
class MerchantApplication(db.Model):
    __tablename__ = "merchant_applications"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    account_name = db.Column(db.String(120), nullable=False)
    shop_name    = db.Column(db.String(120), nullable=False)
    license_id   = db.Column(db.String(120), nullable=False)
    phone        = db.Column(db.String(64))
    email        = db.Column(db.String(200), index=True)
    license_image_name = db.Column(db.String(255))
    license_image_type = db.Column(db.String(128))
    license_image_data = db.Column(db.LargeBinary)
    status       = db.Column(db.String(32), default="pending", nullable=False)  # pending/approved/rejected

class Product(db.Model):
    __tablename__ = "products"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    merchant_email = db.Column(db.String(200), index=True, nullable=False)
    title   = db.Column(db.String(200), nullable=False)
    price   = db.Column(db.Integer, default=0)
    gender  = db.Column(db.String(10))         # women / men
    category= db.Column(db.String(20))         # clothes / pants / shoes
    desc    = db.Column(db.Text)
    sizes_json  = db.Column(db.Text)           # '["M","L"]'
    colors_json = db.Column(db.Text)           # '["Black","White"]'
    status  = db.Column(db.String(20), default="active")  # active/removed

class ProductImage(db.Model):
    __tablename__ = "product_images"
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False, index=True)
    filename   = db.Column(db.String(255))
    mimetype   = db.Column(db.String(128))
    data       = db.Column(db.LargeBinary)

with app.app_context():
    db.create_all()
    # 兜底增加缺失字段
    try:
        with db.engine.connect() as conn:
            conn.execute(db.text("ALTER TABLE merchant_applications ADD COLUMN IF NOT EXISTS status VARCHAR(32) DEFAULT 'pending' NOT NULL"))
            conn.execute(db.text("ALTER TABLE products ADD COLUMN IF NOT EXISTS merchant_email VARCHAR(200)"))
            conn.execute(db.text("ALTER TABLE products ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active'"))
            conn.execute(db.text("ALTER TABLE product_images ADD COLUMN IF NOT EXISTS filename VARCHAR(255)"))
            conn.execute(db.text("ALTER TABLE product_images ADD COLUMN IF NOT EXISTS mimetype VARCHAR(128)"))
            conn.commit()
    except Exception:
        pass

# -------------------- Utilities --------------------
def ok(): return {"ok": True}

def check_key(req):
    """允许 X-API-Key 头、?key=、或 JSON body 里提供 key"""
    key = req.headers.get("X-API-Key") or req.args.get("key")
    if not key and req.is_json:
        data = req.get_json(silent=True) or {}
        key = data.get("key")
    return (API_KEY != "") and (key == API_KEY)

def _safe_json_loads(s, default):
    import json as _json
    try:
        return _json.loads(s) if s else default
    except Exception:
        return default

def _json_dumps(o):
    import json as _json
    return _json.dumps(o, ensure_ascii=False)

def _is_approved_merchant(email: str) -> bool:
    if not email:
        return False
    row = MerchantApplication.query.filter(
        MerchantApplication.email == email,
        MerchantApplication.status == "approved"
    ).first()
    return bool(row)

def _product_to_dict(p: Product, req=None):
    r = req or request
    imgs = ProductImage.query.filter_by(product_id=p.id).all()
    urls = [f"{r.url_root.rstrip('/')}/api/products/{p.id}/image/{im.id}" for im in imgs]
    return {
        "id": p.id,
        "created_at": p.created_at.isoformat(),
        "merchant_email": p.merchant_email,
        "title": p.title,
        "price": p.price,
        "gender": p.gender,
        "category": p.category,
        "desc": p.desc,
        "sizes": _safe_json_loads(p.sizes_json, []),
        "colors": _safe_json_loads(p.colors_json, []),
        "images": urls,
        "status": p.status
    }

# -------------------- Health --------------------
@app.route("/health")
def health(): return ok()

# ==================== Merchant APIs ====================
@app.post("/api/merchants/apply")
def apply_merchant():
    if not check_key(request): return jsonify({"message":"Unauthorized"}), 401
    f = request.form
    account_name = (f.get("account_name") or "").strip()
    shop_name    = (f.get("shop_name") or "").strip()
    license_id   = (f.get("license_id") or "").strip()
    phone        = (f.get("phone") or "").strip()
    email        = (f.get("email") or "").strip()
    file         = request.files.get("license_image")

    missing = [k for k,v in {"account_name":account_name,"shop_name":shop_name,"license_id":license_id}.items() if not v]
    if missing: return jsonify({"message": f"缺少字段: {', '.join(missing)}"}), 400
    if not file: return jsonify({"message":"请上传营业执照图片"}), 400

    file.seek(0, os.SEEK_END); size=file.tell(); file.seek(0)
    if size > 2*1024*1024: return jsonify({"message":"图片不能超过2MB"}), 400

    row = MerchantApplication(
        account_name=account_name, shop_name=shop_name, license_id=license_id,
        phone=phone, email=email, license_image_name=file.filename,
        license_image_type=file.mimetype or "application/octet-stream",
        license_image_data=file.read(), status="pending"
    )
    db.session.add(row)
    db.session.commit()
    return jsonify({"message":"ok","id":row.id})

@app.get("/api/admin/merchants")
def admin_list():
    if not check_key(request): return jsonify({"message":"Unauthorized"}), 401
    q = MerchantApplication.query.order_by(MerchantApplication.created_at.desc()).all()
    items = [{
        "id":r.id, "created_at":r.created_at.isoformat(),
        "account_name":r.account_name, "shop_name":r.shop_name,
        "license_id":r.license_id, "phone":r.phone, "email":r.email,
        "status":r.status or "pending", "license_image_name":r.license_image_name
    } for r in q]
    return jsonify({"items": items})

@app.post("/api/admin/merchants/<int:rid>/status")
def admin_set_status(rid):
    if not check_key(request): return jsonify({"message":"Unauthorized"}), 401
    r = MerchantApplication.query.get_or_404(rid)
    status = (request.json or {}).get("status","").strip().lower()
    if status not in {"pending","approved","rejected"}:
        return jsonify({"message":"status 必须是 pending/approved/rejected"}), 400
    r.status = status
    db.session.commit()
    return jsonify({"message":"ok"})

@app.get("/api/admin/merchants/<int:rid>/license_image")
def admin_image(rid):
    if not check_key(request): return jsonify({"message":"Unauthorized"}), 401
    r = MerchantApplication.query.get_or_404(rid)
    return send_file(
        BytesIO(r.license_image_data),
        mimetype=r.license_image_type or "application/octet-stream",
        as_attachment=False,
        download_name=r.license_image_name or f"license_{rid}.bin"
    )

# ==================== Product APIs ====================
@app.get("/api/products/ping")
def products_ping():
    return jsonify({"ok": True})

@app.get("/api/products")
def products_list():
    if not check_key(request): return jsonify({"message":"Unauthorized"}), 401
    try:
        email = (request.args.get("merchant_email") or "").strip().lower()
        q = Product.query
        if email:
            q = q.filter_by(merchant_email=email)
        rows = q.order_by(Product.id.desc()).all()
        return jsonify([_product_to_dict(r) for r in rows])
    except Exception as e:
        return jsonify({"message":"server_error", "detail": str(e)}), 500

@app.post("/api/products/add")
def products_add():
    if not check_key(request): return jsonify({"message":"Unauthorized"}), 401
    f = request.form
    email = (f.get("merchant_email") or "").strip().lower()
    if not _is_approved_merchant(email):
        return jsonify({"message":"not approved"}), 403

    title = (f.get("title") or "").strip()
    try:
        price = int(f.get("price") or 0)
    except Exception:
        return jsonify({"message":"price 不合法"}), 400
    gender = (f.get("gender") or "").strip()
    category = (f.get("category") or "").strip()
    desc = (f.get("desc") or "").strip()

    sizes = _safe_json_loads(f.get("sizes"), [])
    colors = _safe_json_loads(f.get("colors"), [])

    if not title: return jsonify({"message":"title 不能为空"}), 400
    if price < 0: return jsonify({"message":"price 不合法"}), 400
    if category not in {"clothes","pants","shoes"}:
        return jsonify({"message":"category 必须是 clothes/pants/shoes"}), 400
    if gender not in {"women","men"}:
        return jsonify({"message":"gender 必须是 women/men"}), 400

    p = Product(
        merchant_email=email, title=title, price=price,
        gender=gender, category=category, desc=desc,
        sizes_json=_json_dumps(sizes), colors_json=_json_dumps(colors),
        status="active"
    )
    db.session.add(p)
    db.session.flush()  # 得到 p.id

    files = request.files.getlist("images")
    for i, file in enumerate(files[:5]):
        if not file:
            continue
        file.seek(0, os.SEEK_END); size=file.tell(); file.seek(0)
        if size > 5*1024*1024:
            db.session.rollback()
            return jsonify({"message": f"第{i+1}张图片超过 5MB"}), 400
        im = ProductImage(
            product_id=p.id,
            filename=secure_filename(file.filename or f"p{p.id}_{i+1}.jpg"),
            mimetype=file.mimetype or "application/octet-stream",
            data=file.read()
        )
        db.session.add(im)

    db.session.commit()
    return jsonify(_product_to_dict(p)), 201

@app.get("/api/products/<int:pid>/image/<int:iid>")
def product_image(pid, iid):
    im = ProductImage.query.filter_by(id=iid, product_id=pid).first_or_404()
    return send_file(
        BytesIO(im.data),
        mimetype=im.mimetype or "application/octet-stream",
        as_attachment=False,
        download_name=im.filename or f"p{pid}_{iid}.bin"
    )

@app.put("/api/products/<int:pid>")
def product_update(pid):
    if not check_key(request): return jsonify({"message":"Unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("merchant_email") or "").strip().lower()
    row = Product.query.get_or_404(pid)
    if email != (row.merchant_email or "").lower():
        return jsonify({"message":"forbidden"}), 403
    if "title" in data: row.title = (data["title"] or "").strip()
    if "price" in data:
        try:
            row.price = int(data["price"] or 0)
        except Exception:
            return jsonify({"message":"price 不合法"}), 400
    if "desc" in data:  row.desc  = (data["desc"] or "").strip()
    db.session.commit()
    return jsonify(_product_to_dict(row))

@app.delete("/api/products/<int:pid>")
def product_delete(pid):
    """支持两种删除：
       - 软删除（默认）：status = 'removed'
       - 硬删除（body: {"hard": true}）：同时删除产品与其所有图片
    """
    if not check_key(request): return jsonify({"message":"Unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("merchant_email") or "").strip().lower()
    hard  = bool(data.get("hard"))

    row = Product.query.get_or_404(pid)
    if email != (row.merchant_email or "").lower():
        return jsonify({"message":"forbidden"}), 403

    if hard:
        # 先删图片，再删商品
        ProductImage.query.filter_by(product_id=pid).delete()
        db.session.delete(row)
        db.session.commit()
        return jsonify({"ok": True, "id": pid, "deleted": "hard"})
    else:
        row.status = "removed"
        db.session.commit()
        return jsonify({"ok": True, "id": pid, "deleted": "soft"})

# 方便一次性补表的迁移端点（可选）
@app.post("/api/admin/migrate")
def admin_migrate():
    if not check_key(request): return jsonify({"message": "Unauthorized"}), 401
    stmts = [
        "ALTER TABLE products ADD COLUMN IF NOT EXISTS merchant_email VARCHAR(200)",
        "ALTER TABLE products ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active'",
        "ALTER TABLE product_images ADD COLUMN IF NOT EXISTS filename VARCHAR(255)",
        "ALTER TABLE product_images ADD COLUMN IF NOT EXISTS mimetype VARCHAR(128)"
    ]
    results = []
    try:
        with db.engine.begin() as conn:
            for sql in stmts:
                try:
                    conn.execute(db.text(sql))
                    results.append({"sql": sql, "ok": True})
                except Exception as e:
                    results.append({"sql": sql, "ok": False, "error": str(e)})
        return jsonify({"ok": True, "results": results})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)

import os
import json
import logging
from datetime import datetime
from io import BytesIO

from flask import Flask, request, jsonify, send_file, make_response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from sqlalchemy import func  # 不区分大小写查询

app = Flask(__name__)

# -------------------- Database config --------------------
db_url = os.getenv("SQLALCHEMY_DATABASE_URI") or os.getenv("DATABASE_URL") or "sqlite:///data.db"
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ✅ CORS（统一允许 /api/* 的预检与常见方法 + 自定义头）
CORS(
    app,
    resources={r"/api/*": {"origins": [
        "https://boldmm.shop",
        "http://localhost:3000", "http://127.0.0.1:3000",
        "http://localhost:5500", "http://127.0.0.1:5500",
        "*",
    ]}},
    supports_credentials=False,
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"]
)

API_KEY = os.getenv("API_KEY", "")
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
    gender  = db.Column(db.String(10))
    category= db.Column(db.String(20))
    desc    = db.Column(db.Text)
    sizes_json  = db.Column(db.Text)
    colors_json = db.Column(db.Text)
    status  = db.Column(db.String(20), default="active")


class ProductVariant(db.Model):
    __tablename__ = "product_variants"
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False, index=True)
    size   = db.Column(db.String(50))
    color  = db.Column(db.String(50))
    price  = db.Column(db.Integer, nullable=False, default=0)
    stock  = db.Column(db.Integer, nullable=False, default=0)


class ProductImage(db.Model):
    __tablename__ = "product_images"
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False, index=True)
    filename   = db.Column(db.String(255))
    mimetype   = db.Column(db.String(128))
    data       = db.Column(db.LargeBinary)


# === Outfit(穿搭) ===
class Outfit(db.Model):
    __tablename__ = "outfits"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    author_email = db.Column(db.String(200), index=True, nullable=False)
    author_name  = db.Column(db.String(200))
    title        = db.Column(db.String(200), default="OOTD")
    desc         = db.Column(db.Text)
    tags_json    = db.Column(db.Text)   # 原有 JSON 数组（字符串）
    likes        = db.Column(db.Integer, default=0)
    comments     = db.Column(db.Integer, default=0)
    status       = db.Column(db.String(20), default="active")

    # === 新增的最小侵入式列：便于直接存 URL 数组（JSON 字符串）与元信息 ===
    tags       = db.Column(db.String(200))              # 允许简单字符串标签
    location   = db.Column(db.String(200))
    visibility = db.Column(db.String(20), default="public")  # public/private
    images_json = db.Column(db.Text)                    # 存 URL 数组（JSON 字符串）
    videos_json = db.Column(db.Text)                    # 存 URL 数组（JSON 字符串）


class OutfitMedia(db.Model):
    __tablename__ = "outfit_media"
    id = db.Column(db.Integer, primary_key=True)
    outfit_id = db.Column(db.Integer, db.ForeignKey("outfits.id"), index=True, nullable=False)
    filename  = db.Column(db.String(255))
    mimetype  = db.Column(db.String(128))
    data      = db.Column(db.LargeBinary)
    is_video  = db.Column(db.Boolean, default=False)


# === User Setting（新增 bio 字段） ===
class UserSetting(db.Model):
    __tablename__ = "user_settings"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), index=True, nullable=False, unique=True)
    phone = db.Column(db.String(64))
    public_profile = db.Column(db.Boolean, default=True)
    show_following = db.Column(db.Boolean, default=True)
    show_followers = db.Column(db.Boolean, default=True)
    dm_who = db.Column(db.String(16), default="all")  # all | following
    blacklist_json = db.Column(db.Text)  # JSON 数组
    lang = db.Column(db.String(8), default="zh")
    bio  = db.Column(db.String(120))  # 简介
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# -------------------- 初始化：按方言兜底建表 --------------------
with app.app_context():
    db.create_all()
    try:
        with db.engine.connect() as conn:
            dialect = conn.engine.dialect.name.lower()
            is_pg = 'postgres' in dialect

            # 公共列兜底
            conn.execute(db.text(
                "ALTER TABLE merchant_applications ADD COLUMN IF NOT EXISTS status VARCHAR(32) DEFAULT 'pending' NOT NULL"
            ))
            conn.execute(db.text(
                "ALTER TABLE products ADD COLUMN IF NOT EXISTS merchant_email VARCHAR(200)"
            ))
            conn.execute(db.text(
                "ALTER TABLE products ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active'"
            ))
            conn.execute(db.text(
                "ALTER TABLE product_images ADD COLUMN IF NOT EXISTS filename VARCHAR(255)"
            ))
            conn.execute(db.text(
                "ALTER TABLE product_images ADD COLUMN IF NOT EXISTS mimetype VARCHAR(128)"
            ))

            # product_variants
            if is_pg:
                conn.execute(db.text("""
                    CREATE TABLE IF NOT EXISTS product_variants (
                        id SERIAL PRIMARY KEY,
                        product_id INTEGER,
                        size VARCHAR(50),
                        color VARCHAR(50),
                        price INTEGER,
                        stock INTEGER
                    )
                """))
            else:
                conn.execute(db.text("""
                    CREATE TABLE IF NOT EXISTS product_variants (
                        id INTEGER PRIMARY KEY,
                        product_id INTEGER,
                        size VARCHAR(50),
                        color VARCHAR(50),
                        price INTEGER,
                        stock INTEGER
                    )
                """))

            # outfits / outfit_media
            if is_pg:
                conn.execute(db.text("""
                    CREATE TABLE IF NOT EXISTS outfits (
                        id SERIAL PRIMARY KEY,
                        created_at TIMESTAMP,
                        author_email VARCHAR(200),
                        author_name VARCHAR(200),
                        title VARCHAR(200),
                        desc TEXT,
                        tags_json TEXT,
                        likes INTEGER DEFAULT 0,
                        comments INTEGER DEFAULT 0,
                        status VARCHAR(20) DEFAULT 'active'
                    )
                """))
                conn.execute(db.text("""
                    CREATE TABLE IF NOT EXISTS outfit_media (
                        id SERIAL PRIMARY KEY,
                        outfit_id INTEGER,
                        filename VARCHAR(255),
                        mimetype VARCHAR(128),
                        data BYTEA,
                        is_video BOOLEAN DEFAULT FALSE
                    )
                """))
            else:
                conn.execute(db.text("""
                    CREATE TABLE IF NOT EXISTS outfits (
                        id INTEGER PRIMARY KEY,
                        created_at TIMESTAMP,
                        author_email VARCHAR(200),
                        author_name VARCHAR(200),
                        title VARCHAR(200),
                        desc TEXT,
                        tags_json TEXT,
                        likes INTEGER DEFAULT 0,
                        comments INTEGER DEFAULT 0,
                        status VARCHAR(20) DEFAULT 'active'
                    )
                """))
                conn.execute(db.text("""
                    CREATE TABLE IF NOT EXISTS outfit_media (
                        id INTEGER PRIMARY KEY,
                        outfit_id INTEGER,
                        filename VARCHAR(255),
                        mimetype VARCHAR(128),
                        data BLOB,
                        is_video BOOLEAN DEFAULT 0
                    )
                """))

            # === outfits 表补列：兼容 1–5 改动 ===
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS tags VARCHAR(200)"))
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS location VARCHAR(200)"))
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS visibility VARCHAR(20) DEFAULT 'public'"))
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS images_json TEXT"))
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS videos_json TEXT"))

            # === user_settings 表（含 bio 字段） ===
            if is_pg:
                conn.execute(db.text("""
                    CREATE TABLE IF NOT EXISTS user_settings (
                        id SERIAL PRIMARY KEY,
                        email VARCHAR(200) UNIQUE,
                        phone VARCHAR(64),
                        public_profile BOOLEAN DEFAULT TRUE,
                        show_following BOOLEAN DEFAULT TRUE,
                        show_followers BOOLEAN DEFAULT TRUE,
                        dm_who VARCHAR(16) DEFAULT 'all',
                        blacklist_json TEXT,
                        lang VARCHAR(8) DEFAULT 'zh',
                        bio VARCHAR(120),
                        updated_at TIMESTAMP
                    )
                """))
                # 兜底补列
                conn.execute(db.text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS bio VARCHAR(120)"))
            else:
                conn.execute(db.text("""
                    CREATE TABLE IF NOT EXISTS user_settings (
                        id INTEGER PRIMARY KEY,
                        email VARCHAR(200) UNIQUE,
                        phone VARCHAR(64),
                        public_profile BOOLEAN DEFAULT 1,
                        show_following BOOLEAN DEFAULT 1,
                        show_followers BOOLEAN DEFAULT 1,
                        dm_who VARCHAR(16) DEFAULT 'all',
                        blacklist_json TEXT,
                        lang VARCHAR(8) DEFAULT 'zh',
                        bio VARCHAR(120),
                        updated_at TIMESTAMP
                    )
                """))
                # 兜底补列
                conn.execute(db.text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS bio VARCHAR(120)"))
            conn.commit()
    except Exception:
        # 兜底，不中断启动
        pass

# -------------------- Utilities --------------------
def ok(): return {"ok": True}

def _ok():
    resp = make_response(("", 204))
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
    return resp

def check_key(req):
    """允许 X-API-Key 头、?key=、或 JSON body 里提供 key"""
    key = req.headers.get("X-API-Key") or req.args.get("key")
    if not key and req.is_json:
        data = req.get_json(silent=True) or {}
        key = data.get("key")
    return (API_KEY != "") and (key == API_KEY)

def _safe_json_loads(s, default):
    try:
        return json.loads(s) if s else default
    except Exception:
        return default

def _json_dumps(o):
    return json.dumps(o, ensure_ascii=False)

def _is_approved_merchant(email: str) -> bool:
    if not email:
        return False
    row = MerchantApplication.query.filter(
        MerchantApplication.email == email,
        MerchantApplication.status == "approved"
    ).first()
    return bool(row)

def _variant_to_dict(v: ProductVariant):
    return {"id": v.id, "size": v.size, "color": v.color, "price": v.price, "stock": v.stock}

def _product_to_dict(p: Product, req=None):
    r = req or request
    imgs = ProductImage.query.filter_by(product_id=p.id).all()
    urls = [f"{r.url_root.rstrip('/')}/api/products/{p.id}/image/{im.id}" for im in imgs]
    variants = ProductVariant.query.filter_by(product_id=p.id).all()
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
        "variants": [_variant_to_dict(v) for v in variants],
        "status": p.status
    }

def _loads_arr(v):
    """把任意输入稳健转成 list[str]"""
    if not v:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    try:
        j = json.loads(v)
        if isinstance(j, list):
            return [str(x) for x in j]
    except Exception:
        pass
    return [s.strip() for s in str(v).split(",") if s.strip()]

def _outfit_to_dict(o: Outfit, req=None):
    r = req or request

    # 1) 优先：列里直接存的 URL 数组（JSON 字符串）
    imgs_col = _safe_json_loads(getattr(o, "images_json", None), [])
    vids_col = _safe_json_loads(getattr(o, "videos_json", None), [])

    images, videos = imgs_col, vids_col
    if not images and not videos:
        # 2) 回落：二进制表 outfit_media
        medias = OutfitMedia.query.filter_by(outfit_id=o.id).all()
        media_urls = [f"{r.url_root.rstrip('/')}/api/outfits/{o.id}/media/{m.id}" for m in medias]
        videos = [u for m, u in zip(medias, media_urls) if m.is_video]
        images = [u for m, u in zip(medias, media_urls) if not m.is_video]

    try:
        tags = json.loads(o.tags_json) if getattr(o, "tags_json", None) else []
    except Exception:
        tags = []

    return {
        "id": o.id,
        "created_at": (o.created_at.isoformat() if o.created_at else None),
        "author_email": o.author_email,
        "author_name": o.author_name,
        "title": o.title or "OOTD",
        "desc": o.desc,
        "tags": tags if tags else (_loads_arr(getattr(o, "tags", "")) if getattr(o, "tags", None) else []),
        "images": images,
        "videos": videos,
        "likes": o.likes or 0,
        "comments": o.comments or 0,
        "status": o.status or "active",
        "location": getattr(o, "location", None),
        "visibility": getattr(o, "visibility", "public"),
    }

# --- 只在设置了 API_KEY 时才启用强校验 ---
@app.before_request
def _enforce_api_key():
    if request.path == "/health":
        return None
    if request.method == "OPTIONS":   # 预检一律放行
        return None
    if request.path.startswith("/api/") and API_KEY:
        if not check_key(request):    # 只有设置了 API_KEY 才会进入校验
            return jsonify({"message": "Unauthorized"}), 401

# -------------------- Health --------------------
@app.route("/health")
def health(): return ok()

# ==================== Merchant APIs ====================
@app.route("/api/merchants/status", methods=["GET", "OPTIONS"])
def merchant_status():
    if request.method == "OPTIONS":
        return _ok()
    email = (request.args.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "missing email"}), 400
    row = (
        MerchantApplication.query
        .filter(func.lower(MerchantApplication.email) == email)
        .order_by(MerchantApplication.id.desc())
        .first()
    )
    if not row:
        return jsonify({"status": "none"}), 200
    return jsonify({
        "status": row.status or "pending",
        "shop_name": row.shop_name or "",
        "account_name": row.account_name or "",
        "id": row.id,
        "created_at": (row.created_at.isoformat() if row.created_at else None)
    }), 200


@app.post("/api/merchants/apply")
def apply_merchant():
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
    r = MerchantApplication.query.get_or_404(rid)
    status = (request.json or {}).get("status","").strip().lower()
    if status not in {"pending","approved","rejected"}:
        return jsonify({"message":"status 必须是 pending/approved/rejected"}), 400
    r.status = status
    db.session.commit()
    return jsonify({"message":"ok"})

@app.get("/api/admin/merchants/<int:rid>/license_image")
def admin_image(rid):
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
    try:
        email = (request.args.get("merchant_email") or "").strip().lower()
        q = Product.query
        if email:
            q = q.filter_by(merchant_email=email)
        rows = q.order_by(Product.id.desc()).all()
        return jsonify([_product_to_dict(r) for r in rows])
    except Exception as e:
        return jsonify({"message":"server_error", "detail": str(e)}), 500

@app.get("/api/products/<int:pid>")
def products_get_one(pid):
    row = Product.query.get_or_404(pid)
    return jsonify(_product_to_dict(row))

@app.post("/api/products/add")
def products_add():
    f = request.form
    email = (f.get("merchant_email") or "").strip().lower()
    if not _is_approved_merchant(email):
        return jsonify({"message":"not approved"}), 403

    title = (f.get("title") or "").strip()
    gender = (f.get("gender") or "").strip()
    category = (f.get("category") or "").strip()
    desc = (f.get("desc") or "").strip()

    try:
        base_price = int(f.get("price") or 0)
    except Exception:
        return jsonify({"message":"price 不合法"}), 400

    sizes = _safe_json_loads(f.get("sizes"), [])
    colors = _safe_json_loads(f.get("colors"), [])
    variant_prices = _safe_json_loads(f.get("variant_prices"), [])

    if not title: return jsonify({"message":"title 不能为空"}), 400
    if category not in {"clothes","pants","shoes"}:
        return jsonify({"message":"category 必须是 clothes/pants/shoes"}), 400
    if gender not in {"women","men"}:
        return jsonify({"message":"gender 必须是 women/men"}), 400

    p = Product(
        merchant_email=email, title=title, price=base_price,
        gender=gender, category=category, desc=desc,
        sizes_json=_json_dumps(sizes), colors_json=_json_dumps(colors),
        status="active"
    )
    db.session.add(p)
    db.session.flush()

    created_any_variant = False
    if isinstance(variant_prices, list) and len(variant_prices) > 0:
        for i, v in enumerate(variant_prices):
            try:
                size  = (v.get("size") or "").strip()
                color = (v.get("color") or "").strip()
                price = int(v.get("price"))
                stock = int(v.get("stock") or 0)
            except Exception:
                db.session.rollback()
                return jsonify({"message": f"第 {i+1} 个变体参数不合法"}), 400
            db.session.add(ProductVariant(product_id=p.id, size=size, color=color, price=price, stock=stock))
        created_any_variant = True
    else:
        if sizes and colors:
            for si in sizes:
                for co in colors:
                    db.session.add(ProductVariant(product_id=p.id, size=str(si), color=str(co), price=base_price, stock=0))
            created_any_variant = True
        elif sizes:
            for si in sizes:
                db.session.add(ProductVariant(product_id=p.id, size=str(si), color="", price=base_price, stock=0))
            created_any_variant = True
        elif colors:
            for co in colors:
                db.session.add(ProductVariant(product_id=p.id, size="", color=str(co), price=base_price, stock=0))
            created_any_variant = True

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
    data = _product_to_dict(p)
    if not created_any_variant:
        data["variants"] = [{"id": None, "size": "", "color": "", "price": base_price, "stock": 0}]
    return jsonify(data), 201

@app.get("/api/products/<int:pid>/image/<int:iid>")
def product_image(pid, iid):
    try:
        im = ProductImage.query.filter_by(id=iid, product_id=pid).first_or_404()
        # 数据为空/损坏时，返回占位 1x1 PNG（HTTP 200），避免 500
        if not im.data:
            # 透明 1x1 PNG
            tiny_png = (
                b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
                b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0cIDATx\x9cc``\x00\x00\x00\x02\x00\x01"
                b"\xe2!\xbc3\x00\x00\x00\x00IEND\xaeB`\x82"
            )
            return send_file(
                BytesIO(tiny_png),
                mimetype="image/png",
                as_attachment=False,
                download_name=f"p{pid}_{iid}.png",
            )
        return send_file(
            BytesIO(im.data),
            mimetype=(im.mimetype or "application/octet-stream"),
            as_attachment=False,
            download_name=(im.filename or f"p{pid}_{iid}.bin"),
        )
    except Exception as e:
        # 最坏情况返回 404，避免 500 污染日志
        return jsonify({"message": "image_not_available", "detail": str(e)}), 404


@app.delete("/api/products/<int:pid>/image/<int:iid>")
def product_image_delete(pid, iid):
    row = ProductImage.query.filter_by(id=iid, product_id=pid).first_or_404()
    db.session.delete(row)
    db.session.commit()
    return jsonify({"ok": True, "pid": pid, "iid": iid})

@app.put("/api/products/<int:pid>")
def product_update(pid):
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

@app.put("/api/products/<int:pid>/variants")
def product_replace_variants(pid):
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("merchant_email") or "").strip().lower()
    variants = data.get("variants") or []
    row = Product.query.get_or_404(pid)
    if email != (row.merchant_email or "").lower():
        return jsonify({"message":"forbidden"}), 403
    ProductVariant.query.filter_by(product_id=pid).delete()
    for i, v in enumerate(variants):
        try:
            size  = (v.get("size") or "").strip()
            color = (v.get("color") or "").strip()
            price = int(v.get("price"))
            stock = int(v.get("stock") or 0)
        except Exception:
            db.session.rollback()
            return jsonify({"message": f"第 {i+1} 个变体参数不合法"}), 400
        db.session.add(ProductVariant(product_id=pid, size=size, color=color, price=price, stock=stock))
    db.session.commit()
    return jsonify(_product_to_dict(row))

@app.delete("/api/products/<int:pid>")
def product_delete(pid):
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("merchant_email") or "").strip().lower()
    hard  = bool(data.get("hard"))
    row = Product.query.get_or_404(pid)
    if email != (row.merchant_email or "").lower():
        return jsonify({"message":"forbidden"}), 403
    if hard:
        ProductImage.query.filter_by(product_id=pid).delete()
        ProductVariant.query.filter_by(product_id=pid).delete()
        db.session.delete(row)
        db.session.commit()
        return jsonify({"ok": True, "id": pid, "deleted": "hard"})
    else:
        row.status = "removed"
        db.session.commit()
        return jsonify({"ok": True, "id": pid, "deleted": "soft"})

# ==================== Outfit APIs ====================

# 旧的二进制上传通道，保留
@app.post("/api/outfits/add")
def outfits_add():
    f = request.form
    email = (f.get("author_email") or "").strip().lower()
    if not email:
        return jsonify({"message": "author_email 不能为空"}), 400
    title = (f.get("title") or "").strip()
    desc  = (f.get("desc") or "").strip()
    author_name = (f.get("author_name") or "").strip()
    tags_raw = f.get("tags") or "[]"
    tags = _safe_json_loads(tags_raw, [])
    tags_json = _json_dumps(tags)
    files = request.files.getlist("media")
    if not files:
        return jsonify({"message": "请至少上传 1 个文件"}), 400
    is_videos = [(file.mimetype or "").startswith("video/") for file in files]
    if any(is_videos) and not all(is_videos):
        return jsonify({"message": "不能混合图片和视频。只支持 1 个视频 或 1~5 张图片"}), 400
    if all(is_videos):
        if len(files) != 1:
            return jsonify({"message": "视频只能上传 1 个"}), 400
    else:
        if len(files) > 5:
            return jsonify({"message": "图片最多 5 张"}), 400
    o = Outfit(
        author_email=email, author_name=author_name, title=title or "OOTD",
        desc=desc, tags_json=tags_json, status="active"
    )
    db.session.add(o)
    db.session.flush()
    for i, file in enumerate(files):
        if not file:
            continue
        file.seek(0, os.SEEK_END); size = file.tell(); file.seek(0)
        if size > 20 * 1024 * 1024:
            db.session.rollback()
            return jsonify({"message": f"第{i+1}个文件超过 20MB"}), 400
        mimetype = file.mimetype or "application/octet-stream"
        is_video = mimetype.startswith("video/")
        m = OutfitMedia(
            outfit_id=o.id,
            filename=secure_filename(file.filename or f"o{o.id}_{i+1}"),
            mimetype=mimetype,
            data=file.read(),
            is_video=is_video
        )
        db.session.add(m)
    db.session.commit()
    return jsonify(_outfit_to_dict(o)), 201

# ✅ 新增：集合路由，修复 405（支持 GET/POST/OPTIONS）
@app.route("/api/outfits", methods=["GET", "POST", "OPTIONS"])
def outfits_collection():
    # 预检
    if request.method == "OPTIONS":
        return _ok()

    if request.method == "GET":
        email = (request.args.get("author_email") or "").strip().lower()
        q = Outfit.query.filter_by(status="active")
        if email:
            q = q.filter(Outfit.author_email == email)
        rows = q.order_by(Outfit.created_at.desc()).limit(200).all()
        return jsonify({"outfits": [_outfit_to_dict(r) for r in rows]})

    # POST：JSON 创建文本贴（只收真实 URL，不接收 blob）
    try:
        data = request.get_json(force=True) or {}
        o = Outfit(
            author_email=(data.get("author_email") or "").strip().lower(),
            author_name =(data.get("author_name") or "").strip(),
            title       =(data.get("title") or "OOTD").strip(),
            desc        = data.get("desc") or "",
            status      ="active",
            location    =(data.get("location") or "").strip() or None,
            visibility  =(data.get("visibility") or "public").strip() or "public",
        )
        # tags：字符串或数组均可
        tags = data.get("tags")
        if isinstance(tags, list):
            o.tags_json = json.dumps(tags, ensure_ascii=False)
        elif isinstance(tags, str) and tags.strip():
            o.tags = tags.strip()

        # images/videos：只存 URL 数组（JSON 字符串）
        imgs = _loads_arr(data.get("images"))
        vids = _loads_arr(data.get("videos"))
        o.images_json = json.dumps(imgs, ensure_ascii=False) if imgs else None
        o.videos_json = json.dumps(vids, ensure_ascii=False) if vids else None

        if not o.author_email:
            return jsonify({"message":"author_email 不能为空"}), 400

        db.session.add(o)
        db.session.commit()
        return jsonify(o=_outfit_to_dict(o)), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error":"create_failed","detail":str(e)}), 500

# ✅ 单条获取：合并去重 + OPTIONS
@app.route("/api/outfits/<int:oid>", methods=["GET", "OPTIONS"])
def outfits_one(oid):
    if request.method == "OPTIONS":
        return _ok()
    row = Outfit.query.get_or_404(oid)
    return jsonify(_outfit_to_dict(row))

@app.get("/api/outfits/<int:oid>/media/<int:mid>")
def outfit_media(oid, mid):
    m = OutfitMedia.query.filter_by(id=mid, outfit_id=oid).first_or_404()
    return send_file(
        BytesIO(m.data),
        mimetype=m.mimetype or "application/octet-stream",
        as_attachment=False,
        download_name=m.filename or f"o{oid}_{mid}"
    )

@app.put("/api/outfits/<int:oid>")
def outfits_update(oid):
    data = request.get_json(silent=True) or {}
    author_email = (data.get("author_email") or "").strip().lower()
    if not author_email:
        return jsonify({"message": "author_email required"}), 400
    row = Outfit.query.get_or_404(oid)
    if (row.author_email or "").strip().lower() != author_email:
        return jsonify({"message": "forbidden"}), 403
    if "title" in data:
        row.title = (data.get("title") or "").strip()
    if "desc" in data:
        row.desc = (data.get("desc") or "").strip()
    db.session.commit()
    return jsonify(_outfit_to_dict(row))

@app.delete("/api/outfits/<int:oid>")
def outfits_delete(oid):
    data = request.get_json(silent=True) or {}
    author_email = (data.get("author_email") or "").strip().lower()
    if not author_email:
        return jsonify({"message": "author_email required"}), 400
    row = Outfit.query.get_or_404(oid)
    if (row.author_email or "").strip().lower() != author_email:
        return jsonify({"message": "forbidden"}), 403
    OutfitMedia.query.filter_by(outfit_id=oid).delete()
    db.session.delete(row)
    db.session.commit()
    return jsonify({"ok": True, "deleted_id": oid})

@app.get("/api/outfit/feed")
def outfit_feed():
    tab = (request.args.get("tab") or "recommend").strip()
    qstr = (request.args.get("q") or "").strip().lower()
    try:
        offset = int(request.args.get("offset") or 0)
        limit  = min(50, int(request.args.get("limit") or 12))
    except Exception:
        offset, limit = 0, 12
    q = Outfit.query.filter_by(status="active")
    if qstr:
        like = f"%{qstr}%"
        q = q.filter(
            db.or_(
                Outfit.title.ilike(like),
                Outfit.desc.ilike(like),
                Outfit.tags_json.ilike(like)
            )
        )
    q = q.order_by(Outfit.created_at.desc())
    total = q.count()
    rows = q.offset(offset).limit(limit).all()

    def to_card(o: Outfit):
        # 优先列图，否则取媒体表作为封面
        imgs = _safe_json_loads(getattr(o, "images_json", None), [])
        cover = imgs[0] if imgs else ""
        if not cover:
            medias = OutfitMedia.query.filter_by(outfit_id=o.id).all()
            for m in medias:
                url = f"{request.url_root.rstrip('/')}/api/outfits/{o.id}/media/{m.id}"
                if not m.is_video:
                    cover = url
                    break
            if not cover and medias:
                cover = f"{request.url_root.rstrip('/')}/api/outfits/{o.id}/media/{medias[0].id}"
        return {
            "id": o.id,
            "title": o.title or "OOTD",
            "cover": cover,
            "likes": o.likes or 0,
            "comments": o.comments or 0,
            "user": {"name": o.author_name or (o.author_email or "")}
        }

    items = [to_card(o) for o in rows]
    has_more = (offset + len(items) < total)
    return jsonify({"items": items, "has_more": has_more})

@app.post("/api/outfits/<int:oid>/like")
def outfit_like(oid):
    delta = 1
    try:
        body = request.get_json(silent=True) or {}
        if "delta" in body:
            delta = int(body["delta"])
    except Exception:
        pass
    row = Outfit.query.get_or_404(oid)
    row.likes = max(0, (row.likes or 0) + delta)
    db.session.commit()
    return jsonify({"id": oid, "likes": row.likes})

@app.post("/api/outfits/<int:oid>/comment")
def outfit_comment(oid):
    delta = 1
    try:
        body = request.get_json(silent=True) or {}
        if "delta" in body:
            delta = int(body["delta"])
    except Exception:
        pass
    row = Outfit.query.get_or_404(oid)
    row.comments = max(0, (row.comments or 0) + delta)
    db.session.commit()
    return jsonify({"id": oid, "comments": row.comments})

# ==================== Settings APIs（含 bio） ====================
def _default_settings(email: str):
    return {
        "email": (email or "").lower(),
        "phone": "",
        "public_profile": True,
        "show_following": True,
        "show_followers": True,
        "dm_who": "all",
        "blacklist": [],
        "lang": "zh",
        "bio": "",
        "updated_at": None
    }

def _settings_to_dict(s: UserSetting):
    if not s: return None
    return {
        "email": s.email,
        "phone": s.phone or "",
        "public_profile": bool(s.public_profile),
        "show_following": bool(s.show_following),
        "show_followers": bool(s.show_followers),
        "dm_who": s.dm_who or "all",
        "blacklist": _safe_json_loads(s.blacklist_json, []),
        "lang": s.lang or "zh",
        "bio": (s.bio or ""),
        "updated_at": s.updated_at.isoformat() if s.updated_at else None
    }

@app.get("/api/settings")
def get_settings():
    email = (request.args.get("email") or "").strip().lower()
    if not email: return jsonify({"message":"missing email"}), 400
    try:
        s = UserSetting.query.filter(func.lower(UserSetting.email) == email).first()
        return jsonify(_settings_to_dict(s) or _default_settings(email))
    except Exception as e:
        # 表不存在或其它数据库错误时，先给默认，不让前端炸
        return jsonify(_default_settings(email) | {"_warning":"fallback","_detail":str(e)}), 200


@app.put("/api/settings")
def put_settings():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email: return jsonify({"message":"missing email"}), 400
    try:
        s = UserSetting.query.filter(func.lower(UserSetting.email) == email).first()
        if not s: s = UserSetting(email=email)
        s.phone = (data.get("phone") or "").strip()
        s.public_profile = bool(data.get("public_profile", s.public_profile if s.public_profile is not None else True))
        s.show_following = bool(data.get("show_following", s.show_following if s.show_following is not None else True))
        s.show_followers = bool(data.get("show_followers", s.show_followers if s.show_followers is not None else True))
        dm = (data.get("dm_who") or "all").strip().lower()
        s.dm_who = dm if dm in {"all","following"} else "all"
        s.blacklist_json = _json_dumps(data.get("blacklist") or _safe_json_loads(s.blacklist_json, []))
        s.lang = (data.get("lang") or s.lang or "zh").strip()[:8]
        db.session.add(s); db.session.commit()
        return jsonify(_settings_to_dict(s))
    except Exception as e:
        return jsonify({"message":"db_error","detail":str(e)}), 500


@app.post("/api/settings/blacklist")
def settings_blacklist():
    """body: {email, op: add|remove, value: 'someone@example.com'}"""
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    op = (body.get("op") or "").strip().lower()
    value = (body.get("value") or "").strip()
    if not email or not op or not value:
        return jsonify({"message":"missing params"}), 400
    s = UserSetting.query.filter(func.lower(UserSetting.email) == email).first()
    if not s: s = UserSetting(email=email)
    lst = _safe_json_loads(s.blacklist_json, [])
    if op == "add":
        if value not in lst: lst.append(value)
    elif op == "remove":
        lst = [x for x in lst if x != value]
    else:
        return jsonify({"message":"op must be add/remove"}), 400
    s.blacklist_json = _json_dumps(lst)
    db.session.add(s)
    db.session.commit()
    return jsonify(_settings_to_dict(s))

# === 简化的 profile bio 端点（可选用） ===
@app.get("/api/profile/bio")
def get_bio():
    email = (request.args.get("email") or "").strip().lower()
    if not email: return jsonify({"message":"missing email"}), 400
    s = UserSetting.query.filter(func.lower(UserSetting.email) == email).first()
    return jsonify({"email": email, "bio": (s.bio if s else "")})

@app.post("/api/profile/bio")
def set_bio():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    bio = (data.get("bio") or "")[:30]
    if not email:
        return jsonify({"message":"missing email"}), 400
    s = UserSetting.query.filter(func.lower(UserSetting.email) == email).first()
    if not s:
        s = UserSetting(email=email)
    s.bio = bio
    db.session.add(s)
    db.session.commit()
    return jsonify({"ok": True, "email": email, "bio": s.bio or ""})

# ==================== 迁移端点（按方言执行） ====================
@app.post("/api/admin/migrate")
def admin_migrate():
    try:
        with db.engine.begin() as conn:
            dialect = conn.engine.dialect.name.lower()
            is_pg = 'postgres' in dialect
            results = []

            def run(sql):
                try:
                    conn.execute(db.text(sql))
                    results.append({"sql": sql, "ok": True})
                except Exception as e:
                    results.append({"sql": sql, "ok": False, "error": str(e)})

            # 通用列兜底
            run("ALTER TABLE products ADD COLUMN IF NOT EXISTS merchant_email VARCHAR(200)")
            run("ALTER TABLE products ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active'")
            run("ALTER TABLE product_images ADD COLUMN IF NOT EXISTS filename VARCHAR(255)")
            run("ALTER TABLE product_images ADD COLUMN IF NOT EXISTS mimetype VARCHAR(128)")

            # outfits 补列（1–5 改动）
            run("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS tags VARCHAR(200)")
            run("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS location VARCHAR(200)")
            run("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS visibility VARCHAR(20) DEFAULT 'public'")
            run("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS images_json TEXT")
            run("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS videos_json TEXT")

            if is_pg:
                run("""
                    CREATE TABLE IF NOT EXISTS product_variants (
                        id SERIAL PRIMARY KEY,
                        product_id INTEGER,
                        size VARCHAR(50),
                        color VARCHAR(50),
                        price INTEGER,
                        stock INTEGER
                    )
                """)
                run("""
                    CREATE TABLE IF NOT EXISTS outfits (
                        id SERIAL PRIMARY KEY,
                        created_at TIMESTAMP,
                        author_email VARCHAR(200),
                        author_name VARCHAR(200),
                        title VARCHAR(200),
                        desc TEXT,
                        tags_json TEXT,
                        likes INTEGER DEFAULT 0,
                        comments INTEGER DEFAULT 0,
                        status VARCHAR(20) DEFAULT 'active'
                    )
                """)
                run("""
                    CREATE TABLE IF NOT EXISTS outfit_media (
                        id SERIAL PRIMARY KEY,
                        outfit_id INTEGER,
                        filename VARCHAR(255),
                        mimetype VARCHAR(128),
                        data BYTEA,
                        is_video BOOLEAN DEFAULT FALSE
                    )
                """)
                run("""
                    CREATE TABLE IF NOT EXISTS user_settings (
                        id SERIAL PRIMARY KEY,
                        email VARCHAR(200) UNIQUE,
                        phone VARCHAR(64),
                        public_profile BOOLEAN DEFAULT TRUE,
                        show_following BOOLEAN DEFAULT TRUE,
                        show_followers BOOLEAN DEFAULT TRUE,
                        dm_who VARCHAR(16) DEFAULT 'all',
                        blacklist_json TEXT,
                        lang VARCHAR(8) DEFAULT 'zh',
                        bio VARCHAR(120),
                        updated_at TIMESTAMP
                    )
                """)
                run("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS bio VARCHAR(120)")
            else:
                run("""
                    CREATE TABLE IF NOT EXISTS product_variants (
                        id INTEGER PRIMARY KEY,
                        product_id INTEGER,
                        size VARCHAR(50),
                        color VARCHAR(50),
                        price INTEGER,
                        stock INTEGER
                    )
                """)
                run("""
                    CREATE TABLE IF NOT EXISTS outfits (
                        id INTEGER PRIMARY KEY,
                        created_at TIMESTAMP,
                        author_email VARCHAR(200),
                        author_name VARCHAR(200),
                        title VARCHAR(200),
                        desc TEXT,
                        tags_json TEXT,
                        likes INTEGER DEFAULT 0,
                        comments INTEGER DEFAULT 0,
                        status VARCHAR(20) DEFAULT 'active'
                    )
                """)
                run("""
                    CREATE TABLE IF NOT EXISTS outfit_media (
                        id INTEGER PRIMARY KEY,
                        outfit_id INTEGER,
                        filename VARCHAR(255),
                        mimetype VARCHAR(128),
                        data BLOB,
                        is_video BOOLEAN DEFAULT 0
                    )
                """)
                run("""
                    CREATE TABLE IF NOT EXISTS user_settings (
                        id INTEGER PRIMARY KEY,
                        email VARCHAR(200) UNIQUE,
                        phone VARCHAR(64),
                        public_profile BOOLEAN DEFAULT 1,
                        show_following BOOLEAN DEFAULT 1,
                        show_followers BOOLEAN DEFAULT 1,
                        dm_who VARCHAR(16) DEFAULT 'all',
                        blacklist_json TEXT,
                        lang VARCHAR(8) DEFAULT 'zh',
                        bio VARCHAR(120),
                        updated_at TIMESTAMP
                    )
                """)
                run("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS bio VARCHAR(120)")
        return jsonify({"ok": True, "results": results})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)

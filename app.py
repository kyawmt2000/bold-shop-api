import os
import json
import logging
from datetime import datetime
from io import BytesIO

from flask import Flask, request, jsonify, send_file, make_response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from sqlalchemy import func, or_  # 不区分大小写查询 + 逻辑 or_

app = Flask(__name__)

# -------------------- Database config --------------------
db_url = os.getenv("SQLALCHEMY_DATABASE_URI") or os.getenv("DATABASE_URL") or "sqlite:///data.db"

# Render 给的是 postgres://，要转成 postgresql://
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# -------------------- CORS --------------------
CORS(
    app,
    resources={
        r"/*": {
            "origins": [
                "https://boldmm.shop",
                "http://boldmm.shop",
                "https://www.boldmm.shop",
                "http://www.boldmm.shop",
                "http://localhost:5500",
                "http://127.0.0.1:5500",
            ]
        }
    },
    supports_credentials=False,
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)

API_KEY = os.getenv("API_KEY", "")

db = SQLAlchemy(app)

# -------------------- Models --------------------
class MerchantApplication(db.Model):
    __tablename__ = "merchant_applications"
    id = db.Column(db.Integer, primary_key=True)
    shop_name = db.Column(db.String(100), nullable=False)
    owner_name = db.Column(db.String(100))
    phone = db.Column(db.String(50))
    email = db.Column(db.String(120), unique=True, nullable=False)
    address = db.Column(db.String(200))
    license_id = db.Column(db.String(100))
    license_images = db.Column(db.Text)  # JSON 数组
    status = db.Column(db.String(32), default="pending", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Product(db.Model):
    __tablename__ = "products"
    id = db.Column(db.Integer, primary_key=True)
    merchant_email = db.Column(db.String(200), index=True)
    title = db.Column(db.String(200), nullable=False)
    desc = db.Column(db.Text)
    price = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(10))  # men / women
    category = db.Column(db.String(50))  # top / bottom / shoes
    status = db.Column(db.String(20), default="active")  # active / removed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ProductVariant(db.Model):
    __tablename__ = "product_variants"
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(
        db.Integer, db.ForeignKey("products.id"), nullable=False, index=True
    )
    size = db.Column(db.String(50))
    color = db.Column(db.String(50))
    price = db.Column(db.Integer, nullable=False, default=0)
    stock = db.Column(db.Integer, nullable=False, default=0)


class ProductImage(db.Model):
    __tablename__ = "product_images"
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(
        db.Integer, db.ForeignKey("products.id"), nullable=False, index=True
    )
    filename = db.Column(db.String(255))
    mimetype = db.Column(db.String(128))
    data = db.Column(db.LargeBinary)


# Outfit 贴文
class Outfit(db.Model):
    __tablename__ = "outfits"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow, index=True
    )  # 创建时间
    author_email = db.Column(
        db.String(200), index=True, nullable=False
    )  # 发帖人邮箱（Google / 商家）
    author_name = db.Column(db.String(200))  # 发帖人昵称
    author_avatar = db.Column(db.String(500))  # 头像 URL

    title = db.Column(db.String(200), default="OOTD")  # 标题
    desc = db.Column(db.Text)  # 文本描述
    tags_json = db.Column(db.Text)  # JSON 数组字符串
    likes = db.Column(db.Integer, default=0)
    comments = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default="active")  # active / deleted

    # 兼容扩展列
    tags = db.Column(db.String(200))  # 简单标签字符串
    location = db.Column(db.String(200))
    visibility = db.Column(db.String(20), default="public")  # public / private
    images_json = db.Column(db.Text)  # JSON 数组：图片 URL
    videos_json = db.Column(db.Text)  # JSON 数组：视频 URL


class OutfitMedia(db.Model):
    __tablename__ = "outfit_media"
    id = db.Column(db.Integer, primary_key=True)
    outfit_id = db.Column(db.Integer, db.ForeignKey("outfits.id"), nullable=False)
    filename = db.Column(db.String(255))
    mimetype = db.Column(db.String(128))
    data = db.Column(db.LargeBinary)
    is_video = db.Column(db.Boolean, default=False)


class UserSetting(db.Model):
    __tablename__ = "user_settings"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), index=True, nullable=False, unique=True)
    phone = db.Column(db.String(64))
    public_profile = db.Column(db.Boolean, default=True)
    show_following = db.Column(db.Boolean, default=True)
    show_followers = db.Column(db.Boolean, default=True)
    dm_who = db.Column(db.String(16), default="all")  # all | following
    blacklist_json = db.Column(db.Text)
    lang = db.Column(db.String(8), default="zh")
    bio = db.Column(db.String(120))  # 简介
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


# -------------------- 初始化 & 补列 --------------------
with app.app_context():
    db.create_all()

    try:
        with db.engine.connect() as conn:
            dialect = conn.engine.dialect.name.lower()
            is_pg = "postgres" in dialect

            # product_variants
            if is_pg:
                conn.execute(
                    db.text(
                        """
                    CREATE TABLE IF NOT EXISTS product_variants (
                        id SERIAL PRIMARY KEY,
                        product_id INTEGER,
                        size VARCHAR(50),
                        color VARCHAR(50),
                        price INTEGER,
                        stock INTEGER
                    )
                """
                    )
                )
            else:
                conn.execute(
                    db.text(
                        """
                    CREATE TABLE IF NOT EXISTS product_variants (
                        id INTEGER PRIMARY KEY,
                        product_id INTEGER,
                        size VARCHAR(50),
                        color VARCHAR(50),
                        price INTEGER,
                        stock INTEGER
                    )
                """
                    )
                )

            # outfits / outfit_media 初始建表（只要存在即可）
            if is_pg:
                conn.execute(
                    db.text(
                        """
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
                """
                    )
                )
                conn.execute(
                    db.text(
                        """
                    CREATE TABLE IF NOT EXISTS outfit_media (
                        id SERIAL PRIMARY KEY,
                        outfit_id INTEGER,
                        filename VARCHAR(255),
                        mimetype VARCHAR(128),
                        data BYTEA,
                        is_video BOOLEAN DEFAULT FALSE
                    )
                """
                    )
                )
            else:
                conn.execute(
                    db.text(
                        """
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
                """
                    )
                )
                conn.execute(
                    db.text(
                        """
                    CREATE TABLE IF NOT EXISTS outfit_media (
                        id INTEGER PRIMARY KEY,
                        outfit_id INTEGER,
                        filename VARCHAR(255),
                        mimetype VARCHAR(128),
                        data BLOB,
                        is_video BOOLEAN DEFAULT 0
                    )
                """
                    )
                )

            # === outfits 表补列：兼容 1–5 改动 ===
            conn.execute(
                db.text(
                    "ALTER TABLE outfits ADD COLUMN IF NOT EXISTS author_avatar VARCHAR(500)"
                )
            )
            conn.execute(
                db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS tags VARCHAR(200)")
            )
            conn.execute(
                db.text(
                    "ALTER TABLE outfits ADD COLUMN IF NOT EXISTS location VARCHAR(200)"
                )
            )
            conn.execute(
                db.text(
                    "ALTER TABLE outfits ADD COLUMN IF NOT EXISTS visibility VARCHAR(20) DEFAULT 'public'"
                )
            )
            conn.execute(
                db.text(
                    "ALTER TABLE outfits ADD COLUMN IF NOT EXISTS images_json TEXT"
                )
            )
            conn.execute(
                db.text(
                    "ALTER TABLE outfits ADD COLUMN IF NOT EXISTS videos_json TEXT"
                )
            )

            # user_settings
            if is_pg:
                conn.execute(
                    db.text(
                        """
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
                """
                    )
                )
                # 兜底补列
                conn.execute(
                    db.text(
                        "ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS bio VARCHAR(120)"
                    )
                )
            else:
                conn.execute(
                    db.text(
                        """
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
                """
                    )
                )
                conn.execute(
                    db.text(
                        "ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS bio VARCHAR(120)"
                    )
                )
    except Exception as e:
        print("❌ outfits/user_settings ALTER TABLE failed:", e)

    # 公共列兜底（其他表）
    try:
        with db.engine.connect() as conn:
            dialect = conn.engine.dialect.name.lower()
            is_pg = "postgres" in dialect

            conn.execute(
                db.text(
                    "ALTER TABLE merchant_applications ADD COLUMN IF NOT EXISTS status VARCHAR(32) DEFAULT 'pending' NOT NULL"
                )
            )
            conn.execute(
                db.text(
                    "ALTER TABLE products ADD COLUMN IF NOT EXISTS merchant_email VARCHAR(200)"
                )
            )
            conn.execute(
                db.text(
                    "ALTER TABLE products ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active'"
                )
            )
            conn.execute(
                db.text(
                    "ALTER TABLE product_images ADD COLUMN IF NOT EXISTS filename VARCHAR(255)"
                )
            )
            conn.execute(
                db.text(
                    "ALTER TABLE product_images ADD COLUMN IF NOT EXISTS mimetype VARCHAR(128)"
                )
            )
    except Exception as e:
        print("❌ common ALTER TABLE failed:", e)


# -------------------- 辅助函数 --------------------
def _ok(data=None):
    return jsonify({"ok": True, "data": data or {}})


def _err(msg, status=400):
    return jsonify({"ok": False, "error": msg}), status


def check_key(req):
    key = req.headers.get("X-API-Key") or req.args.get("key")
    if not key and req.is_json:
        body = req.get_json(silent=True) or {}
        key = body.get("key")
    return (API_KEY != "") and (key == API_KEY)


def _safe_json_loads(s, default):
    try:
        return json.loads(s) if s else default
    except Exception:
        return default


def _json_dumps(o):
    return json.dumps(o, ensure_ascii=False)


def _variant_to_dict(v: ProductVariant):
    return {
        "id": v.id,
        "size": v.size,
        "color": v.color,
        "price": v.price,
        "stock": v.stock,
    }


def _product_to_dict(p: Product, req=None):
    r = req or request
    imgs = ProductImage.query.filter_by(product_id=p.id).all()
    urls = [
        f"{r.url_root.rstrip('/')}/api/products/{p.id}/image/{im.id}"
        for im in imgs
    ]
    variants = ProductVariant.query.filter_by(product_id=p.id).all()
    return {
        "id": p.id,
        "created_at": p.created_at.isoformat(),
        "merchant_email": p.merchant_email,
        "title": p.title,
        "price": p.price,
        "gender": p.gender,
        "category": p.category,
        "status": p.status,
        "desc": p.desc,
        "images": urls,
        "variants": [_variant_to_dict(v) for v in variants],
    }


def _outfit_to_dict(o: Outfit, req=None):
    r = req or request

    imgs_raw = _safe_json_loads(getattr(o, "images_json", None), [])
    vids_raw = _safe_json_loads(getattr(o, "videos_json", None), [])

    imgs_col = [u for u in imgs_raw if isinstance(u, str) and not u.startswith("blob:")]
    vids_col = [u for u in vids_raw if isinstance(u, str) and not u.startswith("blob:")]

    if imgs_col or vids_col:
        images = imgs_col
        videos = vids_col
    else:
        media_rows = OutfitMedia.query.filter_by(outfit_id=o.id).all()
        images = []
        videos = []
        for m in media_rows:
            url = f"{r.url_root.rstrip('/')}/api/outfits/{o.id}/media/{m.id}"
            if m.is_video:
                videos.append(url)
            else:
                images.append(url)

    tags_list = _safe_json_loads(o.tags_json, [])
    if isinstance(tags_list, list):
        tags_list = [str(x) for x in tags_list]
    else:
        tags_list = []

    return {
        "id": o.id,
        "created_at": (o.created_at.isoformat() if o.created_at else None),
        "author_email": o.author_email,
        "author_name": o.author_name,
        "author_avatar": getattr(o, "author_avatar", None),
        "title": o.title,
        "desc": o.desc,
        "tags": tags_list,
        "tags_raw": o.tags_json,
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
    if request.method == "OPTIONS":
        return None
    if request.path.startswith("/api/") and API_KEY:
        if not check_key(request):
            return jsonify({"message": "Unauthorized"}), 401


# -------------------- Health --------------------
@app.route("/health")
def health():
    return _ok()


# -------------------- 一次性修复 outfits 表字段 --------------------
@app.get("/api/debug/fix_outfits_columns")
def debug_fix_outfits_columns():
    if not check_key(request):
        return jsonify({"message": "Unauthorized"}), 401
    try:
        with db.engine.begin() as conn:
            sql_list = [
                "ALTER TABLE outfits ADD COLUMN IF NOT EXISTS author_avatar VARCHAR(500)",
                "ALTER TABLE outfits ADD COLUMN IF NOT EXISTS tags VARCHAR(200)",
                "ALTER TABLE outfits ADD COLUMN IF NOT EXISTS location VARCHAR(200)",
                "ALTER TABLE outfits ADD COLUMN IF NOT EXISTS visibility VARCHAR(20) DEFAULT 'public'",
                "ALTER TABLE outfits ADD COLUMN IF NOT EXISTS images_json TEXT",
                "ALTER TABLE outfits ADD COLUMN IF NOT EXISTS videos_json TEXT",
            ]
            for s in sql_list:
                conn.execute(db.text(s))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ==================== 下面保留你原来的路由（商品、商家、Outfit 发布等） ====================
# ⚠️ 这里我没有一行一行展开，如果你需要我也可以帮你把整份补全。
# 重点是：上面的 import + _outfit_to_dict + outfit_feed 已经修好。


@app.get("/api/outfit/feed")
def outfit_feed():
    """
    简化版 feed：
    - 按 created_at 倒序
    - 返回完整 outfit 数据（_outfit_to_dict），前端 outfit.html / myaccount.html 都可以用
    """
    try:
        limit = min(50, int(request.args.get("limit") or 20))
    except Exception:
        limit = 20

    qstr = (request.args.get("q") or "").strip().lower()
    q = Outfit.query.filter_by(status="active")

    if qstr:
        like = f"%{qstr}%"
        q = q.filter(
            or_(
                Outfit.title.ilike(like),
                Outfit.desc.ilike(like),
                Outfit.tags_json.ilike(like),
            )
        )

    rows = q.order_by(Outfit.created_at.desc()).limit(limit).all()
    items = [_outfit_to_dict(o) for o in rows]
    return jsonify({"items": items, "has_more": False})


# ... 其他路由（/api/outfits/add 等）保持你原来的实现 ...


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))

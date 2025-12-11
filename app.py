import os
import json
import logging
from datetime import datetime
from io import BytesIO
from sqlalchemy import text

from flask import Flask, request, jsonify, send_file, make_response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from sqlalchemy import func
from uuid import uuid4
from google.cloud import storage

# -----------------------------------------
#          ⭐ 正确初始化 Flask + DB ⭐
# -----------------------------------------

app = Flask(__name__)
CORS(app)

# 从 Render 环境变量读取 DATABASE_URL
db_url = os.getenv("DATABASE_URL")
if not db_url:
    raise RuntimeError("DATABASE_URL is not set")
# Render 提供的是 postgres:// 前缀，需要替换成 postgresql:// 才能被 SQLAlchemy 识别
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

API_KEY = os.getenv("API_KEY", "")

GCS_BUCKET   = (os.getenv("GCS_BUCKET") or "").strip()
GCS_KEY_JSON = os.getenv("GCS_KEY_JSON")  # Render 里存整个 JSON

# 如果提供了 JSON，就写到临时文件，并设置 GOOGLE_APPLICATION_CREDENTIALS
if GCS_KEY_JSON and not os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
    try:
        key_path = "/tmp/gcs-key.json"
        with open(key_path, "w") as f:
            f.write(GCS_KEY_JSON)
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = key_path
    except Exception as e:
        logging.exception("Failed to write GCS_KEY_JSON: %s", e)

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
    images_json = db.Column(db.Text)
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
    product_id = db.Column(
        db.Integer,
        db.ForeignKey("products.id"),
        nullable=False,
        index=True,
    )
    filename = db.Column(db.String(255))
    mimetype = db.Column(db.String(128))
    data = db.Column(db.LargeBinary)

class OutfitMedia(db.Model):
    __tablename__ = "outfit_media"
    __table_args__ = {"extend_existing": True}

    id = db.Column(db.Integer, primary_key=True)
    outfit_id = db.Column(
        db.Integer,
        db.ForeignKey("outfits.id"),
        nullable=False,
        index=True,
    )
    filename = db.Column(db.String(255))
    mimetype = db.Column(db.String(128))
    data = db.Column(db.LargeBinary)
    is_video = db.Column(db.Boolean, default=False)


# === Outfit(穿搭) ===
class Outfit(db.Model):
    __tablename__ = "outfits"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    author_email = db.Column(db.String(200), index=True, nullable=False)
    author_name  = db.Column(db.String(200))
    author_avatar = db.Column(db.String(500))
    title        = db.Column(db.String(200), default="OOTD")
    desc         = db.Column(db.Text)
    tags_json    = db.Column(db.Text)   # 原有 JSON 数组（字符串）
    likes        = db.Column(db.Integer, default=0)
    comments     = db.Column(db.Integer, default=0)
    favorites    = db.Column(db.Integer, default=0)
    shares       = db.Column(db.Integer, default=0)
    status       = db.Column(db.String(20), default="active")

    # === 新增的最小侵入式列：便于直接存 URL 数组（JSON 字符串）与元信息 ===
    tags       = db.Column(db.String(200))              # 允许简单字符串标签
    location   = db.Column(db.String(200))
    visibility = db.Column(db.String(20), default="public")  # public/private
    images_json = db.Column(db.Text)                    # 存 URL 数组（JSON 字符串）
    videos_json = db.Column(db.Text)                    # 存 URL 数组（JSON 字符串）

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


# === User Setting（新增 bio 字段） ===
class UserSetting(db.Model):
    """
    Per-user settings model.  This table stores profile information such as
    nickname, avatar, bio and location, plus privacy settings.  Each row is
    uniquely keyed by the user's email.  Keeping these fields consistent
    with the frontend prevents runtime errors when serializing/unserializing
    JSON data.
    """
    __tablename__ = "user_settings"

    # Primary key and identity
    id = db.Column(db.Integer, primary_key=True)
    # Each email maps to one settings record
    email = db.Column(db.String(120), unique=True, nullable=False)

    # Profile fields
    nickname = db.Column(db.String(80))               # 用户昵称
    avatar_url = db.Column(db.String(500))            # 头像 URL
    bio = db.Column(db.String(120))                   # 个性签名
    birthday = db.Column(db.String(16))               # 生日 YYYY-MM-DD
    city = db.Column(db.String(120))                  # 城市
    gender = db.Column(db.String(16))                 # 性别

    # Privacy / account settings
    phone = db.Column(db.String(64))
    public_profile = db.Column(db.Boolean, default=True)
    show_following = db.Column(db.Boolean, default=True)
    show_followers = db.Column(db.Boolean, default=True)
    dm_who = db.Column(db.String(16), default="all")
    blacklist_json = db.Column(db.Text)               # 黑名单 JSON 字符串
    lang = db.Column(db.String(8), default="zh")

    # Record last update timestamp for concurrency control
    updated_at = db.Column(db.TIMESTAMP)

class UserFollow(db.Model):
    __tablename__ = "user_follows"

    id = db.Column(db.Integer, primary_key=True)
    follower_email = db.Column(db.String(200), index=True, nullable=False)
    target_email   = db.Column(db.String(200), index=True, nullable=False)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("follower_email", "target_email", name="uix_follow_pair"),
    )

class Notification(db.Model):
    """
    通知表：
    - 谁（actor）对谁（user_email）的 outfit 做了什么（like / comment）
    """
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)

    # 收到通知的人（帖子作者）
    user_email   = db.Column(db.String(200), index=True, nullable=False)

    # 操作人（点赞 / 评论的人）
    actor_email  = db.Column(db.String(200), index=True)
    actor_name   = db.Column(db.String(200))
    actor_avatar = db.Column(db.String(500))

    # 关联的帖子
    outfit_id    = db.Column(db.Integer, db.ForeignKey("outfits.id"), index=True)

    # 操作类型：like / comment
    action       = db.Column(db.String(32))

    # 额外信息，比如评论内容
    payload_json = db.Column(db.Text)

    is_read      = db.Column(db.Boolean, default=False, index=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow, index=True)

def create_notification_for_outfit(outfit, action, actor=None, payload=None):
    """
    给帖子作者生成一条通知：
    - action: "like" / "comment"
    - actor: {"email","name","avatar"}
    - payload: 任意 dict，比如 {"text": "..."}
    """
    try:
        if not outfit or not outfit.author_email:
            return

        user_email = (outfit.author_email or "").strip().lower()
        if not user_email:
            return

        actor = actor or {}
        actor_email = (actor.get("email") or "").strip().lower() or None

        # 自己给自己点/评就不通知了
        if actor_email and actor_email == user_email:
            return

        n = Notification(
            user_email=user_email,
            actor_email=actor_email,
            actor_name=actor.get("name") or None,
            actor_avatar=actor.get("avatar") or None,
            outfit_id=outfit.id,
            action=action,
            payload_json=json.dumps(payload or {}, ensure_ascii=False),
        )
        db.session.add(n)
    except Exception as e:
        app.logger.exception("create_notification_for_outfit failed: %s", e)

# -------------------- 初始化：按方言兜底建表 --------------------
with app.app_context():
    db.create_all()

    try:
        with db.engine.connect() as conn:
            dialect = conn.engine.dialect.name.lower()
            is_pg = 'postgres' in dialect

            # outfits 表补充字段
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS author_avatar VARCHAR(500)"))
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS tags VARCHAR(200)"))
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS location VARCHAR(200)"))
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS visibility VARCHAR(20) DEFAULT 'public'"))
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS images_json TEXT"))
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS videos_json TEXT"))
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS favorites INTEGER DEFAULT 0"))
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS shares INTEGER DEFAULT 0"))

    except Exception as e:
        print("❌ outfits ALTER TABLE failed:", e)
    

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
                        "desc" TEXT,
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
                        "desc" TEXT,
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
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS author_avatar VARCHAR(500)"))
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS tags VARCHAR(200)"))
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS location VARCHAR(200)"))
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS visibility VARCHAR(20) DEFAULT 'public'"))
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS images_json TEXT"))
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS videos_json TEXT"))
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS favorites INTEGER DEFAULT 0"))
            conn.execute(db.text("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS shares INTEGER DEFAULT 0"))
            
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

def upload_to_gcs_product(file, filename):
    """上传商品图片到 GCS，返回公开 URL；失败返回 None"""
    if not GCS_BUCKET:
        return None

    try:
        client = storage.Client()
        bucket = client.bucket(GCS_BUCKET)
        blob = bucket.blob(f"products/{filename}")  # 存放在 products/ 目录下

        file.seek(0)
        blob.upload_from_file(
            file,
            content_type=(file.content_type or "application/octet-stream"),
        )

        try:
            blob.make_public()
        except Exception:
            # 设公开失败也不致命，只是可能用不了匿名访问
            pass

        return blob.public_url
    except Exception as e:
        app.logger.exception("upload_to_gcs_product failed: %s", e)
        return None

def _touch_user(email: str):
    """
    确保 users 表里有这条记录：
    - 第一次看到这个 email：创建新用户
    - 以后再看到：只更新 last_seen_at
    """
    email = (email or "").strip().lower()
    if not email:
        return None
    try:
        row = User.query.filter(func.lower(User.email) == email).first()
        now = datetime.utcnow()
        if not row:
            row = User(email=email, created_at=now, last_seen_at=now)
            db.session.add(row)
        else:
            row.last_seen_at = now
        db.session.commit()
        return row
    except Exception as e:
        db.session.rollback()
        app.logger.exception("_touch_user failed: %s", e)
        return None

def upload_file_to_gcs(file, folder="outfits"):
    """
    上传单个文件到 GCS：
    - 成功：返回公开 URL
    - 失败或未配置 GCS：返回 None
    """
    # 如果没配置 bucket，直接跳过，用旧逻辑
    if not GCS_BUCKET:
        return None

    try:
        # 初始化 GCS client
        client = storage.Client()
        bucket = client.bucket(GCS_BUCKET)

        # 生成一个干净的文件名 + 路径
        raw_name = secure_filename(file.filename or "upload")
        _, ext = os.path.splitext(raw_name)
        # 路径：outfits/2025/02/05/uuid.jpg
        today = datetime.utcnow().strftime("%Y/%m/%d")
        blob_name = f"{folder}/{today}/{uuid4().hex}{ext}"

        blob = bucket.blob(blob_name)

        # 重新把文件指针移到开头
        file.seek(0)
        blob.upload_from_file(
            file,
            content_type=(file.mimetype or "application/octet-stream"),
        )

        # 设为公开可读（你 bucket 那边必须没有开启“Enforce public access prevention”）
        try:
            blob.make_public()
        except Exception:
            # 即使设公开失败，也不影响主流程，只是可能需要签名 URL
            pass

        return blob.public_url
    except Exception as e:
        app.logger.exception("upload_file_to_gcs failed: %s", e)
        return None

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
    """把 Product 转成前端需要的结构，尽量防止旧数据导致 500"""
    r = req or request

    # created_at 可能是 None，用 try/except 包一下最安全
    try:
        created_at = p.created_at.isoformat() if getattr(p, "created_at", None) else None
    except Exception:
        created_at = None

    # 商品图片：现在还是走 /api/products/<pid>/image/<iid> 的老逻辑
        # 商品图片：
    # - 如果 filename 是 http(s) 开头 => 直接当成 GCS URL
    # - 否则还是走 /api/products/<pid>/image/<iid> 老逻辑
    try:
        imgs = ProductImage.query.filter_by(product_id=p.id).all()
    except Exception:
        imgs = []

    urls = []
    imgs_from_product = _safe_json_loads(getattr(p, "images_json", None), [])
    if imgs_from_product:
        urls = [u for u in imgs_from_product if isinstance(u, str) and u]
    else:
        # 2) 旧逻辑：从 product_images 表拼 URL
        try:
            imgs = ProductImage.query.filter_by(product_id=p.id).all()
        except Exception:
            imgs = []
    base = (r.url_root or "").rstrip("/")
    for im in imgs:
        try:
            if im.filename and isinstance(im.filename, str) and im.filename.startswith("http"):
                # GCS URL 直接返回
                urls.append(im.filename)
            else:
                # 老的二进制图片走本地接口
                urls.append(f"{base}/api/products/{p.id}/image/{im.id}")
        except Exception:
            continue


    # 变体列表
    try:
        variants = ProductVariant.query.filter_by(product_id=p.id).all()
    except Exception:
        variants = []

    return {
        "id": p.id,
        "created_at": created_at,
        "merchant_email": getattr(p, "merchant_email", "") or "",
        "title": p.title,
        "price": p.price,
        "gender": p.gender,
        "category": p.category,
        "desc": p.desc,
        "sizes": _safe_json_loads(getattr(p, "sizes_json", None), []),
        "colors": _safe_json_loads(getattr(p, "colors_json", None), []),
        "images": urls,
        "variants": [_variant_to_dict(v) for v in variants],
        "status": getattr(p, "status", "active") or "active",
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

def _safe_json_list(raw):
    """
    把各种乱七八糟的存法，尽量稳健地变成 list[str]
    支持：
    - None / "" -> []
    - 已经是 list/tuple -> 直接转成字符串列表
    - JSON 字符串（["a","b"]）-> 列表
    - 普通用逗号分隔的字符串 "a,b,c" -> 列表
    """
    if not raw:
        return []
    if isinstance(raw, (list, tuple)):
        return [str(x) for x in raw]
    try:
        j = json.loads(raw)
        if isinstance(j, list):
            return [str(x) for x in j]
    except Exception:
        pass
    if isinstance(raw, str):
        return [s.strip() for s in raw.split(",") if s.strip()]
    return []

def _outfit_to_dict(o: Outfit, req=None):
    """统一把 Outfit 模型转换成前端用的 dict；兼容各种旧数据格式，不要抛异常。"""

    # ---------- tags ----------
    tags = []
    try:
        raw_tags = getattr(o, "tags_json", None)
        if raw_tags:
            t = json.loads(raw_tags)
            if isinstance(t, list):
                tags = [str(x) for x in t]
    except Exception:
        tags = []

    # ---------- images / videos ----------
    images: list[str] = []
    videos: list[str] = []

    # 1) 优先使用新字段 images_json / videos_json（如果有）
    try:
        raw_img = getattr(o, "images_json", None)
        if raw_img:
            parsed = json.loads(raw_img)
            if isinstance(parsed, list):
                images = [str(x) for x in parsed if x]
    except Exception:
        pass

    try:
        raw_vid = getattr(o, "videos_json", None)
        if raw_vid:
            parsed = json.loads(raw_vid)
            if isinstance(parsed, list):
                videos = [str(x) for x in parsed if x]
    except Exception:
        pass

    # 2) 如果还都是空，再兼容旧字段 media_json
    if not images and not videos:
        mlist = []
        try:
            media = getattr(o, "media_json", None)
            if media:
                parsed = json.loads(media)
                if isinstance(parsed, list):
                    mlist = parsed
                elif isinstance(parsed, dict):
                    mlist = [parsed]
        except Exception:
            mlist = []

        for m in mlist:
            # 兼容两种情况：dict / str
            if isinstance(m, dict):
                mtype = (m.get("type") or "image").lower()
                url = m.get("url") or m.get("src")
            else:
                mtype = "image"
                url = str(m)

            if not url:
                continue

            if mtype == "video":
                videos.append(url)
            else:
                images.append(url)

    # ---------- 点赞 / 评论 ----------
    raw_likes = getattr(o, "likes", None)
    raw_likes_count = getattr(o, "likes_count", None)
    likes_val = raw_likes_count if raw_likes_count is not None else (raw_likes or 0)

    raw_comments = getattr(o, "comments", None)
    raw_comments_count = getattr(o, "comments_count", None)
    comments_val = raw_comments_count if raw_comments_count is not None else (raw_comments or 0)

    # ---------- 收藏 / 分享 ----------
    favorites_val = getattr(o, "favorites_count", None)
    if favorites_val is None:
        favorites_val = getattr(o, "favorites", 0) or 0

    shares_val = getattr(o, "shares_count", None)
    if shares_val is None:
        shares_val = getattr(o, "shares", 0) or 0

    return {
        "id": o.id,
        "created_at": o.created_at.isoformat() if getattr(o, "created_at", None) else None,

        "author_email": getattr(o, "author_email", None),
        "author_name": getattr(o, "author_name", None),
        "author_avatar": getattr(o, "author_avatar", None),

        "title": getattr(o, "title", None) or "OOTD",
        "desc": getattr(o, "desc", None),

        "tags": tags,
        "images": images,
        "videos": videos,

        # 旧字段（给没改 JS 的地方用）
        "likes": likes_val,
        "comments": comments_val,

        # 新计数字段
        "likes_count": likes_val,
        "comments_count": comments_val,
        "favorites_count": favorites_val,
        "shares_count": shares_val,

        "status": getattr(o, "status", "active") or "active",
        "location": getattr(o, "location", None),
        "visibility": getattr(o, "visibility", "public") or "public",
    }


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
# 只保护后台 / 调试接口，公开接口不需要 key
PROTECTED_PREFIXES = ["/api/admin", "/api/debug"]

@app.before_request
def _enforce_api_key():
    # health / 预检 直接放行
    if request.path == "/health":
        return None
    if request.method == "OPTIONS":
        return None

    # 没有设置 API_KEY，就不做任何校验
    if not API_KEY:
        return None

    # 只有这些前缀才需要 key
    if not any(request.path.startswith(p) for p in PROTECTED_PREFIXES):
        return None

    # 校验失败返回 401
    if not check_key(request):
        return jsonify({"message": "Unauthorized"}), 401


# -------------------- Health --------------------
@app.route("/health")
def health(): return ok()

from sqlalchemy import text  # 你 app.py 最上面已经有的话就不用重复加

# ================== 旧库兼容：自动补充 outfits 缺的列 ==================
def ensure_outfits_legacy_columns():
    """
    确保旧数据库里的 outfits 表有 favorites / shares 这些新列。
    如果没有，就自动 ADD COLUMN（IF NOT EXISTS，不会重复报错）。
    """
    try:
        with db.engine.begin() as conn:
            # 点赞 / 收藏 / 分享计数列
            conn.execute(text("""
                ALTER TABLE outfits
                ADD COLUMN IF NOT EXISTS favorites integer DEFAULT 0
            """))
            conn.execute(text("""
                ALTER TABLE outfits
                ADD COLUMN IF NOT EXISTS shares integer DEFAULT 0
            """))

            # 如果你担心 tags_json / images_json / videos_json 旧库也没有，
            # 也可以一起兜底加上（TEXT 类型，默认 '[]'）：
            conn.execute(text("""
                ALTER TABLE outfits
                ADD COLUMN IF NOT EXISTS tags_json   text DEFAULT '[]'
            """))
            conn.execute(text("""
                ALTER TABLE outfits
                ADD COLUMN IF NOT EXISTS images_json text DEFAULT '[]'
            """))
            conn.execute(text("""
                ALTER TABLE outfits
                ADD COLUMN IF NOT EXISTS videos_json text DEFAULT '[]'
            """))

            # 如果旧表里没有 created_at，也可以一并加上（可选）：
            conn.execute(text("""
                ALTER TABLE outfits
                ADD COLUMN IF NOT EXISTS created_at timestamptz DEFAULT NOW()
            """))

        app.logger.info("ensure_outfits_legacy_columns: OK")
    except Exception as e:
        app.logger.exception("ensure_outfits_legacy_columns failed: %s", e)

# 在应用启动时，进入 app context 手动跑一次补列逻辑
with app.app_context():
    try:
        ensure_outfits_legacy_columns()
    except Exception as e:
        app.logger.exception("run ensure_outfits_legacy_columns on startup failed: %s", e)

@app.get("/api/admin/users")
def api_admin_users():
    """
    后台用户列表：
    - 主来源：users 表（真正注册/出现过的账号）
    - 额外信息：user_settings 里的昵称、手机、生日等
    """

    # 如果你想用 ADMIN_API_KEY 做保护，可以在环境变量里配一个
    admin_key = os.getenv("ADMIN_API_KEY") or ""
    if admin_key:
        req_key = (request.headers.get("X-API-Key") or "").strip()
        if req_key != admin_key:
            return jsonify({"error": "forbidden"}), 403

    try:
        q = (
            db.session
            .query(User, UserSetting)
            .outerjoin(
                UserSetting,
                func.lower(User.email) == func.lower(UserSetting.email)
            )
            .order_by(User.created_at.desc())
            .limit(500)
        )

        out = []
        for u, s in q.all():
            created_at = u.created_at.isoformat(timespec="seconds") if u.created_at else None

            out.append({
                "id": u.id,
                "email": u.email,
                "username": getattr(s, "nickname", None),
                "phone": getattr(s, "phone", None),
                "created_at": created_at,
                "gender": getattr(s, "gender", None) if hasattr(s, "gender") else None,
                "birthday": getattr(s, "birthday", None),
            })

        return jsonify(out)
    except Exception as e:
        app.logger.exception("api_admin_users failed: %s", e)
        return jsonify({"error": "db_error", "detail": str(e)}), 500

    # 如果你以后想用 ADMIN_API_KEY 来保护这个接口，可以打开下面这几行：
    admin_key = os.getenv("ADMIN_API_KEY") or ""
    if admin_key:
        req_key = (request.headers.get("X-API-Key") or "").strip()
        if req_key != admin_key:
            return jsonify({"error": "forbidden"}), 403

    rows = UserSetting.query.order_by(
        UserSetting.updated_at.desc().nullslast()
    ).limit(500).all()

    out = []
    for s in rows:
        # 注册时间：优先 updated_at，然后 created_at，如果都没有就用当前时间
        ts = s.updated_at or s.created_at or datetime.utcnow()
        out.append({
            "id": s.id,
            "email": s.email,
            "username": getattr(s, "nickname", None),
            "phone": getattr(s, "phone", None),
            "created_at": ts.isoformat(timespec="seconds"),
            "gender": getattr(s, "gender", None),      # 你现在表里没有 gender 的话就是 None
            "birthday": getattr(s, "birthday", None),
        })

    return jsonify(out)
        
# -------------------- 一次性修复 outfits 表字段 --------------------
@app.get("/api/debug/fix_outfits_columns")
def debug_fix_outfits_columns():
    """
    把 outfits 表需要的列全部补上：
    - author_avatar
    - tags
    - location
    - visibility
    - images_json
    - videos_json
    调用一次就可以，之后可以不再访问。
    """
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

        return jsonify({"ok": True}), 200
    except Exception as e:
        app.logger.exception("debug_fix_outfits_columns error")
        return jsonify({"ok": False, "error": str(e)}), 500


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

@app.route("/api/products/add", methods=["POST"])
def add_product():
    merchant_email = request.form.get("merchant_email", "").strip().lower()
    title = request.form.get("title", "").strip()
    gender = request.form.get("gender", "")
    category = request.form.get("category", "")
    price = request.form.get("price", "0")
    desc = request.form.get("desc", "")

    sizes = request.form.get("sizes", "[]")
    colors = request.form.get("colors", "[]")

    try:
        sizes_list = json.loads(sizes)
        colors_list = json.loads(colors)
    except:
        return jsonify({"ok": False, "error": "Invalid JSON in sizes or colors"}), 400

    # 上传图片（GCS）
    files = request.files.getlist("images")
    image_urls = []

    for f in files:
        if f:
            filename = uuid4().hex + os.path.splitext(f.filename)[1]
            url = upload_to_gcs_product(f, filename)
            image_urls.append(url)

    # 存入数据库
    p = Product(
        merchant_email=merchant_email,
        title=title,
        gender=gender,
        category=category,
        price=price,
        desc=desc,
        sizes_json=json.dumps(sizes_list),
        colors_json=json.dumps(colors_list),
        images_json=json.dumps(image_urls),   # <<< 关键
        status="active",
        created_at=datetime.utcnow()
    )

    db.session.add(p)
    db.session.commit()

    return jsonify({"ok": True, "id": p.id, "images": image_urls})



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
        return jsonify({"message": "forbidden"}), 403

    if "title" in data:
        row.title = (data.get("title") or "").strip()

    if "price" in data:
        try:
            row.price = int(data.get("price") or 0)
        except Exception:
            return jsonify({"message": "price 不合法"}), 400

    if "desc" in data:
        row.desc = (data.get("desc") or "").strip()

    if "gender" in data:
        row.gender = (data.get("gender") or "").strip()

    if "category" in data:
        row.category = (data.get("category") or "").strip()

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

@app.post("/api/outfits/add")
def outfits_add():
    """表单上传穿搭：支持 1~5 张图片 或 1 个视频；优先上传到 GCS"""
    try:
        f = request.form
        email = (f.get("author_email") or "").strip().lower()
        if not email:
            return jsonify({"message": "author_email 不能为空"}), 400

        title = (f.get("title") or "").strip() or "OOTD"
        desc  = (f.get("desc") or "").strip()
        author_name = (f.get("author_name") or "").strip()

        # 标签：前端传 JSON 字符串
        tags_raw = f.get("tags") or "[]"
        tags = _safe_json_loads(tags_raw, [])
        tags_json = _json_dumps(tags)

        files = request.files.getlist("media")
        if not files:
            return jsonify({"message": "请至少上传 1 个文件"}), 400

        # 判断是图片还是视频，不能混合
        is_videos = [(file.mimetype or "").startswith("video/") for file in files]
        if any(is_videos) and not all(is_videos):
            return jsonify({"message": "不能混合图片和视频。只支持 1 个视频 或 1~5 张图片"}), 400
        if all(is_videos):
            if len(files) != 1:
                return jsonify({"message": "视频只能上传 1 个"}), 400
        else:
            if len(files) > 5:
                return jsonify({"message": "图片最多 5 张"}), 400

        # 这里准备两个列表：存 GCS 的 URL
        image_urls = []
        video_urls = []

        # 新建 outfit 记录（先不管图片）
        o = Outfit(
            author_email=email,
            author_name=author_name,
            title=title,
            desc=desc,
            tags_json=tags_json,
            status="active",
        )
        db.session.add(o)
        db.session.flush()  # 拿到 o.id

        # 优先：上传到 GCS，保存 URL；如果 GCS 不可用，再退回旧逻辑存数据库二进制
        for i, file in enumerate(files):
            if not file:
                continue
            file.seek(0, os.SEEK_END)
            size = file.tell()
            file.seek(0)
            if size > 20 * 1024 * 1024:
                db.session.rollback()
                return jsonify({"message": f"第{i+1}个文件超过 20MB"}), 400

            mimetype = file.mimetype or "application/octet-stream"
            is_video = mimetype.startswith("video/")

            # ① 先尝试上传到 GCS
            gcs_url = upload_file_to_gcs(file, folder="outfits")

            if gcs_url:
                # GCS 成功：只存 URL，后面 _outfit_to_dict 会直接用 images_json / videos_json
                if is_video:
                    video_urls.append(gcs_url)
                else:
                    image_urls.append(gcs_url)
            else:
                # ② 如果 GCS 没配置 / 出错，则退回旧逻辑：写二进制到 OutfitMedia
                m = OutfitMedia(
                    outfit_id=o.id,
                    filename=secure_filename(file.filename or f"o{o.id}_{i+1}"),
                    mimetype=mimetype,
                    data=file.read(),
                    is_video=is_video,
                )
                db.session.add(m)

        # 把 GCS 的 URL 写回 Outfit 记录
        if image_urls:
            o.images_json = json.dumps(image_urls, ensure_ascii=False)
        if video_urls:
            o.videos_json = json.dumps(video_urls, ensure_ascii=False)

        db.session.commit()
        return jsonify(_outfit_to_dict(o)), 201

    except Exception as e:
        # 有异常时回滚并返回错误信息（方便前端看到具体原因）
        db.session.rollback()
        app.logger.exception("outfits_add error")
        return jsonify({"message": "server error", "error": str(e)}), 500



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
        return jsonify([_outfit_to_dict(r) for r in rows])

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

    # 标题 / 正文
    if "title" in data:
        row.title = (data.get("title") or "").strip()
    if "desc" in data:
        row.desc = (data.get("desc") or "").strip()

    # 可见性：public / following / private
    if "visibility" in data:
        vis = (data.get("visibility") or "public").strip().lower()
        if vis not in ("public", "following", "private"):
            vis = "public"
        row.visibility = vis

    # 位置（可选）
    if "location" in data:
        row.location = (data.get("location") or "").strip() or None

    # 风格 = tags（数组或字符串）
    if "tags" in data:
        tags = data.get("tags") or []
        if isinstance(tags, str):
            try:
                j = json.loads(tags)
                if isinstance(j, list):
                    tags = j
                else:
                    tags = [tags]
            except Exception:
                tags = [
                    x.strip()
                    for x in tags.replace("，", ",").split(",")
                    if x.strip()
                ]
        if isinstance(tags, list):
            row.tags_json = json.dumps(tags, ensure_ascii=False)

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

# ==================== New Feed API (Unified) ====================
@app.get("/api/outfits/feed")
@app.get("/api/outfit/feed2")
def api_outfits_feed_list():
    try:
        limit = min(200, int(request.args.get("limit") or 50))
    except Exception:
        limit = 50

    q = Outfit.query
    try:
        rows = q.order_by(Outfit.created_at.desc()).limit(limit).all()
    except Exception as e:
        app.logger.exception(
            "outfits_feed order_by created_at failed, fallback to id desc: %s", e
        )
        try:
            db.session.rollback()
        except Exception:
            pass

        rows = Outfit.query.order_by(Outfit.id.desc()).limit(limit).all()

    items = []
    for o in rows:
        try:
            items.append(_outfit_to_dict(o))
        except Exception as e:
            app.logger.exception(
                "outfit_to_dict failed for id=%s: %s", getattr(o, "id", None), e
            )

    return jsonify({"items": items, "has_more": False})


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
    q = Outfit.query   # 先不要按 status 过滤

    if qstr:
        like = f"%{qstr}%"
        q = q.filter(
            db.or_(
                Outfit.title.ilike(like),
                Outfit.desc.ilike(like),
                Outfit.tags_json.ilike(like),
            )
        )

    rows = q.order_by(Outfit.created_at.desc()).limit(limit).all()
    items = [_outfit_to_dict(o) for o in rows]
    return jsonify({"items": items, "has_more": False})

@app.post("/api/outfits/<int:oid>/like")
def outfit_like(oid):
    delta = 1
    body = {}
    actor = {}

    try:
        body = request.get_json(silent=True) or {}
        if "delta" in body:
            delta = int(body["delta"])
    except Exception:
        body = {}

    # 点赞用户信息（前端可选传）
    try:
        actor = {
            "email": body.get("actor_email"),
            "name": body.get("actor_name"),
            "avatar": body.get("actor_avatar"),
        }
    except Exception:
        actor = {}

    row = Outfit.query.get_or_404(oid)
    old = row.likes or 0
    row.likes = max(0, old + delta)

    # 只有增加点赞时才发通知（取消赞 delta=-1 不发）
    if delta > 0:
        try:
            create_notification_for_outfit(
                row,
                action="like",
                actor=actor,
                payload={"delta": delta},
            )
        except Exception as e:
            app.logger.exception("create like notification failed: %s", e)

    db.session.commit()
    likes = row.likes or 0
    return jsonify({
        "id": oid,
        "likes": likes,
        "likes_count": likes,
    })

@app.post("/api/outfits/<int:oid>/comment")
def outfit_comment(oid):
    delta = 1
    body = {}
    actor = {}
    comment_text = ""

    try:
        body = request.get_json(silent=True) or {}
        if "delta" in body:
            delta = int(body["delta"])
    except Exception:
        body = {}

    try:
        actor = {
            "email": body.get("actor_email"),
            "name": body.get("actor_name"),
            "avatar": body.get("actor_avatar"),
        }
        comment_text = (body.get("text") or "")[:200]  # 评论内容可选，截断一下
    except Exception:
        actor = {}
        comment_text = ""

    row = Outfit.query.get_or_404(oid)
    old = row.comments or 0
    row.comments = max(0, old + delta)

    if delta > 0:
        try:
            create_notification_for_outfit(
                row,
                action="comment",
                actor=actor,
                payload={"text": comment_text, "delta": delta},
            )
        except Exception as e:
            app.logger.exception("create comment notification failed: %s", e)

    db.session.commit()
    comments = row.comments or 0
    return jsonify({
        "id": oid,
        "comments": comments,
        "comments_count": comments,
    })

@app.get("/api/notifications")
def api_notifications():
    """
    查询当前用户的通知：
    GET /api/notifications?email=xxx&limit=50&unread=1
    """
    email = (request.args.get("email") or "").strip().lower()
    if not email:
        return jsonify({"items": []})

    try:
        limit = int(request.args.get("limit") or 50)
    except Exception:
        limit = 50
    limit = max(1, min(limit, 100))

    unread_only = (request.args.get("unread") or "").strip() in ("1", "true", "yes")

    q = Notification.query.filter_by(user_email=email)
    if unread_only:
        q = q.filter_by(is_read=False)

    rows = q.order_by(Notification.created_at.desc()).limit(limit).all()

    items = []
    for n in rows:
        try:
            payload = json.loads(n.payload_json or "{}")
        except Exception:
            payload = {}

        items.append({
            "id": n.id,
            "user_email": n.user_email,
            "actor_email": n.actor_email,
            "actor_name": n.actor_name,
            "actor_avatar": n.actor_avatar,
            "outfit_id": n.outfit_id,
            "action": n.action,          # like / comment
            "payload": payload,          # {text, delta...}
            "is_read": bool(n.is_read),
            "created_at": n.created_at.isoformat() if n.created_at else None,
        })

    return jsonify({"items": items})

@app.post("/api/notifications/mark_read")
def api_notifications_mark_read():
    """
    标记通知为已读：
    body: {"email": "...", "ids": [1,2,3]}  或只传 email 标记全部
    """
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    if not email:
        return jsonify({"ok": False, "error": "email required"}), 400

    ids = body.get("ids") or []
    q = Notification.query.filter_by(user_email=email)
    if ids:
        q = q.filter(Notification.id.in_(ids))

    updated = q.update({Notification.is_read: True}, synchronize_session=False)
    db.session.commit()
    return jsonify({"ok": True, "updated": updated})

@app.post("/api/outfits/<int:oid>/favorite")
def outfit_favorite(oid):
    """
    收藏 / 取消收藏：
    body = {"delta": 1}  -> +1
    body = {"delta": -1} -> -1
    不传 delta 默认 +1
    """
    delta = 1
    try:
        body = request.get_json(silent=True) or {}
        if "delta" in body:
            delta = int(body["delta"])
    except Exception:
        pass

    row = Outfit.query.get_or_404(oid)
    row.favorites = max(0, (row.favorites or 0) + delta)
    db.session.commit()
    favorites = row.favorites or 0
    return jsonify({
        "id": oid,
        "favorites": favorites,
        "favorites_count": favorites,
        "saved_count": favorites,
    })

@app.post("/api/outfits/<int:oid>/share")
def outfit_share(oid):
    """
    分享次数统计：每点一次 +1，就算取消不了也没关系
    """
    delta = 1
    try:
        body = request.get_json(silent=True) or {}
        if "delta" in body:
            delta = int(body["delta"])
    except Exception:
        pass

    row = Outfit.query.get_or_404(oid)
    row.shares = max(0, (row.shares or 0) + delta)
    db.session.commit()
    shares = row.shares or 0
    return jsonify({
        "id": oid,
        "shares": shares,
        "shares_count": shares,
    })

@app.get("/api/outfits/<int:oid>/stats")
def outfit_stats(oid):
    row = Outfit.query.get_or_404(oid)
    likes     = row.likes or 0
    comments  = row.comments or 0
    favorites = getattr(row, "favorites", 0) or 0
    shares    = getattr(row, "shares", 0) or 0

    return jsonify({
        "id": row.id,
        "likes": likes,
        "likes_count": likes,
        "comments": comments,
        "comments_count": comments,
        "favorites": favorites,
        "favorites_count": favorites,
        "saved_count": favorites,
        "shares": shares,
        "shares_count": shares,
    })

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

def _settings_to_dict(s: UserSetting) -> dict:
    """
    Convert a UserSetting object into a JSON-serializable dict for the frontend.

    We normalize the avatar field to always come from `avatar_url` and remove any
    accidental base64 data URI. Missing values are returned as empty strings.
    """
    if not s:
        return {}

    # Normalize the avatar to avoid storing data URIs inadvertently
    avatar = (s.avatar_url or "")
    if isinstance(avatar, str) and avatar.startswith("data:image"):
        avatar = ""

    updated_at = None
    try:
        if s.updated_at is not None and hasattr(s.updated_at, "isoformat"):
            updated_at = s.updated_at.isoformat()
    except Exception:
        updated_at = None

    return {
        "email": s.email,
        "nickname": s.nickname or "",
        "avatar": avatar,
        "bio": s.bio or "",
        "birthday": s.birthday or "",
        "city": s.city or "",
        "gender": s.gender or "",
        "lang": s.lang or "en",
        "public_profile": bool(s.public_profile) if s.public_profile is not None else True,
        "show_followers": bool(s.show_followers) if s.show_followers is not None else True,
        "show_following": bool(s.show_following) if s.show_following is not None else True,
        "updated_at": updated_at,
    }

@app.get("/api/settings")
def api_get_settings():
    """
    根据 email 返回用户设置（防止 500，字段都给默认值）
    """
    try:
        email = (request.args.get("email") or
                 request.headers.get("X-User-Email") or "").strip().lower()
        if not email:
            return jsonify({"message": "missing_email"}), 400

        s = UserSetting.query.filter_by(email=email).first()

        if not s:
            # 没有记录就返回一份默认配置
            return jsonify({
                "email": email,
                "nickname": "",
                "avatar": "",
                "bio": "",
                "birthday": "",
                "city": "",
                "gender": "",
                "lang": "en",
                "public_profile": True,
                "show_followers": True,
                "show_following": True,
                "updated_at": None,
            })

        def g(obj, name, default=None):
            return getattr(obj, name, default)

        avatar = g(s, "avatar_url") or g(s, "avatar") or ""

        return jsonify({
            "email": s.email,
            "nickname": g(s, "nickname", "") or "",
            "avatar": avatar,
            "bio": g(s, "bio", "") or "",
            "birthday": g(s, "birthday", "") or "",
            "city": g(s, "city", "") or "",
            "gender": g(s, "gender", "") or "",
            "lang": g(s, "lang", "en") or "en",
            "public_profile": bool(g(s, "public_profile", True)),
            "show_followers": bool(g(s, "show_followers", True)),
            "show_following": bool(g(s, "show_following", True)),
            "updated_at": (
                g(s, "updated_at", None).isoformat()
                if g(s, "updated_at", None) else None
            ),
        })
    except Exception as e:
        app.logger.exception("api_get_settings failed: %s", e)
        return jsonify({"message": "server_error"}), 500

@app.put("/api/settings")
def api_put_settings():
    """
    更新用户设定：
    - email（必须）
    - nickname / bio / birthday / city / gender / lang
    - avatar / avatar_url 任选其一（可以直接存字符串，后面你有需要再接 GCS）
    - 隐私相关：public_profile / show_followers / show_following
    """
    try:
        data = request.get_json(force=True) or {}

        email = (
            data.get("email")
            or request.args.get("email")
            or request.headers.get("X-User-Email")
            or ""
        ).strip().lower()

        if not email:
            return jsonify({"message": "missing_email"}), 400

        s = UserSetting.query.filter_by(email=email).first()
        if not s:
            s = UserSetting(email=email)
            db.session.add(s)

        # 基本信息
        for field in ["nickname", "bio", "birthday", "city", "gender", "lang"]:
            if field in data:
                setattr(s, field, (data.get(field) or "").strip())

        # avatar 相关（可以先不处理 GCS，直接存）
        avatar_val = data.get("avatar_url") or data.get("avatar") or ""
        if avatar_val:
            s.avatar_url = avatar_val

        # 隐私设置（如果前端暂时没传，这里不会覆盖原值）
        for field in ["public_profile", "show_followers", "show_following"]:
            if field in data:
                setattr(s, field, bool(data.get(field)))

        s.updated_at = datetime.utcnow()

        db.session.commit()
        return jsonify(_settings_to_dict(s))

    except Exception as e:
        db.session.rollback()
        app.logger.exception("put /api/settings failed")
        return jsonify({"message": "db_error", "detail": str(e)}), 500


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

@app.route("/api/outfits/<int:outfit_id>/like", methods=["POST"])
def toggle_like(outfit_id):
    user_id = request.json.get("user_id")

    outfit = Outfit.query.get(outfit_id)
    if not outfit:
        return jsonify({"error": "Outfit not found"}), 404

    # 检查该用户是否已经点赞过
    existing = db.session.execute(
        text("SELECT 1 FROM likes WHERE outfit_id=:oid AND user_id=:uid"),
        {"oid": outfit_id, "uid": user_id}
    ).fetchone()

    if existing:
        # 取消点赞
        db.session.execute(
            text("DELETE FROM likes WHERE outfit_id=:oid AND user_id=:uid"),
            {"oid": outfit_id, "uid": user_id}
        )
        outfit.likes_count = outfit.likes_count - 1 if outfit.likes_count > 0 else 0
        db.session.commit()
        return jsonify({"liked": False, "likes_count": outfit.likes_count})

    else:
        # 新点赞
        db.session.execute(
            text("INSERT INTO likes (outfit_id, user_id) VALUES (:oid, :uid)"),
            {"oid": outfit_id, "uid": user_id}
        )
        outfit.likes_count += 1
        db.session.commit()
        return jsonify({"liked": True, "likes_count": outfit.likes_count})

@app.route("/api/outfits/<int:outfit_id>/favorite", methods=["POST"])
def toggle_favorite(outfit_id):
    user_id = request.json.get("user_id")

    outfit = Outfit.query.get(outfit_id)
    if not outfit:
        return jsonify({"error": "Outfit not found"}), 404

    existing = db.session.execute(
        text("SELECT 1 FROM favorites WHERE outfit_id=:oid AND user_id=:uid"),
        {"oid": outfit_id, "uid": user_id}
    ).fetchone()

    if existing:
        db.session.execute(
            text("DELETE FROM favorites WHERE outfit_id=:oid AND user_id=:uid"),
            {"oid": outfit_id, "uid": user_id}
        )
        outfit.favorites_count = max(outfit.favorites_count - 1, 0)
        db.session.commit()
        return jsonify({"saved": False, "favorites_count": outfit.favorites_count})

    else:
        db.session.execute(
            text("INSERT INTO favorites (outfit_id, user_id) VALUES (:oid, :uid)"),
            {"oid": outfit_id, "uid": user_id}
        )
        outfit.favorites_count += 1
        db.session.commit()
        return jsonify({"saved": True, "favorites_count": outfit.favorites_count})

@app.route("/api/outfits/<int:outfit_id>/comment", methods=["POST"])
def create_comment(outfit_id):
    user_id = request.json.get("user_id")
    content = request.json.get("content")

    outfit = Outfit.query.get(outfit_id)
    if not outfit:
        return jsonify({"error": "Outfit not found"}), 404

    db.session.execute(
        text("""
            INSERT INTO comments (outfit_id, user_id, content, created_at)
            VALUES (:oid, :uid, :content, NOW())
        """),
        {"oid": outfit_id, "uid": user_id, "content": content}
    )

    outfit.comments_count += 1
    db.session.commit()

    return jsonify({"success": True, "comments_count": outfit.comments_count})

@app.route("/api/outfits/<int:outfit_id>/share", methods=["POST"])
def share_post(outfit_id):
    outfit = Outfit.query.get(outfit_id)
    if not outfit:
        return jsonify({"error": "Outfit not found"}), 404

    outfit.shares_count += 1
    db.session.commit()

    return jsonify({"shared": True, "shares_count": outfit.shares_count})

@app.route("/api/follow", methods=["POST"])
def api_follow():
    data = request.get_json(silent=True) or {}
    follower = (data.get("follower") or "").strip().lower()
    target   = (data.get("target") or "").strip().lower()
    action   = (data.get("action") or "toggle").strip().lower()

    if not follower or not target:
        return jsonify({"ok": False, "error": "missing_email"}), 400
    if follower == target:
        # 自己不能关注自己
        return jsonify({"ok": False, "error": "self_not_allowed"}), 400

    try:
        q = UserFollow.query.filter_by(follower_email=follower, target_email=target)
        rel = q.first()

        if action in ("follow", "on"):
            if not rel:
                rel = UserFollow(follower_email=follower, target_email=target)
                db.session.add(rel)
        elif action in ("unfollow", "off"):
            if rel:
                db.session.delete(rel)
        else:  # toggle
            if rel:
                db.session.delete(rel)
                rel = None
            else:
                rel = UserFollow(follower_email=follower, target_email=target)
                db.session.add(rel)

        db.session.commit()

        followers_cnt = db.session.query(func.count(UserFollow.id))\
            .filter_by(target_email=target).scalar() or 0

        return jsonify({
            "ok": True,
            "is_following": bool(rel),
            "followers": followers_cnt,
        })
    except Exception as e:
        db.session.rollback()
        app.logger.exception("follow error: %s", e)
        return jsonify({"ok": False, "error": "server_error"}), 500

@app.route("/api/follow/stats")
def api_follow_stats():
    target = (request.args.get("email") or "").strip().lower()
    viewer = (request.args.get("viewer") or "").strip().lower()

    if not target:
        return jsonify({"ok": False, "error": "missing_email"}), 400

    followers_cnt = db.session.query(func.count(UserFollow.id))\
        .filter_by(target_email=target).scalar() or 0

    is_following = False
    if viewer:
        is_following = db.session.query(UserFollow.id)\
            .filter_by(follower_email=viewer, target_email=target)\
            .first() is not None

    return jsonify({
        "ok": True,
        "email": target,
        "followers": followers_cnt,
        "is_following": is_following,
    })

@app.route("/api/follow/mine")
def api_follow_mine():
    email = (request.args.get("email") or "").strip().lower()
    if not email:
        return jsonify({"ok": False, "error": "missing_email"}), 400

    try:
        following_cnt = db.session.query(func.count(UserFollow.id))\
            .filter_by(follower_email=email).scalar() or 0

        followers_cnt = db.session.query(func.count(UserFollow.id))\
            .filter_by(target_email=email).scalar() or 0

        return jsonify({
            "ok": True,
            "email": email,
            "following": following_cnt,
            "followers": followers_cnt,
        })
    except Exception as e:
        app.logger.exception("follow_mine error: %s", e)
        # 出错也返回 200，前端就不会黄三角
        return jsonify({
            "ok": False,
            "email": email,
            "following": 0,
            "followers": 0,
        })

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

@app.route("/api/profile/avatar", methods=["POST", "OPTIONS"])
def profile_avatar():
    if request.method == "OPTIONS":
        return _ok()

    email = (request.form.get("email") or "").strip().lower()
    if not email:
        return jsonify({"ok": False, "error": "missing_email"}), 400

    file = request.files.get("avatar")
    if not file or file.filename == "":
        return jsonify({"ok": False, "error": "missing_file"}), 400

    # 限制大小：5MB
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    if size > 5 * 1024 * 1024:
        return jsonify({"ok": False, "error": "too_large"}), 400

    # 1）上传到 GCS 的 avatars/ 目录
    url = upload_file_to_gcs(file, folder="avatars")
    if not url:
        app.logger.error("avatar upload: upload_file_to_gcs returned None, email=%s", email)
        return jsonify({"ok": False, "error": "gcs_upload_failed"}), 500

    # 2）写入 user_settings.avatar_url
    try:
        s = UserSetting.query.filter(func.lower(UserSetting.email) == email).first()
        if not s:
            s = UserSetting(email=email)
            db.session.add(s)

        s.avatar_url = url
        s.updated_at = datetime.utcnow()
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.exception("save avatar_url failed: %s", e)
        return jsonify({
            "ok": False,
            "error": "db_error",
            "detail": str(e),
        }), 500

    # 3）成功返回 GCS URL
    return jsonify({"ok": True, "url": url}), 200


# ==================== 迁移端点（按方言执行） ====================
@app.route("/api/admin/migrate", methods=["GET", "POST"])
def admin_migrate():
    try:
        db.engine.dispose()
        with db.engine.begin() as conn:
            dialect = conn.engine.dialect.name.lower()
            is_pg = "postgres" in dialect
            results = []

            def run(sql: str):
                try:
                    conn.execute(db.text(sql))
                    results.append({"sql": sql, "ok": True})
                except Exception as e:
                    results.append({"sql": sql, "ok": False, "error": str(e)})

            # 通用列兜底
            run("ALTER TABLE products ADD COLUMN IF NOT EXISTS merchant_email VARCHAR(200)")
            run("ALTER TABLE products ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active'")
            run("ALTER TABLE products ADD COLUMN IF NOT EXISTS images_json TEXT")
            run("ALTER TABLE product_images ADD COLUMN IF NOT EXISTS filename VARCHAR(255)")
            run("ALTER TABLE product_images ADD COLUMN IF NOT EXISTS mimetype VARCHAR(128)")

            # outfits 补列
            run("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS author_avatar VARCHAR(500)")
            run("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS tags VARCHAR(200)")
            run("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS location VARCHAR(200)")
            run("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS visibility VARCHAR(20) DEFAULT 'public'")
            run("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS images_json TEXT")
            run("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS videos_json TEXT")
            run("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS favorites INTEGER DEFAULT 0")
            run("ALTER TABLE outfits ADD COLUMN IF NOT EXISTS shares INTEGER DEFAULT 0")

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
                        "desc" TEXT,
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

                # user_settings + 补列
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
                run("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS nickname VARCHAR(80)")
                run("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(500)")
                run("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS birthday VARCHAR(16)")
                run("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS city VARCHAR(120)")

                # user_follows 关注关系表（Postgres）
                run("""
                    CREATE TABLE IF NOT EXISTS user_follows (
                        id SERIAL PRIMARY KEY,
                        follower_email VARCHAR(200) NOT NULL,
                        target_email   VARCHAR(200) NOT NULL,
                        created_at     TIMESTAMP DEFAULT NOW()
                    )
                """)
                run("""
                    CREATE UNIQUE INDEX IF NOT EXISTS uix_follow_pair
                    ON user_follows (follower_email, target_email)
                """)
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
                        "desc" TEXT,
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
                run("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS nickname VARCHAR(80)")
                run("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(500)")
                run("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS birthday VARCHAR(16)")
                run("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS city VARCHAR(120)")

                # user_follows（SQLite）
                run("""
                    CREATE TABLE IF NOT EXISTS user_follows (
                        id INTEGER PRIMARY KEY,
                        follower_email VARCHAR(200) NOT NULL,
                        target_email   VARCHAR(200) NOT NULL,
                        created_at     TIMESTAMP
                    )
                """)
                run("""
                    CREATE UNIQUE INDEX IF NOT EXISTS uix_follow_pair
                    ON user_follows (follower_email, target_email)
                """)
        return jsonify({"ok": True, "results": results}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)

# ------------------- Additive Outfit helpers (non-breaking) -------------------
from datetime import datetime, timezone, timedelta

@app.get("/api/outfits/by-ts/<int:ts_ms>")
def outfits_by_ts(ts_ms: int):
    """
    Resolve a local timestamp id (milliseconds) to the nearest created outfit.
    Searches within +/- 3 days around the timestamp.
    Useful when front-end used Date.now() as an id before DB insert.
    """
    try:
        # ts_ms may be seconds or milliseconds — normalize
        if ts_ms > 10_000_000_000:  # looks like milliseconds
            dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc).replace(tzinfo=None)
        else:
            dt = datetime.fromtimestamp(ts_ms, tz=timezone.utc).replace(tzinfo=None)
        lo = dt - timedelta(days=3)
        hi = dt + timedelta(days=3)
        row = (Outfit.query
               .filter(Outfit.created_at >= lo, Outfit.created_at <= hi)
               .order_by(Outfit.created_at.asc(), Outfit.id.asc())
               .first())
        if not row:
            return jsonify({"message": "Not Found"}), 404
        return jsonify({"item": _outfit_to_dict(row)})
    except Exception as e:
        return jsonify({"message": "server_error", "detail": str(e)}), 500


@app.post("/api/outfits/import_draft")
def outfits_import_draft():
    """
    Persist a local draft into DB.
    body JSON fields (all optional except author_email & images when provided):
      - title, desc, author_name, author_email
      - images: list[str]   (supports http(s), data:, blob: — saved as-is in JSON)
      - tags:   list[str] or "a,b,c"
      - location, visibility
      - created_at_ms: number (use local draft Date.now(); server will set created_at accordingly)
    """
    data = request.get_json(silent=True) or {}
    author_email = (data.get("author_email") or "").strip().lower()
    if not author_email:
        return jsonify({"message": "author_email 不能为空"}), 400

    def _as_list(v):
        if v is None or v == "":
            return []
        if isinstance(v, (list, tuple)):
            return [str(x) for x in v if x is not None]
        if isinstance(v, str):
            try:
                j = json.loads(v)
                if isinstance(j, list):
                    return [str(x) for x in j if x is not None]
            except Exception:
                pass
            return [s for s in [x.strip() for x in v.replace("，", ",").split(",")] if s]
        return []

    # Build row
    o = Outfit(
        author_email=author_email,
        author_name=(data.get("author_name") or "").strip(),
        title=(data.get("title") or "OOTD").strip(),
        desc=data.get("desc") or "",
        status="active",
        location=(data.get("location") or "").strip() or None,
        visibility=(data.get("visibility") or "public").strip() or "public",
    )

    tags = _as_list(data.get("tags"))
    if tags:
        o.tags_json = json.dumps(tags, ensure_ascii=False)

    images = _as_list(data.get("images"))
    videos = _as_list(data.get("videos"))
    if images:
        o.images_json = json.dumps(images, ensure_ascii=False)
    if videos:
        o.videos_json = json.dumps(videos, ensure_ascii=False)

    # Optional: created_at from client draft timestamp
    try:
        ts = int(data.get("created_at_ms") or data.get("draft_ts") or 0)
        if ts:
            if ts > 10_000_000_000:  # ms
                o.created_at = datetime.fromtimestamp(ts / 1000.0)
            else:
                o.created_at = datetime.fromtimestamp(ts)
    except Exception:
        pass

    db.session.add(o); db.session.commit()
    return jsonify({"id": o.id, "item": _outfit_to_dict(o)}), 201

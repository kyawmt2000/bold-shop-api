import os
import uuid
import base64
import random
import json
import logging
import re
import random, string
import hashlib
import jwt, requests
from datetime import datetime
from io import BytesIO
from sqlalchemy import text
from datetime import timedelta
from functools import wraps
from flask import request, jsonify
from sqlalchemy import func
from flask import current_app, request, jsonify

from urllib.parse import urlparse, unquote
from flask import Flask, request, jsonify, send_file, make_response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from sqlalchemy import func
from uuid import uuid4
from google.cloud import storage
from sqlalchemy import and_, or_
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import UniqueConstraint
from sqlalchemy.exc import SQLAlchemyError

from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

app = Flask(__name__)

JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is not set in environment")
JWT_ALG = "HS256"
JWT_EXPIRE_DAYS = int(os.getenv("JWT_EXPIRE_DAYS", "30"))

app.config["JWT_SECRET_KEY"] = JWT_SECRET
app.config["JWT_ALG"] = JWT_ALG

def get_token_from_request():
    # 1) Authorization: Bearer xxx
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        auth = auth[7:].strip()

    token = auth

    if not token:
        token = (request.headers.get("X-Auth-Token") or "").strip()
    if not token:
        token = (request.headers.get("X-Token") or "").strip()

    if not token:
        token = (request.args.get("token") or "").strip()

    if not token:
        data = request.get_json(silent=True) or {}
        token = (data.get("token") or "").strip()

    return token.strip().strip('"').strip("'")

"""def get_uid_from_request():
    token = get_token_from_request()
    if not token:
        #return None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])

        uid = payload.get("uid") or payload.get("user_id") or payload.get("id") or payload.get("sub")
        if uid is None:
            return None
        return int(uid)
    except Exception:
        return None"""

"""def verify_access_token(token: str):
    try:
        payload = jwt.decode(
            token,
            current_app.config["JWT_SECRET_KEY"],
            algorithms=[current_app.config.get("JWT_ALG", "HS256")]
        )
        return payload.get("uid") or payload.get("user_id") or payload.get("sub")
    except Exception as e:
        current_app.logger.warning("verify_access_token failed: %s", e)
        return None"""

def require_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        tk = get_token_from_request()
        if not tk:
            return jsonify(ok=False, error="unauthorized", message="missing token"), 401

        try:
            payload = jwt.decode(
                tk,
                current_app.config["JWT_SECRET_KEY"],
                algorithms=[current_app.config.get("JWT_ALG", "HS256")],
                options={"require": ["exp"]}  # 可选：强制必须有 exp
            )
        except jwt.ExpiredSignatureError:
            return jsonify(ok=False, error="unauthorized", message="token expired"), 401
        except Exception as e:
            current_app.logger.warning("JWT decode failed: %s", e)  # ✅ 看日志
            return jsonify(ok=False, error="unauthorized", message="invalid token"), 401

        uid = payload.get("uid") or payload.get("user_id") or payload.get("id")
        if not uid:
            return jsonify(ok=False, error="unauthorized", message="token missing uid"), 401

        u = User.query.get(int(uid))
        if not u:
            return jsonify(ok=False, error="unauthorized", message="user not found"), 401

        request.current_user = u
        return fn(*args, **kwargs)
    return wrapper

@app.route("/api/me", methods=["GET"])
@require_login
def api_me():
    u = request.current_user
    return jsonify(ok=True, user={
        "id": u.id,
        "email": u.email,
        "role": getattr(u, "role", "user"),
        "status": getattr(u, "status", "active")
    })

def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = getattr(request, "current_user", None)
        if not u:
            return jsonify(ok=False, error="unauthorized"), 401
        if getattr(u, "role", "user") != "admin":
            return jsonify(ok=False, error="forbidden"), 403
        return fn(*args, **kwargs)
    return wrapper

@app.route("/api/admin/me")
@require_admin
def admin_me():
    u = request.current_user
    return jsonify(ok=True, email=u.email, role=u.role)

def issue_session_token(user_id: int, email: str, provider: str = "apple"):
    payload = {
        "uid": int(user_id),
        "email": (email or "").lower().strip(),
        "provider": provider,
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(days=JWT_EXPIRE_DAYS)).timestamp()),
    }
    return jwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm=app.config["JWT_ALG"])

def make_token(user_id: int):
    payload = {
        "uid": int(user_id),
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(days=JWT_EXPIRE_DAYS)).timestamp())
    }
    return jwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm=app.config["JWT_ALG"])

@app.route("/api/account/delete", methods=["POST", "OPTIONS"])
@require_login
def api_delete_account():
    if request.method == "OPTIONS":
        return _cors(make_response("", 204))

    u = request.current_user
    app.logger.info("DELETE: current_user id=%s email=%s", getattr(u, "id", None), getattr(u, "email", None))
    data = request.get_json(silent=True) or {}
    confirm_email = (data.get("confirm_email") or "").strip().lower()

    email = (u.email or "").strip().lower()
    if not email:
        return _cors(jsonify({"ok": False, "error": "unauthorized"})), 401

    # ✅ 必须输入邮箱确认
    if not confirm_email:
        return _cors(jsonify({"ok": False, "error": "confirm_required"})), 400
    if confirm_email != email:
        return _cors(jsonify({"ok": False, "error": "email_not_match"})), 400

    try:
        user = request.current_user

        if getattr(user, "status", "active") == "deleted":
            return _cors(jsonify({"ok": True, "deleted": True, "email": email}))

        # ====== 删除关联数据（你原来的 safe_model_delete 全部保留） ======
        safe_model_delete(OutfitCommentLike, getattr(OutfitCommentLike, "viewer_email", None) == email)
        safe_model_delete(OutfitCommentLike, getattr(OutfitCommentLike, "user_email", None) == email)
        safe_model_delete(OutfitCommentLike, OutfitCommentLike.comment_id.in_(
            db.session.query(OutfitComment.id).filter(OutfitComment.author_email == email)
        ))
        safe_model_delete(OutfitComment, OutfitComment.author_email == email)

        safe_model_delete(OutfitLike, getattr(OutfitLike, "viewer_email", None) == email)
        safe_model_delete(OutfitLike, getattr(OutfitLike, "user_email", None) == email)
        safe_model_delete(OutfitLike, getattr(OutfitLike, "author_email", None) == email)
        safe_model_delete(OutfitLike, getattr(OutfitLike, "outfit_author_email", None) == email)

        safe_model_delete(Notification, getattr(Notification, "user_email", None) == email)
        safe_model_delete(Notification, getattr(Notification, "actor_email", None) == email)
        safe_model_delete(Notification, getattr(Notification, "from_email", None) == email)
        safe_model_delete(Notification, getattr(Notification, "sender_email", None) == email)

        safe_model_delete(Outfit, Outfit.author_email == email)

        safe_model_delete(ProductQALike, ProductQALike.user_email == email)
        safe_model_delete(ProductQA, ProductQA.user_email == email)
        safe_model_delete(ProductReview, ProductReview.user_email == email)
        safe_model_delete(Product, Product.merchant_email == email)

        safe_model_delete(MerchantApplication, MerchantApplication.email == email)
        safe_model_delete(PaymentOrder, PaymentOrder.buyer_email == email)
        safe_model_delete(UserSetting, UserSetting.email == email)

        # ✅ 不删 AuthIdentity，不然 Apple sub 又能重新绑定
        # safe_model_delete(AuthIdentity, AuthIdentity.user_id == user.id)

        # ✅ 软删 user：以后永远不能登录
        user.status = "deleted"
        user.deleted_at = datetime.utcnow()
        user.last_seen_at = datetime.utcnow()
        db.session.add(user)
        db.session.commit()

        return _cors(jsonify({"ok": True, "deleted": True, "email": email}))

    except Exception as e:
        db.session.rollback()
        app.logger.exception("DELETE ACCOUNT FAILED email=%s", email)
        return _cors(jsonify({"ok": False, "error": "delete_failed", "message": str(e)})), 500

# -----------------------------------------
#          ⭐ 正确初始化 Flask + DB ⭐
# -----------------------------------------

from flask_cors import CORS

from flask_cors import CORS
    
CORS(
    app,
    resources={r"/api/*": {"origins": [
        "https://www.boldmm.shop",
        "https://boldmm.shop"
    ]}},
    supports_credentials=False,
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-API-Key",
        "X-Auth-Token",
        "X-Token",
    ],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    max_age=86400,
)

@app.after_request
def add_cors_headers(resp):
    return _cors(resp)

# 从 Render 环境变量读取 DATABASE_URL
import os

db_url = os.getenv("DATABASE_URL")
if not db_url:
    raise RuntimeError("DATABASE_URL is not set")

# 1️⃣ Render 的 postgres:// → postgresql://
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

# 2️⃣ 强制 SSL（非常关键）
if "sslmode=" not in db_url:
    joiner = "&" if "?" in db_url else "?"
    db_url = db_url + f"{joiner}sslmode=require"

# 3️⃣ SQLAlchemy 基本配置
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# 4️⃣ 🔥 关键：防止坏的 SSL 连接被复用（解决你现在的 500）
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,   # 每次取连接先 ping，断了就重连
    "pool_recycle": 300,     # 5 分钟回收连接，避免 SSL 老化
}

db = SQLAlchemy(app)

API_KEY = os.getenv("API_KEY", "")
if not API_KEY:
    raise RuntimeError("Missing API_KEY env var")

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

def _fmt_dt(dt):
    if not dt:
        return ""
    try:
        # 统一成字符串，前端直接显示
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return str(dt)

def parse_image_urls(image_urls: str):
    """
    image_urls 可能是:
    - JSON string: '["url1","url2"]'
    - comma string: 'url1,url2'
    - single url: 'url1'
    """
    if not image_urls:
        return []

    s = str(image_urls).strip()
    if not s:
        return []

    # JSON list
    if s.startswith("[") and s.endswith("]"):
        try:
            arr = json.loads(s)
            if isinstance(arr, list):
                return [str(x).strip() for x in arr if str(x).strip()]
        except:
            pass

    # comma separated
    if "," in s:
        return [x.strip() for x in s.split(",") if x.strip()]

    # single
    return [s]


def parse_gcs_bucket_and_blob(url: str):
    """
    支持：
    - https://storage.googleapis.com/bucket/path
    - https://bucket.storage.googleapis.com/path
    - gs://bucket/path
    返回 (bucket, blob_path) or (None, None)
    """
    if not url:
        return None, None

    u = str(url).strip()
    if not u:
        return None, None

    # gs://bucket/path
    if u.startswith("gs://"):
        rest = u[5:]
        parts = rest.split("/", 1)
        if len(parts) == 2:
            return parts[0], parts[1]
        return None, None

    # https url
    try:
        p = urlparse(u)
        host = (p.netloc or "").lower()
        path = (p.path or "").lstrip("/")
        path = unquote(path)

        # https://storage.googleapis.com/bucket/path
        if host == "storage.googleapis.com":
            parts = path.split("/", 1)
            if len(parts) == 2:
                return parts[0], parts[1]
            return None, None

        # https://bucket.storage.googleapis.com/path
        m = re.match(r"^([a-z0-9.\-_]+)\.storage\.googleapis\.com$", host)
        if m:
            bucket = m.group(1)
            return bucket, path if path else None

    except:
        return None, None

    return None, None


def delete_gcs_objects_by_urls(urls):
    """
    给一组 urls，能解析出 bucket/path 的就删。
    删除失败不中断（避免一张删不了导致整体失败）。
    """
    if not urls:
        return

    client = storage.Client()

    for u in urls:
        bucket, blob_path = parse_gcs_bucket_and_blob(u)
        if not bucket or not blob_path:
            continue
        try:
            client.bucket(bucket).blob(blob_path).delete()
        except Exception:
            # 你可以在这里 print / logging
            pass

def _pair_ids(x: str, y: str):
    return (x, y) if x < y else (y, x)

def _peer_profile(uid14: str):
    try:
        s = UserSetting.query.filter_by(user_id=uid14).first()
        if s:
            return {
                "id": uid14,
                "username": (getattr(s, "nickname", None) or "User"),
                "avatar": (
                    getattr(s, "avatar_url", None)
                    or getattr(s, "avatar", None)
                    or "https://boldmm.shop/default-avatar.png"
                ),
            }
    except Exception as e:
        print("[peer_profile] lookup failed:", e)

    return {
        "id": uid14,
        "username": f"User {str(uid14)[-4:]}",
        "avatar": "https://boldmm.shop/default-avatar.png"
    }

def log_dbinfo_once():
    try:
        with app.app_context():
            r = db.session.execute(text("""
                select
                  current_database() as db,
                  inet_server_addr() as ip,
                  inet_server_port() as port,
                  version() as ver
            """)).mappings().first()
            app.logger.warning("DBINFO: %s", dict(r))
    except Exception:
        app.logger.exception("DBINFO print failed")

log_dbinfo_once()

APPLE_JWKS_URL = "https://appleid.apple.com/auth/keys"
APPLE_ISS = "https://appleid.apple.com"

def get_apple_audiences():
    # 环境变量示例：
    # APPLE_CLIENT_IDS="com.boldmm.bold,com.boldmm.web"
    raw = (os.getenv("APPLE_CLIENT_IDS") or "").strip()
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]

def verify_apple_id_token(id_token: str):
    jwks = requests.get(APPLE_JWKS_URL, timeout=8).json()
    headers = jwt.get_unverified_header(id_token)

    key = None
    for k in jwks.get("keys", []):
        if k.get("kid") == headers.get("kid"):
            key = jwt.algorithms.RSAAlgorithm.from_jwk(k)
            break
    if not key:
        raise Exception("apple_jwk_not_found")

    APPLE_AUDIENCES = [
        "com.boldmm.shop.web",  # ✅ 你日志里真实 aud
        os.getenv("APPLE_CLIENT_ID", "").strip(),  # 你环境变量（有就加）
    ]
    APPLE_AUDIENCES = [a for a in APPLE_AUDIENCES if a]

    payload = jwt.decode(
        id_token,
        key=key,
        algorithms=["RS256"],
        audience=APPLE_AUDIENCES,   # ✅ 这里改成 list
        issuer=APPLE_ISS,
        options={"verify_exp": True},
    )
    return payload

@app.route("/api/auth/apple", methods=["POST"])
def auth_apple():
    data = request.get_json(force=True) or {}
    id_token = data.get("id_token") or ""
    mode = (data.get("mode") or "login").lower().strip()   # ✅ 新增：login / signup

    if not id_token:
        return jsonify(ok=False, message="missing id_token"), 400

    try:
        p = verify_apple_id_token(id_token)
        sub = p.get("sub")
        email = (p.get("email") or "").lower().strip()

        if not sub:
            return jsonify(ok=False, message="missing sub"), 400

        ident = AuthIdentity.query.filter_by(provider="apple", provider_sub=sub).first()
        if ident:
            u = ident.user

            if getattr(u, "status", "active") == "deleted":
                if mode != "signup":
                    return jsonify(ok=False, error="account_deleted", message="account deleted"), 403
                u.status = "active"
                u.deleted_at = None
                db.session.add(u)
                db.session.commit()

            u.last_seen_at = datetime.utcnow()
            db.session.commit()

            token = issue_session_token(u.id, u.email, provider="apple")
            return jsonify(ok=True, token=token, user={"id": u.id, "email": u.email})

        u = None
        if email:
            u = User.query.filter_by(email=email).first()

        if u and getattr(u, "status", "active") == "deleted":
            if mode != "signup":
                return jsonify(ok=False, error="account_deleted", message="account deleted"), 403
            u.status = "active"
            u.deleted_at = None
            db.session.add(u)
            db.session.commit()

        if not u:
            u = User(email=email or f"apple_{sub}@noemail.local")
            db.session.add(u)
            db.session.flush()

        ident = AuthIdentity(provider="apple", provider_sub=sub, email=email or None, user_id=u.id)
        db.session.add(ident)
        db.session.commit()

        token = issue_session_token(u.id, u.email, provider="apple")
        return jsonify(ok=True, token=token, user={"id": u.id, "email": u.email})

    except Exception as e:
        return jsonify(ok=False, message=str(e)), 400

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
    is_pinned = db.Column(db.Boolean, default=False, nullable=False)
    pinned_at = db.Column(db.DateTime, nullable=True)
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
    quantity = db.Column(db.Integer, nullable=False, default=0)
    status  = db.Column(db.String(20), default="active")

class ProductReview(db.Model):
    __tablename__ = "product_reviews"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, nullable=False, index=True)
    user_email = db.Column(db.String(255), nullable=False)
    user_name = db.Column(db.String(255))
    rating = db.Column(db.Integer)
    content = db.Column(db.Text, nullable=False)
    parent_id = db.Column(db.Integer, nullable=True)
    images = db.Column(JSONB, nullable=False, default=list, server_default='[]')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ProductQA(db.Model):
    __tablename__ = "product_qas"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, nullable=False, index=True)
    user_email = db.Column(db.String(255), nullable=False)
    user_name = db.Column(db.String(255))
    content = db.Column(db.Text, nullable=False)
    parent_id = db.Column(db.Integer, nullable=True)
    images = db.Column(JSONB, nullable=False, default=list, server_default='[]')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


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
    
    is_pinned = db.Column(db.Boolean, default=False, nullable=False)
    pinned_at = db.Column(db.DateTime, nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    author_email = db.Column(db.String(200), index=True, nullable=False)
    author_name  = db.Column(db.String(200))
    author_avatar = db.Column(db.String(500))
    title        = db.Column(db.String(200), default="OOTD")
    desc         = db.Column(db.Text)
    tags_json    = db.Column(db.Text)  
    likes        = db.Column(db.Integer, default=0)
    comments     = db.Column(db.Integer, default=0)
    favorites    = db.Column(db.Integer, default=0)
    shares       = db.Column(db.Integer, default=0)
    status       = db.Column(db.String(20), default="active")
    tag_products_json = db.Column(db.Text, nullable=True)

    tags       = db.Column(db.String(200))              
    location   = db.Column(db.String(200))
    visibility = db.Column(db.String(20), default="public")  
    images_json = db.Column(db.Text)                    
    videos_json = db.Column(db.Text)                    

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    status = db.Column(db.String(20), default="active", index=True)
    deleted_at = db.Column(db.DateTime)

    role = db.Column(db.String(20), default="user") 

class AuthIdentity(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    provider = db.Column(db.String(20), nullable=False)     # "apple" / "google"
    provider_sub = db.Column(db.String(255), nullable=False) # Apple/Google 的用户唯一ID(sub)

    email = db.Column(db.String(120), index=True)           # 可能为空/可能是 relay
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    user = db.relationship("User", backref=db.backref("identities", lazy=True))

    __table_args__ = (
        db.UniqueConstraint("provider", "provider_sub", name="uq_provider_sub"),
    )


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

    user_id = db.Column(db.String(14), unique=True, index=True, nullable=True)

    # Profile fields
    nickname = db.Column(db.String(80))               # 用户昵称
    avatar_url = db.Column(db.String(500))            # 头像 URL
    cover_url  = db.Column(db.String(500))
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

from datetime import datetime
from sqlalchemy import func

class OutfitLike(db.Model):
    __tablename__ = "outfit_likes"
    id = db.Column(db.Integer, primary_key=True)
    outfit_id = db.Column(db.Integer, nullable=False, index=True)
    viewer_email = db.Column(db.String(255), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("outfit_id", "viewer_email", name="uq_outfit_like"),
    )

class OutfitComment(db.Model):
    __tablename__ = "outfit_comments"
    id = db.Column(db.Integer, primary_key=True)
    outfit_id = db.Column(db.Integer, nullable=False, index=True)

    author_email = db.Column(db.String(255), nullable=False, index=True)
    author_name  = db.Column(db.String(255), nullable=False, default="User")
    author_avatar = db.Column(db.Text, nullable=True)

    text = db.Column(db.Text, nullable=False)
    images_json = db.Column(db.Text, nullable=True)  # 存 ["url1","url2"...] 的 JSON

    # ✅ 回复：parent_id 指向被回复的评论 id（顶级评论为 None）
    parent_id = db.Column(db.Integer, nullable=True, index=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

# 例子：Outfit 评论点赞表
class OutfitCommentLike(db.Model):
    __tablename__ = "outfit_comment_likes"

    id = db.Column(db.Integer, primary_key=True)
    outfit_id = db.Column(db.Integer, nullable=False)
    comment_id = db.Column(db.Integer, nullable=False, index=True)
    user_email = db.Column(db.String(255), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("comment_id", "user_email", name="uq_comment_like"),
    )

class ProductQALike(db.Model):
    __tablename__ = "product_qa_likes"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, index=True, nullable=False)
    qa_id = db.Column(db.Integer, index=True, nullable=False)
    user_email = db.Column(db.String(255), index=True, nullable=False)
    user_name = db.Column(db.String(255))   # ✅ 建议加上
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("product_id", "qa_id", "user_email", name="uq_product_qa_like"),
    )

class PaymentOrder(db.Model):
    __tablename__ = "payment_orders"

    id = db.Column(db.Integer, primary_key=True)
    order_no = db.Column(db.String(32), unique=True, nullable=False)

    # buyer
    user_id = db.Column(db.String(64), nullable=True)
    buyer_email = db.Column(db.String(255), nullable=False, index=True)
    buyer_nickname = db.Column(db.String(120), nullable=True)
    buyer_phone = db.Column(db.String(50), nullable=True)

    # items (包含分类/尺码/颜色/卖家信息等)
    items = db.Column(db.JSON, nullable=False, default=list)

    subtotal = db.Column(db.Integer, nullable=False, default=0)
    tax = db.Column(db.Integer, nullable=False, default=0)
    shipping = db.Column(db.Integer, nullable=False, default=0)
    total = db.Column(db.Integer, nullable=False, default=0)

    # status
    status = db.Column(db.String(32), nullable=False, default="pending")  # pending / confirmed
    paid_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    confirmed_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class ChatThread(db.Model):
    __tablename__ = "chat_threads"
    id = db.Column(db.Integer, primary_key=True)
    a_id = db.Column(db.String(20), nullable=False, index=True)  # 14位
    b_id = db.Column(db.String(20), nullable=False, index=True)  # 14位
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        db.UniqueConstraint("a_id", "b_id", name="uq_chat_pair"),
    )

class ChatMessage(db.Model):
    __tablename__ = "chat_messages"
    id = db.Column(db.Integer, primary_key=True)
    thread_id = db.Column(db.Integer, db.ForeignKey("chat_threads.id"), nullable=False, index=True)
    sender_id = db.Column(db.String(20), nullable=False, index=True)
    type = db.Column(db.String(16), default="text")  # text/image/video/product/order
    text = db.Column(db.Text)
    url = db.Column(db.Text)     # image/video url（后面你可以接 GCS）
    payload_json = db.Column(db.Text)  # product/order 等结构 json
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

# -------------------- 初始化：按方言兜底建表 --------------------
with app.app_context():
    db.create_all()


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

def ensure_outfit_comment_tables():
    try:
        with db.engine.begin() as conn:
            # comments
            conn.execute(db.text("""
                CREATE TABLE IF NOT EXISTS outfit_comments (
                    id SERIAL PRIMARY KEY,
                    outfit_id INTEGER NOT NULL,
                    author_email VARCHAR(255) NOT NULL,
                    author_name VARCHAR(255) NOT NULL,
                    author_avatar TEXT,
                    text TEXT NOT NULL,
                    images_json TEXT,
                    parent_id INTEGER,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """))

            conn.execute(db.text("""
                ALTER TABLE outfit_comments
                ADD COLUMN IF NOT EXISTS parent_id INTEGER
            """))

            conn.execute(db.text("""
                ALTER TABLE outfit_comments
                ADD COLUMN IF NOT EXISTS images_json TEXT
            """))

            # comment likes（统一 user_email）
            conn.execute(db.text("""
                CREATE TABLE IF NOT EXISTS outfit_comment_likes (
                    id SERIAL PRIMARY KEY,
                    outfit_id INTEGER NOT NULL,
                    comment_id INTEGER NOT NULL,
                    user_email VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """))

            conn.execute(db.text("""
                CREATE UNIQUE INDEX IF NOT EXISTS uq_comment_like
                ON outfit_comment_likes (comment_id, user_email)
            """))
    except Exception as e:
        app.logger.exception("ensure_outfit_comment_tables failed: %s", e)

with app.app_context():
    ensure_outfit_comment_tables()

def ensure_outfit_comment_likes_columns():
    try:
        with db.engine.begin() as conn:
            conn.execute(db.text("""
                ALTER TABLE outfit_comment_likes
                ADD COLUMN IF NOT EXISTS outfit_id INTEGER
            """))
            conn.execute(db.text("""
                ALTER TABLE outfit_comment_likes
                ADD COLUMN IF NOT EXISTS user_email VARCHAR(255)
            """))
            conn.execute(db.text("""
                ALTER TABLE outfit_comment_likes
                ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()
            """))

            # 重新确保唯一索引存在（不重复建）
            conn.execute(db.text("""
                CREATE UNIQUE INDEX IF NOT EXISTS uq_comment_like
                ON outfit_comment_likes (comment_id, user_email)
            """))
    except Exception as e:
        app.logger.exception("ensure_outfit_comment_likes_columns failed: %s", e)

with app.app_context():
    ensure_outfit_comment_likes_columns()

def ensure_outfit_like_comment_tables_fix():
    try:
        with db.engine.begin() as conn:
            # 1) outfit_comments 补 author_avatar
            conn.execute(db.text("""
                ALTER TABLE outfit_comments
                ADD COLUMN IF NOT EXISTS author_avatar TEXT
            """))

            # 2) 确保 outfit_likes 存在（给 toggle like 用）
            conn.execute(db.text("""
                CREATE TABLE IF NOT EXISTS outfit_likes (
                    id SERIAL PRIMARY KEY,
                    outfit_id INTEGER NOT NULL,
                    viewer_email VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """))
            conn.execute(db.text("""
                CREATE UNIQUE INDEX IF NOT EXISTS uq_outfit_like
                ON outfit_likes (outfit_id, viewer_email)
            """))
    except Exception as e:
        app.logger.exception("ensure_outfit_like_comment_tables_fix failed: %s", e)

with app.app_context():
    ensure_outfit_like_comment_tables_fix()

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

    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"

    # ✅ 关键：浏览器预检要什么 header，就放行什么 header（最稳）
    req_hdrs = request.headers.get("Access-Control-Request-Headers", "")
    resp.headers["Access-Control-Allow-Headers"] = req_hdrs or "Content-Type, X-API-Key"

    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
    resp.headers["Access-Control-Max-Age"] = "86400"

    # ✅ 如果你前端会带 cookie/credential，就加；不带也不影响
    resp.headers["Access-Control-Allow-Credentials"] = "true"
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

    # created_at
    try:
        created_at = p.created_at.isoformat() if getattr(p, "created_at", None) else None
    except Exception:
        created_at = None

    # images
    urls = []
    imgs = []  # ✅ 先定义，避免 images_json 有数据时 imgs 未定义

    imgs_from_product = _safe_json_loads(getattr(p, "images_json", None), [])
    if imgs_from_product:
        urls = [u for u in imgs_from_product if isinstance(u, str) and u]
    else:
        try:
            imgs = ProductImage.query.filter_by(product_id=p.id).all()
        except Exception:
            imgs = []

        base = (r.url_root or "").rstrip("/")
        for im in imgs:
            try:
                if im.filename and isinstance(im.filename, str) and im.filename.startswith("http"):
                    urls.append(im.filename)  # GCS URL
                else:
                    urls.append(f"{base}/api/products/{p.id}/image/{im.id}")  # 老接口
            except Exception:
                continue

    # ✅ 去重（保持顺序）
    seen = set()
    urls = [u for u in urls if (u not in seen and not seen.add(u))]

    # variants
    try:
        variants = ProductVariant.query.filter_by(product_id=p.id).all()
    except Exception:
        variants = []

    return {
        "id": p.id,
        "created_at": created_at,
        "is_pinned": bool(getattr(p, "is_pinned", False)),
        "pinned_at": p.pinned_at.isoformat() if getattr(p, "pinned_at", None) else None,
        "merchant_email": getattr(p, "merchant_email", "") or "",
        "title": p.title,
        "price": p.price,
        "gender": p.gender,
        "category": p.category,
        "desc": p.desc,
        "sizes": _safe_json_loads(getattr(p, "sizes_json", None), []),
        "colors": _safe_json_loads(getattr(p, "colors_json", None), []),
        "images": urls,
        "quantity": int(getattr(p, "quantity", 0) or 0),
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
                tags = [str(x) for x in t if x]
    except Exception:
        tags = []

    # ---------- images / videos ----------
    images = []
    videos = []

    # 1) 新字段 images_json / videos_json
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

    # 2) 旧字段 media_json 兜底
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

    # ---------- ✅ 作者信息补齐（关键：让 outfit.html 能搜用户名） ----------
    author_email = (getattr(o, "author_email", None) or "").strip().lower()
    author_name = (getattr(o, "author_name", None) or "").strip()
    author_avatar = (getattr(o, "author_avatar", None) or "").strip()
    author_id = ""

    try:
        if author_email:
            us = UserSetting.query.filter_by(email=author_email).first()
            if us:
                if not author_name:
                    author_name = (us.nickname or "").strip()
                if not author_avatar:
                    author_avatar = (us.avatar_url or "").strip()
                author_id = str(getattr(us, "id", "") or "").strip()
    except Exception:
        pass

    if not author_name and author_email:
         author_name = author_email.split("@")[0]

   # ✅ tag_products 一定要在 if 外面（同级缩进）
    tag_products = []
    try:
        raw_tp = getattr(o, "tag_products_json", None) or "[]"
        tp = json.loads(raw_tp) if isinstance(raw_tp, str) else (raw_tp or [])
        if isinstance(tp, list):
            tag_products = [int(x) for x in tp if str(x).strip().isdigit()]
    except Exception:
        tag_products = []

    # ---------- return（只 return 一次） ----------
    return {
        "id": o.id,
        "created_at": o.created_at.isoformat() if getattr(o, "created_at", None) else None,

        "is_pinned": bool(getattr(o, "is_pinned", False)),
        "pinned_at": o.pinned_at.isoformat() if getattr(o, "pinned_at", None) else None,

        "author_email": author_email,
        "author_name": author_name,
        "author_avatar": author_avatar,
        "author_id": author_id,

        "title": getattr(o, "title", None) or "OOTD",
        "desc": getattr(o, "desc", None),

        "tags": tags,
        "images": images,
        "videos": videos,

        "likes": likes_val,
        "comments": comments_val,

        "likes_count": likes_val,
        "comments_count": comments_val,
        "favorites_count": favorites_val,
        "shares_count": shares_val,

        "tag_products": tag_products,

        "status": getattr(o, "status", "active") or "active",
        "location": getattr(o, "location", None),
        "visibility": getattr(o, "visibility", "public") or "public",
    }


import requests

def get_client_ip(req):
    """
    Render/反代环境下优先取 X-Forwarded-For
    """
    xff = (req.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    if xff:
        return xff
    xrip = (req.headers.get("X-Real-IP") or "").strip()
    if xrip:
        return xrip
    return (req.remote_addr or "").strip()

def ip_to_city(ip: str) -> str:
    """
    通过 IP 推测城市（不是真 GPS）
    你可以换成自己的服务/有 key 的服务
    """
    if not ip or ip.startswith("127.") or ip == "localhost":
        return ""
    try:
        # 例：ipapi.co 免费接口（可能有频率限制）
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2.5)
        if r.status_code != 200:
            return ""
        js = r.json() or {}
        city = (js.get("city") or "").strip()
        region = (js.get("region") or js.get("region_code") or "").strip()
        country = (js.get("country_name") or js.get("country") or "").strip()

        # 组合显示：Yangon, Yangon Region, Myanmar
        parts = [p for p in [city, region, country] if p]
        return ", ".join(parts).strip()
    except Exception:
        return ""


# --- 只在设置了 API_KEY 时才启用强校验 ---
# 只保护后台 / 调试接口，公开接口不需要 key
PROTECTED_PREFIXES = ["/api/admin", "/api/debug"]

@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        return _cors(make_response("", 204))

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

def ensure_user_settings_columns():
    try:
        with db.engine.begin() as conn:
            conn.execute(text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS user_id VARCHAR(32)"))
            conn.execute(text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS created_at TIMESTAMP"))
            conn.execute(text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS nickname VARCHAR(80)"))
            conn.execute(text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(500)"))
            conn.execute(text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS bio VARCHAR(120)"))
            conn.execute(text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS birthday VARCHAR(16)"))
            conn.execute(text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS city VARCHAR(120)"))
            conn.execute(text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS gender VARCHAR(16)"))
            conn.execute(text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS phone VARCHAR(64)"))
            conn.execute(text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS public_profile BOOLEAN DEFAULT TRUE"))
            conn.execute(text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS show_followers BOOLEAN DEFAULT TRUE"))
            conn.execute(text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS show_following BOOLEAN DEFAULT TRUE"))
            conn.execute(text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS dm_who VARCHAR(16) DEFAULT 'all'"))
            conn.execute(text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS blacklist_json TEXT"))
            conn.execute(text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS lang VARCHAR(8) DEFAULT 'en'"))
            conn.execute(text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP"))
        app.logger.info("ensure_user_settings_columns: OK")
    except Exception as e:
        app.logger.exception("ensure_user_settings_columns failed: %s", e)
        
with app.app_context():
    ensure_user_settings_columns()

def _admin_auth_ok():
    incoming = (request.headers.get("X-API-Key") or "").strip()
    admin_key = (os.getenv("ADMIN_API_KEY") or "").strip()

    # ✅ 如果你配置了 ADMIN_API_KEY，就必须用它
    if admin_key:
        return incoming == admin_key

    # ✅ 否则就用你现有的 API_KEY
    return incoming == API_KEY

def _get_tag_products(outfit_id: int):
    try:
        raw = db.session.execute(
            text("SELECT tag_products_json FROM outfits WHERE id=:id"),
            {"id": outfit_id}
        ).scalar()
        if not raw:
            return []
        if isinstance(raw, (list, tuple)):
            return [int(x) for x in raw if str(x).isdigit()]
        arr = json.loads(raw)
        if isinstance(arr, list):
            return [int(x) for x in arr if str(x).isdigit()]
        return []
    except Exception:
        return []

@app.get("/api/admin/users")
@require_login
@require_admin
def admin_users_list():
    try:
        sql = text("""
            WITH all_emails AS (
              SELECT lower(email) AS email, created_at FROM users
              UNION
              SELECT lower(email) AS email, NULL AS created_at FROM user_settings
            )
            SELECT
              e.email,
              u.created_at            AS created_at,
              u.last_seen_at          AS last_seen_at,
              s.user_id               AS user_id,
              s.nickname              AS nickname,
              s.avatar_url            AS avatar_url,
              s.gender                AS gender,
              s.birthday              AS birthday,
              s.city                  AS city,
              s.updated_at            AS settings_updated_at
            FROM all_emails e
            LEFT JOIN users u
              ON lower(u.email) = e.email
            LEFT JOIN user_settings s
              ON lower(s.email) = e.email
            ORDER BY COALESCE(u.created_at, s.updated_at) DESC
            LIMIT 5000
        """)

        rows = db.session.execute(sql).mappings().all()

        return jsonify([{
            "email": r["email"] or "",
            "user_id": r.get("user_id") or "",
            "nickname": r.get("nickname") or "",
            "avatar_url": r.get("avatar_url") or "",
            "gender": r.get("gender") or "",
            "birthday": r.get("birthday") or "",
            "city": r.get("city") or "",
            "created_at": (
                r["created_at"].isoformat()
                if r.get("created_at") else ""
            ),
            "last_seen_at": (
                r["last_seen_at"].isoformat()
                if r.get("last_seen_at") else ""
            ),
            "settings_updated_at": (
                r["settings_updated_at"].isoformat()
                if r.get("settings_updated_at") else ""
            ),
        } for r in rows])

    except Exception as e:
        return jsonify({"message": "server_error", "detail": str(e)}), 500
        
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

@app.route("/api/products", methods=["GET", "OPTIONS"], strict_slashes=False)
def products_list():
    if request.method == "OPTIONS":
        return _cors(make_response("", 204))

    try:
        email = (request.args.get("merchant_email") or "").strip().lower()
        q = Product.query.filter_by(status="active")
        if email:
            q = q.filter_by(merchant_email=email)

        rows = q.order_by(
            Product.is_pinned.desc(),
            Product.pinned_at.desc().nullslast(),
            Product.id.desc()
        ).all()

        items = []
        for r in rows:
            try:
                items.append(_product_to_dict(r))
            except Exception as e:
                app.logger.exception("product_to_dict failed id=%s: %s", getattr(r, "id", None), e)
                # 跳过坏数据，不让整页 500
                continue

        resp = jsonify(items)   # 仍然保持你前端兼容：返回数组
        return _cors(resp)

    except Exception as e:
        resp = jsonify({"message":"server_error", "detail": str(e)})
        return _cors(resp), 500

@app.get("/api/products/<int:pid>")
def products_get_one(pid):
    row = Product.query.get_or_404(pid)

    # ✅ 软删商品：详情接口直接当不存在
    if (getattr(row, "status", "") or "") != "active":
        return jsonify({"message":"not_found"}), 404

    return jsonify(_product_to_dict(row))

@app.route("/api/products/add", methods=["POST", "OPTIONS"])
def add_product():
    merchant_email = request.form.get("merchant_email", "").strip().lower()
    title = request.form.get("title", "").strip()
    gender = request.form.get("gender", "")
    category = request.form.get("category", "")
    price_raw = request.form.get("price", "0")
    desc = request.form.get("desc", "")

    sizes = request.form.get("sizes", "[]")
    colors = request.form.get("colors", "[]")

    # ✅ quantity
    quantity_raw = request.form.get("quantity", "0")

    # ------- 基础校验 -------
    if not merchant_email or not title:
        return jsonify({"ok": False, "error": "Missing merchant_email or title"}), 400

    try:
        price = int(float(price_raw or 0))
    except:
        return jsonify({"ok": False, "error": "Invalid price"}), 400

    try:
        quantity = int(float(quantity_raw or 0))
    except:
        return jsonify({"ok": False, "error": "Invalid quantity"}), 400

    if quantity < 0:
        return jsonify({"ok": False, "error": "Quantity must be >= 0"}), 400

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
        images_json=json.dumps(image_urls),
        quantity=quantity,          # ✅ 现在 quantity 已定义
        status="active"
    )

    db.session.add(p)
    db.session.commit()

    return jsonify({"ok": True, "id": p.id, "images": image_urls, "quantity": p.quantity})

# ----------- 商品评价：读取 -----------
@app.get("/api/products/<int:pid>/reviews")
def get_reviews(pid):
    try:
        rows = ProductReview.query.filter_by(product_id=pid)\
            .order_by(ProductReview.created_at.asc()).all()

        return jsonify({"items": [{
            "id": r.id,
            "product_id": r.product_id,
            "user_email": r.user_email,
            "user_name": r.user_name,
            "rating": r.rating,
            "content": r.content,
            "parent_id": r.parent_id,
            "images": r.images or [],
            "created_at": r.created_at.isoformat()
        } for r in rows]})
    except Exception as e:
        current_app.logger.exception("GET reviews failed")
        return jsonify({"items": []})

# ----------- 商品评价：新增（含回复） -----------
@app.post("/api/products/<int:pid>/reviews")
def add_review(pid):
    data = request.json or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "missing_email"}), 400

    content = (data.get("content") or "").strip()
    if not content:
        return jsonify({"error": "missing_content"}), 400

    images = data.get("images") or []
    if not isinstance(images, list):
        images = []

    r = ProductReview(
        product_id=pid,
        user_email=email,
        user_name=data.get("user_name", ""),
        rating=data.get("rating"),
        content=content,
        parent_id=data.get("parent_id"),
        images=(data.get("images") or [])      
    )
    #r.images = images                                 # ✅ 新增

    db.session.add(r)
    db.session.commit()
    return jsonify({"success": True, "id": r.id})

@app.get("/api/products/<int:pid>/qa")
def get_qa(pid):
    try:
        viewer = (request.args.get("viewer") or "").strip().lower()
        rows = ProductQA.query.filter_by(product_id=pid)\
            .order_by(ProductQA.created_at.asc()).all()

        items = []
        for q in rows:
            like_count = ProductQALike.query.filter_by(
                product_id=pid, qa_id=q.id
            ).count()

            liked = False
            if viewer:
                liked = ProductQALike.query.filter_by(
                    product_id=pid, qa_id=q.id, user_email=viewer
                ).first() is not None

            items.append({
                "id": q.id,
                "product_id": q.product_id,
                "user_email": q.user_email,
                "user_name": q.user_name,
                "content": q.content,
                "parent_id": q.parent_id,
                "images": q.images or [],
                "created_at": q.created_at.isoformat(),
                "like_count": like_count,
                "liked": liked
            })

        return jsonify({"ok": True, "items": items})
    except Exception:
        current_app.logger.exception("GET qa failed")
        return jsonify({"ok": True, "items": []})

# ----------- 商品讨论：新增（含回答） -----------
@app.post("/api/products/<int:pid>/qa")
def add_qa(pid):
    data = request.json or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "missing_email"}), 400

    content = (data.get("content") or "").strip()
    if not content:
        return jsonify({"error": "missing_content"}), 400

    images = data.get("images") or []
    if not isinstance(images, list):
        images = []

    q = ProductQA(
        product_id=pid,
        user_email=email,
        user_name=data.get("user_name", ""),
        content=content,
        parent_id=data.get("parent_id"),
        images=(data.get("images") or [])      # ✅ 新增
    )
    #q.images = images                                 # ✅ 新增

    db.session.add(q)
    db.session.commit()
    return jsonify({"success": True, "id": q.id})

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

    # 1) 先删 GCS
    url = (getattr(row, "url", None) or getattr(row, "image_url", None) or "").strip()
    if url:
        try:
            delete_gcs_objects_by_urls([url])   # 复用你已有的函数
        except Exception as e:
            app.logger.warning("delete product image gcs failed: %s", e)

    # 2) 再删 DB
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
        return jsonify({"message": "forbidden"}), 403

    if hard:
        # 0) 先收集所有图片 url
        imgs = ProductImage.query.filter_by(product_id=pid).all()
        urls = []
        for r in imgs:
            u = (getattr(r, "url", None) or getattr(r, "image_url", None) or "").strip()
            if u:
                urls.append(u)

        # 1) 删 GCS
        if urls:
            try:
                delete_gcs_objects_by_urls(urls)
            except Exception as e:
                app.logger.warning("delete product gcs failed: %s", e)

        # 2) 再删 DB 关联表
        ProductImage.query.filter_by(product_id=pid).delete(synchronize_session=False)
        ProductVariant.query.filter_by(product_id=pid).delete(synchronize_session=False)

        # 3) 删商品
        db.session.delete(row)
        db.session.commit()
        return jsonify({"ok": True, "id": pid, "deleted": "hard"})

    # 软删除（不 hard 的情况）
    row.status = "deleted"
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

                # 关联商品：前端传 JSON 字符串，例如 "[12,33]"
        raw_tp = (f.get("tag_products") or "").strip()
        tp_list = []
        if raw_tp:
            try:
                tp = json.loads(raw_tp)
                if isinstance(tp, list):
                    tp_list = [int(x) for x in tp if str(x).strip().isdigit()]
            except Exception:
                tp_list = []

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
            tag_products_json=json.dumps(tp_list, ensure_ascii=False)
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
    if (row.status or "") != "active":
        return jsonify({"message":"not_found"}), 404
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

def gcs_delete_by_url(url):
    # 支持 https://storage.googleapis.com/<bucket>/<path>
    # 或 https://<bucket>.storage.googleapis.com/<path>
    # 或 gs://<bucket>/<path>
    bucket, blob_path = parse_bucket_and_path(url)
    if not bucket or not blob_path:
        return
    storage.Client().bucket(bucket).blob(blob_path).delete()

@app.delete("/api/outfits/<int:oid>")
def api_delete_outfit(oid):
    data = request.get_json(silent=True) or {}
    author_email = (data.get("author_email") or "").strip().lower()
    if not author_email:
        return jsonify({"ok": False, "message": "author_email required"}), 400

    o = Outfit.query.get_or_404(oid)
    if (o.author_email or "").strip().lower() != author_email:
        return jsonify({"ok": False, "message": "not_owner"}), 403

    try:
        # 1) 删 GCS 文件（来自 image_urls）
        urls = []
        if getattr(o, "image_urls", None):
            urls = parse_image_urls(o.image_urls)   # 你用我上次给你的那个 parse_image_urls
        elif getattr(o, "image_url", None):
            urls = [o.image_url]

        delete_gcs_objects_by_urls(urls)            # 你用我上次给你的 delete_gcs_objects_by_urls

        # 2) 删关联表，避免外键错误
        OutfitMedia.query.filter_by(outfit_id=oid).delete(synchronize_session=False)
        Notification.query.filter_by(outfit_id=oid).delete(synchronize_session=False)

        # 3) 删帖子本身（推荐软删）
        if hasattr(o, "status"):
            o.status = "deleted"
            db.session.commit()
            return jsonify({"ok": True, "deleted_id": oid, "mode": "soft"})
        else:
            db.session.delete(o)
            db.session.commit()
            return jsonify({"ok": True, "deleted_id": oid, "mode": "hard"})

    except Exception as e:
        db.session.rollback()
        app.logger.exception("delete outfit %s failed: %s", oid, e)
        return jsonify({"ok": False, "error": "delete_failed", "detail": str(e)}), 500

# ==================== New Feed API (Unified) ====================
@app.get("/api/outfits/feed")
@app.get("/api/outfit/feed2")
def api_outfits_feed_list():
    try:
        limit = min(200, int(request.args.get("limit") or 50))
    except Exception:
        limit = 50

    q = Outfit.query.filter_by(status="active")

    try:
        rows = q.order_by(
            Outfit.is_pinned.desc(),
            Outfit.pinned_at.desc(),
            Outfit.created_at.desc()
        ).limit(limit).all()

    except Exception as e:
        app.logger.exception("feed pinned order failed: %s", e)
        try:
            db.session.rollback()
        except Exception:
            pass

        # ✅ fallback：不要再引用 is_pinned/pinned_at（否则会继续 500）
        rows = q.order_by(Outfit.created_at.desc(), Outfit.id.desc()).limit(limit).all()

    items = []
    for o in rows:
        try:
            items.append(_outfit_to_dict(o))
        except Exception as e:
            app.logger.exception("outfit_to_dict failed id=%s: %s", getattr(o, "id", None), e)

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
    q = Outfit.query.filter_by(status="active")

    if qstr:
        like = f"%{qstr}%"
        q = q.filter(
            db.or_(
                Outfit.title.ilike(like),
                Outfit.desc.ilike(like),
                Outfit.tags_json.ilike(like),
            )
        )

    rows = q.order_by(
        Outfit.is_pinned.desc(),
        Outfit.pinned_at.desc(),
        Outfit.created_at.desc()
    ).limit(limit).all()
    items = [_outfit_to_dict(o) for o in rows]
    return jsonify({"items": items, "has_more": False})
  
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

# ===========================
#  新版：获取用户设定
# ===========================
def _gen_user_id_ddmmyy():
    # 4位随机 + DDMMYY + 4位随机  => 共14位
    ddmmyy = datetime.utcnow().strftime("%d%m%y")
    left   = f"{random.randint(0, 9999):04d}"
    right  = f"{random.randint(0, 9999):04d}"
    return f"{left}{ddmmyy}{right}"

def _ensure_user_id(s):
    """
    给 UserSetting 补上 user_id（只在为空时生成一次）
    并保证尽可能唯一（有碰撞就重试）
    """
    if getattr(s, "user_id", None):
        return s.user_id

    # 如果模型还没加字段，直接跳过（防止你还没迁移就报错）
    if not hasattr(s, "user_id"):
        return ""

    for _ in range(30):
        uid = _gen_user_id_ddmmyy()
        exists = UserSetting.query.filter_by(user_id=uid).first()
        if not exists:
            s.user_id = uid
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.exception("ensure_user_id commit fail: %s", e)
                return ""
            return uid

    # 极低概率到这里：还是给一个，但不强求唯一（避免卡死）
    uid = _gen_user_id_ddmmyy()
    s.user_id = uid
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return ""
    return uid


@app.get("/api/settings")
def api_get_settings():
    """
    根据 email 返回用户设置：
    - 找不到记录：✅ 现在会自动创建一条（保证 user_id 永久固定）
    - avatar 使用 avatar_url 字段（如果有）
    - 新增 phone 字段（如果模型有该字段则读取）
    - ✅ 新增 user_id：4随机 + DDMMYY + 4随机，创建后永不改变
    """
    def default_payload(email: str):
        return {
            "email": email,
            "user_id": "",              # ✅ 默认也带上
            "nickname": "",
            "avatar": "",
            "avatar_url": s.avatar_url,
            "cover_url": "",
            "bio": "",
            "birthday": "",
            "city": "",
            "gender": "",
            "phone": "",
            "lang": "en",
            "public_profile": True,
            "show_followers": True,
            "show_following": True,
            "updated_at": None,
        }

    # 1) 取 email
    email = (
        request.args.get("email")
        or request.headers.get("X-User-Email")
        or ""
    ).strip().lower()

    if not email:
        return jsonify({"message": "missing_email"}), 400

    # 2) 查数据库（出错时也不要 500）
    try:
        s = UserSetting.query.filter(
            func.lower(UserSetting.email) == email
        ).first()
    except Exception as e:
        current_app.logger.exception("GET /api/settings DB error: %s", e)
        return jsonify(default_payload(email)), 200

    # 3) 没有记录 → ✅ 创建记录（这样 user_id 才能“开账号后固定”）
    if not s:
        try:
            s = UserSetting(email=email)
            db.session.add(s)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.exception("GET /api/settings create row error: %s", e)
            return jsonify(default_payload(email)), 200

    # ✅ 3.5) 确保 user_id 生成并持久化（只生成一次）
    try:
        uid = _ensure_user_id(s)
    except Exception as e:
        current_app.logger.exception("GET /api/settings ensure user_id error: %s", e)
        uid = ""

        # ✅ 3.6) 自动写入 city（仅当数据库 city 为空时）
    try:
        cur_city = (getattr(s, "city", "") or "").strip()
        if not cur_city:
            ip = get_client_ip(request)
            geo_city = ip_to_city(ip)
            if geo_city:
                s.city = geo_city
                s.updated_at = datetime.utcnow()
                db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("GET /api/settings auto city failed: %s", e)

    # 4) 组装返回（尽量兼容之前结构）
    try:
        try:
            data = _settings_to_dict(s)
        except Exception:
            data = {}

        data["email"] = email

        # ✅ user_id 永久返回
        data["user_id"] = uid or getattr(s, "user_id", "") or data.get("user_id", "") or ""

        # avatar：优先用 avatar_url / avatar
        avatar_val = (
            getattr(s, "avatar_url", None)
            or getattr(s, "avatar", None)
            or data.get("avatar")
            or ""
        )
        data["avatar"] = avatar_val

        # 基本字段兜底
        data.setdefault("nickname", getattr(s, "nickname", "") or "")
        data.setdefault("bio", getattr(s, "bio", "") or "")
        data.setdefault("birthday", getattr(s, "birthday", "") or "")
        data.setdefault("city", getattr(s, "city", "") or "")
        data.setdefault("gender", getattr(s, "gender", "") or "")
        data.setdefault("lang", getattr(s, "lang", "en") or "en")
        data.setdefault("public_profile", bool(getattr(s, "public_profile", True)))
        data.setdefault("show_followers", bool(getattr(s, "show_followers", True)))
        data.setdefault("show_following", bool(getattr(s, "show_following", True)))

        # phone（如果模型有这个字段）
        if hasattr(s, "phone"):
            data["phone"] = getattr(s, "phone", "") or ""
        else:
            data.setdefault("phone", "")

        data["updated_at"] = getattr(s, "updated_at", None)

        return jsonify(data), 200

    except Exception as e:
        current_app.logger.exception("GET /api/settings serialize error: %s", e)
        payload = default_payload(email)
        payload["user_id"] = uid or ""
        return jsonify({"ok": True, **payload}), 200

@app.get("/api/follow/following")
def api_follow_following_list():
    """
    我关注的人列表
    GET /api/follow/following?email=me@example.com
    """
    email = (request.args.get("email") or "").strip().lower()
    if not email:
        return jsonify({"ok": False, "message": "missing_email"}), 400

    try:
        # 我关注的人（target）
        rows = (db.session.query(UserFollow.target_email)
                .filter(UserFollow.follower_email == email)
                .order_by(UserFollow.id.desc())
                .limit(500)
                .all())
        targets = [r[0] for r in rows if r and r[0]]

        # 尝试补充头像/昵称（如果你有 UserSetting 表）
        items = []
        if "UserSetting" in globals():
            settings = UserSetting.query.filter(UserSetting.email.in_(targets)).all()
            m = {s.email.lower(): s for s in settings}
            for em in targets:
                s = m.get(em.lower())
                avatar = ""
                nick = ""
                if s:
                    nick = (getattr(s, "nickname", "") or "")
                    avatar = (getattr(s, "avatar_url", "") or getattr(s, "avatar", "") or "")
                items.append({"email": em, "nickname": nick, "avatar": avatar})
        else:
            items = [{"email": em, "nickname": "", "avatar": ""} for em in targets]

        return jsonify({"ok": True, "items": items})
    except Exception as e:
        app.logger.exception("api_follow_following_list error: %s", e)
        return jsonify({"ok": False, "message": "server_error", "detail": str(e)}), 500


@app.get("/api/follow/followers")
def api_follow_followers_list():
    """
    关注我的人列表
    GET /api/follow/followers?email=me@example.com
    """
    email = (request.args.get("email") or "").strip().lower()
    if not email:
        return jsonify({"ok": False, "message": "missing_email"}), 400

    try:
        # 关注我的人（follower）
        rows = (db.session.query(UserFollow.follower_email)
                .filter(UserFollow.target_email == email)
                .order_by(UserFollow.id.desc())
                .limit(500)
                .all())
        followers = [r[0] for r in rows if r and r[0]]

        items = []
        if "UserSetting" in globals():
            settings = UserSetting.query.filter(UserSetting.email.in_(followers)).all()
            m = {s.email.lower(): s for s in settings}
            for em in followers:
                s = m.get(em.lower())
                avatar = ""
                nick = ""
                if s:
                    nick = (getattr(s, "nickname", "") or "")
                    avatar = (getattr(s, "avatar_url", "") or getattr(s, "avatar", "") or "")
                items.append({"email": em, "nickname": nick, "avatar": avatar})
        else:
            items = [{"email": em, "nickname": "", "avatar": ""} for em in followers]

        return jsonify({"ok": True, "items": items})
    except Exception as e:
        app.logger.exception("api_follow_followers_list error: %s", e)
        return jsonify({"ok": False, "message": "server_error", "detail": str(e)}), 500

# ===========================
#  新版：保存用户设定
# ===========================
@app.post("/api/settings")
def api_post_settings():
    """
    保存 / 更新用户设定（配合 setting.html 使用）：

    Body JSON:
    {
      "email": "xxx@gmail.com",   # 必填
      "nickname": "...",
      "bio": "...",
      "gender": "male|female|other|''",
      "birthday": "YYYY-MM-DD",
      "phone": "...",
      "avatar": "https://gcs-url...",  # 头像 URL（由 /api/profile/avatar 返回）
      // 以下可选：
      "city": "...",
      "lang": "en|zh|...",
      "public_profile": true/false,
      "show_followers": true/false,
      "show_following": true/false
    }
    """
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"message": "invalid_json"}), 400

    # 1) email
    email = (
        data.get("email")
        or request.args.get("email")
        or request.headers.get("X-User-Email")
        or ""
    ).strip().lower()

    if not email:
        return jsonify({"message": "missing_email"}), 400

    # ✅ 确保 users 表一定有这个账号（没有就创建）
    _touch_user(email)

    try:
        # 2) 找 / 建记录（不区分大小写）
        s = UserSetting.query.filter(
            func.lower(UserSetting.email) == email
        ).first()
        if not s:
            s = UserSetting(email=email)
            db.session.add(s)

        # 3) 基本信息（去掉前后空格）
        for field in ["nickname", "bio", "birthday", "city", "gender", "lang"]:
            if field in data:
                value = (data.get(field) or "").strip()
                setattr(s, field, value)

        # 4) phone 字段（如果模型有）
        if "phone" in data and hasattr(s, "phone"):
            s.phone = (data.get("phone") or "").strip()

        # 5) avatar URL（由前端 /api/profile/avatar 上传后返回的 url）
        avatar_val = data.get("avatar") or data.get("avatar_url") or ""
        if avatar_val:
            if hasattr(s, "avatar_url"):
                s.avatar_url = avatar_val
            else:
                # 某些旧表可能直接叫 avatar
                if hasattr(s, "avatar"):
                    s.avatar = avatar_val

        # 6) 隐私相关（如果前端没传就不改原来的）
        def to_bool(v):
            if isinstance(v, bool):
                return v
            if isinstance(v, str):
                return v.strip().lower() in ("1", "true", "yes", "on")
            if isinstance(v, (int, float)):
                return bool(v)
            return False

        for field in ["public_profile", "show_followers", "show_following"]:
            if field in data:
                setattr(s, field, to_bool(data.get(field)))

        # 7) 更新时间
        s.updated_at = datetime.utcnow()

        db.session.commit()

        # 8) 返回最新设置（结构跟 GET 一样）
        try:
            resp = _settings_to_dict(s)
        except Exception:
            resp = {}

        resp["email"] = email

        avatar_val = (
            getattr(s, "avatar_url", None)
            or getattr(s, "avatar", None)
            or resp.get("avatar")
            or ""
        )
        resp["avatar"] = avatar_val
        resp["nickname"] = getattr(s, "nickname", "") or ""
        resp["bio"] = getattr(s, "bio", "") or ""
        resp["birthday"] = getattr(s, "birthday", "") or ""
        resp["city"] = getattr(s, "city", "") or ""
        resp["gender"] = getattr(s, "gender", "") or ""
        resp["lang"] = getattr(s, "lang", "en") or "en"
        resp["public_profile"] = bool(getattr(s, "public_profile", True))
        resp["show_followers"] = bool(getattr(s, "show_followers", True))
        resp["show_following"] = bool(getattr(s, "show_following", True))
        if hasattr(s, "phone"):
            resp["phone"] = getattr(s, "phone", "") or ""
        else:
            resp.setdefault("phone", "")
        resp["updated_at"] = getattr(s, "updated_at", None)

        return jsonify(resp), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("POST /api/settings failed: %s", e)
        return jsonify({"message": "db_error", "detail": str(e)}), 500

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

from datetime import datetime

@app.get("/api/debug/comments_tables")
def debug_comments_tables():
    try:
        with db.engine.connect() as conn:
            # 适配 Postgres / SQLite
            dialect = conn.engine.dialect.name.lower()
            if "postgres" in dialect:
                q = db.text("""
                    SELECT table_name
                    FROM information_schema.tables
                    WHERE table_schema='public'
                    AND table_name IN ('outfit_comments','outfit_comment_likes')
                    ORDER BY table_name
                """)
                rows = conn.execute(q).fetchall()
                tables = [r[0] for r in rows]
            else:
                q = db.text("""
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name IN ('outfit_comments','outfit_comment_likes')
                    ORDER BY name
                """)
                rows = conn.execute(q).fetchall()
                tables = [r[0] for r in rows]

            # 顺便查数量（如果表存在）
            counts = {}
            for t in ("outfit_comments", "outfit_comment_likes"):
                if t in tables:
                    counts[t] = conn.execute(db.text(f"SELECT COUNT(*) FROM {t}")).scalar()

            return jsonify({"ok": True, "dialect": dialect, "tables": tables, "counts": counts})
    except Exception as e:
        return jsonify({"ok": False, "detail": str(e), "type": e.__class__.__name__}), 500

@app.get("/api/outfits/<int:outfit_id>/stats")
def api_outfit_stats(outfit_id):
    viewer = (request.args.get("viewer") or "").strip().lower()

    like_count = db.session.query(func.count(OutfitLike.id)).filter(
        OutfitLike.outfit_id == outfit_id
    ).scalar() or 0

    comment_count = db.session.query(func.count(OutfitComment.id)).filter(
        OutfitComment.outfit_id == outfit_id
    ).scalar() or 0

    liked = False
    if viewer:
        liked = db.session.query(OutfitLike.id).filter(
            OutfitLike.outfit_id == outfit_id,
            OutfitLike.viewer_email == viewer
        ).first() is not None

    return jsonify({
        "ok": True,
        "outfit_id": outfit_id,
        "like_count": int(like_count),
        "comment_count": int(comment_count),
        "liked": bool(liked),
    })

@app.get("/api/outfits/<int:outfit_id>/comments")
def api_outfit_comments(outfit_id):
    """
    GET /api/outfits/<id>/comments
    - 评论作者昵称 / 头像 永远来自 UserSetting（最新）
    """
    try:
        limit = int(request.args.get("limit") or 50)
    except Exception:
        limit = 50
    limit = max(1, min(200, limit))

    viewer = (request.args.get("viewer") or "").strip().lower()

    try:
        # 1️⃣ 查评论
        rows = (
            OutfitComment.query
            .filter_by(outfit_id=outfit_id)
            .order_by(OutfitComment.created_at.asc())
            .limit(limit)
            .all()
        )

        # 2️⃣ 批量取所有作者 email
        emails = list({
            (c.author_email or "").lower()
            for c in rows
            if c.author_email
        })

        # 3️⃣ 一次性查 UserSetting（避免 N+1）
        settings = (
            UserSetting.query
            .filter(func.lower(UserSetting.email).in_(emails))
            .all()
        )
        setting_map = {s.email.lower(): s for s in settings}

        items = []

        for c in rows:
            em = (c.author_email or "").lower()
            s = setting_map.get(em)

            author_name = (
                s.nickname if s and s.nickname
                else (em.split("@")[0] if em else "User")
            )
            author_avatar = (s.avatar_url if s and s.avatar_url else "")

            like_q = OutfitCommentLike.query.filter_by(comment_id=c.id)
            like_count = like_q.count()

            liked = False
            if viewer:
                liked = like_q.filter_by(user_email=viewer).first() is not None

            # ✅ 解析评论图片
            images = []
            try:
                raw = getattr(c, "images_json", None)
                if raw:
                    images = json.loads(raw) or []
                    if not isinstance(images, list):
                        images = []
            except Exception:
                images = []

            items.append({
                "id": c.id,
                "outfit_id": c.outfit_id,
                "author_email": em,
                "author_name": author_name,
                "author_avatar": author_avatar,
                "text": c.text or "",
                "images": images,
                "parent_id": c.parent_id,
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "like_count": int(like_count),
                "liked": bool(liked),
            })

        return jsonify({"ok": True, "items": items})

    except Exception as e:
        app.logger.exception("api_outfit_comments failed: %s", e)
        return jsonify({
            "ok": False,
            "message": "server_error",
            "detail": str(e)
        }), 500

@app.post("/api/profile/avatar")
def upload_profile_avatar():
    """
    上传头像到 GCS
    body:
      {
        "email": "user@email.com",
        "avatar_base64": "data:image/webp;base64,AAAA..."
      }

    return:
      { ok: true, avatar_url: "https://storage.googleapis.com/xxx/avatars/xxx.webp" }
    """
    try:
        data = request.get_json(silent=True) or {}
        email = (data.get("email") or "").strip().lower()
        b64   = data.get("avatar_base64") or ""

        if not email or not b64.startswith("data:image"):
            return jsonify({"ok": False, "message": "bad_request"}), 400

        # 1️⃣ 解析 base64
        header, encoded = b64.split(",", 1)
        ext = "png"
        if "webp" in header: ext = "webp"
        elif "jpeg" in header or "jpg" in header: ext = "jpg"

        raw = base64.b64decode(encoded)

        # 2️⃣ GCS 路径：avatars/邮箱/uuid.webp
        filename = f"avatars/{email}/{uuid.uuid4().hex}.{ext}"

        client = storage.Client()
        bucket = client.bucket(GCS_BUCKET)
        blob   = bucket.blob(filename)

        blob.upload_from_file(
            BytesIO(raw),
            content_type=f"image/{ext}",
            rewind=True
        )

        blob.make_public()  # 或你自己的 ACL 逻辑

        avatar_url = blob.public_url

        # 3️⃣ 如果你有 User / UserSetting 表，建议顺手存一下
        try:
            u = UserSetting.query.filter_by(email=email).first()
            if u:
                u.avatar_url = avatar_url
                db.session.commit()
        except Exception:
            db.session.rollback()

        return jsonify({
            "ok": True,
            "avatar_url": avatar_url
        })

    except Exception as e:
        app.logger.exception("upload_profile_avatar failed")
        return jsonify({"ok": False, "message": "server_error"}), 500

@app.post("/api/profile/cover")
def upload_profile_cover():
    """
    上传封面到 GCS（兼容 uniform bucket-level access）
    body:
      {
        "email": "user@email.com",
        "cover_base64": "data:image/jpeg;base64,AAAA..."
      }

    return:
      { ok: true, cover_url: "https://storage.googleapis.com/xxx/covers/xxx.jpg" }
    """
    try:
        data = request.get_json(silent=True) or {}
        email = (data.get("email") or "").strip().lower()
        b64   = data.get("cover_base64") or ""

        if not email or not b64.startswith("data:image"):
            return jsonify({"ok": False, "message": "bad_request"}), 400

        header, encoded = b64.split(",", 1)

        ext = "jpg"
        if "webp" in header: ext = "webp"
        elif "png" in header: ext = "png"
        elif "jpeg" in header or "jpg" in header: ext = "jpg"

        raw = base64.b64decode(encoded)

        filename = f"covers/{email}/{uuid.uuid4().hex}.{ext}"

        client = storage.Client()
        bucket = client.bucket(GCS_BUCKET)
        blob   = bucket.blob(filename)

        blob.upload_from_file(
            BytesIO(raw),
            content_type=f"image/{'jpeg' if ext=='jpg' else ext}",
            rewind=True
        )

        # ✅ UBLA: 不要 make_public()

        cover_url = blob.public_url  # 前提：bucket IAM 已经给 allUsers objectViewer

        # ✅ 存 DB
        try:
            u = UserSetting.query.filter_by(email=email).first()
            if u:
                u.cover_url = cover_url
                db.session.commit()
        except Exception:
            db.session.rollback()

        return jsonify({"ok": True, "cover_url": cover_url})

    except Exception:
        app.logger.exception("upload_profile_cover failed")
        return jsonify({"ok": False, "message": "server_error"}), 500

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

@app.post("/api/outfits/<int:oid>/comments/<int:comment_id>/like")
def api_toggle_comment_like(oid, comment_id):
    """
    点赞 / 取消点赞 一条评论（toggle）
    body: { "email": "xxx@email.com" }
    返回: { ok: true, like_count: 3, liked: true/false }
    """
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"ok": False, "message": "missing_email"}), 400

    try:
        c = OutfitComment.query.filter_by(id=comment_id, outfit_id=oid).first()
        if not c:
            return jsonify({"ok": False, "message": "comment_not_found"}), 404

        rel = OutfitCommentLike.query.filter_by(
            comment_id=comment_id,
            user_email=email
        ).first()

        if rel:
            db.session.delete(rel)
            liked = False
        else:
            db.session.add(
                OutfitCommentLike(
                    outfit_id=oid,
                    comment_id=comment_id,
                    user_email=email
                )
            )
            liked = True

        db.session.commit()

        like_count = OutfitCommentLike.query.filter_by(comment_id=comment_id).count()
        return jsonify({"ok": True, "like_count": int(like_count), "liked": bool(liked)})

    except Exception as e:
        app.logger.exception("api_toggle_comment_like error: %s", e)
        db.session.rollback()
        return jsonify({"ok": False, "message": "server_error", "detail": str(e)}), 500

@app.post("/api/outfits/<int:outfit_id>/like")
def api_outfit_like_toggle(outfit_id):
    data = request.get_json(silent=True) or {}
    viewer = (data.get("viewer") or "").strip().lower()
    if not viewer:
        return jsonify({"ok": False, "message": "missing_viewer"}), 400

    row = OutfitLike.query.filter_by(outfit_id=outfit_id, viewer_email=viewer).first()
    if row:
        db.session.delete(row)
        liked = False
    else:
        db.session.add(OutfitLike(outfit_id=outfit_id, viewer_email=viewer))
        liked = True

    db.session.commit()

    like_count = db.session.query(func.count(OutfitLike.id)).filter(
        OutfitLike.outfit_id == outfit_id
    ).scalar() or 0

    return jsonify({"ok": True, "liked": liked, "like_count": int(like_count)})

@app.post("/api/outfits/<int:outfit_id>/comments")
def api_outfit_comment_create(outfit_id):
    data = request.get_json(silent=True) or {}
    author_email = (data.get("author_email") or "").strip().lower()
    text = (data.get("text") or "").strip()

    parent_id = data.get("parent_id")
    try:
        parent_id = int(parent_id) if parent_id is not None else None
    except Exception:
        parent_id = None

    images = data.get("images") or []
    if not isinstance(images, list):
        images = []
    images_json = json.dumps(images, ensure_ascii=False)

    if not author_email:
        return jsonify({"ok": False, "message": "missing_author_email"}), 400
    if not text:
        return jsonify({"ok": False, "message": "empty_text"}), 400

    author_name = (data.get("author_name") or author_email.split("@")[0] or "User").strip()
    author_avatar = (data.get("author_avatar") or "").strip() or None

    c = OutfitComment(
        outfit_id=outfit_id,
        author_email=author_email,
        author_name=author_name,
        author_avatar=author_avatar,
        text=text,
        parent_id=parent_id,
        images_json=images_json,
    )
    db.session.add(c)
    db.session.commit()

    comment_count = db.session.query(func.count(OutfitComment.id)).filter(
        OutfitComment.outfit_id == outfit_id
    ).scalar() or 0

    return jsonify({
        "ok": True,
        "item": {
            "id": c.id,
            "outfit_id": c.outfit_id,
            "author_email": c.author_email,
            "author_name": c.author_name,
            "author_avatar": c.author_avatar,
            "text": c.text,
            "images": images,
            "parent_id": c.parent_id,
            "created_at": c.created_at.isoformat() + "Z",
        },
        "comment_count": int(comment_count)
    })

@app.post("/api/products/<int:pid>/qa/<int:qa_id>/like")
def api_product_qa_toggle_like(pid, qa_id):
    try:
        data = request.get_json(silent=True) or {}
        email = (data.get("email") or "").strip().lower()
        if not email:
            return jsonify({"ok": False, "message": "missing_email"}), 400

        # 是否已点赞
        like = ProductQALike.query.filter_by(product_id=pid, qa_id=qa_id, user_email=email).first()
        if like:
            db.session.delete(like)
            db.session.commit()
            liked = False
        else:
            db.session.add(ProductQALike(product_id=pid, qa_id=qa_id, user_email=email))
            db.session.commit()
            liked = True

        like_count = ProductQALike.query.filter_by(product_id=pid, qa_id=qa_id).count()
        return jsonify({"ok": True, "liked": liked, "like_count": like_count})
    except Exception as e:
        return jsonify({"ok": False, "message": "server_error", "error": str(e)}), 500

from uuid import uuid4
from datetime import datetime
from werkzeug.utils import secure_filename
import os

@app.post("/api/upload/comment-image")
def upload_comment_image():
    try:
        if not GCS_BUCKET:
            return jsonify({"ok": False, "message": "gcs_not_configured"}), 500

        upfile = request.files.get("file")
        if not upfile or not upfile.filename:
            return jsonify({"ok": False, "message": "no_file"}), 400

        pid = (request.form.get("pid") or "0").strip()
        kind = (request.form.get("kind") or "misc").strip().lower()
        kind = kind if kind in ("review", "qa", "misc") else "misc"

        raw = secure_filename(upfile.filename or "img.jpg")
        _, ext = os.path.splitext(raw)
        ext = (ext or ".jpg").lower()
        if ext not in (".jpg", ".jpeg", ".png", ".webp"):
            ext = ".jpg"

        now = datetime.utcnow()
        key = f"comment_images/products/{pid}/{kind}/{now:%Y/%m/%d}/{uuid4().hex}{ext}"

        client = storage.Client()
        bucket = client.bucket(GCS_BUCKET)
        blob = bucket.blob(key)

        content_type = upfile.mimetype or "image/jpeg"

        # ✅ 关键：只上传一次，并且 rewind=True 防止流位置问题
        blob.upload_from_file(upfile.stream, content_type=content_type)
        return jsonify({"ok": True, "url": blob.public_url})

    except Exception as e:
        current_app.logger.exception(e)
        return jsonify({"ok": False, "message": str(e)}), 500

@app.post("/api/settings/reset_user_id")
def api_reset_user_id():
    # 简单鉴权：必须带 X-API-Key
    if (request.headers.get("X-API-Key") or "") != API_KEY:
        return jsonify({"ok": False, "message": "unauthorized"}), 401

    js = request.get_json(silent=True) or {}
    email = (js.get("email") or "").strip().lower()
    if not email:
        return jsonify({"ok": False, "message": "missing_email"}), 400

    s = UserSetting.query.filter(func.lower(UserSetting.email) == email).first()
    if not s:
        return jsonify({"ok": False, "message": "not_found"}), 404

    # ✅ 清空旧ID，然后让 _ensure_user_id 重新生成新规则
    if hasattr(s, "user_id"):
        s.user_id = None
        db.session.commit()

    uid = _ensure_user_id(s)
    return jsonify({"ok": True, "user_id": uid}), 200

@app.delete("/api/outfits/<int:oid>/comments/<int:comment_id>")
def api_delete_outfit_comment(oid, comment_id):
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or data.get("author_email") or "").strip().lower()
    if not email:
        return jsonify({"ok": False, "message": "missing_email"}), 400

    try:
        c = OutfitComment.query.filter_by(id=comment_id, outfit_id=oid).first()
        if not c:
            return jsonify({"ok": False, "message": "comment_not_found"}), 404

        # ✅ 只能删自己的评论
        if (c.author_email or "").strip().lower() != email:
            return jsonify({"ok": False, "message": "forbidden"}), 403

        # ✅ 先删该评论&其回复的点赞
        reply_ids = [
            r.id for r in OutfitComment.query
            .filter_by(outfit_id=oid, parent_id=comment_id).all()
        ]
        all_ids = [comment_id] + reply_ids

        OutfitCommentLike.query.filter(OutfitCommentLike.comment_id.in_(all_ids)).delete(synchronize_session=False)

        # ✅ 先删回复，再删主评论
        OutfitComment.query.filter_by(outfit_id=oid, parent_id=comment_id).delete(synchronize_session=False)
        db.session.delete(c)
        db.session.commit()

        return jsonify({"ok": True})
    except Exception as e:
        db.session.rollback()
        app.logger.exception("api_delete_outfit_comment error: %s", e)
        return jsonify({"ok": False, "message": "server_error", "detail": str(e)}), 500
      
@app.get("/api/follow/state")
def api_follow_state():
    follower = (request.args.get("follower") or "").strip().lower()
    target   = (request.args.get("target") or "").strip().lower()

    if not follower or not target:
        return jsonify({"ok": False, "message": "missing_params"}), 400
    if follower == target:
        return jsonify({"ok": True, "is_following": False})

    rel = UserFollow.query.filter_by(follower_email=follower, target_email=target).first()
    return jsonify({"ok": True, "is_following": bool(rel)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)

@app.get("/api/products/<int:pid>/qa/<int:qa_id>/likes")
def api_product_qa_like_users(pid, qa_id):
    try:
        rows = ProductQALike.query.filter_by(
            product_id=pid,
            qa_id=qa_id
        ).order_by(ProductQALike.created_at.asc()).all()

        users = []
        for r in rows:
            # 可选：联表 UserSetting，拿头像/昵称
            s = UserSetting.query.filter_by(email=r.user_email).first() if UserSetting else None
            nickname = (getattr(s, "nickname", None) if s else None) or r.user_email.split("@")[0]
            avatar = (getattr(s, "avatar_url", None) if s else None) or ""

            users.append({
                "email": r.user_email,
                "name": (s.nickname if s and s.nickname else r.user_email.split("@")[0]),
                "avatar": (s.avatar_url if s and s.avatar_url else "")
            })

        return jsonify({
            "ok": True,
            "items": users
        })
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 500

@app.get("/api/outfits/<int:oid>/comments/<int:cid>/likes")
def api_outfit_comment_like_users(oid, cid):
    try:
        rows = (OutfitCommentLike.query
                .filter_by(outfit_id=oid, comment_id=cid)
                .order_by(OutfitCommentLike.created_at.desc())
                .limit(200).all())

        # 1) 收集所有点赞用户 email
        emails = list({
            (r.user_email or "").strip().lower()
            for r in rows
            if r.user_email
        })

        # 2) 一次性查 UserSetting（避免 N+1）
        setting_map = {}
        if emails:
            settings = (UserSetting.query
                        .filter(func.lower(UserSetting.email).in_(emails))
                        .all())
            setting_map = {s.email.lower(): s for s in settings}

        # 3) 组装返回
        items = []
        for r in rows:
            email = (r.user_email or "").strip().lower()
            s = setting_map.get(email)

            name = (getattr(s, "nickname", "") or "").strip()
            if not name:
                name = email.split("@")[0] if email else "User"

            avatar = (getattr(s, "avatar_url", "") or "").strip()
            if not avatar:
                avatar = "https://boldmm.shop/default-avatar.png"

            items.append({
                "name": name,
                "avatar": avatar
                # 不返回 email（按你的要求）
            })

        return jsonify({"ok": True, "items": items})

    except Exception as e:
        app.logger.exception("api_outfit_comment_like_users failed: %s", e)
        return jsonify({"ok": False, "message": str(e)}), 500

def gen_order_no():
    # 例如：BOLD20251216XXXX
    suffix = ''.join(random.choices(string.digits, k=6))
    return f"BOLD{datetime.utcnow().strftime('%Y%m%d')}{suffix}"

@app.post("/api/payments/create")
def api_payment_create():
    try:
        data = request.get_json(force=True) or {}

        buyer_email = (data.get("email") or "").strip().lower()
        if not buyer_email:
            return jsonify({"message": "missing_email"}), 400

        items = data.get("items") or []
        if not isinstance(items, list) or len(items) == 0:
            return jsonify({"message": "empty_items"}), 400

        subtotal = int(data.get("subtotal") or 0)
        tax = int(data.get("tax") or 0)
        shipping = int(data.get("shipping") or 0)
        total = int(data.get("total") or (subtotal + tax + shipping))

        po = PaymentOrder(
            order_no=gen_order_no(),
            user_id=str(data.get("user_id") or ""),
            buyer_email=buyer_email,
            buyer_nickname=str(data.get("nickname") or ""),
            buyer_phone=str(data.get("phone") or ""),
            items=items,
            subtotal=subtotal,
            tax=tax,
            shipping=shipping,
            total=total,
            status="pending",
            paid_at=datetime.utcnow(),
        )
        db.session.add(po)
        db.session.commit()

        return jsonify({
            "ok": True,
            "payment_id": po.id,
            "order_no": po.order_no,
            "status": po.status
        })
    except Exception as e:
        return jsonify({"message": "server_error", "error": str(e)}), 500

@app.get("/api/payments/<int:pid>")
def api_payment_get(pid):
    try:
        po = PaymentOrder.query.get(pid)
        if not po:
            return jsonify({"message":"not_found"}), 404

        return jsonify({
            "id": po.id,
            "order_no": po.order_no,
            "status": po.status,
            "paid_at": po.paid_at.isoformat() if po.paid_at else None,
            "confirmed_at": po.confirmed_at.isoformat() if po.confirmed_at else None,
            "total": po.total
        })
    except Exception as e:
        return jsonify({"message":"server_error","error":str(e)}), 500

@app.get("/api/admin/payments")
def api_admin_payments_list():
    try:
        limit = min(200, int(request.args.get("limit") or 100))
        rows = PaymentOrder.query.order_by(PaymentOrder.created_at.desc()).limit(limit).all()

        def short_items(items):
            # 给后台快速展示：最多 3 个商品标题
            try:
                names = [str(x.get("title") or "") for x in (items or []) if isinstance(x, dict)]
                names = [n for n in names if n]
                return names[:3]
            except:
                return []

        out = []
        for r in rows:
            out.append({
                "id": r.id,
                "order_no": r.order_no,
                "user_id": r.user_id,
                "buyer_email": r.buyer_email,
                "buyer_nickname": r.buyer_nickname,
                "buyer_phone": r.buyer_phone,
                "items": r.items or [],
                "items_preview": short_items(r.items),
                "subtotal": r.subtotal,
                "tax": r.tax,
                "shipping": r.shipping,
                "total": r.total,
                "status": r.status,
                "paid_at": r.paid_at.isoformat() if r.paid_at else None,
                "confirmed_at": r.confirmed_at.isoformat() if r.confirmed_at else None,
            })
        return jsonify({"items": out})
    except Exception as e:
        return jsonify({"message":"server_error","error":str(e)}), 500

@app.get("/api/chats/threads")
def api_chat_threads():
    try:
        me = str(request.args.get("me") or "").strip()

        if not re.fullmatch(r"\d{14}", me):
            return jsonify({"ok": False, "error": "bad_me"}), 400

        rows = (ChatThread.query
                .filter((ChatThread.a_id == me) | (ChatThread.b_id == me))
                .order_by(ChatThread.updated_at.desc())
                .limit(200)
                .all())

        items = []
        for t in rows:
            peer = t.b_id if t.a_id == me else t.a_id

            last = (ChatMessage.query
                    .filter(ChatMessage.thread_id == t.id)
                    .order_by(ChatMessage.id.desc())
                    .first())

            last_obj = None
            if last:
                try:
                    payload = json.loads(last.payload_json) if last.payload_json else {}
                except Exception:
                    payload = {}

                to_id = peer if last.sender_id == me else me
                last_obj = {
                    "id": last.id,
                    "from": last.sender_id,
                    "to": to_id,
                    "type": last.type or "text",
                    "text": last.text or "",
                    "url": last.url or "",
                    "payload": payload,
                    "ts": _fmt_dt(last.created_at),
                }

            items.append({
                "thread_id": t.id,
                "peer": _peer_profile(peer),   # ✅ 用你的 _peer_profile
                "updated_at": _fmt_dt(t.updated_at),
                "last": last_obj
            })

        return jsonify({"ok": True, "items": items})

    except Exception as e:
        print("CHAT THREADS ERROR:", repr(e))
        return jsonify({"ok": False, "error": "threads_failed", "detail": str(e)}), 500

@app.get("/api/chats/messages")
def api_chat_messages():
    tid = request.args.get("thread_id")
    me  = str(request.args.get("me") or "").strip()

    if not tid or not re.fullmatch(r"\d{14}", me):
        return jsonify({"ok": False, "error":"bad_args"}), 400

    msgs = (ChatMessage.query
            .filter_by(thread_id=int(tid))
            .order_by(ChatMessage.created_at.asc())
            .all())

    out = []
    for m in msgs:
        try:
            payload = json.loads(m.payload_json) if m.payload_json else {}
        except Exception:
            payload = {}

        out.append({
            "id": m.id,
            "from": m.sender_id,
            "type": m.type,
            "text": m.text or "",
            "url": m.url or "",
            "payload": payload,
            "created_at": m.created_at.isoformat()
        })

    return jsonify({"ok": True, "items": out})

@app.get("/api/chats/thread")
def api_chat_thread():
    me = str(request.args.get("me") or "").strip()
    peer = str(request.args.get("peer") or "").strip()
    limit = int(request.args.get("limit") or 200)
    limit = max(1, min(limit, 500))

    if not re.fullmatch(r"\d{14}", me) or not re.fullmatch(r"\d{14}", peer):
        return jsonify({"ok": False, "error": "bad_me_or_peer"}), 400

    a, b = _pair_ids(me, peer)
    t = ChatThread.query.filter_by(a_id=a, b_id=b).first()
    if not t:
        return jsonify({"ok": True, "thread_id": None, "peer": _peer_profile(peer), "items": []})

    msgs = ChatMessage.query.filter_by(thread_id=t.id).order_by(ChatMessage.id.asc()).limit(limit).all()

    items = []
    for m in msgs:
        payload = {}
        try:
            payload = json.loads(m.payload_json) if m.payload_json else {}
        except:
            payload = {}
        to_id = peer if m.sender_id == me else me
        items.append({
            "id": m.id,
            "from": m.sender_id,
            "to": to_id,
            "type": m.type or "text",
            "text": m.text or "",
            "url": m.url or "",
            "payload": payload,
            "ts": m.created_at.strftime("%Y-%m-%d %H:%M:%S")
        })

    return jsonify({"ok": True, "thread_id": t.id, "peer": _peer_profile(peer), "items": items})

@app.get("/api/admin/fix_chats_tables")
def fix_chats_tables():
    try:
        db.session.execute(db.text("DROP TABLE IF EXISTS chat_messages CASCADE;"))
        db.session.execute(db.text("DROP TABLE IF EXISTS chat_threads CASCADE;"))
        db.session.commit()

        db.create_all()
        return jsonify({"ok": True, "message": "chat tables rebuilt"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok": False, "error": str(e)}), 500

@app.get("/api/admin/db_schema_chat_threads")
def db_schema_chat_threads():
    try:
        rows = db.session.execute(db.text("""
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name='chat_threads'
            ORDER BY ordinal_position;
        """)).fetchall()
        return jsonify({"ok": True, "columns": [[r[0], r[1]] for r in rows]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.get("/api/admin/rebuild_chats_tables")
def rebuild_chats_tables():
    try:
        # 1) drop
        db.session.execute(db.text("DROP TABLE IF EXISTS chat_messages CASCADE;"))
        db.session.execute(db.text("DROP TABLE IF EXISTS chat_threads CASCADE;"))
        db.session.commit()

        # 2) create only these 2 tables (不用全库 create_all 以免影响其他表)
        ChatThread.__table__.create(db.engine, checkfirst=True)
        ChatMessage.__table__.create(db.engine, checkfirst=True)

        # 3) verify
        cols = db.session.execute(db.text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name='chat_threads'
            ORDER BY ordinal_position;
        """)).fetchall()

        return jsonify({"ok": True, "chat_threads_columns": [c[0] for c in cols]})

    except Exception as e:
        db.session.rollback()
        return jsonify({"ok": False, "error": str(e)}), 500

@app.get("/api/admin/db_check")
def db_check():
    try:
        # 1) 当前连接的数据库信息
        ver = db.session.execute(db.text("select version();")).scalar()
        dbname = db.session.execute(db.text("select current_database();")).scalar()
        user = db.session.execute(db.text("select current_user;")).scalar()

        # 2) chat_threads 的列
        cols = db.session.execute(db.text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name='chat_threads'
            ORDER BY ordinal_position;
        """)).fetchall()

        return jsonify({
            "ok": True,
            "current_database": dbname,
            "current_user": user,
            "version": ver,
            "chat_threads_columns": [c[0] for c in cols],
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.post("/api/admin/payments/<int:pid>/confirm")
def api_admin_payments_confirm(pid):
    try:
        po = PaymentOrder.query.get(pid)
        if not po:
            return jsonify({"message":"not_found"}), 404

        po.status = "confirmed"
        po.confirmed_at = datetime.utcnow()
        db.session.commit()

        return jsonify({"ok": True, "id": po.id, "status": po.status})
    except Exception as e:
        return jsonify({"message":"server_error","error":str(e)}), 500

@app.post("/api/chats/thread")
def api_chat_get_or_create_thread():
    try:
        data = request.get_json(force=True) or {}
        me   = str(data.get("me") or "").strip()
        peer = str(data.get("peer") or "").strip()

        if not re.fullmatch(r"\d{14}", me):
            return jsonify({"ok": False, "error": "bad_me"}), 400
        if not re.fullmatch(r"\d{14}", peer):
            return jsonify({"ok": False, "error": "bad_peer"}), 400
        if me == peer:
            return jsonify({"ok": False, "error": "same_user"}), 400

        a, b = _pair_ids(me, peer)
        t = ChatThread.query.filter_by(a_id=a, b_id=b).first()
        if not t:
            t = ChatThread(a_id=a, b_id=b, updated_at=datetime.utcnow())
            db.session.add(t)
            db.session.commit()

        return jsonify({"ok": True, "thread_id": t.id, "peer_id": peer})
    except Exception as e:
        return jsonify({"ok": False, "error": "thread_failed", "detail": str(e)}), 500

@app.post("/api/chats/send")
def api_chat_send():
    try:
        data = request.get_json(force=True, silent=True) or {}

        me   = str(data.get("me") or "").strip()
        peer = str(data.get("peer") or "").strip()

        if not re.fullmatch(r"\d{14}", me) or not re.fullmatch(r"\d{14}", peer):
            return jsonify({"ok": False, "error": "invalid_user_id"}), 400
        if me == peer:
            return jsonify({"ok": False, "error": "same_user"}), 400

        msg_type = str(data.get("type") or "text").strip()
        text     = str(data.get("text") or "")
        url      = str(data.get("url") or "")
        payload  = data.get("payload") or {}

        if msg_type not in ("text","image","video","product","order"):
            msg_type = "text"

        # 1) get/create thread
        a, b = _pair_ids(me, peer)
        t = ChatThread.query.filter_by(a_id=a, b_id=b).first()
        if not t:
            t = ChatThread(a_id=a, b_id=b, updated_at=datetime.utcnow())
            db.session.add(t)
            db.session.flush()

        # 2) insert message (把字段写进列里，payload_json只存payload本身)
        m = ChatMessage(
            thread_id=t.id,
            sender_id=me,
            type=msg_type,
            text=text,
            url=url,
            payload_json=json.dumps(payload, ensure_ascii=False) if payload else None,
            created_at=datetime.utcnow()
        )
        db.session.add(m)

        # 3) update thread time
        t.updated_at = datetime.utcnow()
        db.session.commit()

        return jsonify({
            "ok": True,
            "thread_id": t.id,
            "message": {
                "id": m.id,
                "from": me,
                "to": peer,
                "type": msg_type,
                "text": text,
                "url": url,
                "payload": payload,
                "ts": m.created_at.strftime("%Y-%m-%d %H:%M:%S")
            }
        })
    except Exception as e:
        return jsonify({"ok": False, "error": "send_failed", "detail": str(e)}), 500

@app.post("/api/chats/upload")
def upload_chat_file():
    app.logger.warning("CHAT UPLOAD v2 HIT")   # ✅ 加这一行

    """
    FormData:
      - file: File
      - me: 14位我的 user_id
      - peer: 14位对方 user_id
      - kind: image | video
    return:
      { ok: true, url: "https://storage.googleapis.com/<bucket>/chats/..." }
    """
    try:
        if not GCS_BUCKET:
            return jsonify({"ok": False, "error": "gcs_not_configured"}), 500

        # 1) 取参数
        me = (request.form.get("me") or "").strip()
        peer = (request.form.get("peer") or "").strip()
        kind = (request.form.get("kind") or "").strip().lower()  # image/video

        upfile = request.files.get("file")
        if not upfile or not upfile.filename:
            return jsonify({"ok": False, "error": "no_file"}), 400

        if kind not in ("image", "video"):
            return jsonify({"ok": False, "error": "bad_kind"}), 400

        # 2) 判断扩展名 & content-type
        #    （优先用 mimetype，fallback 用文件名）
        mimetype = (upfile.mimetype or "").lower()
        filename = (upfile.filename or "").lower()

        ext = "bin"
        if kind == "image":
            if "webp" in mimetype or filename.endswith(".webp"): ext = "webp"
            elif "png" in mimetype or filename.endswith(".png"): ext = "png"
            elif "jpeg" in mimetype or "jpg" in mimetype or filename.endswith(".jpg") or filename.endswith(".jpeg"): ext = "jpg"
            else: ext = "jpg"  # 默认
            content_type = f"image/{'jpeg' if ext=='jpg' else ext}"
        else:
            # video
            if "mp4" in mimetype or filename.endswith(".mp4"): ext = "mp4"
            elif "webm" in mimetype or filename.endswith(".webm"): ext = "webm"
            elif "quicktime" in mimetype or filename.endswith(".mov"): ext = "mov"
            else: ext = "mp4"
            content_type = f"video/{ext if ext!='mov' else 'quicktime'}"

        # 3) GCS 路径
        # chats/<kind>/<me>/<peer>/<uuid>.<ext>
        object_name = f"chats/{kind}/{me}/{peer}/{uuid.uuid4().hex}.{ext}"

        client = storage.Client()
        bucket = client.bucket(GCS_BUCKET)
        blob = bucket.blob(object_name)

        # 4) 上传（直接从 file stream）
        blob.upload_from_file(upfile.stream, content_type=content_type, rewind=True)

        return jsonify({"ok": True, "url": blob.public_url})

    except Exception as e:
        app.logger.exception("upload_chat_file failed")
        return jsonify({"ok": False, "error": "upload_failed", "detail": str(e)}), 500

app.logger.info("DB configured: %s", bool(os.environ.get("DATABASE_URL")))
# 或者只打印 host，不打印密码（更麻烦就先用上面那行）

ALLOWED_ORIGINS = {
    "https://boldmm.shop",
    "https://www.boldmm.shop",
}

def _cors(resp):
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"

    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,PATCH,DELETE,OPTIONS"

    req_hdrs = request.headers.get("Access-Control-Request-Headers", "")
    resp.headers["Access-Control-Allow-Headers"] = req_hdrs or "Content-Type, X-API-Key"

    resp.headers["Access-Control-Max-Age"] = "86400"
    return resp
    
def safe_model_delete(model, *filters):
    try:
        q = model.query
        for f in filters:
            if f is None:
                return True  # 没这个条件就当跳过
            q = q.filter(f)
        q.delete(synchronize_session=False)
        return True
    except Exception as e:
        app.logger.warning("safe delete skip %s: %s", getattr(model, "__name__", model), e)
        return False

@app.get("/api/dbinfo")
def api_dbinfo():
    r = db.session.execute(db.text("""
      select
        current_database() as db,
        inet_server_addr() as ip,
        inet_server_port() as port,
        version() as ver
    """)).mappings().first()

    cols = db.session.execute(db.text("""
      select table_name, column_name
      from information_schema.columns
      where table_schema='public'
        and table_name in ('product_reviews','product_qas')
        and column_name='images'
      order by table_name
    """)).mappings().all()

    return jsonify({
      "db": dict(r) if r else None,
      "images_columns_found": [dict(x) for x in cols],
    })

@app.post("/api/admin/outfits/<int:outfit_id>/pin")
@require_login
@require_admin
def admin_pin_outfit(outfit_id):
    if not API_KEY:
        return jsonify({"ok": False, "error": "API_KEY_not_set"}), 500

    api_key = request.headers.get("X-API-Key", "")
    if api_key != API_KEY:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    pinned = bool(data.get("pinned"))

    outfit = Outfit.query.get(outfit_id)
    if not outfit:
        return jsonify({"ok": False, "error": "not_found"}), 404

    outfit.is_pinned = pinned
    outfit.pinned_at = datetime.utcnow() if pinned else None
    db.session.commit()
    return jsonify({"ok": True, "id": outfit_id, "is_pinned": outfit.is_pinned})

from datetime import datetime

@app.post("/api/admin/products/<int:pid>/pin")
@require_login
@require_admin
def admin_pin_product(pid):
    api_key = request.headers.get("X-API-Key", "")
    if api_key != API_KEY:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    pinned = bool(data.get("pinned"))

    p = Product.query.get(pid)
    if not p:
        return jsonify({"ok": False, "error": "not_found"}), 404

    p.is_pinned = pinned
    p.pinned_at = datetime.utcnow() if pinned else None
    db.session.commit()
    return jsonify({"ok": True, "id": pid, "is_pinned": p.is_pinned})

@app.delete("/api/admin/products/<int:pid>")
@require_login
@require_admin
def admin_delete_product(pid):
    api_key = request.headers.get("X-API-Key", "")
    if api_key != API_KEY:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    p = Product.query.get(pid)
    if not p:
        return jsonify({"ok": False, "error": "not_found"}), 404

    p.status = "deleted"   # 软删
    db.session.commit()
    return jsonify({"ok": True, "id": pid})

def get_session_payload():
    # 1) Authorization: Bearer xxx
    auth = (request.headers.get("Authorization") or "").strip()
    token = ""
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()

    # 2) 兼容：X-User-Token: xxx（可选）
    if not token:
        token = (request.headers.get("X-User-Token") or "").strip()

    if not token:
        return None

    try:
        return jwt.decode(token, SESSION_SECRET, algorithms=["HS256"])
    except Exception:
        return None

def get_google_audiences():
    raw = (os.getenv("GOOGLE_CLIENT_IDS") or "").strip()
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]

def verify_google_id_token(id_token: str):
    req = google_requests.Request()
    payload = google_id_token.verify_oauth2_token(id_token, req, audience=None)

    aud = payload.get("aud")
    allowed = get_google_audiences()
    if allowed and aud not in allowed:
        raise Exception("google_bad_audience")

    return payload

@app.route("/api/auth/google", methods=["POST"])
def auth_google():
    data = request.get_json(force=True) or {}
    id_token = data.get("id_token") or ""
    mode = (data.get("mode") or "login").lower().strip()

    if not id_token:
        return jsonify(ok=False, message="missing id_token"), 400

    try:
        p = verify_google_id_token(id_token)
        sub = p.get("sub")
        email = (p.get("email") or "").lower().strip()

        if not sub:
            return jsonify(ok=False, message="missing sub"), 400

        # 1) provider+sub 已绑定
        ident = AuthIdentity.query.filter_by(provider="google", provider_sub=sub).first()
        if ident:
            u = ident.user

            # ✅ 如果账号 deleted：login 继续禁止；signup 允许激活
            if getattr(u, "status", "active") == "deleted":
                if mode != "signup":
                    return jsonify(ok=False, error="account_deleted", message="account deleted"), 403
                u.status = "active"
                u.deleted_at = None
                db.session.add(u)
                db.session.commit()

            u.last_seen_at = datetime.utcnow()
            db.session.commit()

            token = issue_session_token(u.id, u.email, provider="google")
            return jsonify(ok=True, token=token, user={"id": u.id, "email": u.email})

        # 2) 没绑定：email 合并
        u = None
        if email:
            u = User.query.filter_by(email=email).first()

        if u and getattr(u, "status", "active") == "deleted":
            if mode != "signup":
                return jsonify(ok=False, error="account_deleted", message="account deleted"), 403
            u.status = "active"
            u.deleted_at = None
            db.session.add(u)
            db.session.commit()

        # 3) 否则创建新用户
        if not u:
            u = User(email=email or f"google_{sub}@noemail.local")
            db.session.add(u)
            db.session.flush()

        ident = AuthIdentity(provider="google", provider_sub=sub, email=email or None, user_id=u.id)
        db.session.add(ident)
        db.session.commit()

        token = issue_session_token(u.id, u.email, provider="google")
        return jsonify(ok=True, token=token, user={"id": u.id, "email": u.email})

    except Exception as e:
        return jsonify(ok=False, message=str(e)), 400


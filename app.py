import os
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from io import BytesIO

app = Flask(__name__)

# DB
db_url = os.getenv("SQLALCHEMY_DATABASE_URI") or os.getenv("DATABASE_URL") or "sqlite:///data.db"
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

CORS(app, resources={r"/api/*": {"origins": "*"}})

API_KEY = os.getenv("API_KEY", "")

db = SQLAlchemy(app)

class MerchantApplication(db.Model):
    __tablename__ = "merchant_applications"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    account_name = db.Column(db.String(120), nullable=False)
    shop_name    = db.Column(db.String(120), nullable=False)
    license_id   = db.Column(db.String(120), nullable=False)
    phone        = db.Column(db.String(64),  nullable=True)
    email        = db.Column(db.String(200), nullable=True)
    license_image_name = db.Column(db.String(255))
    license_image_type = db.Column(db.String(128))
    license_image_data = db.Column(db.LargeBinary)
    # 新增：审核状态
    status       = db.Column(db.String(32), default="pending", nullable=False)

with app.app_context():
    db.create_all()
    # 保险：尝试给老表加 status（如果是旧版本）
    try:
        with db.engine.connect() as conn:
            conn.execute(db.text("ALTER TABLE merchant_applications ADD COLUMN IF NOT EXISTS status VARCHAR(32) DEFAULT 'pending' NOT NULL"))
            conn.commit()
    except Exception as e:
        pass

def ok(): return {"ok": True}

def check_key(req):
    """
    Accept API key via:
    - Header: X-API-Key: <key>
    - Query:  ?key=<key>
    - JSON body: {"key": "<key>"}  (for POST/PUT with application/json)
    """
    key = req.headers.get("X-API-Key") or req.args.get("key")
    if not key and req.is_json:
        try:
            data = req.get_json(silent=True) or {}
            key = data.get("key")
        except Exception:
            key = None
    return API_KEY and key == API_KEY

@app.route("/health")
def health():
    return ok()

@app.route("/api/merchants/apply", methods=["POST"])
def apply_merchant():
    if not check_key(request): return jsonify({"message":"Unauthorized"}), 401
    account_name = (request.form.get("account_name") or "").strip()
    shop_name    = (request.form.get("shop_name") or "").strip()
    license_id   = (request.form.get("license_id") or "").strip()
    phone        = (request.form.get("phone") or "").strip()
    email        = (request.form.get("email") or "").strip()
    f            = request.files.get("license_image")
    missing = [k for k,v in {"account_name":account_name,"shop_name":shop_name,"license_id":license_id}.items() if not v]
    if missing: return jsonify({"message": f"缺少字段: {', '.join(missing)}"}), 400
    if not f: return jsonify({"message":"请上传营业执照图片"}), 400
    f.seek(0, os.SEEK_END); size=f.tell(); f.seek(0)
    if size > 2*1024*1024: return jsonify({"message":"图片不能超过2MB"}), 400
    row = MerchantApplication(
        account_name=account_name, shop_name=shop_name, license_id=license_id,
        phone=phone, email=email, license_image_name=f.filename,
        license_image_type=f.mimetype or "application/octet-stream",
        license_image_data=f.read(), status="pending"
    )
    db.session.add(row); db.session.commit()
    return jsonify({"message":"ok","id":row.id})

@app.route("/api/admin/merchants", methods=["GET"])
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

@app.route("/api/admin/merchants/<int:rid>/status", methods=["POST"])
def admin_set_status(rid):
    if not check_key(request): return jsonify({"message":"Unauthorized"}), 401
    r = MerchantApplication.query.get_or_404(rid)
    status = (request.json or {}).get("status","").strip().lower()
    if status not in {"pending","approved","rejected"}:
        return jsonify({"message":"status 必须是 pending/approved/rejected"}), 400
    r.status = status; db.session.commit()
    return jsonify({"message":"ok"})

@app.route("/api/admin/merchants/<int:rid>/license_image")
def admin_image(rid):
    if not check_key(request): return jsonify({"message":"Unauthorized"}), 401
    r = MerchantApplication.query.get_or_404(rid)
    return send_file(BytesIO(r.license_image_data),
                     mimetype=r.license_image_type or "application/octet-stream",
                     as_attachment=False,
                     download_name=r.license_image_name or f"license_{rid}.bin")

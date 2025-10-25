import os
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from io import BytesIO

# ---------- Config ----------
app = Flask(__name__)

# DB: Render's Postgres uses DATABASE_URL
db_url = os.getenv("SQLALCHEMY_DATABASE_URI") or os.getenv("DATABASE_URL") or "sqlite:///data.db"
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# CORS (front端域名可替换为你的正式域名以提高安全性)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# API 密钥（与前端 X-API-Key 对应）
API_KEY = os.getenv("API_KEY", "")

db = SQLAlchemy(app)

# ---------- Model ----------
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
    license_image_data = db.Column(db.LargeBinary)  # <=2MB

with app.app_context():
    db.create_all()

# ---------- Utils ----------
def check_api_key(req):
    key = req.headers.get("X-API-Key", "")
    return (API_KEY and key == API_KEY)

# ---------- Routes ----------
@app.route("/health")
def health():
    return {"ok": True}

@app.route("/api/merchants/apply", methods=["POST"])
def apply_merchant():
    # API key check
    if not check_api_key(request):
        return jsonify({"message": "Unauthorized"}), 401

    # Fields
    account_name = (request.form.get("account_name") or "").strip()
    shop_name    = (request.form.get("shop_name") or "").strip()
    license_id   = (request.form.get("license_id") or "").strip()
    phone        = (request.form.get("phone") or "").strip()
    email        = (request.form.get("email") or "").strip()
    f            = request.files.get("license_image")

    # Validate
    missing = [k for k,v in {
        "account_name": account_name,
        "shop_name": shop_name,
        "license_id": license_id
    }.items() if not v]
    if missing:
        return jsonify({"message": f"缺少字段: {', '.join(missing)}"}), 400
    if not f:
        return jsonify({"message": "请上传营业执照图片"}), 400

    # Size limit 2MB
    f.seek(0, os.SEEK_END)
    size = f.tell()
    f.seek(0)
    if size > 2 * 1024 * 1024:
        return jsonify({"message": "图片不能超过2MB"}), 400

    row = MerchantApplication(
        account_name=account_name,
        shop_name=shop_name,
        license_id=license_id,
        phone=phone,
        email=email,
        license_image_name=f.filename,
        license_image_type=f.mimetype or "application/octet-stream",
        license_image_data=f.read()
    )
    db.session.add(row)
    db.session.commit()

    return jsonify({"message": "ok", "id": row.id})

# Optional: 简单查看图片（临时调试用）
@app.route("/api/merchants/<int:rid>/license_image")
def get_image(rid):
    # 也用 API_KEY 保护，避免被随便访问
    if not check_api_key(request):
        return jsonify({"message": "Unauthorized"}), 401

    row = MerchantApplication.query.get_or_404(rid)
    return send_file(BytesIO(row.license_image_data),
                     mimetype=row.license_image_type or "application/octet-stream",
                     as_attachment=False,
                     download_name=row.license_image_name or f"license_{rid}.bin")

if __name__ == "__main__":
    # For local testing
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))

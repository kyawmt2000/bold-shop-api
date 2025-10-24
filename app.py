
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import os, secrets

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Merchant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    shop_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(50))
    address = db.Column(db.String(200))
    status = db.Column(db.String(20), default="pending")
    api_key = db.Column(db.String(120), unique=True)

@app.route('/health')
def health():
    return jsonify({"status": "ok"})

@app.route('/merchants/register', methods=['POST'])
def register():
    data = request.json
    if not data or not all(k in data for k in ("shop_name", "email", "password")):
        return jsonify({"error": "shop_name, email, password required"}), 400
    if Merchant.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "Email already registered"}), 400
    merchant = Merchant(shop_name=data["shop_name"], email=data["email"],
                        password=data["password"], phone=data.get("phone"),
                        address=data.get("address"))
    db.session.add(merchant)
    db.session.commit()
    return jsonify({"message": "Registered. Awaiting approval", "merchant_id": merchant.id})

@app.route('/admin/merchants/<int:merchant_id>/approve', methods=['PATCH'])
def approve(merchant_id):
    admin_token = request.headers.get("X-Admin-Token")
    if admin_token != os.getenv("ADMIN_TOKEN", "boldAdmin2025"):
        return jsonify({"error": "Unauthorized"}), 403
    merchant = Merchant.query.get(merchant_id)
    if not merchant:
        return jsonify({"error": "Merchant not found"}), 404
    merchant.status = "approved"
    merchant.api_key = secrets.token_hex(16)
    db.session.commit()
    return jsonify({"message": "approved", "api_key": merchant.api_key})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)

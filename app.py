from flask import Flask, request, jsonify, send_from_directory, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os, secrets, time

# -------------------------
# Flask 初始化
# -------------------------
app = Flask(__name__)
CORS(app)

# -------------------------
# 配置
# -------------------------
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 上传目录（本地存储）
UPLOAD_ROOT = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_ROOT, exist_ok=True)
ALLOWED_EXTS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

db = SQLAlchemy(app)

# -------------------------
# 数据表
# -------------------------
class Merchant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    shop_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(50))
    address = db.Column(db.String(200))
    status = db.Column(db.String(20), default="pending")
    api_key = db.Column(db.String(120), unique=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    merchant_id = db.Column(db.Integer, db.ForeignKey('merchant.id'), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(80), index=True)
    gender = db.Column(db.String(20), index=True)  # men / women / unisex
    sizes = db.Column(db.String(200))    # 逗号分隔，例如 S,M,L
    colors = db.Column(db.String(200))   # 逗号分隔，例如 red,blue
    image_path = db.Column(db.String(400))  # /uploads/<merchant>/<file>

# -------------------------
# 工具函数
# -------------------------
def get_merchant_by_api_key():
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return None
    return Merchant.query.filter_by(api_key=api_key, status="approved").first()

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTS

# -------------------------
# 静态文件（上传图片）访问
# -------------------------
@app.route('/uploads/<path:subpath>')
def serve_uploads(subpath):
    # subpath 形如: "<merchant_id>/<filename>"
    directory = os.path.join(UPLOAD_ROOT, os.path.dirname(subpath))
    filename = os.path.basename(subpath)
    return send_from_directory(directory, filename)

# -------------------------
# 健康检查
# -------------------------
@app.get('/health')
def health():
    return jsonify({"status": "ok"})

# -------------------------
# 商家注册 / 登录 / 审核
# -------------------------
@app.post('/merchants/register')
def register():
    data = request.get_json(silent=True)
    if not data or not all(k in data for k in ("shop_name", "email", "password")):
        return jsonify({"error": "shop_name, email, password required"}), 400

    if Merchant.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "Email already registered"}), 400

    m = Merchant(
        shop_name=data["shop_name"],
        email=data["email"],
        password=data["password"],
        phone=data.get("phone"),
        address=data.get("address")
    )
    db.session.add(m)
    db.session.commit()
    return jsonify({"message": "Registered. Awaiting approval", "merchant_id": m.id}), 201

@app.post('/merchants/login')
def merchant_login():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"error": "email and password required"}), 400

    m = Merchant.query.filter_by(email=email, password=password).first()
    if not m:
        return jsonify({"error": "Invalid credentials"}), 401
    if m.status != "approved":
        return jsonify({"error": "Merchant not approved yet"}), 403
    # 确保有 api_key
    if not m.api_key:
        m.api_key = secrets.token_hex(16)
        db.session.commit()

    return jsonify({"merchant_id": m.id, "api_key": m.api_key})

@app.patch('/admin/merchants/<int:merchant_id>/approve')
def approve(merchant_id):
    admin_token = (
        request.headers.get("X-Admin-Token")
        or request.headers.get("Admin-Token")
        or request.headers.get("ADMIN_TOKEN")
    )
    if admin_token != os.getenv("ADMIN_TOKEN", "boldAdmin2025"):
        return jsonify({"error": "Unauthorized"}), 403

    m = Merchant.query.get(merchant_id)
    if not m:
        return jsonify({"error": "Merchant not found"}), 404

    m.status = "approved"
    if not m.api_key:
        m.api_key = secrets.token_hex(16)
    db.session.commit()
    return jsonify({"message": "approved", "api_key": m.api_key})

# -------------------------
# 商品：新增 / 查询
# -------------------------
@app.post('/products')
def add_product():
    """商家新增商品（支持图片上传）
       Header: X-API-Key
       Body: multipart/form-data (title, price, category, gender, sizes, colors, image?)
    """
    merchant = get_merchant_by_api_key()
    if not merchant:
        return jsonify({"error": "Unauthorized (X-API-Key missing or invalid)"}), 401

    title = request.form.get('title')
    price = request.form.get('price')
    category = request.form.get('category')
    gender = request.form.get('gender')
    sizes = request.form.get('sizes')   # 例如 "S,M,L"
    colors = request.form.get('colors') # 例如 "red,blue"

    if not title or not price:
        return jsonify({"error": "title and price required"}), 400

    # 处理图片
    image_path = None
    if 'image' in request.files and request.files['image'].filename:
        f = request.files['image']
        if not allowed_file(f.filename):
            return jsonify({"error": "invalid image type"}), 400
        filename = secure_filename(f.filename)
        basename, ext = os.path.splitext(filename)
        # 去商家自己的子目录
        merchant_dir = os.path.join(UPLOAD_ROOT, str(merchant.id))
        os.makedirs(merchant_dir, exist_ok=True)
        new_name = f"{int(time.time())}_{basename}{ext}"
        save_path = os.path.join(merchant_dir, new_name)
        f.save(save_path)
        image_path = f"/uploads/{merchant.id}/{new_name}"

    p = Product(
        merchant_id=merchant.id,
        title=title,
        price=float(price),
        category=category,
        gender=gender,
        sizes=sizes,
        colors=colors,
        image_path=image_path
    )
    db.session.add(p)
    db.session.commit()

    return jsonify({
        "id": p.id,
        "image_path": p.image_path
    }), 201

@app.get('/products')
def list_products():
    """获取商品列表（用于前端展示）
       支持 query 参数：gender, category, q(关键词), merchant_id, page, page_size
    """
    q = Product.query
    gender = request.args.get('gender')
    category = request.args.get('category')
    kw = request.args.get('q')
    merchant_id = request.args.get('merchant_id', type=int)

    if merchant_id:
        q = q.filter_by(merchant_id=merchant_id)
    if gender:
        q = q.filter_by(gender=gender)
    if category:
        q = q.filter_by(category=category)
    if kw:
        like = f"%{kw}%"
        q = q.filter(Product.title.ilike(like))

    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 20, type=int)
    items = q.order_by(Product.id.desc()).paginate(page=page, per_page=page_size, error_out=False)

    data = []
    for p in items.items:
        data.append({
            "id": p.id,
            "merchant_id": p.merchant_id,
            "title": p.title,
            "price": p.price,
            "category": p.category,
            "gender": p.gender,
            "sizes": p.sizes,
            "colors": p.colors,
            "image": p.image_path
        })
    return jsonify({
        "items": data,
        "page": items.page,
        "pages": items.pages,
        "total": items.total
    })

# -------------------------
# 初始化数据库（放最后，确保模型已加载）
# -------------------------
with app.app_context():
    db.create_all()

# -------------------------
# 本地启动
# -------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

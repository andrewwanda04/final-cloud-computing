import json
import midtransclient
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# 1. SETUP APLIKASI
app = Flask(__name__)
app.config['SECRET_KEY'] = 'rahasia_kelompok_1'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///loker.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# SETUP LOGIN MANAGER (Satpam)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Kalau belum login, lempar ke sini

# SETUP MIDTRANS (Ganti dengan Key Sandbox Kamu)
MIDTRANS_SERVER_KEY = 'Mid-server-czCsYyrgmS-0QY4R4BeZhwD1'  
MIDTRANS_CLIENT_KEY = 'Mid-client-tNWToejSoxiwJGJo'  

snap = midtransclient.Snap(
    is_production=False,
    server_key=MIDTRANS_SERVER_KEY,
    client_key=MIDTRANS_CLIENT_KEY
)

# 2. MODEL DATABASE
# Tambah UserMixin biar dikenali Flask-Login
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False) # Password di-hash biar aman
    role = db.Column(db.String(20), default='user') # 'user' atau 'admin'

class Locker(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nomor = db.Column(db.String(10), unique=True, nullable=False)
    lokasi = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), default='Tersedia')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 3. ROUTE AUTH (LOGIN/REGISTER)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        # Cek password hash
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Username atau Password salah!')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Cek user kembar
        if User.query.filter_by(username=username).first():
            flash('Username sudah dipakai!')
            return redirect(url_for('register'))
            
        # Bikin user baru (Password di-acak/hash)
        new_user = User(username=username, password=generate_password_hash(password, method='scrypt'))
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# 4. ROUTE UTAMA
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard')
@login_required # Wajib login buat masuk sini
def dashboard():
    daftar_loker = Locker.query.all()
    # current_user dikirim otomatis ke HTML buat ngecek dia admin/bukan
    return render_template('dashboard.html', lokers=daftar_loker, user=current_user)

# FITUR ADMIN: TAMBAH LOKER
@app.route('/add-locker', methods=['POST'])
@login_required
def add_locker():
    if current_user.role != 'admin':
        return "Eits, kamu bukan Admin!", 403
    
    nomor = request.form.get('nomor')
    lokasi = request.form.get('lokasi')
    
    new_locker = Locker(nomor=nomor, lokasi=lokasi)
    db.session.add(new_locker)
    db.session.commit()
    return redirect(url_for('dashboard'))

# FITUR ADMIN: RESET LOKER
@app.route('/reset-locker/<int:id>')
@login_required
def reset_locker(id):
    # Cuma ADMIN yang boleh reset
    if current_user.role != 'admin':
        return "Dilarang! Anda bukan Admin.", 403

    loker_target = Locker.query.get(id)
    if loker_target:
        loker_target.status = 'Tersedia'
        db.session.commit()
    return redirect(url_for('dashboard'))

# FITUR USER: BOOKING (DP 50%)
@app.route('/book/<int:id>')
@login_required
def book_locker(id):
    loker_target = Locker.query.get(id)
    if not loker_target or 'Tersedia' not in loker_target.status:
        return "Loker tidak tersedia!", 400

    # Hitung DP
    harga_full = 20000
    dp = 10000
    
    order_id = f"DP-{loker_target.nomor}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    param = {
        "transaction_details": {"order_id": order_id, "gross_amount": dp},
        "item_details": [{"id": f"LOKER-{id}", "price": dp, "quantity": 1, "name": f"DP Loker {loker_target.nomor}"}],
        "customer_details": {"first_name": current_user.username, "email": "user@telkom.ac.id"}
    }

    try:
        transaction = snap.create_transaction(param)
        token = transaction['token']
    except Exception as e:
        return f"Error Midtrans: {e}"

    return render_template('payment.html', loker=loker_target, token=token, client_key=MIDTRANS_CLIENT_KEY, harga_full=harga_full, harga_dp=dp)

@app.route('/payment-success/<int:id>')
@login_required
def payment_success(id):
    loker_target = Locker.query.get(id)
    if loker_target:
        loker_target.status = 'Terisi'
        db.session.commit()
    return redirect(url_for('dashboard'))

# UTILITY: SETUP DATABASE & ADMIN DEFAULT
@app.route('/setup-db')
def setup_db():
    with app.app_context():
        db.create_all()
        # Bikin Admin Default kalau belum ada
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password=generate_password_hash('admin123', method='scrypt'), role='admin')
            db.session.add(admin)
        
        if not Locker.query.first():
            db.session.add(Locker(nomor="A1", lokasi="Gedung TULT"))
        
        db.session.commit()
    return "Database Reset! Akun 'admin' (pass: admin123) telah dibuat."

if __name__ == '__main__':
    app.run(debug=True)
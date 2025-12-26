import json
import time
import midtransclient
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date
from authlib.integrations.flask_client import OAuth # <-- LIBRARY GOOGLE

# 1. SETUP APLIKASI
app = Flask(__name__)
app.config['SECRET_KEY'] = 'rahasia_kelompok_1'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///loker.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# SETUP LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# SETUP MIDTRANS
MIDTRANS_SERVER_KEY = 'Mid-server-czCsYyrgmS-0QY4R4BeZhwD1'  
MIDTRANS_CLIENT_KEY = 'Mid-client-tNWToejSoxiwJGJo'  

snap = midtransclient.Snap(
    is_production=False,
    server_key=MIDTRANS_SERVER_KEY,
    client_key=MIDTRANS_CLIENT_KEY
)

# --- SETUP GOOGLE OAUTH (BARU) ---
oauth = OAuth(app)
google = oauth.register(
    name='google',
    # !!! GANTI DUA BARIS DI BAWAH INI SAMA KODE DARI GOOGLE !!!
    client_id='880928398460-0q9dllk7i6t0247p9u53644ajcrrbuik.apps.googleusercontent.com', 
    client_secret='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', 
    # ----------------------------------------------------------
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)

# --- TRACKING PENGUNJUNG ---
@app.before_request
def track_visitor():
    # Anti-Crash pas Setup Database
    if request.endpoint == 'setup_db':
        return

    try:
        # 1. Cek Expired Subscription
        if current_user.is_authenticated and current_user.is_subscribed:
            if current_user.subscription_end and datetime.now() > current_user.subscription_end:
                current_user.is_subscribed = False
                current_user.subscription_end = None 
                db.session.commit()
                flash('Masa berlaku paket Anda telah habis.', 'warning')

        # 2. Catat Pengunjung (Grafik)
        if not request.path.startswith('/static') and not request.path.startswith('/favicon'):
            today = date.today()
            log = VisitorLog.query.filter_by(date=today).first()
            if log:
                log.count += 1
            else:
                new_log = VisitorLog(date=today, count=1)
                db.session.add(new_log)
            db.session.commit()
            
    except Exception as e:
        pass

# 2. MODEL DATABASE
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    email = db.Column(db.String(150), unique=True) 
    password = db.Column(db.String(150))
    role = db.Column(db.String(50))
    is_subscribed = db.Column(db.Boolean, default=False)
    subscription_end = db.Column(db.DateTime, nullable=True)

class Locker(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nomor = db.Column(db.String(10), unique=True, nullable=False)
    lokasi = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), default='Tersedia')

class VisitorLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False) 
    count = db.Column(db.Integer, default=0)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 3. ROUTE AUTH BIASA
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
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
        email = request.form.get('email') 

        if User.query.filter_by(username=username).first():
            flash('Username sudah dipakai!')
            return redirect(url_for('register'))
            
        new_user = User(username=username, email=email, password=generate_password_hash(password, method='scrypt'), role='user')
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

# --- ROUTE GOOGLE LOGIN (BARU) ---
@app.route('/login/google')
def google_login():
    # Arahkan user ke halaman login Google
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorized')
def google_authorize():
    try:
        token = google.authorize_access_token()
        resp = google.get('userinfo')
        user_info = resp.json()
        
        user_email = user_info['email']
        user_name = user_info['name'] 

        # Cek apakah user udah ada di database?
        user = User.query.filter_by(email=user_email).first()
        
        if not user:
            # Register Otomatis
            dummy_password = generate_password_hash('google_auth_user', method='scrypt')
            user = User(username=user_name, email=user_email, password=dummy_password, role='user')
            db.session.add(user)
            db.session.commit()
        
        login_user(user)
        flash(f'Login berhasil! Halo, {user.username}', 'success')
        return redirect(url_for('dashboard'))
    
    except Exception as e:
        flash(f'Gagal login Google: {e}', 'danger')
        return redirect(url_for('login'))


# 4. ROUTE UTAMA
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/dashboard')
@login_required
def dashboard():
    daftar_loker = Locker.query.all()
    all_users = []
    chart_labels = []
    chart_values = []

    if current_user.role == 'admin':
        all_users = User.query.all()
        logs = VisitorLog.query.order_by(VisitorLog.date.desc()).limit(7).all()
        for log in logs[::-1]:
            chart_labels.append(log.date.strftime('%d %b')) 
            chart_values.append(log.count)

    return render_template('dashboard.html', 
                           lokers=daftar_loker, 
                           user=current_user, 
                           all_users=all_users,
                           chart_labels=chart_labels,
                           chart_values=chart_values)

# FITUR ADMIN
@app.route('/add-locker', methods=['POST'])
@login_required
def add_locker():
    if current_user.role != 'admin':
        return "Access Denied", 403
    nomor = request.form.get('nomor')
    lokasi = request.form.get('lokasi')
    db.session.add(Locker(nomor=nomor, lokasi=lokasi))
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/reset-locker/<int:id>')
@login_required
def reset_locker(id):
    if current_user.role != 'admin':
        return "Access Denied", 403
    loker = Locker.query.get(id)
    loker.status = 'Tersedia'
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/admin/unsubscribe/<int:user_id>')
@login_required
def admin_unsubscribe(user_id):
    if current_user.role != 'admin':
        flash('Anda bukan Admin!', 'danger')
        return redirect(url_for('dashboard'))
    
    target = User.query.get(user_id)
    if target:
        target.is_subscribed = False
        target.subscription_end = None
        db.session.commit()
        flash(f'Langganan {target.username} berhasil dicabut!', 'success')
        
    return redirect(url_for('dashboard'))

# LOGIC BOOKING
@app.route('/booking/<int:loker_id>', methods=['POST'])
@login_required
def booking(loker_id):
    loker = Locker.query.get(loker_id)
    tipe_paket = request.form.get('paket') 
    
    if tipe_paket == 'semester':
        gross_amount = 500000
    elif tipe_paket == 'bulanan':
        gross_amount = 100000
    elif tipe_paket == 'testing':
        gross_amount = 1
    else: 
        gross_amount = 5000
        
    order_id = f"LOKER-{loker.id}-{int(time.time())}"
    
    param = {
        "transaction_details": {
            "order_id": order_id,
            "gross_amount": gross_amount
        },
        "customer_details": {
            "first_name": current_user.username,
            "email": current_user.email,
        },
        "item_details": [{
            "id": f"LOKER-{loker.id}",
            "price": gross_amount,
            "quantity": 1,
            "name": f"Sewa {tipe_paket} Loker {loker.nomor}"
        }]
    }

    try:
        transaction = snap.create_transaction(param)
        token = transaction['token']
    except Exception as e:
        return f"Error Midtrans: {e}"
    
    return render_template('payment.html', token=token, client_key=MIDTRANS_CLIENT_KEY, amount=gross_amount, loker=loker)

# PAYMENT FINISH
@app.route('/payment-finish/<int:loker_id>')
@login_required
def payment_finish(loker_id):
    current_user.is_subscribed = True
    current_user.subscription_end = datetime.now() + timedelta(days=30)
    
    loker = Locker.query.get(loker_id)
    if loker:
        loker.status = 'Terisi (Booked)'
    
    db.session.commit()
    flash('Pembayaran Berhasil! Paket Langganan Aktif.', 'success')
    return redirect(url_for('dashboard'))

# SETUP DB
@app.route('/setup-db')
def setup_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@test.com', password=generate_password_hash('admin123', method='scrypt'), role='admin')
            db.session.add(admin)
        if not Locker.query.first():
            db.session.add(Locker(nomor="A1", lokasi="TULT Lt.1"))
            db.session.add(Locker(nomor="B5", lokasi="GKU Lt.3"))
            db.session.add(Locker(nomor="C9", lokasi="Gedung Bangkit"))
        db.session.commit()
    return "Database Reset & Admin Created!"

if __name__ == '__main__':
    app.run(debug=True)
"""
⚡ FLASH KEY STORE — ULTIMATE ENTERPRISE PRODUCTION APPLICATION
Author: Elite Engineering Team
Architecture: Flask (Serverless Vercel-Ready) + MongoDB Atlas + FamGateway UPI
Security: HMAC-SHA256 Signatures, Atomic Inventory Locks, CSRF Protection, Anti-Replay
"""

import os
import re
import hmac
import json
import secrets
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps

# ---------------------------------------------------------------------------
# Resilient DNS Engine Setup (Permanent MongoDB Atlas SRV Fix)
# ---------------------------------------------------------------------------
try:
    import dns.resolver
    # Construct a dedicated, high-availability public resolver pool
    resilient_resolver = dns.resolver.Resolver(configure=False)
    resilient_resolver.nameservers = [
        "1.1.1.1",  # Cloudflare Primary
        "1.0.0.1",  # Cloudflare Secondary
        "8.8.8.8",  # Google Primary
        "8.8.4.4",  # Google Secondary
    ]
    resilient_resolver.timeout = 5.0
    resilient_resolver.lifetime = 5.0
    # Override dnspython's default resolver to prevent SRV lookup failures
    dns.resolver.default_resolver = resilient_resolver
except Exception as dns_err:
    logging.warning(f"Custom DNS resolver setup skipped: {dns_err}")

import requests
from bson.objectid import ObjectId
from flask import (
    Flask,
    request,
    session,
    redirect,
    url_for,
    render_template_string,
    jsonify,
    abort,
    flash,
)
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------------------------------------------------------
# Global App Setup & Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("FlashKeyStore")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("VERCEL_ENV") == "production"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)

MONGO_URI = os.environ.get(
    "MONGO_URI",
    "mongodb+srv://tusaropop7475_db_user:zY4MJmAQUaf1nZGd@cluster0.hu0hqpt.mongodb.net/?appName=Cluster0"
)
FAMGATEWAY_BASE_URL = os.environ.get("FAMGATEWAY_BASE_URL", "https://famgateway.in").rstrip("/")
FAMGATEWAY_API_KEY = os.environ.get("FAMGATEWAY_API_KEY", "fam_5fcfeea57257135beedda3a96909a0ca98be7cab")
FAMGATEWAY_WEBHOOK_SECRET = os.environ.get("FAMGATEWAY_WEBHOOK_SECRET", FAMGATEWAY_API_KEY)
SITE_URL = os.environ.get("SITE_URL", "http://127.0.0.1:5000").rstrip("/")

# ---------------------------------------------------------------------------
# MongoDB Database Singleton with Fallback & Diagnostics
# ---------------------------------------------------------------------------
_client = None
_db = None

def get_db():
    global _client, _db
    if _db is not None:
        return _db
    try:
        _client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=8000,
            socketTimeoutMS=15000,
            maxPoolSize=50,
            minPoolSize=2,
            retryWrites=True
        )
        _client.admin.command("ping")
        _db = _client.get_default_database("flashkeystore")
        _init_db_indexes(_db)
        logger.info("⚡ MongoDB Atlas cluster verified and connected successfully.")
        return _db
    except (ConnectionFailure, ServerSelectionTimeoutError) as err:
        logger.error(f"MongoDB Atlas connection failure: {err}")
        return None

def _init_db_indexes(database):
    try:
        database.users.create_index("email", unique=True)
        database.orders.create_index("order_id", unique=True)
        database.orders.create_index("gateway_order_id", sparse=True)
        database.licenses.create_index([("product_id", ASCENDING), ("status", ASCENDING)])
        database.licenses.create_index("license_key", unique=True)
        database.webhook_events.create_index("event_id", unique=True)
        database.audit_logs.create_index("timestamp", expireAfterSeconds=60 * 60 * 24 * 60)
    except Exception as e:
        logger.debug(f"Index provisioning note: {e}")

# ---------------------------------------------------------------------------
# Initial Product Catalog & Settings Seeder
# ---------------------------------------------------------------------------
DEFAULT_PLANS = [
    {"id": "1h", "name": "1 Hour VIP Pass", "duration_hours": 1, "price": 30, "popular": False, "active": True},
    {"id": "6h", "name": "6 Hours VIP Pass", "duration_hours": 6, "price": 50, "popular": False, "active": True},
    {"id": "12h", "name": "12 Hours VIP Pass", "duration_hours": 12, "price": 80, "popular": False, "active": True},
    {"id": "1d", "name": "1 Day VIP Pass", "duration_hours": 24, "price": 100, "popular": True, "active": True},
    {"id": "2d", "name": "2 Days VIP Pass", "duration_hours": 48, "price": 220, "popular": False, "active": True},
    {"id": "3d", "name": "3 Days VIP Pass", "duration_hours": 72, "price": 350, "popular": False, "active": True},
    {"id": "4d", "name": "4 Days VIP Pass", "duration_hours": 96, "price": 450, "popular": False, "active": True},
    {"id": "5d", "name": "5 Days VIP Pass", "duration_hours": 120, "price": 550, "popular": False, "active": True},
    {"id": "6d", "name": "6 Days VIP Pass", "duration_hours": 144, "price": 650, "popular": False, "active": True},
    {"id": "7d", "name": "7 Days VIP Pass", "duration_hours": 168, "price": 750, "popular": True, "active": True},
    {"id": "30d", "name": "30 Days VIP Pass", "duration_hours": 720, "price": 3000, "popular": True, "active": True},
]

def ensure_initial_data():
    database = get_db()
    if database is None:
        return
    if database.products.count_documents({}) == 0:
        prod_doc = {
            "slug": "flash-pro-suite",
            "name": "Flash Key Pro Suite",
            "tagline": "Pʀᴇᴍɪᴜᴍ Dɪɢɪᴛᴀʟ Pʀᴏᴅᴜᴄᴛs • Iɴsᴛᴀɴᴛ Dᴇʟɪᴠᴇʀʏ",
            "description": "High-performance enterprise activation keys delivering instant cloud software clearance.",
            "plans": DEFAULT_PLANS,
            "created_at": datetime.now(timezone.utc)
        }
        p_id = database.products.insert_one(prod_doc).inserted_id

        # Seed initial authentic license vault
        sample_keys = [
            f"FLASH-{secrets.token_hex(3).upper()}-{secrets.token_hex(4).upper()}-{secrets.token_hex(3).upper()}"
            for _ in range(25)
        ]
        for key in sample_keys:
            database.licenses.insert_one({
                "product_id": str(p_id),
                "license_key": key,
                "status": "available",
                "assigned_to": None,
                "order_id": None,
                "created_at": datetime.now(timezone.utc)
            })

    if database.settings.count_documents({}) == 0:
        database.settings.insert_one({
            "site_title": "FLASH KEY STORE",
            "tagline": "Pʀᴇᴍɪᴜᴍ Dɪɢɪᴛᴀʟ Pʀᴏᴅᴜᴄᴛs. Iɴsᴛᴀɴᴛ Dᴇʟɪᴠᴇʀʏ.",
            "announcement": "⚡ FLASH NODE ONLINE: 100% Automated UPI Deliveries Available 24/7.",
            "support_email": "tusaropop7475@gmail.com",
            "support_whatsapp": "9832810279",
            "maintenance_mode": False
        })

# ---------------------------------------------------------------------------
# Security Middlewares & Helpers
# ---------------------------------------------------------------------------
@app.before_request
def csrf_protect():
    if request.method == "POST":
        if request.path.startswith("/api/famgateway-webhook"):
            return
        token = session.get("_csrf_token")
        submitted_token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not token or not submitted_token or not hmac.compare_digest(token, submitted_token):
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"error": "Security validation failed (CSRF mismatch)."}), 403
            return render_template_string(
                BASE_LAYOUT,
                title="Security Alert",
                content="<div class='glass-card p-8 text-center text-red-400 font-bold'>CSRF session token expired or invalid. Please refresh the page and try again.</div>",
                current_year=datetime.now().year
            ), 403

def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

app.jinja_env.globals["csrf_token"] = generate_csrf_token

def customer_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to access your digital vault.", "info")
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("is_admin", False):
            flash("Administrator credential check required.", "error")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated

def log_audit(actor, action, details):
    database = get_db()
    if database is not None:
        database.audit_logs.insert_one({
            "actor": actor,
            "action": action,
            "details": details,
            "ip_address": request.headers.get("X-Forwarded-For", request.remote_addr),
            "timestamp": datetime.now(timezone.utc)
        })

# ---------------------------------------------------------------------------
# VIP Luxury Glassmorphic Design System
# ---------------------------------------------------------------------------
BASE_LAYOUT = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ title }} | Fʟᴀsʜ Kᴇʏ Sᴛᴏʀᴇ</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            midnight: '#080B14',
            deepnavy: '#10182B',
            brandblue: '#2563EB',
            brandcyan: '#00D9FF',
            brandpurple: '#8B5CF6',
            brandgold: '#F5C451',
          },
          fontFamily: {
            sans: ['"Plus Jakarta Sans"', 'sans-serif'],
            mono: ['"JetBrains Mono"', 'monospace'],
          }
        }
      }
    }
  </script>
  <style>
    body { background-color: #080B14; color: #F4F7FC; font-family: 'Plus Jakarta Sans', sans-serif; }
    .glass-nav { background: rgba(16, 24, 43, 0.85); backdrop-filter: blur(16px); border-bottom: 1px solid rgba(255, 255, 255, 0.08); }
    .glass-card { background: rgba(16, 24, 43, 0.7); backdrop-filter: blur(14px); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 1.25rem; transition: border-color 0.3s ease, box-shadow 0.3s ease; }
    .glass-card:hover { border-color: rgba(0, 217, 255, 0.35); box-shadow: 0 10px 30px -10px rgba(0, 217, 255, 0.15); }
    .btn-gradient { background: linear-gradient(135deg, #2563EB, #00D9FF); transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); }
    .btn-gradient:hover { filter: brightness(1.15); transform: translateY(-1.5px); box-shadow: 0 10px 25px -5px rgba(0, 217, 255, 0.4); }
    .btn-gold { background: linear-gradient(135deg, #F5C451, #D97706); }
    .glow-cyan { text-shadow: 0 0 25px rgba(0, 217, 255, 0.7); }
    .badge-vip { background: rgba(0, 217, 255, 0.12); border: 1px solid rgba(0, 217, 255, 0.3); color: #00D9FF; }
    @media (prefers-reduced-motion: reduce) { *, ::before, ::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; } }
  </style>
</head>
<body class="min-h-screen flex flex-col justify-between selection:bg-brandcyan selection:text-midnight">
  <!-- Top Luxury Announcement Header -->
  <div class="bg-gradient-to-r from-brandblue/30 via-brandpurple/20 to-brandblue/30 border-b border-white/10 text-xs py-2 px-4 text-center tracking-widest text-brandcyan font-semibold flex items-center justify-center space-x-2">
    <span>⚡ Fʟᴀsʜ Kᴇʏ Sᴛᴏʀᴇ</span>
    <span>•</span>
    <span>Pʀᴇᴍɪᴜᴍ Dɪɢɪᴛᴀʟ Pʀᴏᴅᴜᴄᴛs</span>
    <span>•</span>
    <span>Iɴsᴛᴀɴᴛ Dᴇʟɪᴠᴇʀʏ</span>
  </div>

  <!-- Navigation Bar -->
  <nav class="glass-nav sticky top-0 z-50 px-4 lg:px-12 py-3.5 flex items-center justify-between">
    <a href="/" class="flex items-center space-x-2.5">
      <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-brandblue to-brandcyan flex items-center justify-center font-black text-midnight shadow-lg shadow-brandblue/40 text-xl">⚡</div>
      <div>
        <span class="text-xl font-black tracking-tight text-white">FLASH <span class="text-brandcyan">KEY</span></span>
        <span class="hidden md:inline-block text-[10px] uppercase font-bold text-slate-400 tracking-wider ml-1">Sᴛᴏʀᴇ</span>
      </div>
    </a>

    <div class="hidden md:flex items-center space-x-8 text-sm font-semibold text-slate-300">
      <a href="/" class="hover:text-brandcyan transition-colors">Catalog</a>
      <a href="/#pricing" class="hover:text-brandcyan transition-colors">Subscriptions</a>
      <a href="/#benefits" class="hover:text-brandcyan transition-colors">Security</a>
      <a href="/#faq" class="hover:text-brandcyan transition-colors">Support</a>
    </div>

    <div class="flex items-center space-x-3 text-xs md:text-sm font-bold">
      {% if session.get('user_id') %}
        <a href="/dashboard" class="px-4 py-2 rounded-xl bg-white/5 border border-white/15 hover:border-brandcyan text-white transition-all flex items-center space-x-1.5">
          <span>Vault</span>
          <span class="w-2 h-2 rounded-full bg-brandcyan animate-pulse"></span>
        </a>
        <a href="/logout" class="px-3 py-2 text-slate-400 hover:text-white transition-colors">Logout</a>
      {% elif session.get('is_admin') %}
        <a href="/admin/dashboard" class="px-4 py-2 rounded-xl bg-brandpurple/30 border border-brandpurple text-brandpurple">Terminal</a>
        <a href="/admin/logout" class="px-3 py-2 text-slate-400 hover:text-white">Exit</a>
      {% else %}
        <a href="/login" class="px-4 py-2 text-slate-300 hover:text-white transition-colors">Sign In</a>
        <a href="/register" class="btn-gradient px-4 py-2 rounded-xl text-midnight font-black tracking-wide">Register</a>
      {% endif %}
    </div>
  </nav>

  <!-- Flash Notification Banners -->
  <div class="max-w-5xl mx-auto w-full px-4 pt-4">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
          <div class="mb-4 p-4 rounded-xl text-xs md:text-sm border flex items-center justify-between {% if category == 'error' %}bg-red-950/50 border-red-500/50 text-red-200{% elif category == 'success' %}bg-emerald-950/50 border-emerald-500/50 text-emerald-200{% else %}bg-blue-950/50 border-blue-500/50 text-blue-200{% endif %} shadow-lg">
            <span class="font-medium">{{ message }}</span>
            <button onclick="this.parentElement.remove()" class="text-white/70 hover:text-white font-bold ml-4 text-base">&times;</button>
          </div>
        {% endfor %}
      {% endif %}
    {% endwith %}
  </div>

  <!-- Dynamic Content Slot -->
  <main class="flex-grow w-full max-w-7xl mx-auto px-4 py-8">
    {{ content | safe }}
  </main>

  <!-- Modern Luxury Footer -->
  <footer class="bg-deepnavy/95 border-t border-white/10 py-12 px-4 mt-20 text-slate-400 text-xs">
    <div class="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-4 gap-8">
      <div class="space-y-3">
        <div class="flex items-center space-x-2">
          <div class="w-8 h-8 rounded-lg bg-gradient-to-tr from-brandblue to-brandcyan flex items-center justify-center font-bold text-midnight text-sm">⚡</div>
          <span class="text-base font-extrabold text-white">FLASH KEY STORE</span>
        </div>
        <p class="text-slate-500 leading-relaxed">
          Autonomous UPI fulfilment platform with instant cryptographic licence key delivery. 100% verified authentic activation software.
        </p>
      </div>
      <div>
        <h4 class="text-white font-bold mb-3 uppercase tracking-wider text-[11px]">Verification Node</h4>
        <p class="text-slate-400 leading-relaxed">Orders are verified via encrypted HMAC-SHA256 FamGateway webhooks. Keys are reserved atomically.</p>
      </div>
      <div>
        <h4 class="text-white font-bold mb-3 uppercase tracking-wider text-[11px]">Customer Care</h4>
        <p class="text-slate-400 leading-relaxed">WhatsApp: +91 98765 43210<br>Support: support@flashkeystore.com<br>24/7 Automated Dispatch</p>
      </div>
      <div>
        <h4 class="text-white font-bold mb-3 uppercase tracking-wider text-[11px]">Authorized Terminal</h4>
        <a href="/admin/login" class="text-slate-500 hover:text-brandcyan underline transition-colors">Admin Console &rarr;</a>
      </div>
    </div>
    <div class="max-w-7xl mx-auto mt-10 pt-6 border-t border-white/5 flex flex-col md:flex-row items-center justify-between text-slate-500">
      <span>&copy; {{ current_year }} FLASH KEY STORE. All Rights Reserved.</span>
      <span class="mt-2 md:mt-0 font-mono text-[10px]">Secure UPI • SHA-256 HMAC • Atomic Ingestion</span>
    </div>
  </footer>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# View: Catalog & Homepage
# ---------------------------------------------------------------------------
HOME_PAGE = """
<div class="space-y-24">
  <!-- Hero Section -->
  <section class="text-center py-12 md:py-20 relative overflow-hidden">
    <div class="inline-flex items-center space-x-2 px-4 py-1.5 rounded-full badge-vip text-xs font-bold mb-6 tracking-wider">
      <span>⚡ Vɪᴘ Aᴄᴛɪᴠᴀᴛɪᴏɴ Nᴏᴅᴇ</span>
      <span>•</span>
      <span>Iɴsᴛᴀɴᴛ UPI Dᴇʟɪᴠᴇʀʏ</span>
    </div>
    <h1 class="text-4xl sm:text-6xl font-black tracking-tight text-white mb-6 max-w-4xl mx-auto leading-tight">
      Legitimate Software Licences <br>
      <span class="text-transparent bg-clip-text bg-gradient-to-r from-brandcyan via-brandblue to-brandpurple glow-cyan">
        Delivered In 3 Seconds
      </span>
    </h1>
    <p class="text-slate-400 max-w-2xl mx-auto text-sm sm:text-base mb-10 leading-relaxed">
      Purchase authentic activation keys and digital subscriptions securely through FamGateway UPI. Verified instantly and stored securely in your private vault.
    </p>
    <div class="flex flex-wrap items-center justify-center gap-4">
      <a href="#pricing" class="btn-gradient px-8 py-4 rounded-xl font-black text-midnight text-sm tracking-wide shadow-xl shadow-brandcyan/20">
        Browse Subscription Tiers &rarr;
      </a>
      <a href="#benefits" class="px-8 py-4 rounded-xl font-bold bg-white/5 border border-white/10 hover:border-white/30 text-white text-sm transition-all">
        Why Flash Key?
      </a>
    </div>
  </section>

  <!-- Pricing Catalogue Section -->
  <section id="pricing" class="space-y-10">
    <div class="text-center max-w-xl mx-auto">
      <span class="text-xs font-bold text-brandcyan tracking-widest uppercase">Verified Tier Catalog</span>
      <h2 class="text-3xl font-black text-white mt-1">Select Your Access Pass</h2>
      <p class="text-slate-400 text-xs sm:text-sm mt-2">Guaranteed authentic keys. Pricing verified directly by our secure MongoDB backend.</p>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
      {% for plan in product.plans %}
        {% if plan.active %}
        <div class="glass-card p-6 flex flex-col justify-between relative transition-all duration-300 {% if plan.popular %}border-brandcyan shadow-xl shadow-brandcyan/10{% endif %}">
          {% if plan.popular %}
            <span class="absolute -top-3 right-4 px-3 py-1 rounded-full bg-gradient-to-r from-brandcyan to-brandblue text-[10px] font-black text-midnight uppercase tracking-wider shadow">
              Most Popular
            </span>
          {% endif %}
          <div>
            <div class="flex items-center justify-between mb-2">
              <h3 class="text-lg font-bold text-white">{{ plan.name }}</h3>
              <span class="text-xs font-mono text-brandcyan bg-brandcyan/10 px-2 py-0.5 rounded">{{ plan.duration_hours }}h</span>
            </div>
            <p class="text-xs text-slate-400 mb-6">Unrestricted digital suite clearance with instant delivery.</p>
            <div class="text-3xl font-extrabold text-white mb-6">
              ₹{{ plan.price }}<span class="text-xs font-normal text-slate-400"> / one-time</span>
            </div>
            <ul class="text-xs text-slate-300 space-y-2.5 mb-8">
              <li class="flex items-center space-x-2">
                <span class="text-brandcyan font-bold">✓</span>
                <span>Instant atomic vault delivery</span>
              </li>
              <li class="flex items-center space-x-2">
                <span class="text-brandcyan font-bold">✓</span>
                <span>FamGateway 24/7 UPI checkout</span>
              </li>
              <li class="flex items-center space-x-2">
                <span class="text-brandcyan font-bold">✓</span>
                <span>Permanent dashboard storage</span>
              </li>
            </ul>
          </div>

          <form action="/checkout/order" method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="hidden" name="product_id" value="{{ product._id }}">
            <input type="hidden" name="plan_id" value="{{ plan.id }}">
            <button type="submit" class="w-full py-3 rounded-xl text-xs font-black tracking-wide text-midnight {% if plan.popular %}btn-gradient{% else %}bg-white/10 hover:bg-white/20 text-white border border-white/10{% endif %} transition-all">
              Instant Activation
            </button>
          </form>
        </div>
        {% endif %}
      {% endfor %}
    </div>
  </section>

  <!-- Benefits Section -->
  <section id="benefits" class="grid grid-cols-1 md:grid-cols-3 gap-6 pt-6">
    <div class="glass-card p-6">
      <div class="w-12 h-12 rounded-xl bg-brandblue/20 border border-brandblue/40 flex items-center justify-center text-xl mb-4">⚡</div>
      <h3 class="text-white font-bold text-base mb-2">Immediate Auto-Dispatch</h3>
      <p class="text-slate-400 text-xs leading-relaxed">Our gateway daemon listens for signed UPI UTR confirmation. The second your payment clears, your legitimate licence key is delivered.</p>
    </div>
    <div class="glass-card p-6">
      <div class="w-12 h-12 rounded-xl bg-brandcyan/20 border border-brandcyan/40 flex items-center justify-center text-xl mb-4">🛡️</div>
      <h3 class="text-white font-bold text-base mb-2">Atomic Licence Reserve</h3>
      <p class="text-slate-400 text-xs leading-relaxed">No out-of-stock ghost sales. Our system atomically reserves genuine licences straight from our encrypted vault during payment processing.</p>
    </div>
    <div class="glass-card p-6">
      <div class="w-12 h-12 rounded-xl bg-brandpurple/20 border border-brandpurple/40 flex items-center justify-center text-xl mb-4">📱</div>
      <h3 class="text-white font-bold text-base mb-2">FamGateway UPI Ready</h3>
      <p class="text-slate-400 text-xs leading-relaxed">Scan QR or trigger seamless mobile UPI intents with Google Pay, PhonePe, Paytm, or BHIM with zero convenience surcharges.</p>
    </div>
  </section>

  <!-- FAQ Section -->
  <section id="faq" class="max-w-3xl mx-auto space-y-4 pt-6">
    <div class="text-center mb-8">
      <h2 class="text-2xl font-bold text-white">Frequently Answered Questions</h2>
      <p class="text-xs text-slate-400 mt-1">Everything you need to know about purchasing licences</p>
    </div>
    <div class="glass-card p-5">
      <h4 class="text-white font-bold text-xs mb-1">How soon do I receive my licence code?</h4>
      <p class="text-slate-400 text-xs">Instantly. Delivery is fully automated and dispatched the millisecond the bank marks the UPI transaction successful.</p>
    </div>
    <div class="glass-card p-5">
      <h4 class="text-white font-bold text-xs mb-1">What if the network interrupts during checkout?</h4>
      <p class="text-slate-400 text-xs">Our background webhook processor and server verification fallbacks match your bank UTR and allocate your key to your account dashboard regardless.</p>
    </div>
  </section>
</div>
"""

# ---------------------------------------------------------------------------
# View: Customer Vault & Dashboard
# ---------------------------------------------------------------------------
CUSTOMER_DASHBOARD = """
<div class="space-y-8">
  <div class="glass-card p-6 md:p-8 flex flex-col md:flex-row md:items-center justify-between gap-4">
    <div>
      <span class="text-xs uppercase tracking-widest text-brandcyan font-bold">Authorized Customer Portal</span>
      <h1 class="text-2xl md:text-3xl font-extrabold text-white mt-1">Hello, {{ user.name }}</h1>
      <p class="text-xs text-slate-400 mt-1">{{ user.email }} • Vault Status: <span class="text-emerald-400 font-semibold">Active & Synced</span></p>
    </div>
    <a href="/#pricing" class="btn-gradient px-5 py-3 rounded-xl text-xs font-black text-midnight self-start md:self-auto">
      + Purchase New Access Pass
    </a>
  </div>

  <div>
    <h2 class="text-lg font-bold text-white mb-4">Your Purchased Licences & Subscription Keys</h2>
    {% if orders %}
      <div class="space-y-4">
        {% for ord in orders %}
          <div class="glass-card p-5 md:p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div class="space-y-1.5">
              <div class="flex items-center space-x-3">
                <span class="font-bold text-white text-sm md:text-base">{{ ord.plan_name }}</span>
                <span class="px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider {% if ord.delivery_status == 'delivered' %}bg-emerald-950/80 text-emerald-400 border border-emerald-500/50{% elif ord.payment_status == 'pending' %}bg-amber-950/80 text-amber-400 border border-amber-500/50{% else %}bg-red-950/80 text-red-400 border border-red-500/50{% endif %}">
                  {{ ord.delivery_status }}
                </span>
              </div>
              <p class="text-xs text-slate-400 font-mono">Order: <span class="text-brandcyan">{{ ord.order_id }}</span> • Amount: ₹{{ ord.amount }}</p>
              {% if ord.utr %}
                <p class="text-[11px] text-slate-500 font-mono">Bank UTR: {{ ord.utr }}</p>
              {% endif %}
            </div>

            <div class="flex items-center gap-3">
              {% if ord.delivery_status == 'delivered' and ord.license_key %}
                <div class="bg-black/60 border border-brandcyan/40 px-4 py-2.5 rounded-xl flex items-center space-x-3 shadow-inner">
                  <span class="font-mono text-brandcyan font-bold text-xs sm:text-sm tracking-wider select-all" id="key-{{ ord.order_id }}">{{ ord.license_key }}</span>
                  <button onclick="copyLicence('{{ ord.order_id }}')" class="btn-gradient text-midnight font-bold text-xs px-3 py-1 rounded-lg transition-transform active:scale-95">
                    Copy
                  </button>
                </div>
              {% elif ord.payment_status == 'pending' %}
                <a href="/checkout/status/{{ ord.order_id }}" class="btn-gradient px-4 py-2.5 rounded-xl text-xs font-bold text-midnight">
                  Complete Payment &rarr;
                </a>
              {% else %}
                <span class="text-xs text-amber-400 font-medium bg-amber-950/40 px-3 py-1.5 rounded-lg border border-amber-500/30">
                  Stock allocation pending admin sync
                </span>
              {% endif %}
            </div>
          </div>
        {% endfor %}
      </div>
    {% else %}
      <div class="glass-card p-12 text-center text-slate-400 space-y-4">
        <div class="text-4xl">🔐</div>
        <p class="text-sm">Your private key vault is currently empty.</p>
        <a href="/#pricing" class="btn-gradient inline-block px-6 py-2.5 rounded-xl text-xs font-black text-midnight">Explore Plans</a>
      </div>
    {% endif %}
  </div>
</div>

<script>
  function copyLicence(orderId) {
    const el = document.getElementById('key-' + orderId);
    navigator.clipboard.writeText(el.innerText).then(() => {
      alert('⚡ Licence key copied to clipboard!');
    });
  }
</script>
"""

# ---------------------------------------------------------------------------
# View: Active Checkout & Polling Experience
# ---------------------------------------------------------------------------
CHECKOUT_PAGE = """
<div class="max-w-xl mx-auto space-y-6">
  <div class="glass-card p-6 md:p-8 space-y-6">
    <div class="border-b border-white/10 pb-4">
      <span class="text-xs uppercase tracking-wider text-brandcyan font-bold">FamGateway UPI Express</span>
      <h2 class="text-2xl font-black text-white mt-1">Complete Your Payment</h2>
      <p class="text-xs text-slate-400 font-mono mt-1">Order Ref: <span class="text-brandcyan">{{ order.order_id }}</span></p>
    </div>

    <div class="bg-black/40 p-5 rounded-2xl border border-white/5 space-y-3 text-xs">
      <div class="flex justify-between text-slate-400">
        <span>Licence Subscription</span>
        <span class="text-white font-bold">{{ order.plan_name }}</span>
      </div>
      <div class="flex justify-between text-slate-400">
        <span>Delivery Node</span>
        <span class="text-brandcyan font-medium">Instant Automatic Dispatch</span>
      </div>
      <div class="flex justify-between border-t border-white/5 pt-3 text-base font-extrabold text-white">
        <span>Total Payable (INR)</span>
        <span class="text-brandcyan font-mono">₹{{ order.amount }}</span>
      </div>
    </div>

    <!-- Polling Visual Feedback -->
    <div id="status-card" class="text-center py-6 px-4 bg-white/5 rounded-2xl border border-white/5 space-y-3">
      <div class="inline-block animate-spin rounded-full h-8 w-8 border-2 border-brandcyan border-t-transparent"></div>
      <p class="text-xs text-slate-300 font-medium" id="status-text">
        Waiting for UPI payment confirmation from FamGateway...
      </p>
      <p class="text-[11px] text-slate-500 font-mono">Polling node active (every 3.5s)</p>
    </div>

    <div class="space-y-3">
      {% if checkout_url %}
        <a href="{{ checkout_url }}" target="_blank" class="btn-gradient w-full py-4 rounded-xl font-black text-midnight text-center block text-xs uppercase tracking-wider shadow-xl shadow-brandcyan/20">
          Open UPI Gateway & Complete Payment &rarr;
        </a>
      {% endif %}

      <button onclick="manualVerify()" class="w-full py-3 rounded-xl text-xs font-bold bg-white/5 border border-white/10 hover:border-white/20 text-slate-300 transition-all">
        I Have Paid — Verify Status Now
      </button>
    </div>

    <p class="text-[11px] text-slate-500 text-center leading-relaxed">
      You may safely switch to your UPI app (Google Pay, PhonePe, Paytm). Do not close this browser tab; you will automatically be redirected upon payment clearance.
    </p>
  </div>
</div>

<script>
  const orderId = "{{ order.order_id }}";
  let checkCount = 0;
  const maxChecks = 160;

  async function checkOrder() {
    try {
      const res = await fetch(`/api/order-status/${orderId}`);
      const data = await res.json();
      if (data.status === "paid" || data.delivery_status === "delivered") {
        document.getElementById('status-card').innerHTML = `
          <div class="text-emerald-400 font-extrabold text-sm space-y-1">
            <div>⚡ Payment Confirmed!</div>
            <div class="text-xs font-normal text-slate-300">Licence dispatched to vault. Redirecting...</div>
          </div>
        `;
        setTimeout(() => { window.location.href = "/dashboard"; }, 1200);
      } else if (data.status === "failed") {
        document.getElementById('status-card').innerHTML = `
          <div class="text-red-400 font-bold text-xs">Payment verification reported failure or expiry.</div>
        `;
      }
    } catch (e) {
      console.warn("Polling network blip:", e);
    }
  }

  function manualVerify() {
    document.getElementById('status-text').innerText = "Querying live FamGateway verification node...";
    checkOrder();
  }

  const poller = setInterval(() => {
    checkCount++;
    if (checkCount > maxChecks) {
      clearInterval(poller);
      document.getElementById('status-text').innerText = "Checkout window timed out. Your order will update on your dashboard once cleared.";
      return;
    }
    checkOrder();
  }, 3500);
</script>
"""

# ---------------------------------------------------------------------------
# View: Admin Terminal & Full Catalog Suite
# ---------------------------------------------------------------------------
ADMIN_DASHBOARD = """
<div class="space-y-8">
  <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/10 pb-5">
    <div>
      <span class="text-xs uppercase tracking-widest text-brandpurple font-bold">Executive Control Terminal</span>
      <h1 class="text-2xl font-black text-white mt-1">System Overview & Analytics</h1>
    </div>
    <div class="flex flex-wrap items-center gap-2">
      <a href="/admin/licenses" class="px-3.5 py-2 bg-brandpurple/20 border border-brandpurple/40 text-brandpurple rounded-xl text-xs font-bold hover:bg-brandpurple/30">+ Stock Key Vault</a>
      <a href="/admin/plans" class="px-3.5 py-2 bg-white/5 border border-white/10 rounded-xl text-xs font-bold text-white hover:border-white/30">Edit Plans & Prices</a>
    </div>
  </div>

  <!-- Real-Time Metrics -->
  <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
    <div class="glass-card p-5">
      <div class="text-xs text-slate-400 font-medium">Total Revenue (Paid)</div>
      <div class="text-2xl font-black text-white mt-1">₹{{ stats.total_revenue }}</div>
    </div>
    <div class="glass-card p-5">
      <div class="text-xs text-slate-400 font-medium">Total Orders</div>
      <div class="text-2xl font-black text-brandcyan mt-1">{{ stats.total_orders }}</div>
    </div>
    <div class="glass-card p-5">
      <div class="text-xs text-slate-400 font-medium">Available Key Stock</div>
      <div class="text-2xl font-black text-emerald-400 mt-1">{{ stats.available_keys }}</div>
    </div>
    <div class="glass-card p-5">
      <div class="text-xs text-slate-400 font-medium">Registered Clients</div>
      <div class="text-2xl font-black text-brandgold mt-1">{{ stats.total_users }}</div>
    </div>
  </div>

  <!-- Search & Ledger -->
  <div class="glass-card p-6 space-y-4">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
      <h3 class="font-bold text-white text-sm">Real-Time Transaction Ledger</h3>
      <form method="GET" action="/admin/dashboard" class="flex gap-2">
        <input type="text" name="q" value="{{ query }}" placeholder="Search Order ID / Email..." class="bg-midnight border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-brandcyan">
        <button type="submit" class="px-3 py-1.5 bg-white/10 rounded-lg text-xs font-bold text-white">Search</button>
      </form>
    </div>

    <div class="overflow-x-auto">
      <table class="w-full text-left text-xs text-slate-300 font-mono">
        <thead class="border-b border-white/10 text-slate-400 uppercase text-[10px]">
          <tr>
            <th class="py-2.5">Order ID</th>
            <th>Customer</th>
            <th>Amount</th>
            <th>Payment</th>
            <th>Delivery</th>
            <th>Bank UTR</th>
            <th>Date</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-white/5">
          {% for ord in orders %}
            <tr>
              <td class="py-3 text-brandcyan font-bold">{{ ord.order_id }}</td>
              <td class="font-sans text-slate-200">{{ ord.customer_email }}</td>
              <td class="text-white font-bold font-sans">₹{{ ord.amount }}</td>
              <td>
                <span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold {% if ord.payment_status == 'paid' %}bg-emerald-950 text-emerald-400 border border-emerald-500/40{% else %}bg-amber-950 text-amber-400{% endif %}">
                  {{ ord.payment_status }}
                </span>
              </td>
              <td>
                <span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold {% if ord.delivery_status == 'delivered' %}bg-blue-950 text-brandcyan{% else %}bg-slate-800 text-slate-400{% endif %}">
                  {{ ord.delivery_status }}
                </span>
              </td>
              <td class="text-slate-400">{{ ord.utr or '-' }}</td>
              <td class="font-sans text-slate-500 text-[11px]">{{ ord.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</div>
"""

ADMIN_PLANS = """
<div class="max-w-4xl mx-auto space-y-6">
  <div class="flex items-center justify-between">
    <div>
      <h2 class="text-2xl font-bold text-white">Manage Subscription Plans & Prices</h2>
      <p class="text-xs text-slate-400">Updates sync in real-time to the MongoDB cluster</p>
    </div>
    <a href="/admin/dashboard" class="text-xs text-slate-400 hover:text-white">&larr; Return to Dashboard</a>
  </div>

  <div class="glass-card p-6 space-y-4">
    <div class="space-y-4">
      {% for plan in product.plans %}
        <form action="/admin/plans/edit" method="POST" class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 bg-midnight/50 border border-white/5 rounded-xl text-xs">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <input type="hidden" name="plan_id" value="{{ plan.id }}">
          <div class="w-48 font-bold text-white">{{ plan.name }}</div>
          <div class="flex items-center space-x-2">
            <span class="text-slate-400">₹</span>
            <input type="number" step="1" name="price" value="{{ plan.price }}" class="w-24 bg-deepnavy border border-white/10 rounded-lg p-1.5 text-xs text-white">
          </div>
          <div class="flex items-center space-x-2">
            <label class="text-slate-400">Active:</label>
            <input type="checkbox" name="active" value="1" {% if plan.active %}checked{% endif %}>
          </div>
          <div class="flex items-center space-x-2">
            <label class="text-slate-400">Popular:</label>
            <input type="checkbox" name="popular" value="1" {% if plan.popular %}checked{% endif %}>
          </div>
          <button type="submit" class="btn-gradient px-4 py-1.5 rounded-lg text-midnight font-bold text-xs">
            Save
          </button>
        </form>
      {% endfor %}
    </div>
  </div>
</div>
"""

# ---------------------------------------------------------------------------
# Core Customer Endpoints
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    database = get_db()
    if database is None:
        return render_template_string(
            BASE_LAYOUT,
            title="Database Offline",
            content="<div class='glass-card p-8 text-center text-red-400'>Database connection unestablished. Please check MONGO_URI and network access allowlist.</div>",
            current_year=datetime.now().year
        ), 500
    ensure_initial_data()
    product = database.products.find_one({"slug": "flash-pro-suite"})
    return render_template_string(
        BASE_LAYOUT,
        title="Instant Activation Store",
        content=render_template_string(HOME_PAGE, product=product),
        current_year=datetime.now().year
    )

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not name or not email or not password:
            flash("All registration fields are required.", "error")
            return redirect(url_for("register"))
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Please specify a valid email address.", "error")
            return redirect(url_for("register"))
        if len(password) < 8 or password != confirm:
            flash("Passwords must match and contain at least 8 characters.", "error")
            return redirect(url_for("register"))

        database = get_db()
        if database.users.find_one({"email": email}):
            flash("An account registered under this email already exists.", "error")
            return redirect(url_for("register"))

        uid = database.users.insert_one({
            "name": name,
            "email": email,
            "password_hash": generate_password_hash(password),
            "created_at": datetime.now(timezone.utc)
        }).inserted_id

        session["user_id"] = str(uid)
        session["user_name"] = name
        session["user_email"] = email
        flash("Registration successful. Welcome to FLASH KEY STORE.", "success")
        return redirect(url_for("dashboard"))

    form_body = """
    <div class="max-w-md mx-auto glass-card p-8 space-y-6">
      <div class="text-center">
        <h2 class="text-2xl font-bold text-white">Create Client Profile</h2>
        <p class="text-xs text-slate-400 mt-1">Automatic digital key storage vault</p>
      </div>
      <form method="POST" class="space-y-4">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <div>
          <label class="block text-xs text-slate-300 mb-1">Full Legal Name</label>
          <input type="text" name="name" required class="w-full bg-midnight border border-white/10 rounded-xl p-2.5 text-xs text-white focus:border-brandcyan focus:outline-none">
        </div>
        <div>
          <label class="block text-xs text-slate-300 mb-1">Email Address</label>
          <input type="email" name="email" required class="w-full bg-midnight border border-white/10 rounded-xl p-2.5 text-xs text-white focus:border-brandcyan focus:outline-none">
        </div>
        <div>
          <label class="block text-xs text-slate-300 mb-1">Password (Min 8 Chars)</label>
          <input type="password" name="password" minlength="8" required class="w-full bg-midnight border border-white/10 rounded-xl p-2.5 text-xs text-white focus:border-brandcyan focus:outline-none">
        </div>
        <div>
          <label class="block text-xs text-slate-300 mb-1">Confirm Password</label>
          <input type="password" name="confirm_password" minlength="8" required class="w-full bg-midnight border border-white/10 rounded-xl p-2.5 text-xs text-white focus:border-brandcyan focus:outline-none">
        </div>
        <button type="submit" class="btn-gradient w-full py-3 rounded-xl text-xs font-bold text-midnight tracking-wide">
          Register Customer Profile
        </button>
      </form>
    </div>
    """
    return render_template_string(BASE_LAYOUT, title="Client Registration", content=form_body, current_year=datetime.now().year)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        database = get_db()
        user = database.users.find_one({"email": email}) if database is not None else None

        if user and check_password_hash(user["password_hash"], password):
            session.permanent = True
            session["user_id"] = str(user["_id"])
            session["user_name"] = user["name"]
            session["user_email"] = user["email"]
            flash("Welcome back.", "success")
            return redirect(request.args.get("next") or url_for("dashboard"))

        flash("Invalid email or password combination.", "error")
        return redirect(url_for("login"))

    form_body = """
    <div class="max-w-md mx-auto glass-card p-8 space-y-6">
      <div class="text-center">
        <h2 class="text-2xl font-bold text-white">Client Authentication</h2>
        <p class="text-xs text-slate-400 mt-1">Access your purchased software vault</p>
      </div>
      <form method="POST" class="space-y-4">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <div>
          <label class="block text-xs text-slate-300 mb-1">Email Address</label>
          <input type="email" name="email" required class="w-full bg-midnight border border-white/10 rounded-xl p-2.5 text-xs text-white focus:border-brandcyan focus:outline-none">
        </div>
        <div>
          <label class="block text-xs text-slate-300 mb-1">Password</label>
          <input type="password" name="password" required class="w-full bg-midnight border border-white/10 rounded-xl p-2.5 text-xs text-white focus:border-brandcyan focus:outline-none">
        </div>
        <button type="submit" class="btn-gradient w-full py-3 rounded-xl text-xs font-bold text-midnight tracking-wide">
          Authenticate & Enter Vault
        </button>
      </form>
    </div>
    """
    return render_template_string(BASE_LAYOUT, title="Client Sign In", content=form_body, current_year=datetime.now().year)

@app.route("/logout")
def logout():
    session.clear()
    flash("Session concluded safely.", "info")
    return redirect(url_for("index"))

@app.route("/dashboard")
@customer_required
def dashboard():
    database = get_db()
    user = database.users.find_one({"_id": ObjectId(session["user_id"])})
    orders = list(database.orders.find({"customer_id": session["user_id"]}).sort("created_at", DESCENDING))
    return render_template_string(
        BASE_LAYOUT,
        title="My Vault",
        content=render_template_string(CUSTOMER_DASHBOARD, user=user, orders=orders),
        current_year=datetime.now().year
    )

# ---------------------------------------------------------------------------
# FamGateway Checkout Engine
# ---------------------------------------------------------------------------
@app.route("/checkout/order", methods=["POST"])
@customer_required
def create_order():
    database = get_db()
    product_id = request.form.get("product_id")
    plan_id = request.form.get("plan_id")

    try:
        product = database.products.find_one({"_id": ObjectId(product_id)})
    except Exception:
        abort(400, "Invalid product identifier")

    if not product:
        abort(404, "Product record unavailable")

    selected_plan = next((p for p in product.get("plans", []) if p["id"] == plan_id and p.get("active", True)), None)
    if not selected_plan:
        abort(400, "Requested duration tier is inactive or invalid.")

    order_id = f"FK-{datetime.now(timezone.utc).strftime('%y%m%d')}-{secrets.token_hex(4).upper()}"
    amount = float(selected_plan["price"])

    order_doc = {
        "order_id": order_id,
        "customer_id": session["user_id"],
        "customer_email": session["user_email"],
        "customer_name": session["user_name"],
        "product_id": str(product["_id"]),
        "product_name": product["name"],
        "plan_id": selected_plan["id"],
        "plan_name": selected_plan["name"],
        "duration_hours": selected_plan["duration_hours"],
        "amount": amount,
        "currency": "INR",
        "payment_status": "pending",
        "delivery_status": "pending",
        "gateway": "FamGateway",
        "gateway_order_id": None,
        "checkout_url": None,
        "transaction_id": None,
        "utr": None,
        "license_key": None,
        "created_at": datetime.now(timezone.utc),
        "paid_at": None,
        "delivered_at": None
    }
    database.orders.insert_one(order_doc)

    redirect_url = f"{SITE_URL}/checkout/status/{order_id}"
    webhook_url = f"{SITE_URL}/api/famgateway-webhook"

    headers = {"X-Api-Key": FAMGATEWAY_API_KEY, "Content-Type": "application/json"}
    payload = {
        "api_key": FAMGATEWAY_API_KEY,
        "amount": amount,
        "customer_name": session["user_name"],
        "customer_email": session["user_email"],
        "redirect_url": redirect_url,
        "webhook_url": webhook_url
    }

    try:
        res = requests.post(f"{FAMGATEWAY_BASE_URL}/api/create-order", json=payload, headers=headers, timeout=12)
        resp_data = res.json()
        logger.info(f"FamGateway order response for {order_id}: {resp_data}")

        if resp_data.get("status") in ["success", True, "200"]:
            data = resp_data.get("data", {})
            gateway_order_id = data.get("order_id")
            checkout_url = data.get("checkout_url")

            database.orders.update_one(
                {"order_id": order_id},
                {"$set": {"gateway_order_id": gateway_order_id, "checkout_url": checkout_url}}
            )
            return redirect(checkout_url or redirect_url)
    except Exception as exc:
        logger.error(f"FamGateway request error: {exc}")

    return redirect(url_for("checkout_status", order_id=order_id))

@app.route("/checkout/status/<order_id>")
@customer_required
def checkout_status(order_id):
    database = get_db()
    order = database.orders.find_one({"order_id": order_id, "customer_id": session["user_id"]})
    if not order:
        abort(404, "Order not found")

    if order.get("payment_status") == "paid" and order.get("delivery_status") == "delivered":
        return redirect(url_for("dashboard"))

    # Backend verification fallback
    _recheck_order_status_backend(order)
    order = database.orders.find_one({"order_id": order_id})

    return render_template_string(
        BASE_LAYOUT,
        title=f"Order Checkout — {order_id}",
        content=render_template_string(CHECKOUT_PAGE, order=order, checkout_url=order.get("checkout_url")),
        current_year=datetime.now().year
    )

@app.route("/api/order-status/<order_id>")
def order_status_api(order_id):
    database = get_db()
    order = database.orders.find_one({"order_id": order_id})
    if not order:
        return jsonify({"error": "Order not found"}), 404

    if order.get("payment_status") != "paid":
        _recheck_order_status_backend(order)
        order = database.orders.find_one({"order_id": order_id})

    return jsonify({
        "order_id": order["order_id"],
        "status": order.get("payment_status"),
        "delivery_status": order.get("delivery_status")
    })

# ---------------------------------------------------------------------------
# Atomic Delivery Core & Webhook Receiver
# ---------------------------------------------------------------------------
def _recheck_order_status_backend(order):
    if not FAMGATEWAY_API_KEY:
        return
    g_id = order.get("gateway_order_id") or order["order_id"]
    try:
        url = f"{FAMGATEWAY_BASE_URL}/api/verify-order.php?api_key={FAMGATEWAY_API_KEY}&order_id={g_id}"
        r = requests.get(url, timeout=7)
        data = r.json()
        if data.get("status") in ["success", True, "PAID", "COMPLETED"]:
            fulfill_order_atomic(
                order["order_id"],
                amount=float(data.get("amount", order["amount"])),
                transaction_id=str(data.get("transaction_id", "")),
                utr=str(data.get("utr", ""))
            )
    except Exception as e:
        logger.debug(f"Direct verification poll skipped: {e}")

def fulfill_order_atomic(order_id, amount, transaction_id, utr):
    database = get_db()
    if database is None:
        return False

    order = database.orders.find_one({"order_id": order_id})
    if not order or (order.get("payment_status") == "paid" and order.get("delivery_status") == "delivered"):
        return True

    if float(amount) < float(order["amount"]):
        logger.error(f"Underpayment alert for order {order_id}: Expected {order['amount']}, got {amount}")
        return False

    database.orders.update_one(
        {"order_id": order_id},
        {"$set": {
            "payment_status": "paid",
            "transaction_id": transaction_id,
            "utr": utr,
            "paid_at": datetime.now(timezone.utc)
        }}
    )

    # Atomic allocation from inventory pool
    licence = database.licenses.find_one_and_update(
        {"product_id": order["product_id"], "status": "available"},
        {"$set": {
            "status": "assigned",
            "assigned_to": order["customer_id"],
            "order_id": order_id,
            "assigned_at": datetime.now(timezone.utc)
        }}
    )

    if licence:
        database.orders.update_one(
            {"order_id": order_id},
            {"$set": {
                "delivery_status": "delivered",
                "license_key": licence["license_key"],
                "delivered_at": datetime.now(timezone.utc)
            }}
        )
        logger.info(f"⚡ Order {order_id} fulfilled with key {licence['license_key']}.")
        log_audit(order["customer_email"], "ORDER_DELIVERED", f"Issued key for {order_id}")
        return True
    else:
        database.orders.update_one(
            {"order_id": order_id},
            {"$set": {"delivery_status": "pending_stock"}}
        )
        logger.critical(f"STOCK DEPLETION: Order {order_id} has paid, but no available licences remain!")
        return False

@app.route("/api/famgateway-webhook", methods=["POST"])
def famgateway_webhook():
    signature = request.headers.get("X-FamGateway-Signature")
    raw_bytes = request.get_data()

    if not signature:
        return jsonify({"error": "Signature missing"}), 400

    expected_sig = hmac.new(
        FAMGATEWAY_WEBHOOK_SECRET.encode("utf-8"),
        raw_bytes,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_sig):
        logger.warning(f"Signature mismatch on webhook.")
        return jsonify({"error": "Invalid signature"}), 403

    try:
        payload = json.loads(raw_bytes.decode("utf-8"))
    except Exception:
        return jsonify({"error": "Malformed payload"}), 400

    event_id = payload.get("event_id") or payload.get("transaction_id") or payload.get("order_id")
    database = get_db()

    # Replay protection check
    if database.webhook_events.find_one({"event_id": event_id}):
        return jsonify({"status": "duplicate_ignored"}), 200

    database.webhook_events.insert_one({
        "event_id": event_id,
        "payload": payload,
        "received_at": datetime.now(timezone.utc)
    })

    if payload.get("status") in ["success", "SUCCESS", "PAID", "COMPLETED", True]:
        fulfill_order_atomic(
            order_id=payload.get("order_id"),
            amount=payload.get("amount"),
            transaction_id=payload.get("transaction_id", ""),
            utr=payload.get("utr", "")
        )

    return jsonify({"status": "acknowledged"}), 200

# ---------------------------------------------------------------------------
# Admin Terminal & Catalog Controls
# ---------------------------------------------------------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        admin_email = os.environ.get("ADMIN_EMAIL", "tusarmondal7475@gmail.com")
        admin_pass_hash = os.environ.get("ADMIN_PASSWORD_HASH")
        fallback_pass = os.environ.get("ADMIN_PASSWORD", "@FLASH_OWERR")

        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        authenticated = False
        if email.lower() == admin_email.lower():
            if admin_pass_hash and check_password_hash(admin_pass_hash, password):
                authenticated = True
            elif password == fallback_pass:
                authenticated = True

        if authenticated:
            session["is_admin"] = True
            session["admin_email"] = email
            log_audit(email, "ADMIN_LOGIN", "Console access granted")
            return redirect(url_for("admin_dashboard"))

        flash("Unauthorized administrative access attempt.", "error")
        return redirect(url_for("admin_login"))

    form_body = """
    <div class="max-w-md mx-auto glass-card p-8 space-y-6">
      <div class="text-center">
        <h2 class="text-2xl font-bold text-white">Administrator Terminal</h2>
        <p class="text-xs text-slate-400 mt-1">Environment signature validation</p>
      </div>
      <form method="POST" class="space-y-4">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <div>
          <label class="block text-xs text-slate-300 mb-1">Operator Email</label>
          <input type="email" name="email" required class="w-full bg-midnight border border-white/10 rounded-xl p-2.5 text-xs text-white">
        </div>
        <div>
          <label class="block text-xs text-slate-300 mb-1">Secret Key</label>
          <input type="password" name="password" required class="w-full bg-midnight border border-white/10 rounded-xl p-2.5 text-xs text-white">
        </div>
        <button type="submit" class="w-full py-3 rounded-xl text-xs font-bold bg-brandpurple text-white hover:bg-brandpurple/80 transition-all">
          Unlock Master Console
        </button>
      </form>
    </div>
    """
    return render_template_string(BASE_LAYOUT, title="Admin Sign In", content=form_body, current_year=datetime.now().year)

@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    session.pop("admin_email", None)
    return redirect(url_for("index"))

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    database = get_db()
    query = request.args.get("q", "").strip()

    filter_dict = {}
    if query:
        filter_dict = {"$or": [
            {"order_id": {"$regex": query, "$options": "i"}},
            {"customer_email": {"$regex": query, "$options": "i"}}
        ]}

    total_orders = database.orders.count_documents({})
    paid_orders = list(database.orders.find({"payment_status": "paid"}))
    total_revenue = sum(float(o.get("amount", 0)) for o in paid_orders)
    available_keys = database.licenses.count_documents({"status": "available"})
    total_users = database.users.count_documents({})
    orders = list(database.orders.find(filter_dict).sort("created_at", DESCENDING).limit(30))

    stats = {
        "total_revenue": total_revenue,
        "total_orders": total_orders,
        "available_keys": available_keys,
        "total_users": total_users
    }
    return render_template_string(
        BASE_LAYOUT,
        title="Admin Terminal",
        content=render_template_string(ADMIN_DASHBOARD, stats=stats, orders=orders, query=query),
        current_year=datetime.now().year
    )

@app.route("/admin/plans")
@admin_required
def admin_plans():
    database = get_db()
    product = database.products.find_one({"slug": "flash-pro-suite"})
    return render_template_string(
        BASE_LAYOUT,
        title="Edit Plans",
        content=render_template_string(ADMIN_PLANS, product=product),
        current_year=datetime.now().year
    )

@app.route("/admin/plans/edit", methods=["POST"])
@admin_required
def admin_plans_edit():
    database = get_db()
    plan_id = request.form.get("plan_id")
    price = float(request.form.get("price", 0))
    active = bool(request.form.get("active"))
    popular = bool(request.form.get("popular"))

    database.products.update_one(
        {"slug": "flash-pro-suite", "plans.id": plan_id},
        {"$set": {
            "plans.$.price": price,
            "plans.$.active": active,
            "plans.$.popular": popular
        }}
    )
    flash(f"Updated plan {plan_id} configuration.", "success")
    return redirect(url_for("admin_plans"))

@app.route("/admin/licenses")
@admin_required
def admin_licenses():
    database = get_db()
    products = list(database.products.find())
    view = """
    <div class="max-w-2xl mx-auto glass-card p-8 space-y-6">
      <div class="flex items-center justify-between">
        <h2 class="text-xl font-bold text-white">Deposit Key Inventory</h2>
        <a href="/admin/dashboard" class="text-xs text-slate-400 hover:text-white">&larr; Return</a>
      </div>
      <form action="/admin/licenses/add" method="POST" class="space-y-4">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <div>
          <label class="block text-xs text-slate-300 mb-1">Target Product</label>
          <select name="product_id" class="w-full bg-deepnavy border border-white/10 rounded-xl p-2.5 text-xs text-white">
            {% for prod in products %}
              <option value="{{ prod._id }}">{{ prod.name }}</option>
            {% endfor %}
          </select>
        </div>
        <div>
          <label class="block text-xs text-slate-300 mb-1">Licence Keys (One per line)</label>
          <textarea name="raw_keys" rows="8" placeholder="PRO-AAAA-BBBB-CCCC&#10;PRO-DDDD-EEEE-FFFF" required class="w-full bg-midnight border border-white/10 rounded-xl p-3 font-mono text-xs text-brandcyan focus:outline-none focus:border-brandcyan"></textarea>
        </div>
        <button type="submit" class="btn-gradient w-full py-3 rounded-xl text-xs font-black text-midnight">
          Stock Keys Into Vault
        </button>
      </form>
    </div>
    """
    return render_template_string(BASE_LAYOUT, title="Key Vault Deposit", content=render_template_string(view, products=products), current_year=datetime.now().year)

@app.route("/admin/licenses/add", methods=["POST"])
@admin_required
def admin_licenses_add():
    database = get_db()
    product_id = request.form.get("product_id")
    raw = request.form.get("raw_keys", "")
    lines = [k.strip() for k in raw.splitlines() if k.strip()]

    count = 0
    for key in lines:
        try:
            database.licenses.insert_one({
                "product_id": product_id,
                "license_key": key,
                "status": "available",
                "assigned_to": None,
                "order_id": None,
                "created_at": datetime.now(timezone.utc)
            })
            count += 1
        except Exception:
            pass

    log_audit(session.get("admin_email"), "VAULT_STOCK", f"Deposited {count} keys")
    flash(f"Successfully stocked {count} authentic licences into vault.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/healthz")
def health_check():
    database = get_db()
    is_ok = False
    if database is not None:
        try:
            database.command("ping")
            is_ok = True
        except Exception:
            pass
    return jsonify({
        "status": "online" if is_ok else "unhealthy",
        "dns_resolver": "active_cloudflare_google_mesh",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), (200 if is_ok else 503)

# ---------------------------------------------------------------------------
# Server Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

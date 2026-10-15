
import os, hmac, secrets, sqlite3
from functools import wraps
from flask import Flask, request, render_template_string, redirect, url_for, session, abort, flash
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
DB_PATH = os.environ.get("DATABASE_PATH", "registrations.db")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")

FORM = """
<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>استمارة التسجيل</title><style>
body{font-family:Arial;background:#f3f6fa;margin:0;padding:18px;color:#172235}main{max-width:560px;margin:20px auto;background:white;padding:24px;border-radius:15px;box-shadow:0 4px 20px #0001}
h1{font-size:24px}p{line-height:1.8;color:#475569}label{display:block;margin:15px 0 6px;font-weight:bold}
input[type=text],input[type=email],input[type=tel],input[type=password]{box-sizing:border-box;width:100%;padding:13px;border:1px solid #cbd5e1;border-radius:8px;font-size:16px}
.consent{display:flex;gap:10px;align-items:flex-start;line-height:1.8;font-weight:normal;margin:18px 0}.notice{background:#eff6ff;padding:12px;border-radius:8px}
button{width:100%;padding:13px;background:#175cd3;color:white;border:0;border-radius:8px;font-size:17px}
</style></head><body><main><h1>استمارة التسجيل</h1>
<p>يرجى إدخال المعلومات المطلوبة. ستستخدمها اللجنة المخوّلة للغرض التنظيمي المعلن فقط، وفق الإجراءات المعتمدة.</p>
<div class="notice">لا تطلب اللجنة كلمة مرور بريدك الإلكتروني أو رموز التحقق.</div>
<form method="post" action="/register"><input type="hidden" name="csrf_token" value="{{ csrf }}">
<label>الاسم الكامل</label><input name="full_name" type="text" maxlength="160" required>
<label>العنوان</label><input name="address" type="text" maxlength="300" required>
<label>اسم الأم الثلاثي</label><input name="mother_name" type="text" maxlength="160" required>
<label>رقم الهاتف</label><input name="phone" type="tel" maxlength="40" required>
<label>البريد الإلكتروني للتواصل عند تعذّر الاتصال الهاتفي</label><input name="email" type="email" maxlength="254" required>
<label class="consent"><input type="checkbox" name="consent" value="yes" required><span>أوافق على تقديم هذه المعلومات للجنة المخوّلة للغرض المعلن.</span></label>
<button type="submit">إرسال التسجيل</button></form></main></body></html>
"""
LOGIN = """
<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:Arial;background:#f3f6fa;padding:20px}main{max-width:420px;margin:40px auto;background:white;padding:24px;border-radius:12px}input{box-sizing:border-box;width:100%;padding:12px;margin:12px 0}button{padding:12px;width:100%}</style>
<main><h2>دخول إدارة التسجيلات</h2><p>لأعضاء اللجنة المخوّلين فقط.</p>{% with m=get_flashed_messages() %}{% if m %}<p>{{m[0]}}</p>{% endif %}{% endwith %}
<form method="post"><input type="hidden" name="csrf_token" value="{{csrf}}"><label>كلمة مرور الإدارة</label><input type="password" name="password" required><button>دخول</button></form></main>
"""
ADMIN = """
<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:Arial;background:#f3f6fa;padding:16px}main{background:white;padding:18px;border-radius:12px;overflow:auto}table{border-collapse:collapse;min-width:850px;width:100%}th,td{border:1px solid #ddd;padding:9px;text-align:right}th{background:#edf2f7}button{padding:8px}</style><main>
<h2>التسجيلات المستلمة</h2><form method="post" action="/admin/logout"><input type="hidden" name="csrf_token" value="{{csrf}}"><button>تسجيل الخروج</button></form>
<p>بيانات شخصية: لا تشاركها إلا مع المخوّلين. عدد التسجيلات المعروضة: {{rows|length}}</p>
<table><tr><th>وقت التسجيل UTC</th><th>الاسم</th><th>العنوان</th><th>اسم الأم</th><th>الهاتف</th><th>البريد الإلكتروني</th></tr>
{% for r in rows %}<tr>{% for v in r %}<td>{{v}}</td>{% endfor %}</tr>{% endfor %}</table></main>
"""

def db():
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.execute("""CREATE TABLE IF NOT EXISTS registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
    full_name TEXT NOT NULL, address TEXT NOT NULL, mother_name TEXT NOT NULL, phone TEXT NOT NULL, email TEXT NOT NULL)""")
    return c

def csrf():
    if "_csrf" not in session: session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]

def verify_csrf():
    a, b = request.form.get("csrf_token", ""), session.get("_csrf", "")
    if not a or not b or not hmac.compare_digest(a, b): abort(400)

def admin_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not session.get("admin"): return redirect("/admin/login")
        return fn(*a, **kw)
    return wrapped

@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Cache-Control"] = "no-store"
    r.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
    return r

@app.get("/")
def home(): return render_template_string(FORM, csrf=csrf())

@app.post("/register")
def register():
    verify_csrf()
    if request.form.get("consent") != "yes": abort(400)
    keys = ["full_name", "address", "mother_name", "phone", "email"]
    vals = [request.form.get(k, "").strip() for k in keys]
    limits = [160, 300, 160, 40, 254]
    if any(not v or len(v) > n for v, n in zip(vals, limits)): abort(400, "تحقق من الحقول")
    if "@" not in vals[4] or "." not in vals[4].split("@")[-1]: abort(400, "البريد الإلكتروني غير صالح")
    c = db()
    try: c.execute("INSERT INTO registrations(full_name,address,mother_name,phone,email) VALUES(?,?,?,?,?)", vals); c.commit()
    finally: c.close()
    return """<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><main style="font-family:Arial;max-width:500px;margin:40px auto;padding:24px"><h2>تم استلام التسجيل بنجاح</h2><p>شكرًا لك.</p></main></html>"""

@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if not ADMIN_PASSWORD_HASH: return ("يجب إعداد ADMIN_PASSWORD_HASH في إعدادات الاستضافة قبل تفعيل الإدارة.", 503)
    if request.method == "POST":
        verify_csrf()
        if check_password_hash(ADMIN_PASSWORD_HASH, request.form.get("password", "")):
            session.clear(); session["admin"] = True; session["_csrf"] = secrets.token_urlsafe(32)
            return redirect("/admin")
        flash("كلمة المرور غير صحيحة.")
    return render_template_string(LOGIN, csrf=csrf())

@app.get("/admin")
@admin_required
def admin():
    c = db()
    try: rows = c.execute("SELECT created_at,full_name,address,mother_name,phone,email FROM registrations ORDER BY id DESC LIMIT 2000").fetchall()
    finally: c.close()
    return render_template_string(ADMIN, rows=rows, csrf=csrf())

@app.post("/admin/logout")
@admin_required
def logout():
    verify_csrf(); session.clear(); return redirect("/admin/login")

@app.get("/health")
def health(): return {"status": "ok"}

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)

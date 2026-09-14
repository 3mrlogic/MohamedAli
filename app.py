from flask import Flask, request, jsonify, render_template, session, g, has_request_context, Response
from flask_cors import CORS
import json, os, re, smtplib, uuid, secrets, hmac, csv, io as _io, html as html_lib
from urllib.parse import quote
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from functools import wraps

from message_templates import TEMPLATES
import db as storage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# مسارات مطلقة: لازمة لأن نقطة الدخول على Vercel تقع داخل مجلد api/
app = Flask(__name__,
            template_folder=os.path.join(BASE_DIR, "templates"),
            static_folder=os.path.join(BASE_DIR, "static"))

# ---- مفتاح ثابت: يبقى بعد إعادة التشغيل حتى لا يُطلب تسجيل الدخول كل مرة ----
app.secret_key = storage.get_secret_key()
app.permanent_session_lifetime = timedelta(days=365)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_REFRESH_EACH_REQUEST=True,
)
CORS(app, supports_credentials=True)

VERSION     = "2.0"
SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT   = int(os.environ.get("SMTP_PORT", "587"))

# ====================== الإعدادات الافتراضية ======================
DEFAULT_SETTINGS = {
    "schoolName":  "أكاديمية الفجيرة العلمية الإسلامية",
    "logoUrl":     "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRlsLa51lTyeKI6ieC1Afuwu-3K7mTNXV-eWw&s",
    "headerNote":  "إدارة شؤون الطلبة",
    "greeting":    "السيد / السيدة الكريم، ولي أمر الطالب",
    "detailsTitle":"بيانات الإشعار",
    "messageTitle":"تفاصيل الرسالة",
    "pointsTitle": "نقاط مهمة",
    "actionTitle": "الإجراء المطلوب",
    "signName":    "إدارة المدرسة",
    "signTitle":   "قسم شؤون الطلبة",
    "contactText": "للتواصل مع الإدارة يُرجى الحضور خلال أوقات الدوام الرسمي أو الرد على هذا البريد.",
    "contactPhone":"",
    "contactEmail":"",
    "footerText":  "هذه رسالة رسمية صادرة عن إدارة المدرسة",
    "bg":          "#f0f2f5",
    "fontSize":    14,
    "showLogo":    True,
    "showDate":    True,
    "showBadge":   True,
    "showStudent": True,
    "showAvatar":  True,
    "showGreeting":True,
    "showDetails": True,
    "showPoints":  True,
    "showAction":  True,
    "showSignature": True,
    "showContact": True,
    "showFooter":  True,
    "showBars":    True,
}

DEFAULT_DB = {
    "classes": [], "students": [], "violations": [],
    "violation_count": 0, "auth": None,
    "settings": dict(DEFAULT_SETTINGS), "custom_templates": {},
}

# ====================== قاعدة البيانات ======================
def load_db():
    """
    يقرأ المستند مرة واحدة فقط لكل طلب.
    بدون هذا التخزين المؤقت يُقرأ المستند مرتين أو ثلاثاً في الطلب الواحد
    (مرة للتحقق من الجلسة ومرة للمعالج)، وهو ما يُبطئ العمل مع قاعدة بعيدة.
    """
    if has_request_context() and "db_doc" in g.__dict__:
        return g.db_doc

    db = storage.read_doc()
    if db is None:
        db = json.loads(json.dumps(DEFAULT_DB))
        save_db(db)
        return db
    db.setdefault("classes", [])
    db.setdefault("students", [])
    db.setdefault("violations", [])
    db.setdefault("violation_count", 0)
    db.setdefault("auth", None)
    db.setdefault("settings", dict(DEFAULT_SETTINGS))
    db.setdefault("custom_templates", {})
    for k, v in DEFAULT_SETTINGS.items():
        db["settings"].setdefault(k, v)
    if has_request_context():
        g.db_doc = db
    return db

def save_db(data):
    storage.write_doc(data)
    if has_request_context():
        g.db_doc = data

def gen_id(): return str(uuid.uuid4())[:8]

# ====================== الجلسات ======================
def current_token(db=None):
    db = db or load_db()
    return (db.get("auth") or {}).get("session_token")

def start_session(email, db):
    auth = db.get("auth") or {}
    if not auth.get("session_token"):
        auth["session_token"] = secrets.token_hex(16)
        db["auth"] = auth
        save_db(db)
    session.permanent = True
    session["logged_in"] = True
    session["email"] = email
    session["token"] = auth["session_token"]

def session_valid():
    if not session.get("logged_in"):
        return False
    tok = current_token()
    return bool(tok) and session.get("token") == tok

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session_valid():
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/api/auth/setup", methods=["POST"])
def auth_setup():
    """الإعداد الأول: البريد وكلمة مرور تطبيقات Gmail فقط — لا يوجد كود منفصل."""
    d = request.json
    email = d.get("email", "").strip().lower()
    smtp_pass = d.get("smtp_password", "").strip()
    if not email or not smtp_pass:
        return jsonify({"error": "البريد وكلمة مرور تطبيقات Gmail مطلوبان"}), 400
    db = load_db()
    old = db.get("auth") or {}
    db["auth"] = {"email": email, "smtp_password": smtp_pass,
                  "session_token": old.get("session_token") or secrets.token_hex(16)}
    save_db(db)
    start_session(email, db)
    return jsonify({"success": True})

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    """الدخول بكلمة مرور تطبيقات Gmail نفسها."""
    d = request.json
    email = d.get("email", "").strip().lower()
    pw    = (d.get("password") or d.get("smtp_password") or d.get("code") or "").strip()
    db = load_db()
    auth = db.get("auth")
    if not auth:
        return jsonify({"error": "لم يتم الإعداد بعد", "needs_setup": True}), 400

    # قفل مؤقت بعد 5 محاولات فاشلة خلال 10 دقائق
    now = datetime.now()
    failed = [t for t in (auth.get("failed") or [])
              if (now - datetime.fromisoformat(t)).total_seconds() < 600]
    if len(failed) >= 5:
        wait = 600 - int((now - datetime.fromisoformat(failed[0])).total_seconds())
        return jsonify({"error": "تم إيقاف الدخول مؤقتاً بعد محاولات خاطئة متكررة. حاول بعد %d دقيقة." % max(1, wait // 60),
                        "locked": True, "retry_after": wait}), 429

    stored = auth.get("smtp_password") or ""

    def same(a, b):
        # المقارنة بزمن ثابت حتى لا تُخمَّن كلمة المرور حرفاً حرفاً.
        # لا بد من الترميز إلى bytes وإلا رُفض أي محرف غير إنجليزي باستثناء.
        return hmac.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))

    same_mail = same(email, (auth.get("email") or "").lower())
    same_pw   = bool(stored) and same(pw, stored)
    # المسافات في كلمة مرور تطبيقات Google اختيارية (xxxx xxxx xxxx xxxx)
    if not same_pw and stored:
        same_pw = same(pw.replace(" ", ""), stored.replace(" ", ""))
    if not (same_mail and same_pw):
        failed.append(now.isoformat())
        auth["failed"] = failed
        db["auth"] = auth
        save_db(db)
        left = 5 - len(failed)
        msg = "البريد أو كلمة المرور غير صحيحة"
        if left <= 2:
            msg += " — متبقٍ %d محاولة قبل الإيقاف المؤقت" % left if left > 0 else ""
        return jsonify({"error": msg, "attempts_left": left}), 401

    if auth.get("failed"):
        auth["failed"] = []
        db["auth"] = auth
        save_db(db)
    start_session(email, db)
    return jsonify({"success": True})

@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    db = load_db()
    auth = db.get("auth")
    if auth:
        auth["session_token"] = secrets.token_hex(16)   # يُبطل كل الجلسات القديمة
        db["auth"] = auth
        save_db(db)
    session.clear()
    return jsonify({"success": True})

@app.route("/api/auth/status")
def auth_status():
    db = load_db()
    return jsonify({"logged_in": session_valid(), "has_setup": bool(db.get("auth"))})

@app.route("/api/auth/credentials")
@login_required
def get_credentials():
    auth = load_db().get("auth", {}) or {}
    return jsonify({"email": auth.get("email", ""), "has_password": bool(auth.get("smtp_password"))})

@app.route("/")
def index(): return render_template("index.html", version=VERSION)

# ====================== الإعدادات ======================
@app.route("/api/settings", methods=["GET"])
@login_required
def get_settings():
    return jsonify(load_db()["settings"])

@app.route("/api/settings", methods=["POST"])
@login_required
def save_settings():
    db = load_db()
    incoming = request.json or {}
    for k in DEFAULT_SETTINGS:
        if k in incoming:
            db["settings"][k] = incoming[k]
    save_db(db)
    return jsonify(db["settings"])

@app.route("/api/settings/reset", methods=["POST"])
@login_required
def reset_settings():
    db = load_db()
    db["settings"] = dict(DEFAULT_SETTINGS)
    save_db(db)
    return jsonify(db["settings"])

# ====================== القوالب ======================
def all_templates(db=None):
    db = db or load_db()
    out = {}
    for k, v in TEMPLATES.items():
        t = json.loads(json.dumps(v)); t["builtin"] = True; out[k] = t
    for k, v in (db.get("custom_templates") or {}).items():
        t = json.loads(json.dumps(v)); t["builtin"] = False; out[k] = t
    return out

@app.route("/api/templates")
@login_required
def get_templates():
    return jsonify(all_templates())

@app.route("/api/templates/custom", methods=["POST"])
@login_required
def save_custom_template():
    d = request.json or {}
    name = (d.get("label") or "").strip()
    if not name:
        return jsonify({"error": "اسم القالب مطلوب"}), 400
    db = load_db()
    key = d.get("key") or ("my_" + gen_id())
    if key in TEMPLATES:
        return jsonify({"error": "هذا المفتاح محجوز لقالب أساسي"}), 400
    db["custom_templates"][key] = {
        "label": name,
        "cat": (d.get("cat") or "قوالبي").strip() or "قوالبي",
        "icon": d.get("icon") or "⭐",
        "color": d.get("color") or "#0f5b8a",
        "subject": d.get("subject") or name,
        "opening": d.get("opening", ""),
        "message": d.get("message", ""),
        "points": [p for p in (d.get("points") or []) if str(p).strip()],
        "action": d.get("action", ""),
        "closing": d.get("closing", ""),
        "details": [r for r in (d.get("details") or []) if r and str(r[0]).strip()],
    }
    save_db(db)
    return jsonify({"success": True, "key": key, "template": db["custom_templates"][key]}), 201

@app.route("/api/templates/custom/<key>", methods=["DELETE"])
@login_required
def delete_custom_template(key):
    db = load_db()
    if key not in (db.get("custom_templates") or {}):
        return jsonify({"error": "القالب غير موجود"}), 404
    db["custom_templates"].pop(key)
    save_db(db)
    return jsonify({"success": True})

# ====================== الفصول ======================
@app.route("/api/classes", methods=["GET"])
@login_required
def get_classes():
    db = load_db()
    for c in db["classes"]:
        c["student_count"] = sum(1 for s in db["students"] if s["classId"] == c["id"])
    return jsonify(db["classes"])

@app.route("/api/classes", methods=["POST"])
@login_required
def add_class():
    d = request.json
    if not d.get("name"): return jsonify({"error": "اسم الفصل مطلوب"}), 400
    db = load_db()
    c = {"id": gen_id(), "name": d["name"].strip(), "icon": d.get("icon", "—"),
         "created_at": datetime.now().isoformat()}
    db["classes"].append(c); save_db(db)
    return jsonify(c), 201

@app.route("/api/classes/<cid>", methods=["DELETE"])
@login_required
def delete_class(cid):
    db = load_db()
    if any(s["classId"] == cid for s in db["students"]):
        return jsonify({"error": "لا يمكن حذف فصل يحتوي على طلاب"}), 400
    db["classes"] = [c for c in db["classes"] if c["id"] != cid]; save_db(db)
    return jsonify({"success": True})

# ====================== الطلبة ======================
@app.route("/api/students", methods=["GET"])
@login_required
def get_students():
    db = load_db(); cm = {c["id"]: c for c in db["classes"]}
    for s in db["students"]:
        cl = cm.get(s["classId"])
        s["class_name"] = cl["name"] if cl else "—"
        s["class_icon"] = cl["icon"] if cl else ""
    return jsonify(db["students"])

@app.route("/api/students", methods=["POST"])
@login_required
def add_student():
    d = request.json
    for f in ["name", "classId"]:
        if not d.get(f): return jsonify({"error": f"الحقل {f} مطلوب"}), 400
    db = load_db()
    if not any(c["id"] == d["classId"] for c in db["classes"]):
        return jsonify({"error": "الفصل غير موجود"}), 400
    s = {"id": gen_id(), "name": d["name"].strip(),
         "phone": d.get("phone", "").strip(),
         "phone2": d.get("phone2", "").strip(),
         "email": d.get("email", "").strip().lower(),
         "classId": d["classId"], "created_at": datetime.now().isoformat()}
    db["students"].append(s); save_db(db)
    return jsonify(s), 201

@app.route("/api/students/<sid>", methods=["PUT"])
@login_required
def update_student(sid):
    d = request.json or {}
    db = load_db()
    s = next((x for x in db["students"] if x["id"] == sid), None)
    if not s: return jsonify({"error": "الطالب غير موجود"}), 404
    if d.get("name"):  s["name"]   = d["name"].strip()
    if "phone"  in d:  s["phone"]  = (d.get("phone") or "").strip()
    if "phone2" in d:  s["phone2"] = (d.get("phone2") or "").strip()
    if "email"  in d:  s["email"]  = (d.get("email") or "").strip().lower()
    if d.get("classId") and any(c["id"] == d["classId"] for c in db["classes"]):
        s["classId"] = d["classId"]
    save_db(db)
    return jsonify(s)

@app.route("/api/students/<sid>", methods=["DELETE"])
@login_required
def delete_student(sid):
    db = load_db()
    db["students"] = [s for s in db["students"] if s["id"] != sid]; save_db(db)
    return jsonify({"success": True})

@app.route("/api/students/search")
@login_required
def search_students():
    q = request.args.get("q", "").strip().lower()
    db = load_db(); cm = {c["id"]: c for c in db["classes"]}
    results = []
    for s in db["students"]:
        cl = cm.get(s["classId"])
        s["class_name"] = cl["name"] if cl else "—"
        s["class_icon"] = cl.get("icon", "") if cl else ""
        hay = " ".join([s["name"].lower(), s.get("phone", ""), s.get("phone2", ""),
                        (s.get("email") or "").lower(), (cl["name"].lower() if cl else "")])
        if q in hay:
            results.append(s)
    return jsonify({"results": results, "total": len(db["students"])})

# ====================== بناء الرسالة ======================
def ar_date():
    months = ["يناير","فبراير","مارس","أبريل","مايو","يونيو",
              "يوليو","أغسطس","سبتمبر","أكتوبر","نوفمبر","ديسمبر"]
    n = datetime.now()
    return "%d %s %d" % (n.day, months[n.month - 1], n.year)

def fill(text, ctx):
    """يستبدل {student} {class} {school} {date} {phone} {email}"""
    if not isinstance(text, str): return text
    for k, v in ctx.items():
        text = text.replace("{%s}" % k, str(v or ""))
    return text

def e(t):
    """تهريب HTML — يمنع كسر التصميم أو حقن وسوم من نص المستخدم."""
    return html_lib.escape(str(t if t is not None else ""), quote=True)

def nl2br(t):
    return e(t).replace("\r\n", "\n").replace("\n", "<br>")

def student_ctx(student, class_name, st):
    return {
        "student": student.get("name", ""),
        "class":   class_name,
        "school":  st["schoolName"],
        "date":    ar_date(),
        "phone":   student.get("phone", ""),
        "email":   student.get("email", ""),
    }

def resolve_options(opts, student, class_name, db):
    """يستبدل المتغيّرات في كل نصوص الخيارات لطالب محدد (آمن على نص مُستبدَل مسبقاً)."""
    ctx = student_ctx(student, class_name, db["settings"])
    out = {}
    for k, v in (opts or {}).items():
        if isinstance(v, str):
            out[k] = fill(v, ctx)
        elif k == "points" and isinstance(v, list):
            out[k] = [fill(str(p), ctx) for p in v]
        elif k == "details" and isinstance(v, list):
            out[k] = [[fill(str(r[0]), ctx), fill(str(r[1]) if len(r) > 1 else "", ctx)] for r in v if r]
        else:
            out[k] = v
    out["studentName"] = ctx["student"]
    out["className"]   = ctx["class"]
    return out

def build_options(tmpl_key, student, class_name, db, overrides=None, keep_placeholders=False):
    """يبني حزمة الخيارات الكاملة: القالب + الإعدادات + تعديلات المستخدم."""
    st = db["settings"]
    tm = all_templates(db).get(tmpl_key) or all_templates(db)["custom"]
    if keep_placeholders:
        # للإرسال الجماعي: تبقى {student} و{class} كما هي وتُستبدل لكل طالب عند الإرسال
        ctx = {k: "{%s}" % k for k in ("student", "class", "school", "date", "phone", "email")}
        ctx["school"] = st["schoolName"]; ctx["date"] = ar_date()
    else:
        ctx = student_ctx(student, class_name, st)
    o = {
        "template": tmpl_key,
        "subject":  fill(tm.get("subject", ""), ctx),
        "accent":   tm.get("color", "#0f5b8a"),
        "bg":       st["bg"],
        "fontSize": st["fontSize"],

        "showBars":    st["showBars"],
        "showLogo":    st["showLogo"],
        "logoUrl":     st["logoUrl"],
        "schoolName":  st["schoolName"],
        "headerNote":  st["headerNote"],
        "showDate":    st["showDate"],
        "dateText":    ctx["date"],

        "showBadge":   st["showBadge"],
        "badgeIcon":   tm.get("icon", ""),
        "badgeLabel":  fill(tm.get("label", ""), ctx),
        "badgeCat":    tm.get("cat", ""),

        "showStudent": st["showStudent"],
        "showAvatar":  st["showAvatar"],
        "studentName": ctx["student"],
        "className":   ctx["class"],

        "showGreeting": st["showGreeting"],
        "greeting":     fill(st["greeting"], ctx),
        "opening":      fill(tm.get("opening", ""), ctx),

        "showDetails":  st["showDetails"],
        "detailsTitle": st["detailsTitle"],
        "details":      [[fill(r[0], ctx), fill(r[1], ctx)] for r in (tm.get("details") or [])],

        "messageTitle": st["messageTitle"],
        "message":      fill(tm.get("message", ""), ctx),

        "showPoints":   st["showPoints"],
        "pointsTitle":  st["pointsTitle"],
        "points":       [fill(p, ctx) for p in (tm.get("points") or [])],

        "showAction":   st["showAction"],
        "actionTitle":  st["actionTitle"],
        "action":       fill(tm.get("action", ""), ctx),

        "showButton":   False,
        "buttonText":   "",
        "buttonUrl":    "",

        "closing":      fill(tm.get("closing", ""), ctx),

        "showSignature": st["showSignature"],
        "signName":      fill(st["signName"], ctx),
        "signTitle":     fill(st["signTitle"], ctx),

        "showContact":  st["showContact"],
        "contactText":  fill(st["contactText"], ctx),
        "contactPhone": st["contactPhone"],
        "contactEmail": st["contactEmail"],

        "showFooter":   st["showFooter"],
        "footerText":   fill(st["footerText"], ctx),
    }
    if overrides:
        o.update({k: v for k, v in overrides.items() if v is not None})
    return o

def build_email_html(o):
    """يبني الرسالة من الخيارات — كل جزء يظهر/يختفي ويُعدَّل بالكامل."""
    c   = o.get("accent") or "#0f5b8a"
    bg  = o.get("bg") or "#f0f2f5"
    fs  = int(o.get("fontSize") or 14)
    P   = "0 48px"          # الحشو الجانبي
    blocks = []

    def on(k): return bool(o.get(k))

    # الشريط العلوي
    if on("showBars"):
        blocks.append('<tr><td style="background:%s;height:5px;line-height:5px;font-size:0">&nbsp;</td></tr>' % c)

    # الترويسة
    logo = ''
    if on("showLogo") and o.get("logoUrl"):
        logo = ('<img src="%s" alt="" width="78" height="78" style="border-radius:50%%;'
                'object-fit:cover;display:block;margin:0 auto 14px;border:3px solid %s33">'
                % (e(o["logoUrl"]), c))
    note = ('<p style="margin:6px 0 0;font-size:12px;color:#8b93a3">%s</p>' % e(o.get("headerNote"))) if o.get("headerNote") else ''
    date = ('<p style="margin:8px 0 0;font-size:12px;color:#9aa0b0">%s</p>' % e(o.get("dateText"))) if on("showDate") else ''
    if o.get("schoolName") or logo:
        blocks.append(
            '<tr><td style="background:#ffffff;padding:34px 48px 24px;text-align:center;'
            'border-bottom:1px solid #f0f0f0">%s'
            '<h1 style="margin:0;font-size:19px;font-weight:700;color:#1a1a2e">%s</h1>%s%s</td></tr>'
            % (logo, e(o.get("schoolName")), note, date))

    # الشارة
    if on("showBadge") and (o.get("badgeLabel") or o.get("badgeIcon")):
        cat = ('&nbsp;&nbsp;·&nbsp;&nbsp;%s' % e(o.get("badgeCat"))) if o.get("badgeCat") else ''
        blocks.append(
            '<tr><td style="background:#fafafa;padding:20px 48px;text-align:center;border-bottom:1px solid #f0f0f0">'
            '<span style="display:inline-block;background:%s14;border:1px solid %s33;border-radius:6px;'
            'padding:8px 20px;font-size:13px;font-weight:600;color:%s">%s&nbsp;&nbsp;%s%s</span></td></tr>'
            % (c, c, c, e(o.get("badgeIcon")), e(o.get("badgeLabel")), cat))

    # بطاقة الطالب
    if on("showStudent") and o.get("studentName"):
        av = ''
        if on("showAvatar"):
            first = (str(o.get("studentName")).strip() or " ")[0]
            av = ('<td width="52" style="vertical-align:middle"><div style="width:52px;height:52px;'
                  'border-radius:50%%;background:%s18;color:%s;text-align:center;line-height:52px;'
                  'font-size:20px;font-weight:700">%s</div></td>' % (c, c, e(first)))
        blocks.append(
            '<tr><td style="padding:28px 48px 0">'
            '<table width="100%%" cellpadding="0" cellspacing="0" style="background:#fafafa;border:1px solid #eee;border-radius:8px">'
            '<tr><td style="padding:16px 20px"><table width="100%%" cellpadding="0" cellspacing="0"><tr>%s'
            '<td style="padding-right:14px;vertical-align:middle">'
            '<p style="margin:0 0 3px;font-size:16px;font-weight:700;color:#1a1a2e">%s</p>'
            '<p style="margin:0;font-size:13px;color:#8b93a3">%s</p></td></tr></table></td></tr></table></td></tr>'
            % (av, e(o.get("studentName")), e(o.get("className"))))

    # التحية + الافتتاحية
    if on("showGreeting") and (o.get("greeting") or o.get("opening")):
        g = ('<p style="margin:0 0 10px;font-size:%dpx;color:#4a5568;font-weight:600">%s</p>'
             % (fs + 1, e(o.get("greeting")))) if o.get("greeting") else ''
        op = ('<p style="margin:0;font-size:%dpx;color:#4a5568;line-height:2">%s</p>'
              % (fs, nl2br(o.get("opening")))) if o.get("opening") else ''
        blocks.append('<tr><td style="padding:26px 48px 0">%s%s</td></tr>' % (g, op))

    # جدول التفاصيل
    rows = [r for r in (o.get("details") or []) if r and str(r[0]).strip()]
    if on("showDetails") and rows:
        trs = "".join(
            '<tr><td style="padding:9px 16px;font-size:12.5px;color:#8b93a3;border-bottom:1px solid #f0f0f0;'
            'width:42%%">%s</td><td style="padding:9px 16px;font-size:13px;color:#2d3748;font-weight:600;'
            'border-bottom:1px solid #f0f0f0">%s</td></tr>' % (e(r[0]), e(r[1] if len(r) > 1 else ""))
            for r in rows)
        title = ('<p style="margin:0 0 10px;font-size:11px;letter-spacing:1px;color:#9aa0b0">%s</p>'
                 % e(o.get("detailsTitle"))) if o.get("detailsTitle") else ''
        blocks.append(
            '<tr><td style="padding:24px 48px 0">%s'
            '<table width="100%%" cellpadding="0" cellspacing="0" style="border:1px solid #eee;border-radius:8px">'
            '%s</table></td></tr>' % (title, trs))

    # نص الرسالة
    if str(o.get("message") or "").strip():
        title = ('<p style="margin:0 0 8px;font-size:11px;letter-spacing:1px;color:#9aa0b0">%s</p>'
                 % e(o.get("messageTitle"))) if o.get("messageTitle") else ''
        blocks.append(
            '<tr><td style="padding:24px 48px 0"><table width="100%%" cellpadding="0" cellspacing="0"><tr>'
            '<td width="4" style="background:%s;font-size:0;line-height:0">&nbsp;</td>'
            '<td style="background:#fafafa;border:1px solid #eee;border-right:none;padding:18px 22px;border-radius:0 8px 8px 0">'
            '%s<p style="margin:0;font-size:%dpx;color:#2d3748;line-height:2">%s</p>'
            '</td></tr></table></td></tr>' % (c, title, fs, nl2br(o.get("message"))))

    # النقاط
    pts = [p for p in (o.get("points") or []) if str(p).strip()]
    if on("showPoints") and pts:
        lis = "".join(
            '<tr><td width="20" style="vertical-align:top;padding:5px 0 5px 8px;color:%s;font-size:13px">◂</td>'
            '<td style="padding:5px 0;font-size:%dpx;color:#4a5568;line-height:1.9">%s</td></tr>'
            % (c, fs - 1, e(p)) for p in pts)
        title = ('<p style="margin:0 0 6px;font-size:11px;letter-spacing:1px;color:#9aa0b0">%s</p>'
                 % e(o.get("pointsTitle"))) if o.get("pointsTitle") else ''
        blocks.append('<tr><td style="padding:22px 48px 0">%s<table width="100%%" cellpadding="0" cellspacing="0">%s</table></td></tr>'
                      % (title, lis))

    # الإجراء المطلوب
    if on("showAction") and str(o.get("action") or "").strip():
        title = ('<p style="margin:0 0 6px;font-size:11px;letter-spacing:1px;color:%s;font-weight:700">%s</p>'
                 % (c, e(o.get("actionTitle")))) if o.get("actionTitle") else ''
        blocks.append(
            '<tr><td style="padding:22px 48px 0">'
            '<table width="100%%" cellpadding="0" cellspacing="0" style="background:%s0d;border:1px solid %s2e;border-radius:8px">'
            '<tr><td style="padding:16px 20px">%s<p style="margin:0;font-size:%dpx;color:#2d3748;line-height:1.95">%s</p>'
            '</td></tr></table></td></tr>' % (c, c, title, fs, nl2br(o.get("action"))))

    # الزر
    if on("showButton") and o.get("buttonText"):
        href = e(o.get("buttonUrl") or "#")
        blocks.append(
            '<tr><td style="padding:24px 48px 0;text-align:center">'
            '<a href="%s" style="display:inline-block;background:%s;color:#ffffff;text-decoration:none;'
            'padding:12px 34px;border-radius:8px;font-size:14px;font-weight:600">%s</a></td></tr>'
            % (href, c, e(o.get("buttonText"))))

    # الخاتمة
    if str(o.get("closing") or "").strip():
        blocks.append('<tr><td style="padding:24px 48px 0"><p style="margin:0;font-size:%dpx;color:#718096;line-height:1.95">%s</p></td></tr>'
                      % (fs, nl2br(o.get("closing"))))

    # التوقيع
    if on("showSignature") and (o.get("signName") or o.get("signTitle")):
        t2 = ('<p style="margin:2px 0 0;font-size:12px;color:#9aa0b0">%s</p>' % e(o.get("signTitle"))) if o.get("signTitle") else ''
        blocks.append(
            '<tr><td style="padding:26px 48px 0"><table width="100%%" cellpadding="0" cellspacing="0">'
            '<tr><td style="border-top:1px solid #eee;padding-top:16px">'
            '<p style="margin:0;font-size:14px;font-weight:700;color:#1a1a2e">%s</p>%s'
            '</td></tr></table></td></tr>' % (e(o.get("signName")), t2))

    # التواصل
    if on("showContact") and (o.get("contactText") or o.get("contactPhone") or o.get("contactEmail")):
        line = []
        if o.get("contactPhone"): line.append('هاتف: %s' % e(o["contactPhone"]))
        if o.get("contactEmail"): line.append('بريد: %s' % e(o["contactEmail"]))
        extra = ('<p style="margin:8px 0 0;font-size:12.5px;color:%s;font-weight:600;direction:ltr;unicode-bidi:plaintext">%s</p>'
                 % (c, " &nbsp;·&nbsp; ".join(line))) if line else ''
        txt = ('<p style="margin:0;font-size:12.5px;color:#718096;line-height:1.9">%s</p>' % e(o.get("contactText"))) if o.get("contactText") else ''
        blocks.append(
            '<tr><td style="padding:22px 48px 0">'
            '<table width="100%%" cellpadding="0" cellspacing="0" style="background:#fafafa;border:1px solid #eee;border-radius:8px">'
            '<tr><td style="padding:14px 18px">%s%s</td></tr></table></td></tr>' % (txt, extra))

    # مساحة سفلية
    blocks.append('<tr><td style="height:30px;font-size:0;line-height:0">&nbsp;</td></tr>')

    # التذييل
    if on("showFooter"):
        blocks.append(
            '<tr><td style="background:#fafafa;border-top:1px solid #f0f0f0;padding:20px 48px;text-align:center">'
            '<p style="margin:0 0 5px;font-size:13px;font-weight:600;color:#1a1a2e">%s</p>'
            '<p style="margin:0;font-size:11.5px;color:#b0b8c8">%s</p></td></tr>'
            % (e(o.get("schoolName")), e(o.get("footerText"))))

    if on("showBars"):
        blocks.append('<tr><td style="background:%s;height:4px;line-height:4px;font-size:0">&nbsp;</td></tr>' % c)

    return """<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title></head>
<body style="margin:0;padding:0;background:%s;font-family:'Segoe UI',Tahoma,Arial,sans-serif">
<table width="100%%" cellpadding="0" cellspacing="0" style="background:%s;padding:36px 14px">
<tr><td align="center">
<table width="620" cellpadding="0" cellspacing="0" style="max-width:620px;width:100%%;background:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 4px 30px rgba(0,0,0,.07)">
%s
</table></td></tr></table></body></html>""" % (e(o.get("subject")), bg, bg, "\n".join(blocks))

def plain_text(o):
    """نسخة نصية بسيطة لعملاء البريد التي لا تدعم HTML."""
    parts = [o.get("schoolName", ""), "", o.get("badgeLabel", ""), "",
             o.get("greeting", ""), o.get("opening", ""), "", o.get("message", "")]
    if o.get("showPoints"):
        parts += ["", *["- " + str(p) for p in (o.get("points") or [])]]
    if o.get("showAction") and o.get("action"):
        parts += ["", str(o.get("actionTitle", "")) + ": " + str(o.get("action"))]
    parts += ["", o.get("closing", ""), "", o.get("signName", ""), o.get("signTitle", "")]
    return "\n".join(str(p) for p in parts if p is not None)

# ====================== واتساب ======================
def normalize_phone(p):
    """يحوّل الرقم إلى الصيغة الدولية بلا رموز: 0501234567 → 971501234567"""
    d = re.sub(r"\D", "", str(p or ""))
    if d.startswith("00"):
        d = d[2:]
    if d.startswith("0") and len(d) <= 10:          # رقم محلي إماراتي
        d = "971" + d[1:]
    return d if 8 <= len(d) <= 15 else ""

def whatsapp_text(o):
    """نسخة نصية منسّقة لواتساب من نفس خيارات الرسالة (*عريض* مدعوم)."""
    L = []
    def add(x=""):
        L.append(str(x))
    if o.get("schoolName"):
        add("*%s*" % o["schoolName"])
    if o.get("showBadge") and o.get("badgeLabel"):
        add("%s %s" % (o.get("badgeIcon", ""), o["badgeLabel"]))
    if o.get("showDate") and o.get("dateText"):
        add("📅 " + o["dateText"])
    add()
    if o.get("showStudent") and o.get("studentName"):
        add("👤 *%s*" % o["studentName"])
        if o.get("className"):
            add("🏫 " + o["className"])
        add()
    if o.get("showGreeting"):
        if o.get("greeting"): add(o["greeting"])
        if o.get("opening"):  add(o["opening"])
        add()
    rows = [r for r in (o.get("details") or []) if r and str(r[0]).strip()]
    if o.get("showDetails") and rows:
        if o.get("detailsTitle"): add("*%s*" % o["detailsTitle"])
        for r in rows:
            add("• %s: %s" % (r[0], r[1] if len(r) > 1 else ""))
        add()
    if str(o.get("message") or "").strip():
        if o.get("messageTitle"): add("*%s*" % o["messageTitle"])
        add(o["message"])
        add()
    pts = [p for p in (o.get("points") or []) if str(p).strip()]
    if o.get("showPoints") and pts:
        if o.get("pointsTitle"): add("*%s*" % o["pointsTitle"])
        for i, p in enumerate(pts, 1):
            add("%d. %s" % (i, p))
        add()
    if o.get("showAction") and str(o.get("action") or "").strip():
        add("⚠️ *%s*" % (o.get("actionTitle") or "الإجراء المطلوب"))
        add(o["action"])
        add()
    if o.get("showButton") and o.get("buttonText") and o.get("buttonUrl"):
        add("🔗 %s: %s" % (o["buttonText"], o["buttonUrl"]))
        add()
    if str(o.get("closing") or "").strip():
        add(o["closing"])
        add()
    if o.get("showSignature") and (o.get("signName") or o.get("signTitle")):
        if o.get("signName"):  add("*%s*" % o["signName"])
        if o.get("signTitle"): add(o["signTitle"])
    if o.get("showContact") and (o.get("contactPhone") or o.get("contactEmail")):
        add()
        if o.get("contactPhone"): add("📞 " + o["contactPhone"])
        if o.get("contactEmail"): add("✉️ " + o["contactEmail"])
    # إزالة الأسطر الفارغة المتتالية
    out, blank = [], False
    for x in L:
        if x.strip() == "":
            if not blank: out.append("")
            blank = True
        else:
            out.append(x); blank = False
    return "\n".join(out).strip()

@app.route("/api/violations/whatsapp", methods=["POST"])
@login_required
def whatsapp_violation():
    """يجهّز رابط واتساب بالرسالة، ويسجّلها في السجل عند commit=true."""
    d = request.json or {}
    student_id = d.get("studentId", "")
    tmpl_key   = d.get("template", "custom")
    db = load_db()
    student, class_name = _student_ctx(db, student_id)
    if not student:
        return jsonify({"error": "الطالب غير موجود"}), 404

    which = d.get("phone") or "phone"
    raw = student.get(which) or student.get("phone") or student.get("phone2") or ""
    phone = normalize_phone(raw)
    if not phone:
        return jsonify({"error": "هذا الطالب ليس له رقم هاتف صالح"}), 400

    opts = d.get("options") or build_options(tmpl_key, student, class_name, db,
                                             {"message": d.get("message")})
    opts = resolve_options(opts, student, class_name, db)
    text = whatsapp_text(opts)
    if not text.strip():
        return jsonify({"error": "الرسالة فارغة"}), 400
    url = "https://wa.me/%s?text=%s" % (phone, quote(text))

    if d.get("commit"):
        rec = {"id": gen_id(), "studentId": student_id, "studentName": student["name"],
               "studentEmail": student.get("email", ""), "studentPhone": phone,
               "className": class_name, "channel": "whatsapp",
               "message": opts.get("message") or opts.get("opening") or "",
               "subject": opts.get("subject") or opts.get("badgeLabel") or "",
               "template": tmpl_key, "templateLabel": opts.get("badgeLabel") or "—",
               "sent": True, "error": None, "created_at": datetime.now().isoformat()}
        db.setdefault("violations", []).append(rec)
        db["violation_count"] = db.get("violation_count", 0) + 1
        save_db(db)

    return jsonify({"success": True, "url": url, "phone": phone, "text": text})

# ====================== SMTP ======================
class _smtp_session:
    """اتصال SMTP واحد يُعاد استخدامه لعدة رسائل (أسرع بكثير في الإرسال الجماعي)."""
    def __init__(self, db):
        auth = db.get("auth", {}) or {}
        self.user = auth.get("email", "")
        self.pw   = auth.get("smtp_password", "")
        self.srv  = None
    def __enter__(self):
        self.srv = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=25)
        self.srv.starttls()
        self.srv.login(self.user, self.pw)
        return self.srv
    def __exit__(self, *a):
        try:
            self.srv.quit()
        except Exception:
            pass
        return False

def _smtp_send(srv, db, to_email, subject, html_body, text_body):
    sender = (db.get("auth", {}) or {}).get("email", "")
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to_email
    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))
    srv.sendmail(sender, to_email, msg.as_string())

# ====================== البلاغات ======================
def _student_ctx(db, student_id):
    cm = {c["id"]: c for c in db["classes"]}
    student = next((s for s in db["students"] if s["id"] == student_id), None)
    if not student:
        return None, None
    cl = cm.get(student["classId"])
    return student, (cl["name"] if cl else "غير محدد")

@app.route("/api/violations/defaults", methods=["POST"])
@login_required
def violation_defaults():
    """يرجع حزمة الخيارات الكاملة الجاهزة للتعديل في الواجهة."""
    d = request.json or {}
    db = load_db()
    student, class_name = _student_ctx(db, d.get("studentId", ""))
    if not student:
        student, class_name = {"name": "[اسم الطالب]", "email": "", "phone": ""}, "[الفصل]"
    return jsonify(build_options(d.get("template", "custom"), student, class_name, db,
                                 keep_placeholders=bool(d.get("bulk"))))

@app.route("/api/violations/preview", methods=["POST"])
@login_required
def preview_violation():
    d = request.json or {}
    opts = d.get("options")
    db = load_db()
    sid = d.get("previewStudentId") or d.get("studentId") or ""
    student, class_name = _student_ctx(db, sid)
    if not opts:
        if not student:
            student, class_name = {"name": "[اسم الطالب]", "email": "", "phone": ""}, "[الفصل]"
        opts = build_options(d.get("template", "custom"), student, class_name, db,
                             {"message": d.get("message")})
    elif student:
        opts = resolve_options(opts, student, class_name, db)
    return jsonify({"html": build_email_html(opts), "subject": opts.get("subject", "")})

@app.route("/api/violations", methods=["POST"])
@login_required
def send_violation():
    d = request.json or {}
    student_id = d.get("studentId", "")
    tmpl_key   = d.get("template", "custom")
    db = load_db()
    student, class_name = _student_ctx(db, student_id)
    if not student:
        return jsonify({"error": "الطالب غير موجود"}), 404
    if not student.get("email"):
        return jsonify({"error": "هذا الطالب ليس له بريد إلكتروني مسجّل"}), 400

    opts = d.get("options") or build_options(tmpl_key, student, class_name, db,
                                             {"message": d.get("message")})
    opts = resolve_options(opts, student, class_name, db)
    if not str(opts.get("message") or "").strip() and not str(opts.get("opening") or "").strip():
        return jsonify({"error": "الرسالة فارغة — اكتب نص الرسالة أولاً"}), 400

    html_body = build_email_html(opts)
    subject   = (opts.get("subject") or "رسالة من إدارة المدرسة").strip()
    if d.get("appendName", True):
        subject = "%s — %s" % (subject, student["name"])

    sent, send_error = False, None
    try:
        with _smtp_session(db) as srv:
            _smtp_send(srv, db, student["email"], subject, html_body, plain_text(opts))
        sent = True
    except Exception as ex:
        send_error = str(ex)

    rec = {"id": gen_id(), "studentId": student_id, "studentName": student["name"],
           "studentEmail": student["email"], "className": class_name, "channel": "email",
           "message": opts.get("message") or opts.get("opening") or "",
           "subject": subject, "template": tmpl_key,
           "templateLabel": opts.get("badgeLabel") or "—",
           "sent": sent, "error": send_error,
           "created_at": datetime.now().isoformat()}
    db.setdefault("violations", []).append(rec)
    db["violation_count"] = db.get("violation_count", 0) + 1
    save_db(db)

    if sent:
        return jsonify({"success": True, "record": rec, "htmlPreview": html_body})
    return jsonify({"success": False, "error": "فشل الإرسال: %s" % send_error,
                    "record": rec, "htmlPreview": html_body}), 207

@app.route("/api/violations", methods=["GET"])
@login_required
def get_violations():
    return jsonify(load_db().get("violations", []))

@app.route("/api/violations/<vid>", methods=["DELETE"])
@login_required
def delete_violation(vid):
    db = load_db()
    before = len(db.get("violations", []))
    db["violations"] = [v for v in db.get("violations", []) if v.get("id") != vid]
    if len(db["violations"]) == before:
        return jsonify({"error": "السجل غير موجود"}), 404
    save_db(db)
    return jsonify({"success": True, "remaining": len(db["violations"])})

@app.route("/api/violations/clear", methods=["POST"])
@login_required
def clear_violations():
    db = load_db()
    n = len(db.get("violations", []))
    db["violations"] = []
    save_db(db)
    return jsonify({"success": True, "deleted": n})

# ====================== الإرسال الجماعي ======================
@app.route("/api/violations/bulk", methods=["POST"])
@login_required
def send_bulk():
    """يرسل نفس الرسالة (بمتغيّراتها) لعدة طلبة عبر اتصال SMTP واحد."""
    d = request.json or {}
    ids = [str(x) for x in (d.get("studentIds") or [])][:200]
    if not ids:
        return jsonify({"error": "لم يتم اختيار أي طالب"}), 400
    tmpl_key = d.get("template", "custom")
    base = d.get("options") or {}
    db = load_db()
    if not str(base.get("message") or "").strip() and not str(base.get("opening") or "").strip():
        return jsonify({"error": "الرسالة فارغة"}), 400

    results, sent, failed, skipped = [], 0, 0, 0
    srv = None
    try:
        srv = _smtp_session(db).__enter__()
        smtp_err = None
    except Exception as ex:
        smtp_err = str(ex)

    for sid in ids:
        student, class_name = _student_ctx(db, sid)
        if not student:
            continue
        if not student.get("email"):
            skipped += 1
            results.append({"id": sid, "name": student["name"], "status": "skipped", "reason": "بدون بريد"})
            continue
        opts = resolve_options(base, student, class_name, db)
        subject = (opts.get("subject") or "رسالة من إدارة المدرسة").strip()
        if d.get("appendName", True):
            subject = "%s — %s" % (subject, student["name"])
        ok, err = False, smtp_err
        if srv is not None:
            try:
                _smtp_send(srv, db, student["email"], subject, build_email_html(opts), plain_text(opts))
                ok = True
            except Exception as ex:
                err = str(ex)
        rec = {"id": gen_id(), "studentId": sid, "studentName": student["name"],
               "studentEmail": student["email"], "className": class_name, "channel": "email",
               "message": opts.get("message") or opts.get("opening") or "",
               "subject": subject, "template": tmpl_key,
               "templateLabel": opts.get("badgeLabel") or "—", "bulk": True,
               "sent": ok, "error": err, "created_at": datetime.now().isoformat()}
        db.setdefault("violations", []).append(rec)
        if ok: sent += 1
        else:  failed += 1
        results.append({"id": sid, "name": student["name"], "status": "sent" if ok else "failed", "reason": err})
    if srv is not None:
        try: srv.quit()
        except Exception: pass
    db["violation_count"] = db.get("violation_count", 0) + sent
    save_db(db)
    return jsonify({"success": failed == 0, "sent": sent, "failed": failed, "skipped": skipped,
                    "results": results, "smtp_error": smtp_err})

@app.route("/api/violations/whatsapp/bulk", methods=["POST"])
@login_required
def whatsapp_bulk():
    """يجهّز رابط واتساب لكل طالب (الفتح والتسجيل يتمّان واحداً واحداً من الواجهة)."""
    d = request.json or {}
    ids = [str(x) for x in (d.get("studentIds") or [])][:200]
    base = d.get("options") or {}
    db = load_db()
    out = []
    for sid in ids:
        student, class_name = _student_ctx(db, sid)
        if not student: continue
        phone = normalize_phone(student.get("phone") or student.get("phone2"))
        if not phone:
            out.append({"id": sid, "name": student["name"], "phone": "", "url": ""}); continue
        opts = resolve_options(base, student, class_name, db)
        text = whatsapp_text(opts)
        out.append({"id": sid, "name": student["name"], "phone": phone,
                    "url": "https://wa.me/%s?text=%s" % (phone, quote(text))})
    return jsonify({"items": out})

# ====================== ملف الطالب ======================
@app.route("/api/students/<sid>/history")
@login_required
def student_history(sid):
    db = load_db()
    student, class_name = _student_ctx(db, sid)
    if not student:
        return jsonify({"error": "الطالب غير موجود"}), 404
    hist = [v for v in db.get("violations", []) if v.get("studentId") == sid]
    hist.sort(key=lambda v: v.get("created_at", ""), reverse=True)
    by_tmpl = {}
    for v in hist:
        by_tmpl[v.get("templateLabel") or "—"] = by_tmpl.get(v.get("templateLabel") or "—", 0) + 1
    return jsonify({"student": dict(student, class_name=class_name),
                    "history": hist, "count": len(hist),
                    "byTemplate": sorted(by_tmpl.items(), key=lambda x: -x[1])})

# ====================== الاستيراد ======================
@app.route("/api/students/import", methods=["POST"])
@login_required
def import_students():
    """يستورد صفوفاً (اسم، فصل، هاتف، هاتف2، بريد). يُنشئ الفصول الناقصة ويحدّث المكرر."""
    d = request.json or {}
    rows = d.get("rows") or []
    mode = d.get("mode", "update")          # update | skip
    db = load_db()
    by_name = {c["name"].strip(): c for c in db["classes"]}
    by_icon = {str(c.get("icon", "")).strip(): c for c in db["classes"]}
    existing = {(x["name"].strip(), x["classId"]): x for x in db["students"]}
    added = updated = skipped = 0
    new_classes = []
    now = datetime.now().isoformat()
    for r in rows[:2000]:
        name = str(r.get("name") or "").strip()
        cname = str(r.get("className") or "").strip()
        if not name or not cname:
            skipped += 1; continue
        cls = by_name.get(cname) or by_icon.get(cname)
        if not cls:
            cls = {"id": gen_id(), "name": cname, "icon": cname[:6], "created_at": now}
            db["classes"].append(cls); by_name[cname] = cls; new_classes.append(cname)
        key = (name, cls["id"])
        rec = {"name": name, "phone": str(r.get("phone") or "").strip(),
               "phone2": str(r.get("phone2") or "").strip(),
               "email": str(r.get("email") or "").strip().lower()}
        if key in existing:
            if mode == "skip":
                skipped += 1; continue
            ex = existing[key]
            for k in ("phone", "phone2", "email"):
                if rec[k]: ex[k] = rec[k]
            updated += 1
        else:
            st = dict(rec, id=gen_id(), classId=cls["id"], created_at=now)
            db["students"].append(st); existing[key] = st; added += 1
    save_db(db)
    return jsonify({"success": True, "added": added, "updated": updated, "skipped": skipped,
                    "newClasses": new_classes, "total": len(db["students"])})

# ====================== التصدير ======================
def _csv_response(rows, header, filename):
    buf = _io.StringIO()
    buf.write("\ufeff")                     # BOM حتى يفتحه Excel بالعربية صحيحاً
    w = csv.writer(buf)
    w.writerow(header)
    for r in rows: w.writerow(r)
    return Response(buf.getvalue(), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename*=UTF-8''%s" % quote(filename)})

@app.route("/api/export/students.csv")
@login_required
def export_students():
    db = load_db(); cm = {c["id"]: c for c in db["classes"]}
    cid = request.args.get("classId", "")
    rows = [(s["name"], cm.get(s["classId"], {}).get("name", ""), s.get("phone", ""),
             s.get("phone2", ""), s.get("email", ""))
            for s in db["students"] if not cid or s["classId"] == cid]
    return _csv_response(rows, ["الاسم", "الفصل", "الهاتف", "هاتف آخر", "البريد"], "الطلبة.csv")

@app.route("/api/export/log.csv")
@login_required
def export_log():
    db = load_db()
    rows = [(v.get("created_at", "")[:16].replace("T", " "), v.get("studentName", ""), v.get("className", ""),
             "واتساب" if v.get("channel") == "whatsapp" else "بريد",
             v.get("templateLabel", ""), v.get("subject", ""),
             v.get("studentPhone") or v.get("studentEmail", ""),
             "تم" if v.get("sent") else "فشل")
            for v in reversed(db.get("violations", []))]
    return _csv_response(rows, ["التاريخ", "الطالب", "الفصل", "القناة", "النوع", "الموضوع", "المرسَل إليه", "الحالة"], "سجل_الرسائل.csv")

# ====================== إحصائيات ======================
@app.route("/api/stats/insights")
@login_required
def insights():
    db = load_db(); cm = {c["id"]: c for c in db["classes"]}
    vios = db.get("violations", [])
    tmpls = all_templates(db)
    by_class, by_cat, by_student, by_chan = {}, {}, {}, {"email": 0, "whatsapp": 0}
    cutoff = (datetime.now() - timedelta(days=30)).isoformat()
    last30 = 0
    for v in vios:
        by_class[v.get("className", "—")] = by_class.get(v.get("className", "—"), 0) + 1
        cat = (tmpls.get(v.get("template"), {}) or {}).get("cat") or "أخرى"
        by_cat[cat] = by_cat.get(cat, 0) + 1
        k = (v.get("studentId"), v.get("studentName"), v.get("className"))
        by_student[k] = by_student.get(k, 0) + 1
        by_chan["whatsapp" if v.get("channel") == "whatsapp" else "email"] += 1
        if v.get("created_at", "") >= cutoff: last30 += 1
    top = sorted(by_student.items(), key=lambda x: -x[1])[:8]
    return jsonify({
        "total": len(vios), "last30": last30, "byChannel": by_chan,
        "byClass": sorted([{"name": k, "count": n} for k, n in by_class.items()], key=lambda x: -x["count"])[:10],
        "byCategory": sorted([{"name": k, "count": n} for k, n in by_cat.items()], key=lambda x: -x["count"]),
        "topStudents": [{"id": k[0], "name": k[1], "className": k[2], "count": n} for k, n in top],
        "noEmail": sum(1 for s in db["students"] if not s.get("email")),
        "noPhone": sum(1 for s in db["students"] if not s.get("phone") and not s.get("phone2")),
    })

@app.route("/api/stats")
@login_required
def get_stats():
    db = load_db()
    return jsonify({"total_students": len(db["students"]), "total_classes": len(db["classes"]),
                    "total_violations": len(db.get("violations", [])),
                    "avg_per_class": round(len(db["students"]) / len(db["classes"]), 1) if db["classes"] else 0})

@app.route("/api/health")
def health():
    """فحص سريع للتأكد أن الاتصال بقاعدة البيانات سليم بعد النشر."""
    try:
        db = load_db()
        return jsonify({"ok": True, "version": VERSION, "storage": storage.backend_name(),
                        "students": len(db["students"]), "classes": len(db["classes"]),
                        "has_setup": bool(db.get("auth"))})
    except Exception as ex:
        return jsonify({"ok": False, "storage": storage.backend_name(),
                        "error": str(ex)}), 500

if __name__ == "__main__":
    print("EduManager  ->  http://localhost:5000")
    print("storage:", "Postgres (Neon)" if storage.USING_POSTGRES else "local data.json")
    app.run(debug=True, port=5000)

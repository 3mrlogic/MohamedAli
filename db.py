# -*- coding: utf-8 -*-
"""
طبقة التخزين.

• على الإنترنت (Vercel): تُخزَّن البيانات في قاعدة Postgres على Neon،
  لأن نظام ملفات Vercel للقراءة فقط ويُمسح مع كل طلب.
• محلياً: تُخزَّن في ملف data.json كما كان، بدون أي إعداد إضافي.

يتم اختيار الوضع تلقائياً حسب وجود متغيّر البيئة DATABASE_URL.
"""
import os, json, secrets

# Neon/Vercel قد يضع الرابط تحت أيٍّ من هذه الأسماء
DB_URL = (os.environ.get("DATABASE_URL")
          or os.environ.get("POSTGRES_URL")
          or os.environ.get("NEON_DATABASE_URL")
          or "").strip()

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
FILE_PATH   = os.path.join(BASE_DIR, "data.json")
SECRET_FILE = os.path.join(BASE_DIR, ".secret_key")

USING_POSTGRES = bool(DB_URL)

# يُعاد استخدام الاتصال داخل نفس النسخة الدافئة من الدالة (Vercel يُبقيها حيّة
# بين الطلبات)، وتُنشأ الجداول مرة واحدة فقط — كل مصافحة TLS أو CREATE TABLE
# زائدة تعني رحلة ذهاب وإياب إضافية إلى القاعدة.
_conn = None
_schema_ready = False


# ───────────────────────────── Postgres ─────────────────────────────
def _dsn():
    url = DB_URL
    if "sslmode=" not in url:
        url += ("&" if "?" in url else "?") + "sslmode=require"
    return url


def _get_conn(fresh=False):
    global _conn, _schema_ready
    import psycopg2
    if fresh and _conn is not None:
        try:
            _conn.close()
        except Exception:
            pass
        _conn = None
        _schema_ready = False          # اتصال جديد ⇐ تحقّق من الجداول مرة أخرى

    if _conn is None or getattr(_conn, "closed", 0):
        _conn = psycopg2.connect(_dsn(), connect_timeout=10)
        try:
            _conn.autocommit = True
        except Exception:
            pass
        _schema_ready = False
    return _conn


def _ensure_schema(conn):
    global _schema_ready
    if _schema_ready:
        return
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_state (
                id         INT PRIMARY KEY,
                doc        JSONB NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_meta (
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL
            )""")
    _schema_ready = True


def _exec(fn):
    """
    يشغّل fn(cur) على اتصال مُعاد استخدامه.
    لو كان الاتصال قد انقطع (نوم الـcompute أو انتهاء المهلة) يُعاد الاتصال ويُحاول مرة أخرى.
    """
    import psycopg2
    for attempt in (0, 1):
        try:
            conn = _get_conn(fresh=(attempt == 1))
            _ensure_schema(conn)
            with conn.cursor() as cur:
                return fn(cur)
        except psycopg2.Error:
            if attempt == 1:      # فشلت المحاولة الثانية على اتصال جديد
                raise


def init_db():
    """ينشئ الجداول إن لم تكن موجودة."""
    if not USING_POSTGRES:
        return False
    _exec(lambda cur: None)
    return True


def _pg_read():
    def run(cur):
        cur.execute("SELECT doc FROM app_state WHERE id = 1")
        row = cur.fetchone()
        return row[0] if row else None
    return _exec(run)


def _pg_write(doc):
    payload = json.dumps(doc, ensure_ascii=False)
    def run(cur):
        cur.execute("""
            INSERT INTO app_state (id, doc) VALUES (1, %s::jsonb)
            ON CONFLICT (id) DO UPDATE
              SET doc = EXCLUDED.doc, updated_at = now()
        """, (payload,))
    _exec(run)


def _pg_meta_set_once(key, value):
    """يكتب القيمة فقط إن لم تكن موجودة، ويُرجع القيمة النهائية المخزَّنة."""
    def run(cur):
        cur.execute("""
            INSERT INTO app_meta (k, v) VALUES (%s, %s)
            ON CONFLICT (k) DO NOTHING
        """, (key, value))
        cur.execute("SELECT v FROM app_meta WHERE k = %s", (key,))
        row = cur.fetchone()
        return row[0] if row else value
    return _exec(run)


# ───────────────────────────── ملف محلي ─────────────────────────────
def _file_read():
    if not os.path.exists(FILE_PATH):
        return None
    with open(FILE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _file_write(doc):
    tmp = FILE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    os.replace(tmp, FILE_PATH)          # كتابة ذرّية تمنع تلف الملف


# ───────────────────────────── الواجهة ─────────────────────────────
def read_doc():
    return _pg_read() if USING_POSTGRES else _file_read()


def write_doc(doc):
    (_pg_write if USING_POSTGRES else _file_write)(doc)


def get_secret_key():
    """
    مفتاح توقيع الجلسات — يجب أن يكون ثابتاً وإلا طُلب تسجيل الدخول كل مرة.
    الأولوية: متغيّر البيئة ← قاعدة البيانات ← ملف محلي.
    """
    env = os.environ.get("SECRET_KEY", "").strip()
    if env:
        return env

    if USING_POSTGRES:
        try:
            return _pg_meta_set_once("secret_key", secrets.token_hex(32))
        except Exception:
            # لا نُسقط التطبيق لو تعذّر الوصول للقاعدة لحظة الإقلاع
            return secrets.token_hex(32)

    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "r", encoding="utf-8") as f:
            k = f.read().strip()
        if k:
            return k
    k = secrets.token_hex(32)
    with open(SECRET_FILE, "w", encoding="utf-8") as f:
        f.write(k)
    return k


def backend_name():
    return "Postgres (Neon)" if USING_POSTGRES else "ملف محلي data.json"

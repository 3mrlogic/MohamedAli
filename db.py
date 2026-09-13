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


# ───────────────────────────── Postgres ─────────────────────────────
def _connect():
    import psycopg2
    url = DB_URL
    if "sslmode=" not in url:
        url += ("&" if "?" in url else "?") + "sslmode=require"
    return psycopg2.connect(url, connect_timeout=10)


def _init_schema(cur):
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


def init_db():
    """ينشئ الجداول إن لم تكن موجودة — يُستدعى مرة واحدة."""
    if not USING_POSTGRES:
        return False
    with _connect() as conn:
        with conn.cursor() as cur:
            _init_schema(cur)
        conn.commit()
    return True


def _pg_read():
    with _connect() as conn:
        with conn.cursor() as cur:
            _init_schema(cur)
            cur.execute("SELECT doc FROM app_state WHERE id = 1")
            row = cur.fetchone()
        conn.commit()
    return row[0] if row else None


def _pg_write(doc):
    with _connect() as conn:
        with conn.cursor() as cur:
            _init_schema(cur)
            cur.execute("""
                INSERT INTO app_state (id, doc) VALUES (1, %s::jsonb)
                ON CONFLICT (id) DO UPDATE
                  SET doc = EXCLUDED.doc, updated_at = now()
            """, (json.dumps(doc, ensure_ascii=False),))
        conn.commit()


def _pg_meta_get(key):
    with _connect() as conn:
        with conn.cursor() as cur:
            _init_schema(cur)
            cur.execute("SELECT v FROM app_meta WHERE k = %s", (key,))
            row = cur.fetchone()
        conn.commit()
    return row[0] if row else None


def _pg_meta_set_once(key, value):
    """يكتب القيمة فقط إن لم تكن موجودة، ويُرجع القيمة النهائية المخزَّنة."""
    with _connect() as conn:
        with conn.cursor() as cur:
            _init_schema(cur)
            cur.execute("""
                INSERT INTO app_meta (k, v) VALUES (%s, %s)
                ON CONFLICT (k) DO NOTHING
            """, (key, value))
            cur.execute("SELECT v FROM app_meta WHERE k = %s", (key,))
            row = cur.fetchone()
        conn.commit()
    return row[0] if row else value


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

# -*- coding: utf-8 -*-
"""
رفع البيانات المحلية (data.json) إلى قاعدة Neon.

الاستخدام:
    set DATABASE_URL=postgresql://...            (Windows CMD)
    $env:DATABASE_URL="postgresql://..."         (PowerShell)
    python migrate_to_neon.py

خيارات:
    --no-auth     لا تنقل بيانات الدخول وكلمة مرور البريد (تُعاد الإعداد على الموقع)
    --force       الكتابة فوق بيانات موجودة في القاعدة
"""
import io, json, os, sys

sys.stdout.reconfigure(encoding="utf-8")

BASE = os.path.dirname(os.path.abspath(__file__))
LOCAL = os.path.join(BASE, "data.json")

NO_AUTH = "--no-auth" in sys.argv
FORCE   = "--force" in sys.argv


def die(msg):
    print("\n[خطأ] " + msg + "\n")
    sys.exit(1)


url = (os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL") or "").strip()
if not url:
    die("لم يتم ضبط DATABASE_URL.\n"
        '       PowerShell:  $env:DATABASE_URL="postgresql://user:pass@host/db?sslmode=require"')

if not os.path.exists(LOCAL):
    die("ملف data.json غير موجود في مجلد المشروع.")

try:
    import psycopg2  # noqa
except ImportError:
    die("المكتبة psycopg2 غير مثبّتة. شغّل:  pip install psycopg2-binary")

import db as storage   # يلتقط DATABASE_URL تلقائياً

if not storage.USING_POSTGRES:
    die("طبقة التخزين لم تلتقط رابط القاعدة — تأكد من ضبط DATABASE_URL في نفس النافذة.")

doc = json.load(io.open(LOCAL, encoding="utf-8"))

print("=" * 58)
print(" رفع البيانات المحلية إلى Neon")
print("=" * 58)
print("  الفصول            : %d" % len(doc.get("classes", [])))
print("  الطلبة            : %d" % len(doc.get("students", [])))
print("  الرسائل المُرسلة   : %d" % len(doc.get("violations", [])))
print("  القوالب المخصصة   : %d" % len(doc.get("custom_templates", {}) or {}))

if NO_AUTH and doc.get("auth"):
    doc["auth"] = None
    print("  بيانات الدخول     : لن تُنقل (--no-auth)")
elif doc.get("auth"):
    print("  بيانات الدخول     : ستُنقل (تشمل كلمة مرور البريد)")
else:
    print("  بيانات الدخول     : لا توجد — ستظهر شاشة الإعداد الأول على الموقع")

print("-" * 58)

print("إنشاء الجداول...")
storage.init_db()

existing = storage.read_doc()
if existing and not FORCE:
    n = len(existing.get("students", []))
    if n:
        die("القاعدة تحتوي بالفعل على %d طالب.\n"
            "       لو متأكد أنك تريد الكتابة فوقها أضف --force" % n)

print("رفع البيانات...")
storage.write_doc(doc)

check = storage.read_doc() or {}
print("-" * 58)
print("تم ✔  القاعدة الآن تحتوي على:")
print("  %d فصل  |  %d طالب" % (len(check.get("classes", [])), len(check.get("students", []))))
names = [s["name"] for s in check.get("students", [])[:3]]
print("  عيّنة: " + " ، ".join(names))
print("=" * 58)

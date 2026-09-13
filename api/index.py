# -*- coding: utf-8 -*-
"""
نقطة الدخول على Vercel.

يكتشف Vercel إطار Flask تلقائياً ويوجّه كل الطلبات إلى هذا الملف،
فيصل المسار الأصلي كما هو إلى التطبيق دون إعادة كتابة.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app          # noqa: E402  (Vercel يبحث عن المتغيّر app)

# بعض إصدارات مُشغّل Python على Vercel تبحث عن الاسم handler
handler = app

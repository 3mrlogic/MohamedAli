# -*- coding: utf-8 -*-
"""نقطة الدخول على Vercel — تستورد تطبيق Flask من جذر المشروع."""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app          # noqa: E402  (Vercel يبحث عن المتغيّر app)

# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
# Framework: Django — urls.py
#
# Registers URL patterns for cwe_injection_django.py views.
# The engine must trace: path("sqli/", view) → view function body.
# ============================================================================
from django.urls import path
from . import cwe_injection_django as v

urlpatterns = [
    # Function-based views
    path("sqli/raw/",         v.sqli_fbv_raw_concat),
    path("sqli/parameterized/", v.sqli_fbv_parameterized),
    path("sqli/orm/",         v.sqli_fbv_orm),
    path("cmd/",              v.cmd_fbv_reachable),
    path("eval/",             v.eval_fbv_reachable),
    path("path/",             v.path_traversal_fbv),
    path("xss/",              v.xss_mark_safe_fbv),
    path("ssrf/",             v.ssrf_fbv),
    # Class-based views
    path("cbv/sqli/",         v.SQLiCBV.as_view()),
    path("cbv/cmd/",          v.CommandInjectionCBV.as_view()),
    path("cbv/path/",         v.PathTraversalCBV.as_view()),
    # DRF views — also registered in DRF router in urls_drf.py
    path("api/sqli/",         v.drf_sqli_view),
    path("api/cmd/",          v.drf_cmd_view),
    # sqli_dead_code, DeadCBV, drf_dead_view — intentionally NOT registered
]

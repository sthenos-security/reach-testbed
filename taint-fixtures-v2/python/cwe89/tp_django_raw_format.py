# Fixture: code_patch · CWE-89 SQL Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: django_raw_sql_format
# SOURCE: http_request (request.GET)
# SINK: Model.objects.raw (% format)
# TAINT_HOPS: 1
from django.http import JsonResponse


def search_users(request):
    query = request.GET.get("q")
    from myapp.models import User
    # VULNERABLE: CWE-89 · Django raw() with string formatting
    users = User.objects.raw("SELECT * FROM myapp_user WHERE name LIKE '%%%s%%'" % query)
    return JsonResponse({"users": [u.name for u in users]})

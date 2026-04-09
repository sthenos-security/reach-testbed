# Fixture: code_patch · CWE-89 SQL Injection · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: django_extra_where_concat
# SOURCE: http_request (request.GET)
# SINK: QuerySet.extra (where clause)
# TAINT_HOPS: 1
from django.http import JsonResponse


def filter_users(request):
    status = request.GET.get("status")
    from myapp.models import User
    # VULNERABLE: CWE-89 · Django extra() with unsanitized where clause
    users = User.objects.extra(where=["status = '%s'" % status])
    return JsonResponse({"users": list(users.values("id", "name"))})

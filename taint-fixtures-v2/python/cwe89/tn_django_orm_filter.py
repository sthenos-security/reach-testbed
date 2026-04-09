# Fixture: code_patch · CWE-89 SQL Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: django_orm_filter
# SOURCE: http_request (request.GET)
# SINK: Model.objects.filter (ORM)
# TAINT_HOPS: 1
# NOTES: Django ORM handles parameterization internally
from django.http import JsonResponse


def search_users(request):
    name = request.GET.get("name")
    from myapp.models import User
    # SAFE: Django ORM filter — handles parameterization automatically
    users = User.objects.filter(name__icontains=name)
    return JsonResponse({"users": list(users.values("id", "name"))})

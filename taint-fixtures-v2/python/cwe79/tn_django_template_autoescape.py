# Fixture: CWE-79 Cross-Site Scripting - Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: django_template_default_autoescape
# SOURCE: request.GET
# SINK: TemplateResponse
# TAINT_HOPS: 1
# NOTES: Django template engine auto-escapes by default
from django.template.response import TemplateResponse

def profile_view(request):
    username = request.GET.get("user", "")
    # SAFE: Django templates auto-escape variables
    return TemplateResponse(request, "profile.html", {"username": username})

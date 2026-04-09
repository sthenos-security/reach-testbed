# Fixture: CWE-79 Cross-Site Scripting - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: django_httpresponse_html_user_input
# SOURCE: request.GET
# SINK: HttpResponse
# TAINT_HOPS: 1
# NOTES: Django HttpResponse with user input in HTML body
# REAL_WORLD: Common Django anti-pattern
from django.http import HttpResponse

def search_view(request):
    query = request.GET.get("q", "")
    # VULNERABLE: user input reflected in HTML
    return HttpResponse(f"<h1>Search: {query}</h1>")

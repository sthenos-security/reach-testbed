# Fixture: CWE-79 Cross-Site Scripting - Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: django_format_html_safe
# SOURCE: function_parameter
# SINK: format_html
# TAINT_HOPS: 1
# NOTES: Django format_html() escapes arguments while keeping template safe
# REAL_WORLD: django/django recommended pattern
from django.utils.html import format_html

def render_badge_safe(username: str) -> str:
    # SAFE: format_html escapes username, only the template structure is trusted
    return format_html('<span class="badge">{}</span>', username)

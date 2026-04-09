# Fixture: CWE-79 Cross-Site Scripting - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: django_mark_safe_user_input
# SOURCE: function_parameter
# SINK: mark_safe
# TAINT_HOPS: 1
# NOTES: Django mark_safe() tells template engine to skip auto-escaping
# REAL_WORLD: django/django common anti-pattern in custom template tags
from django.utils.safestring import mark_safe

def render_badge(username: str) -> str:
    # VULNERABLE: mark_safe bypasses Django auto-escaping on user input
    return mark_safe(f'<span class="badge">{username}</span>')

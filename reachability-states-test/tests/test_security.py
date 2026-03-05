"""
CWE IN TEST FILE
================
This file is in the tests/ directory.
Expected: CWE issues should be marked as TEST_ONLY or excluded.

Security issues in test code are lower priority since they don't
run in production.
"""
import subprocess


def test_command_injection():
    """
    Test that validates command injection behavior.
    
    CWE-78: OS Command Injection - but in test code
    Expected: Lower priority or excluded from actionable items
    """
    # This is intentionally vulnerable for testing purposes
    user_input = "test; echo pwned"
    result = subprocess.run(f"echo {user_input}", shell=True, capture_output=True)
    assert "pwned" in result.stdout.decode()


def test_sql_injection():
    """
    Test SQL injection detection.
    
    CWE-89: SQL Injection - but in test code
    """
    # Intentionally vulnerable for testing
    username = "admin' OR '1'='1"
    query = f"SELECT * FROM users WHERE name = '{username}'"
    assert "OR" in query


def test_eval():
    """
    Test eval behavior.
    
    CWE-94: Code Injection - but in test code
    """
    result = eval("2 + 2")
    assert result == 4


class TestSecurityVulnerabilities:
    """Test class with intentional vulnerabilities for testing."""
    
    def test_xss(self):
        """Test XSS handling."""
        user_input = "<script>alert('xss')</script>"
        # No sanitization - intentional for test
        output = f"<div>{user_input}</div>"
        assert "<script>" in output

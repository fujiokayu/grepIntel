"""
Tests for the pattern_manager module.
"""

import os
import tempfile
import pytest
from src.pattern_manager import PatternManager


class TestPatternManager:
    """Test cases for PatternManager class."""

    def test_init(self):
        """Test initialization of PatternManager."""
        manager = PatternManager()
        assert manager is not None
        assert manager.patterns == {}
        assert manager.language_patterns == {}
        assert manager.framework_patterns == {}
        assert manager.combined_patterns == {}

    def test_load_language_patterns(self):
        """Test loading language patterns from a file."""
        # Create a temporary pattern file
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
            temp_file.write(
                """
[SQL_INJECTION]
description: SQL injection vulnerabilities
patterns:
- mysql_query\\s*\\(\\s*.*\\$.*\\)
- \\$.*\\s*=\\s*.*\\$_GET.*

[XSS]
description: Cross-site scripting vulnerabilities
patterns:
- echo\\s+.*\\$_GET
- print\\s+.*\\$_REQUEST
"""
            )
            temp_path = temp_file.name

        try:
            # Load patterns from the temporary file
            manager = PatternManager()
            manager.load_language_patterns(temp_path, "php")

            # Verify patterns were loaded correctly
            assert "php" in manager.language_patterns
            assert len(manager.language_patterns["php"]) == 2
            assert "SQL_INJECTION" in manager.language_patterns["php"]
            assert "XSS" in manager.language_patterns["php"]

            # Verify pattern details
            sql_injection = manager.language_patterns["php"]["SQL_INJECTION"]
            assert sql_injection["description"] == "SQL injection vulnerabilities"
            assert len(sql_injection["patterns"]) == 2
            assert sql_injection["patterns"][0] == r"mysql_query\s*\(\s*.*\$.*\)"

            xss = manager.language_patterns["php"]["XSS"]
            assert xss["description"] == "Cross-site scripting vulnerabilities"
            assert len(xss["patterns"]) == 2
            assert xss["patterns"][1] == r"print\s+.*\$_REQUEST"

            # Verify combined patterns were updated
            assert "php" in manager.combined_patterns
            assert len(manager.combined_patterns["php"]) == 2
            assert "SQL_INJECTION" in manager.combined_patterns["php"]
            assert "XSS" in manager.combined_patterns["php"]

            # Verify backward compatibility
            assert "php" in manager.patterns
            assert len(manager.patterns["php"]) == 2
        finally:
            # Clean up the temporary file
            os.unlink(temp_path)

    def test_load_framework_patterns(self):
        """Test loading framework patterns from a file."""
        # Create a temporary pattern file for language
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as lang_file:
            lang_file.write(
                """
[SQL_INJECTION]
description: SQL injection vulnerabilities
patterns:
- mysql_query\\s*\\(\\s*.*\\$.*\\)
- \\$.*\\s*=\\s*.*\\$_GET.*
"""
            )
            lang_path = lang_file.name

        # Create a temporary pattern file for framework
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as framework_file:
            framework_file.write(
                """
[FRAMEWORK_SPECIFIC]
description: Laravel specific vulnerabilities
patterns:
- DB::raw\\s*\\(\\s*.*\\$.*\\)
- Input::get\\s*\\(\\s*.*\\)

[SQL_INJECTION]
description: Laravel SQL injection vulnerabilities
patterns:
- Eloquent::whereRaw\\s*\\(\\s*.*\\$.*\\)
"""
            )
            framework_path = framework_file.name

        try:
            # Load patterns from the temporary files
            manager = PatternManager()
            manager.load_language_patterns(lang_path, "php")
            manager.load_framework_patterns(framework_path, "laravel", "php")

            # Verify framework patterns were loaded correctly
            assert "laravel" in manager.framework_patterns
            assert len(manager.framework_patterns["laravel"]) == 2
            assert "FRAMEWORK_SPECIFIC" in manager.framework_patterns["laravel"]
            assert "SQL_INJECTION" in manager.framework_patterns["laravel"]

            # Verify combined patterns were updated
            assert "php" in manager.combined_patterns
            assert len(manager.combined_patterns["php"]) == 2
            assert "FRAMEWORK_SPECIFIC" in manager.combined_patterns["php"]
            assert "SQL_INJECTION" in manager.combined_patterns["php"]

            # Verify SQL_INJECTION patterns were combined
            sql_injection = manager.combined_patterns["php"]["SQL_INJECTION"]
            assert len(sql_injection["patterns"]) == 3
            assert r"Eloquent::whereRaw\s*\(\s*.*\$.*\)" in sql_injection["patterns"]
        finally:
            # Clean up the temporary files
            os.unlink(lang_path)
            os.unlink(framework_path)

    def test_load_patterns_from_file(self):
        """Test loading patterns from a file (backward compatibility)."""
        # Create a temporary pattern file
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
            temp_file.write(
                """
[SQL_INJECTION]
description: SQL injection vulnerabilities
patterns:
- mysql_query\\s*\\(\\s*.*\\$.*\\)
- \\$.*\\s*=\\s*.*\\$_GET.*
"""
            )
            temp_path = temp_file.name

        try:
            # Load patterns from the temporary file
            manager = PatternManager()
            manager.load_patterns_from_file(temp_path, "php")

            # Verify patterns were loaded correctly
            assert "php" in manager.patterns
            assert "php" in manager.language_patterns
            assert "php" in manager.combined_patterns
        finally:
            # Clean up the temporary file
            os.unlink(temp_path)

    def test_get_patterns_for_language(self):
        """Test getting patterns for a specific language."""
        manager = PatternManager()

        # Add some test patterns
        manager.language_patterns = {
            "php": {
                "SQL_INJECTION": {
                    "description": "SQL injection vulnerabilities",
                    "patterns": [r"mysql_query\s*\(\s*.*\$.*\)"],
                }
            }
        }

        manager.framework_patterns = {
            "laravel": {
                "FRAMEWORK_SPECIFIC": {
                    "description": "Laravel specific vulnerabilities",
                    "patterns": [r"DB::raw\s*\(\s*.*\$.*\)"],
                }
            }
        }

        # Update combined patterns
        manager._update_combined_patterns("php")

        # Test getting patterns for PHP
        php_patterns = manager.get_patterns_for_language("php")
        assert php_patterns == manager.combined_patterns["php"]

        # Test getting patterns for unsupported language
        with pytest.raises(ValueError):
            manager.get_patterns_for_language("ruby")

    def test_get_all_patterns(self):
        """Test getting all patterns."""
        manager = PatternManager()

        # Add some test patterns
        manager.language_patterns = {
            "php": {
                "SQL_INJECTION": {
                    "description": "SQL injection vulnerabilities",
                    "patterns": [r"mysql_query\s*\(\s*.*\$.*\)"],
                }
            },
            "java": {
                "SQL_INJECTION": {
                    "description": "SQL injection vulnerabilities",
                    "patterns": [r"executeQuery\s*\(\s*.*\+.*\)"],
                }
            },
        }

        # Update combined patterns
        manager._update_combined_patterns("php")
        manager._update_combined_patterns("java")

        # Test getting all patterns
        all_patterns = manager.get_all_patterns()
        assert all_patterns == manager.combined_patterns

        # Test backward compatibility
        manager.combined_patterns = {}
        all_patterns = manager.get_all_patterns()
        assert all_patterns == manager.patterns

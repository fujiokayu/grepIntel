"""
Tests for the file_scanner module.
"""

import os
import tempfile
import pytest
from src.pattern_manager import PatternManager
from src.file_scanner import FileScanner


class TestFileScanner:
    """Test cases for FileScanner class."""

    def test_init(self):
        """Test initialization of FileScanner."""
        pattern_manager = PatternManager()
        scanner = FileScanner(pattern_manager)
        assert scanner is not None
        assert scanner.pattern_manager == pattern_manager
        assert scanner.results == {}

    def test_get_language_from_file(self):
        """Test getting language from file extension."""
        pattern_manager = PatternManager()
        scanner = FileScanner(pattern_manager)

        # Test PHP file
        assert scanner._get_language_from_file("test.php") == "php"
        assert scanner._get_language_from_file("test.phtml") == "php"

        # Test Java file
        assert scanner._get_language_from_file("test.java") == "java"
        assert scanner._get_language_from_file("test.jsp") == "java"

        # Test Python file
        assert scanner._get_language_from_file("test.py") == "python"

        # Test JavaScript file
        assert scanner._get_language_from_file("test.js") == "javascript"
        assert scanner._get_language_from_file("test.jsx") == "javascript"

        # Test unknown extension
        assert scanner._get_language_from_file("test.unknown") is None

        # Test no extension
        assert scanner._get_language_from_file("test") is None

    def test_match_patterns(self):
        """Test pattern matching."""
        pattern_manager = PatternManager()
        scanner = FileScanner(pattern_manager)

        # Create test patterns
        patterns = {
            "TEST_VULNERABILITY": {
                "description": "Test vulnerability",
                "patterns": [
                    r"vulnerable_function\s*\(\s*.*\$.*\)",
                    r"another_vulnerable_function\s*\(\s*.*\$.*\)",
                ],
            }
        }

        # Test content with matches
        content = """
        <?php
        function test() {
            $result = vulnerable_function($input);
            return $result;
        }
        ?>
        """

        matches = scanner._match_patterns(content, patterns)
        assert len(matches) == 1
        assert matches[0]["vulnerability_type"] == "TEST_VULNERABILITY"
        assert matches[0]["description"] == "Test vulnerability"
        assert matches[0]["line_number"] == 4
        assert "$result = vulnerable_function($input);" in matches[0]["line_content"]

        # Test content with no matches
        content = """
        <?php
        function test() {
            $result = safe_function($input);
            return $result;
        }
        ?>
        """

        matches = scanner._match_patterns(content, patterns)
        assert len(matches) == 0

    def test_scan_file(self):
        """Test scanning a file."""
        # Create a pattern manager with test patterns
        pattern_manager = PatternManager()
        pattern_manager.patterns = {
            "php": {
                "SQL_INJECTION": {
                    "description": "SQL injection vulnerabilities",
                    "patterns": [r"mysql_query\s*\(\s*.*\$.*\)"],
                }
            }
        }

        scanner = FileScanner(pattern_manager)

        # Create a temporary PHP file with vulnerable code
        with tempfile.NamedTemporaryFile(
            mode="w+", suffix=".php", delete=False
        ) as temp_file:
            temp_file.write(
                """
            <?php
            function test() {
                $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
                $result = mysql_query($query);
                return $result;
            }
            ?>
            """
            )
            temp_path = temp_file.name

        try:
            # Test scanning the file
            result = scanner._scan_file(temp_path, "php", None)
            assert result is not None
            assert result["file_path"] == temp_path
            assert result["language"] == "php"
            assert result["framework"] is None
            assert len(result["matches"]) == 1
            assert result["matches"][0]["vulnerability_type"] == "SQL_INJECTION"

            # Test scanning with unsupported language
            result = scanner._scan_file(temp_path, "unknown", None)
            assert result is None

        finally:
            # Clean up the temporary file
            os.unlink(temp_path)

    def test_scan_nonexistent_file(self):
        """Test scanning a nonexistent file."""
        pattern_manager = PatternManager()
        scanner = FileScanner(pattern_manager)

        result = scanner._scan_file("nonexistent_file.php", "php", None)
        assert result is None

    def test_scan(self):
        """Test the main scan method."""
        # Create a pattern manager with test patterns
        pattern_manager = PatternManager()
        pattern_manager.patterns = {
            "php": {
                "SQL_INJECTION": {
                    "description": "SQL injection vulnerabilities",
                    "patterns": [r"mysql_query\s*\(\s*.*\$.*\)"],
                }
            }
        }

        scanner = FileScanner(pattern_manager)

        # Create a temporary directory with test files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a PHP file with vulnerable code
            php_file_path = os.path.join(temp_dir, "test.php")
            with open(php_file_path, "w") as php_file:
                php_file.write(
                    """
                <?php
                function test() {
                    $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
                    $result = mysql_query($query);
                    return $result;
                }
                ?>
                """
                )

            # Create a text file (should be ignored)
            txt_file_path = os.path.join(temp_dir, "test.txt")
            with open(txt_file_path, "w") as txt_file:
                txt_file.write("This is a test file.")

            # Test scanning the directory
            results = scanner.scan(temp_dir, "all", None)
            assert results["target_path"] == temp_dir
            assert results["language"] == "all"
            assert results["framework"] is None
            assert results["files_scanned"] == 1
            assert results["vulnerabilities_found"] == 1
            assert len(results["results"]) == 1
            assert results["results"][0]["file_path"] == php_file_path

            # Test scanning a specific file
            results = scanner.scan(php_file_path, "php", None)
            assert results["target_path"] == php_file_path
            assert results["language"] == "php"
            assert results["files_scanned"] == 1
            assert results["vulnerabilities_found"] == 1

            # Test scanning with nonexistent path
            with pytest.raises(FileNotFoundError):
                scanner.scan("nonexistent_path", "all", None)

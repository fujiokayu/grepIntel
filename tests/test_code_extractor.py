"""
Tests for the code_extractor module.
"""

import os
import tempfile
import pytest
from src.code_extractor import CodeExtractor


class TestCodeExtractor:
    """Test cases for CodeExtractor class."""

    def test_init(self):
        """Test initialization of CodeExtractor."""
        extractor = CodeExtractor()
        assert extractor is not None
        assert extractor.context_lines == 5
        assert extractor.results == {}

        # Test with custom context lines
        extractor = CodeExtractor(context_lines=10)
        assert extractor.context_lines == 10

    def test_extract_context(self):
        """Test extracting context around a line."""
        extractor = CodeExtractor(context_lines=2)

        # Create test lines
        lines = ["Line 1\n", "Line 2\n", "Line 3\n", "Line 4\n", "Line 5\n"]

        # Test middle line
        context = extractor._extract_context(lines, 3)
        assert context["start_line"] == 1
        assert context["end_line"] == 5
        assert context["code"] == "Line 1\nLine 2\nLine 3\nLine 4\nLine 5\n"

        # Test first line
        context = extractor._extract_context(lines, 1)
        assert context["start_line"] == 1
        assert context["end_line"] == 3
        assert context["code"] == "Line 1\nLine 2\nLine 3\n"

        # Test last line
        context = extractor._extract_context(lines, 5)
        assert context["start_line"] == 3
        assert context["end_line"] == 5
        assert context["code"] == "Line 3\nLine 4\nLine 5\n"

    def test_extract_from_file(self):
        """Test extracting code from a file."""
        extractor = CodeExtractor(context_lines=2)

        # Create a temporary file with test code
        with tempfile.NamedTemporaryFile(
            mode="w+", suffix=".php", delete=False
        ) as temp_file:
            temp_file.write(
                """<?php
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
            # Create test matches
            matches = [
                {
                    "vulnerability_type": "SQL_INJECTION",
                    "description": "SQL injection vulnerabilities",
                    "line_number": 4,
                    "line_content": "    $result = mysql_query($query);",
                    "pattern": r"mysql_query\s*\(\s*.*\$.*\)",
                }
            ]

            # Test extraction
            result = extractor._extract_from_file(temp_path, "php", None, matches)

            assert result is not None
            assert result["file_path"] == temp_path
            assert result["language"] == "php"
            assert result["framework"] is None
            assert len(result["extractions"]) == 1

            extraction = result["extractions"][0]
            assert extraction["vulnerability_type"] == "SQL_INJECTION"
            assert extraction["description"] == "SQL injection vulnerabilities"
            assert extraction["line_number"] == 4
            assert extraction["context"]["start_line"] == 2
            assert extraction["context"]["end_line"] == 6
            assert "$result = mysql_query($query);" in extraction["context"]["code"]

        finally:
            # Clean up the temporary file
            os.unlink(temp_path)

    def test_extract(self):
        """Test the main extract method."""
        extractor = CodeExtractor(context_lines=2)

        # Create a temporary file with test code
        with tempfile.NamedTemporaryFile(
            mode="w+", suffix=".php", delete=False
        ) as temp_file:
            temp_file.write(
                """<?php
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
            # Create test scan results
            scan_results = {
                "target_path": "/test/path",
                "language": "php",
                "framework": None,
                "files_scanned": 1,
                "vulnerabilities_found": 1,
                "results": [
                    {
                        "file_path": temp_path,
                        "language": "php",
                        "framework": None,
                        "matches": [
                            {
                                "vulnerability_type": "SQL_INJECTION",
                                "description": "SQL injection vulnerabilities",
                                "line_number": 4,
                                "line_content": "    $result = mysql_query($query);",
                                "pattern": r"mysql_query\s*\(\s*.*\$.*\)",
                            }
                        ],
                    }
                ],
            }

            # Test extraction
            result = extractor.extract(scan_results)

            assert result is not None
            assert result["target_path"] == "/test/path"
            assert result["language"] == "php"
            assert result["framework"] is None
            assert result["files_processed"] == 1
            assert result["vulnerabilities_processed"] == 1
            assert len(result["results"]) == 1

            file_result = result["results"][0]
            assert file_result["file_path"] == temp_path
            assert file_result["language"] == "php"
            assert file_result["framework"] is None
            assert len(file_result["extractions"]) == 1

            extraction = file_result["extractions"][0]
            assert extraction["vulnerability_type"] == "SQL_INJECTION"
            assert extraction["description"] == "SQL injection vulnerabilities"
            assert extraction["line_number"] == 4
            assert extraction["context"]["start_line"] == 2
            assert extraction["context"]["end_line"] == 6
            assert "$result = mysql_query($query);" in extraction["context"]["code"]

        finally:
            # Clean up the temporary file
            os.unlink(temp_path)

    def test_format_for_llm(self):
        """Test formatting extraction results for LLM input."""
        extractor = CodeExtractor()

        # Create test extraction results
        extraction_results = {
            "target_path": "/test/path",
            "language": "php",
            "framework": "laravel",
            "files_processed": 1,
            "vulnerabilities_processed": 1,
            "results": [
                {
                    "file_path": "/test/file.php",
                    "language": "php",
                    "framework": "laravel",
                    "extractions": [
                        {
                            "vulnerability_type": "SQL_INJECTION",
                            "description": "SQL injection vulnerabilities",
                            "line_number": 4,
                            "context": {
                                "start_line": 2,
                                "end_line": 6,
                                "code": "function test() {\n    $query = \"SELECT * FROM users WHERE id = \" . $_GET['id'];\n    $result = mysql_query($query);\n    return $result;\n}\n",
                            },
                            "pattern": r"mysql_query\s*\(\s*.*\$.*\)",
                        }
                    ],
                }
            ],
        }

        # Test formatting
        formatted = extractor.format_for_llm(extraction_results)

        assert "Security Analysis Request" in formatted
        assert "Target: /test/path" in formatted
        assert "Language: php" in formatted
        assert "Framework: laravel" in formatted
        assert "Potential Vulnerabilities:" in formatted
        assert "File: /test/file.php" in formatted
        assert "Vulnerability: SQL_INJECTION" in formatted
        assert "Description: SQL injection vulnerabilities" in formatted
        assert "Line 4" in formatted
        assert "Code Context (lines 2-6):" in formatted
        assert "```php" in formatted
        assert "$result = mysql_query($query);" in formatted

        # Test token limit
        long_extraction_results = {
            "target_path": "/test/path",
            "language": "php",
            "framework": None,
            "files_processed": 1,
            "vulnerabilities_processed": 100,  # Large number to test token limit
            "results": [],
        }

        # Add many identical extractions to exceed token limit
        file_result = {
            "file_path": "/test/file.php",
            "language": "php",
            "framework": None,
            "extractions": [],
        }

        for i in range(100):  # Add many extractions
            file_result["extractions"].append(
                {
                    "vulnerability_type": "SQL_INJECTION",
                    "description": "SQL injection vulnerabilities",
                    "line_number": 4,
                    "context": {
                        "start_line": 2,
                        "end_line": 6,
                        "code": "function test() {\n    $query = \"SELECT * FROM users WHERE id = \" . $_GET['id'];\n    $result = mysql_query($query);\n    return $result;\n}\n",
                    },
                    "pattern": r"mysql_query\s*\(\s*.*\$.*\)",
                }
            )

        long_extraction_results["results"].append(file_result)

        # Test formatting with token limit
        formatted = extractor.format_for_llm(long_extraction_results, max_tokens=500)

        assert "Security Analysis Request" in formatted
        assert "[Additional vulnerabilities omitted due to token limit]" in formatted

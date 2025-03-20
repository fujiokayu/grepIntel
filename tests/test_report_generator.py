"""
Tests for report generator.

This module contains tests for the report generator.
"""
import os
import re
import pytest
from unittest.mock import patch, MagicMock, mock_open
from datetime import datetime

from src.report_generator import ReportGenerator


class TestReportGenerator:
    """Tests for ReportGenerator class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        # Create a report generator with a mock template directory
        self.report_generator = ReportGenerator(template_dir="mock_templates")
    
    @patch("builtins.open", new_callable=mock_open, read_data="Test template {target}")
    def test_load_template(self, mock_file):
        """Test loading a template."""
        # Load template
        template = self.report_generator.load_template("en")
        
        # Verify template was loaded
        assert template == "Test template {target}"
        mock_file.assert_called_once_with(os.path.join("mock_templates", "report_template_en.md"), 'r', encoding='utf-8')
    
    @patch("builtins.open")
    @patch("logging.Logger.warning")
    def test_load_template_fallback(self, mock_warning, mock_file):
        """Test fallback to English template."""
        # Mock file not found for Japanese template, but found for English template
        mock_ja_file = MagicMock()
        mock_ja_file.__enter__.side_effect = FileNotFoundError()
        
        mock_en_file = MagicMock()
        mock_en_file.__enter__.return_value.read.return_value = "English template"
        
        mock_file.side_effect = [mock_ja_file, mock_en_file]
        
        # Load template with fallback
        template = self.report_generator.load_template("ja")
        
        # Verify fallback to English template
        assert template == "English template"
        assert mock_file.call_count == 2
        mock_warning.assert_called_once()
    
    def test_calculate_statistics(self):
        """Test calculating statistics."""
        # Create test analysis results
        analysis_results = {
            "total_vulnerabilities": 10,
            "false_positives": 5,
            "high_severity": 3,
            "medium_severity": 4,
            "low_severity": 3,
            "files_analyzed": 5,
            "vulnerabilities_analyzed": 15
        }
        
        # Calculate statistics
        statistics = self.report_generator.calculate_statistics(analysis_results)
        
        # Verify statistics
        assert statistics["total_vulnerabilities"] == 10
        assert statistics["false_positives"] == 5
        assert statistics["high_severity"] == 3
        assert statistics["medium_severity"] == 4
        assert statistics["low_severity"] == 3
        assert statistics["files_analyzed"] == 5
        assert statistics["vulnerabilities_analyzed"] == 15
    
    def test_generate_summary(self):
        """Test generating an executive summary."""
        # Create test analysis results and statistics
        analysis_results = {}
        statistics = {
            "total_vulnerabilities": 10,
            "false_positives": 5,
            "high_severity": 3,
            "medium_severity": 4,
            "low_severity": 3,
            "files_analyzed": 5,
            "vulnerabilities_analyzed": 15
        }
        
        # Generate summary
        summary = self.report_generator.generate_summary(analysis_results, statistics)
        
        # Verify summary
        assert "10 potential security vulnerabilities" in summary
        assert "5 files" in summary
        assert "3 are high severity" in summary
        assert "4 medium severity" in summary
        assert "3 low severity" in summary
        assert "5 false positives" in summary
    
    def test_generate_findings(self):
        """Test generating vulnerability findings."""
        # Create test analysis results
        analysis_results = {
            "results": [
                {
                    "file_path": "test.java",
                    "language": "java",
                    "vulnerabilities": [
                        {
                            "is_vulnerable": True,
                            "vulnerability_type": "SQL_INJECTION",
                            "severity": "high",
                            "line_number": 10,
                            "pattern": "executeQuery\\s*\\(\\s*.*\\+.*\\)",
                            "code_context": {
                                "code": "String query = \"SELECT * FROM users WHERE id = \" + userId;"
                            },
                            "explanation": "This is vulnerable to SQL injection.",
                            "recommendation": "Use prepared statements."
                        },
                        {
                            "is_vulnerable": False,  # False positive, should be skipped
                            "vulnerability_type": "XSS",
                            "severity": "none",
                            "line_number": 20,
                            "pattern": "response\\.getWriter\\(\\)\\.print\\s*\\(\\s*.*request\\.getParameter.*\\)",
                            "code_context": {
                                "code": "String userInput = request.getParameter(\"input\");\nresponse.getWriter().print(userInput);"
                            },
                            "explanation": "This is not vulnerable.",
                            "recommendation": "Continue using proper sanitization."
                        }
                    ]
                }
            ]
        }
        
        # Generate findings
        findings = self.report_generator.generate_findings(analysis_results)
        
        # Verify findings
        assert len(findings) == 1  # Only one vulnerability (the other is a false positive)
        assert findings[0]["vulnerability_id"] == "VULN-001"
        assert findings[0]["vulnerability_title"] == "Sql Injection"
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["file_path"] == "test.java"
        assert findings[0]["line_number"] == 10
        assert findings[0]["vulnerability_type"] == "SQL_INJECTION"
        assert findings[0]["language"] == "java"
        assert "SELECT * FROM users" in findings[0]["code_snippet"]
        assert "vulnerable to SQL injection" in findings[0]["llm_analysis"]
        assert "prepared statements" in findings[0]["recommendation"]
    
    @patch("builtins.open")
    @patch("src.report_generator.datetime")
    def test_format_report(self, mock_datetime, mock_file):
        """Test formatting a report."""
        # Mock datetime
        mock_now = MagicMock()
        mock_now.strftime.return_value = "2025-03-20 04:00:00"
        mock_datetime.now.return_value = mock_now
        
        # Create test analysis results and statistics
        analysis_results = {
            "target_path": "test_project",
            "language": "java",
            "results": [
                {
                    "file_path": "test.java",
                    "language": "java",
                    "vulnerabilities": [
                        {
                            "is_vulnerable": True,
                            "vulnerability_type": "SQL_INJECTION",
                            "severity": "high",
                            "line_number": 10,
                            "pattern": "executeQuery\\s*\\(\\s*.*\\+.*\\)",
                            "code_context": {
                                "code": "String query = \"SELECT * FROM users WHERE id = \" + userId;"
                            },
                            "explanation": "This is vulnerable to SQL injection.",
                            "recommendation": "Use prepared statements."
                        }
                    ]
                }
            ]
        }
        
        statistics = {
            "total_vulnerabilities": 1,
            "false_positives": 0,
            "high_severity": 1,
            "medium_severity": 0,
            "low_severity": 0,
            "files_analyzed": 1,
            "vulnerabilities_analyzed": 1
        }
        
        # Create a template string
        template_str = """
# Security Assessment Report

## Overview
- **Target:** {target}
- **Scan Date:** {scan_date}
- **Languages Analyzed:** {languages}
- **Files Scanned:** {files_scanned}
- **Vulnerabilities Found:** {total_vulnerabilities}

## Executive Summary
{summary}

## Vulnerability Findings

{for each vulnerability}
### {vulnerability_id}: {vulnerability_title}
**Severity:** {severity}  
**Location:** {file_path}:{line_number}  
**Type:** {vulnerability_type}  
**Pattern Matched:** `{pattern}`

#### Code Snippet
```{language}
{code_snippet}
```

#### Analysis
{llm_analysis}

#### Recommendation
{recommendation}

---
{end for}

## Statistics
- **High Severity Issues:** {high_severity_count}
- **Medium Severity Issues:** {medium_severity_count}
- **Low Severity Issues:** {low_severity_count}
- **False Positives:** {false_positive_count}
"""
        
        # Format report
        report = self.report_generator.format_report(template_str, analysis_results, statistics)
        
        # Verify report
        assert "Target:** test_project" in report
        assert "Scan Date:** 2025-03-20 04:00:00" in report
        assert "Languages Analyzed:** java" in report
        assert "Files Scanned:** 1" in report
        assert "Vulnerabilities Found:** 1" in report
        assert "VULN-001: Sql Injection" in report
        assert "Severity:** HIGH" in report
        assert "Location:** test.java:10" in report
        assert "Type:** SQL_INJECTION" in report
        assert "Pattern Matched:** `executeQuery\\s*\\(\\s*.*\\+.*\\)`" in report
        assert "```java" in report
        assert "String query = \"SELECT * FROM users WHERE id = \" + userId;" in report
        assert "This is vulnerable to SQL injection." in report
        assert "Use prepared statements." in report
        assert "High Severity Issues:** 1" in report
        assert "Medium Severity Issues:** 0" in report
        assert "Low Severity Issues:** 0" in report
        assert "False Positives:** 0" in report
    
    
    @patch("builtins.open", new_callable=mock_open)
    @patch.object(ReportGenerator, "load_template")
    @patch.object(ReportGenerator, "format_report")
    def test_generate(self, mock_format_report, mock_load_template, mock_file):
        """Test generating a report."""
        # Mock template and formatted report
        mock_load_template.return_value = "Test template"
        mock_format_report.return_value = "Formatted report"
        
        # Create test analysis results
        analysis_results = {
            "target_path": "test_project",
            "language": "java",
            "total_vulnerabilities": 1,
            "false_positives": 0,
            "high_severity": 1,
            "medium_severity": 0,
            "low_severity": 0,
            "files_analyzed": 1,
            "vulnerabilities_analyzed": 1,
            "results": []
        }
        
        # Generate report
        self.report_generator.generate(analysis_results, "report.md", "en")
        
        # Verify report was generated
        mock_load_template.assert_called_once_with("en")
        mock_format_report.assert_called_once()
        mock_file.assert_called_once_with("report.md", 'w', encoding='utf-8')
        mock_file.return_value.__enter__.return_value.write.assert_called_once_with("Formatted report")
    
    @patch("builtins.open", new_callable=mock_open)
    @patch.object(ReportGenerator, "load_template")
    @patch.object(ReportGenerator, "format_report")
    def test_generate_with_language_template(self, mock_format_report, mock_load_template, mock_file):
        """Test generating a report with language-specific template."""
        # Mock template and formatted report
        mock_load_template.return_value = "日本語テンプレート"
        mock_format_report.return_value = "日本語でフォーマットされたレポート"
        
        # Create test analysis results
        analysis_results = {
            "target_path": "test_project",
            "language": "java",
            "total_vulnerabilities": 1,
            "false_positives": 0,
            "high_severity": 1,
            "medium_severity": 0,
            "low_severity": 0,
            "files_analyzed": 1,
            "vulnerabilities_analyzed": 1,
            "results": []
        }
        
        # Generate report in Japanese
        self.report_generator.generate(analysis_results, "report.md", "ja")
        
        # Verify Japanese template was loaded
        mock_load_template.assert_called_once_with("ja")
        
        # Verify report was formatted with the template
        mock_format_report.assert_called_once()
        
        # Verify report was written
        mock_file.assert_called_once_with("report.md", 'w', encoding='utf-8')
        mock_file.return_value.__enter__.return_value.write.assert_called_once_with("日本語でフォーマットされたレポート")

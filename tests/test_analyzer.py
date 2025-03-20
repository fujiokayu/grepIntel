"""
Tests for security analyzer.

This module contains tests for the security analyzer.
"""
import os
import pytest
from unittest.mock import patch, MagicMock

from src.analyzer import SecurityAnalyzer
from src.llm.client import LLMClient


class TestSecurityAnalyzer:
    """Tests for SecurityAnalyzer class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        # Create a mock LLM client
        self.mock_llm_client = MagicMock(spec=LLMClient)
        
        # Create a security analyzer with the mock client
        self.analyzer = SecurityAnalyzer(self.mock_llm_client)
        
        # Override the prompt templates to avoid file I/O
        self.analyzer.prompt_templates = {
            'en': "Test prompt template for {vulnerability_type} in {language}",
            'ja': "日本語のテストプロンプトテンプレート {vulnerability_type} in {language}"
        }
    
    def test_format_prompt(self):
        """Test prompt formatting."""
        # Create a test extraction
        extraction = {
            "vulnerability_type": "SQL_INJECTION",
            "description": "SQL injection vulnerabilities",
            "line_number": 10,
            "pattern": "executeQuery\\s*\\(\\s*.*\\+.*\\)",
            "context": {
                "start_line": 5,
                "end_line": 15,
                "code": "String query = \"SELECT * FROM users WHERE id = \" + userId;\nResultSet rs = stmt.executeQuery(query);"
            }
        }
        
        # Format prompt in English
        prompt_en = self.analyzer.format_prompt(extraction, "test.java", "java", "en")
        assert "SQL_INJECTION" in prompt_en
        assert "java" in prompt_en
        assert "Please respond in" not in prompt_en
    
    def test_format_prompt_with_language_instruction(self):
        """Test prompt formatting with language instruction."""
        # Create a test extraction
        extraction = {
            "vulnerability_type": "SQL_INJECTION",
            "description": "SQL injection vulnerabilities",
            "line_number": 10,
            "pattern": "executeQuery\\s*\\(\\s*.*\\+.*\\)",
            "context": {
                "start_line": 5,
                "end_line": 15,
                "code": "String query = \"SELECT * FROM users WHERE id = \" + userId;\nResultSet rs = stmt.executeQuery(query);"
            }
        }
        
        # Format prompt in Japanese
        prompt_ja = self.analyzer.format_prompt(extraction, "test.java", "java", "ja")
        assert "SQL_INJECTION" in prompt_ja
        assert "java" in prompt_ja
        assert "Please respond in Japanese language" in prompt_ja
    
    def test_parse_llm_response_vulnerable(self):
        """Test parsing LLM response for a vulnerable case."""
        # Sample LLM response for a vulnerable case
        response = """
## Vulnerability Assessment
Vulnerable

## Explanation
This code is vulnerable to SQL injection because it directly concatenates user input into the SQL query without any sanitization or parameterization.

## Impact
An attacker could manipulate the userId parameter to execute arbitrary SQL commands, potentially accessing, modifying, or deleting data in the database.

## Secure Alternative
```java
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = conn.prepareStatement(query);
pstmt.setString(1, userId);
ResultSet rs = pstmt.executeQuery();
```

## Recommendation
Use prepared statements with parameterized queries to prevent SQL injection attacks.
"""
        
        # Parse the response
        analysis = self.analyzer.parse_llm_response(response)
        
        # Verify the parsed analysis
        assert analysis["is_vulnerable"] == True
        assert "SQL injection" in analysis["explanation"]
        assert "arbitrary SQL commands" in analysis["impact"]
        assert "PreparedStatement" in analysis["secure_alternative"]
        assert "prepared statements" in analysis["recommendation"]
    
    def test_parse_llm_response_false_positive(self):
        """Test parsing LLM response for a false positive case."""
        # Sample LLM response for a false positive case
        response = """
## Vulnerability Assessment
False Positive

## Explanation
This code is not vulnerable to SQL injection because it uses parameterized queries with prepared statements.

## Recommendation
The code is already using secure practices. Continue using prepared statements for all database operations.
"""
        
        # Parse the response
        analysis = self.analyzer.parse_llm_response(response)
        
        # Verify the parsed analysis
        assert analysis["is_vulnerable"] == False
        assert "not vulnerable" in analysis["explanation"]
        assert analysis["impact"] == ""
        assert analysis["secure_alternative"] == ""
        assert "already using secure practices" in analysis["recommendation"]
    
    def test_determine_severity_high(self):
        """Test severity determination for high severity vulnerabilities."""
        # Test by vulnerability type
        analysis = {"impact": "Some impact"}
        assert self.analyzer.determine_severity("SQL_INJECTION", analysis) == "high"
        assert self.analyzer.determine_severity("COMMAND_INJECTION", analysis) == "high"
        
        # Test by impact keywords
        analysis = {"impact": "This vulnerability has a critical impact on the system"}
        assert self.analyzer.determine_severity("UNKNOWN_TYPE", analysis) == "high"
        
        analysis = {"impact": "This can lead to severe data breach"}
        assert self.analyzer.determine_severity("UNKNOWN_TYPE", analysis) == "high"
    
    def test_determine_severity_medium(self):
        """Test severity determination for medium severity vulnerabilities."""
        # Test by vulnerability type
        analysis = {"impact": "Some impact"}
        assert self.analyzer.determine_severity("XSS", analysis) == "medium"
        assert self.analyzer.determine_severity("CSRF", analysis) == "medium"
        
        # Test default for unknown type with no specific keywords
        analysis = {"impact": "This has some impact on the system"}
        assert self.analyzer.determine_severity("UNKNOWN_TYPE", analysis) == "low"
    
    def test_determine_severity_low(self):
        """Test severity determination for low severity vulnerabilities."""
        # Test by impact keywords
        analysis = {"impact": "This has a minor impact on the system"}
        assert self.analyzer.determine_severity("XSS", analysis) == "low"
        
        analysis = {"impact": "This has a low risk with limited exposure"}
        assert self.analyzer.determine_severity("SQL_INJECTION", analysis) == "low"
    
    def test_analyze_vulnerability(self):
        """Test analyzing a single vulnerability."""
        # Create a test extraction
        extraction = {
            "vulnerability_type": "SQL_INJECTION",
            "description": "SQL injection vulnerabilities",
            "line_number": 10,
            "pattern": "executeQuery\\s*\\(\\s*.*\\+.*\\)",
            "context": {
                "start_line": 5,
                "end_line": 15,
                "code": "String query = \"SELECT * FROM users WHERE id = \" + userId;\nResultSet rs = stmt.executeQuery(query);"
            }
        }
        
        # Mock LLM response
        self.mock_llm_client.analyze.return_value = """
## Vulnerability Assessment
Vulnerable

## Explanation
This code is vulnerable to SQL injection.

## Impact
An attacker could execute arbitrary SQL commands.

## Secure Alternative
```java
PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setString(1, userId);
ResultSet rs = pstmt.executeQuery();
```

## Recommendation
Use prepared statements.
"""
        
        # Analyze the vulnerability
        analysis = self.analyzer.analyze_vulnerability(extraction, "test.java", "java")
        
        # Verify the analysis
        assert analysis["is_vulnerable"] == True
        assert analysis["severity"] == "high"
        assert analysis["vulnerability_type"] == "SQL_INJECTION"
        assert analysis["line_number"] == 10
        assert "SQL injection" in analysis["explanation"]
        assert "arbitrary SQL commands" in analysis["impact"]
        assert "PreparedStatement" in analysis["secure_alternative"]
        assert "prepared statements" in analysis["recommendation"]
        
        # Verify LLM client was called with the correct prompt
        self.mock_llm_client.analyze.assert_called_once()
    
    def test_analyze_vulnerability_error(self):
        """Test analyzing a vulnerability with an error."""
        # Create a test extraction
        extraction = {
            "vulnerability_type": "SQL_INJECTION",
            "description": "SQL injection vulnerabilities",
            "line_number": 10,
            "pattern": "executeQuery\\s*\\(\\s*.*\\+.*\\)",
            "context": {
                "start_line": 5,
                "end_line": 15,
                "code": "String query = \"SELECT * FROM users WHERE id = \" + userId;\nResultSet rs = stmt.executeQuery(query);"
            }
        }
        
        # Mock LLM client to raise an exception
        self.mock_llm_client.analyze.side_effect = Exception("Test error")
        
        # Analyze the vulnerability
        analysis = self.analyzer.analyze_vulnerability(extraction, "test.java", "java")
        
        # Verify the analysis contains error information
        assert analysis["is_vulnerable"] == True  # Default to True for safety
        assert analysis["severity"] == "medium"  # Default to medium
        assert "Error during analysis" in analysis["explanation"]
        assert "Unknown (analysis failed)" in analysis["impact"]
        assert "review this vulnerability manually" in analysis["recommendation"]
    
    def test_format_batch_prompt(self):
        """Test batch prompt formatting."""
        # Create test extractions
        extractions = [
            {
                "vulnerability_type": "SQL_INJECTION",
                "description": "SQL injection vulnerabilities",
                "line_number": 10,
                "pattern": "executeQuery\\s*\\(\\s*.*\\+.*\\)",
                "context": {
                    "start_line": 5,
                    "end_line": 15,
                    "code": "String query = \"SELECT * FROM users WHERE id = \" + userId;\nResultSet rs = stmt.executeQuery(query);"
                }
            },
            {
                "vulnerability_type": "XSS",
                "description": "Cross-site scripting vulnerabilities",
                "line_number": 20,
                "pattern": "response\\.getWriter\\(\\)\\.print\\s*\\(\\s*.*request\\.getParameter.*\\)",
                "context": {
                    "start_line": 15,
                    "end_line": 25,
                    "code": "String userInput = request.getParameter(\"input\");\nresponse.getWriter().print(userInput);"
                }
            }
        ]
        
        # Format batch prompt
        prompt = self.analyzer.format_batch_prompt(extractions, "test.java", "java", "en")
        
        # Verify the prompt contains information about both vulnerabilities
        assert "VULNERABILITY 1:" in prompt
        assert "VULNERABILITY 2:" in prompt
        assert "SQL_INJECTION" in prompt
        assert "XSS" in prompt
        assert "executeQuery" in prompt
        assert "response.getWriter" in prompt
        assert "ANALYSIS FOR VULNERABILITY X:" in prompt
        assert "Please respond in" not in prompt
    
    def test_format_batch_prompt_with_language_instruction(self):
        """Test batch prompt formatting with language instruction."""
        # Create test extractions
        extractions = [
            {
                "vulnerability_type": "SQL_INJECTION",
                "description": "SQL injection vulnerabilities",
                "line_number": 10,
                "pattern": "executeQuery\\s*\\(\\s*.*\\+.*\\)",
                "context": {
                    "start_line": 5,
                    "end_line": 15,
                    "code": "String query = \"SELECT * FROM users WHERE id = \" + userId;\nResultSet rs = stmt.executeQuery(query);"
                }
            },
            {
                "vulnerability_type": "XSS",
                "description": "Cross-site scripting vulnerabilities",
                "line_number": 20,
                "pattern": "response\\.getWriter\\(\\)\\.print\\s*\\(\\s*.*request\\.getParameter.*\\)",
                "context": {
                    "start_line": 15,
                    "end_line": 25,
                    "code": "String userInput = request.getParameter(\"input\");\nresponse.getWriter().print(userInput);"
                }
            }
        ]
        
        # Format batch prompt in Japanese
        prompt = self.analyzer.format_batch_prompt(extractions, "test.java", "java", "ja")
        
        # Verify the prompt contains information about both vulnerabilities
        assert "VULNERABILITY 1:" in prompt
        assert "VULNERABILITY 2:" in prompt
        assert "SQL_INJECTION" in prompt
        assert "XSS" in prompt
        assert "executeQuery" in prompt
        assert "response.getWriter" in prompt
        assert "ANALYSIS FOR VULNERABILITY X:" in prompt
        assert "Please respond in Japanese language" in prompt
    
    def test_parse_batch_response(self):
        """Test parsing batch response."""
        # Create test extractions
        extractions = [
            {
                "vulnerability_type": "SQL_INJECTION",
                "description": "SQL injection vulnerabilities",
                "line_number": 10,
                "pattern": "executeQuery\\s*\\(\\s*.*\\+.*\\)",
                "context": {
                    "start_line": 5,
                    "end_line": 15,
                    "code": "String query = \"SELECT * FROM users WHERE id = \" + userId;\nResultSet rs = stmt.executeQuery(query);"
                }
            },
            {
                "vulnerability_type": "XSS",
                "description": "Cross-site scripting vulnerabilities",
                "line_number": 20,
                "pattern": "response\\.getWriter\\(\\)\\.print\\s*\\(\\s*.*request\\.getParameter.*\\)",
                "context": {
                    "start_line": 15,
                    "end_line": 25,
                    "code": "String userInput = request.getParameter(\"input\");\nresponse.getWriter().print(userInput);"
                }
            }
        ]
        
        # Sample batch response
        batch_response = """
ANALYSIS FOR VULNERABILITY 1:
## Vulnerability Assessment
Vulnerable

## Explanation
This code is vulnerable to SQL injection.

## Impact
An attacker could execute arbitrary SQL commands.

## Secure Alternative
```java
PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setString(1, userId);
ResultSet rs = pstmt.executeQuery();
```

## Recommendation
Use prepared statements.

ANALYSIS FOR VULNERABILITY 2:
## Vulnerability Assessment
False Positive

## Explanation
This is not actually vulnerable because the context shows proper sanitization.

## Recommendation
Continue using proper sanitization.
"""
        
        # Parse the batch response
        results = self.analyzer.parse_batch_response(batch_response, extractions, "test.java", "java", "en")
        
        # Verify the results
        assert len(results) == 2
        
        # Verify SQL injection vulnerability
        sql_vuln = results[0]
        assert sql_vuln["is_vulnerable"] == True
        assert sql_vuln["severity"] == "high"
        assert sql_vuln["vulnerability_type"] == "SQL_INJECTION"
        assert sql_vuln["line_number"] == 10
        assert "SQL injection" in sql_vuln["explanation"]
        
        # Verify XSS vulnerability (false positive)
        xss_vuln = results[1]
        assert xss_vuln["is_vulnerable"] == False
        assert xss_vuln["severity"] == "none"
        assert xss_vuln["vulnerability_type"] == "XSS"
        assert xss_vuln["line_number"] == 20
        assert "not actually vulnerable" in xss_vuln["explanation"]
    
    def test_analyze_vulnerabilities_batch(self):
        """Test analyzing vulnerabilities in batch."""
        # Create test extractions
        extractions = [
            {
                "vulnerability_type": "SQL_INJECTION",
                "description": "SQL injection vulnerabilities",
                "line_number": 10,
                "pattern": "executeQuery\\s*\\(\\s*.*\\+.*\\)",
                "context": {
                    "start_line": 5,
                    "end_line": 15,
                    "code": "String query = \"SELECT * FROM users WHERE id = \" + userId;\nResultSet rs = stmt.executeQuery(query);"
                }
            },
            {
                "vulnerability_type": "XSS",
                "description": "Cross-site scripting vulnerabilities",
                "line_number": 20,
                "pattern": "response\\.getWriter\\(\\)\\.print\\s*\\(\\s*.*request\\.getParameter.*\\)",
                "context": {
                    "start_line": 15,
                    "end_line": 25,
                    "code": "String userInput = request.getParameter(\"input\");\nresponse.getWriter().print(userInput);"
                }
            }
        ]
        
        # Mock LLM response
        self.mock_llm_client.analyze.return_value = """
ANALYSIS FOR VULNERABILITY 1:
## Vulnerability Assessment
Vulnerable

## Explanation
This code is vulnerable to SQL injection.

## Impact
An attacker could execute arbitrary SQL commands.

## Secure Alternative
```java
PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setString(1, userId);
ResultSet rs = pstmt.executeQuery();
```

## Recommendation
Use prepared statements.

ANALYSIS FOR VULNERABILITY 2:
## Vulnerability Assessment
False Positive

## Explanation
This is not actually vulnerable because the context shows proper sanitization.

## Recommendation
Continue using proper sanitization.
"""
        
        # Analyze the vulnerabilities in batch
        results = self.analyzer.analyze_vulnerabilities_batch(extractions, "test.java", "java", "en")
        
        # Verify the results
        assert len(results) == 2
        
        # Verify SQL injection vulnerability
        sql_vuln = results[0]
        assert sql_vuln["is_vulnerable"] == True
        assert sql_vuln["severity"] == "high"
        assert sql_vuln["vulnerability_type"] == "SQL_INJECTION"
        
        # Verify XSS vulnerability (false positive)
        xss_vuln = results[1]
        assert xss_vuln["is_vulnerable"] == False
        assert xss_vuln["severity"] == "none"
        assert xss_vuln["vulnerability_type"] == "XSS"
        
        # Verify LLM client was called once with batch prompt
        self.mock_llm_client.analyze.assert_called_once()
    
    def test_analyze_vulnerabilities_batch_single_item(self):
        """Test analyzing a single vulnerability with batch method."""
        # Create a single test extraction
        extractions = [
            {
                "vulnerability_type": "SQL_INJECTION",
                "description": "SQL injection vulnerabilities",
                "line_number": 10,
                "pattern": "executeQuery\\s*\\(\\s*.*\\+.*\\)",
                "context": {
                    "start_line": 5,
                    "end_line": 15,
                    "code": "String query = \"SELECT * FROM users WHERE id = \" + userId;\nResultSet rs = stmt.executeQuery(query);"
                }
            }
        ]
        
        # Mock LLM response for individual analysis
        self.mock_llm_client.analyze.return_value = """
## Vulnerability Assessment
Vulnerable

## Explanation
This code is vulnerable to SQL injection.

## Impact
An attacker could execute arbitrary SQL commands.

## Secure Alternative
```java
PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setString(1, userId);
ResultSet rs = pstmt.executeQuery();
```

## Recommendation
Use prepared statements.
"""
        
        # Analyze the single vulnerability with batch method
        results = self.analyzer.analyze_vulnerabilities_batch(extractions, "test.java", "java", "en")
        
        # Verify the results
        assert len(results) == 1
        
        # Verify SQL injection vulnerability
        sql_vuln = results[0]
        assert sql_vuln["is_vulnerable"] == True
        assert sql_vuln["severity"] == "high"
        assert sql_vuln["vulnerability_type"] == "SQL_INJECTION"
        
        # Verify LLM client was called once
        self.mock_llm_client.analyze.assert_called_once()
    
    def test_analyze_vulnerabilities_batch_error(self):
        """Test analyzing vulnerabilities in batch with error."""
        # Create test extractions
        extractions = [
            {
                "vulnerability_type": "SQL_INJECTION",
                "description": "SQL injection vulnerabilities",
                "line_number": 10,
                "pattern": "executeQuery\\s*\\(\\s*.*\\+.*\\)",
                "context": {
                    "start_line": 5,
                    "end_line": 15,
                    "code": "String query = \"SELECT * FROM users WHERE id = \" + userId;\nResultSet rs = stmt.executeQuery(query);"
                }
            },
            {
                "vulnerability_type": "XSS",
                "description": "Cross-site scripting vulnerabilities",
                "line_number": 20,
                "pattern": "response\\.getWriter\\(\\)\\.print\\s*\\(\\s*.*request\\.getParameter.*\\)",
                "context": {
                    "start_line": 15,
                    "end_line": 25,
                    "code": "String userInput = request.getParameter(\"input\");\nresponse.getWriter().print(userInput);"
                }
            }
        ]
        
        # Mock LLM client to raise an exception
        self.mock_llm_client.analyze.side_effect = Exception("Test error")
        
        # Set up mock for individual analysis as fallback
        with patch.object(self.analyzer, 'analyze_vulnerability') as mock_analyze:
            mock_analyze.side_effect = [
                {
                    "is_vulnerable": True,
                    "severity": "high",
                    "vulnerability_type": "SQL_INJECTION",
                    "line_number": 10,
                    "pattern": "executeQuery\\s*\\(\\s*.*\\+.*\\)",
                    "code_context": extractions[0]["context"],
                    "explanation": "SQL injection vulnerability",
                    "impact": "Data breach",
                    "secure_alternative": "Use prepared statements",
                    "recommendation": "Fix it"
                },
                {
                    "is_vulnerable": False,
                    "severity": "none",
                    "vulnerability_type": "XSS",
                    "line_number": 20,
                    "pattern": "response\\.getWriter\\(\\)\\.print\\s*\\(\\s*.*request\\.getParameter.*\\)",
                    "code_context": extractions[1]["context"],
                    "explanation": "Not vulnerable",
                    "impact": "",
                    "secure_alternative": "",
                    "recommendation": "No action needed"
                }
            ]
            
            # Analyze the vulnerabilities in batch
            results = self.analyzer.analyze_vulnerabilities_batch(extractions, "test.java", "java", "en")
            
            # Verify the results
            assert len(results) == 2
            
            # Verify SQL injection vulnerability
            sql_vuln = results[0]
            assert sql_vuln["is_vulnerable"] == True
            assert sql_vuln["severity"] == "high"
            assert sql_vuln["vulnerability_type"] == "SQL_INJECTION"
            
            # Verify XSS vulnerability (false positive)
            xss_vuln = results[1]
            assert xss_vuln["is_vulnerable"] == False
            assert xss_vuln["severity"] == "none"
            assert xss_vuln["vulnerability_type"] == "XSS"
            
            # Verify LLM client was called once for batch
            self.mock_llm_client.analyze.assert_called_once()
            
            # Verify individual analysis was called twice as fallback
            assert mock_analyze.call_count == 2
    
    def test_analyze(self):
        """Test analyzing extraction results."""
        # Create test extraction results
        extraction_results = {
            "target_path": "test_project",
            "language": "java",
            "framework": None,
            "files_scanned": 1,
            "vulnerabilities_found": 2,
            "files_processed": 1,
            "results": [
                {
                    "file_path": "test.java",
                    "language": "java",
                    "framework": None,
                    "extractions": [
                        {
                            "vulnerability_type": "SQL_INJECTION",
                            "description": "SQL injection vulnerabilities",
                            "line_number": 10,
                            "pattern": "executeQuery\\s*\\(\\s*.*\\+.*\\)",
                            "context": {
                                "start_line": 5,
                                "end_line": 15,
                                "code": "String query = \"SELECT * FROM users WHERE id = \" + userId;\nResultSet rs = stmt.executeQuery(query);"
                            }
                        },
                        {
                            "vulnerability_type": "XSS",
                            "description": "Cross-site scripting vulnerabilities",
                            "line_number": 20,
                            "pattern": "response\\.getWriter\\(\\)\\.print\\s*\\(\\s*.*request\\.getParameter.*\\)",
                            "context": {
                                "start_line": 15,
                                "end_line": 25,
                                "code": "String userInput = request.getParameter(\"input\");\nresponse.getWriter().print(userInput);"
                            }
                        }
                    ]
                }
            ]
        }
        
        # Set up mock for batch analysis
        with patch.object(self.analyzer, 'analyze_vulnerabilities_batch') as mock_batch:
            mock_batch.return_value = [
                {
                    "is_vulnerable": True,
                    "severity": "high",
                    "vulnerability_type": "SQL_INJECTION",
                    "line_number": 10,
                    "pattern": "executeQuery\\s*\\(\\s*.*\\+.*\\)",
                    "code_context": extraction_results["results"][0]["extractions"][0]["context"],
                    "explanation": "SQL injection vulnerability",
                    "impact": "Data breach",
                    "secure_alternative": "Use prepared statements",
                    "recommendation": "Fix it"
                },
                {
                    "is_vulnerable": False,
                    "severity": "none",
                    "vulnerability_type": "XSS",
                    "line_number": 20,
                    "pattern": "response\\.getWriter\\(\\)\\.print\\s*\\(\\s*.*request\\.getParameter.*\\)",
                    "code_context": extraction_results["results"][0]["extractions"][1]["context"],
                    "explanation": "Not vulnerable",
                    "impact": "",
                    "secure_alternative": "",
                    "recommendation": "No action needed"
                }
            ]
            
            # Analyze the extraction results
            analysis_results = self.analyzer.analyze(extraction_results)
            
            # Verify the analysis results
            assert analysis_results["target_path"] == "test_project"
            assert analysis_results["language"] == "java"
            assert analysis_results["files_analyzed"] == 1
            assert analysis_results["vulnerabilities_analyzed"] == 2
            assert analysis_results["total_vulnerabilities"] == 1
            assert analysis_results["false_positives"] == 1
            assert analysis_results["high_severity"] == 1
            assert analysis_results["medium_severity"] == 0
            assert analysis_results["low_severity"] == 0
            
            # Verify file results
            assert len(analysis_results["results"]) == 1
            file_result = analysis_results["results"][0]
            assert file_result["file_path"] == "test.java"
            assert file_result["language"] == "java"
            assert len(file_result["vulnerabilities"]) == 2
            
            # Verify SQL injection vulnerability
            sql_vuln = file_result["vulnerabilities"][0]
            assert sql_vuln["is_vulnerable"] == True
            assert sql_vuln["severity"] == "high"
            assert sql_vuln["vulnerability_type"] == "SQL_INJECTION"
            
            # Verify XSS vulnerability (false positive)
            xss_vuln = file_result["vulnerabilities"][1]
            assert xss_vuln["is_vulnerable"] == False
            assert xss_vuln["severity"] == "none"
            assert xss_vuln["vulnerability_type"] == "XSS"
            
            # Verify batch analysis was called once
            mock_batch.assert_called_once()

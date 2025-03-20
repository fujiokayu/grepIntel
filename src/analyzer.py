"""
Security analyzer module for GrepIntel.

This module provides functionality to analyze potential security vulnerabilities
using LLM-based analysis.
"""
import os
import re
import logging
from typing import Dict, List, Any, Optional, Tuple

from src.llm.client import LLMClient

# Set up logging
logger = logging.getLogger('grepintel')

class SecurityAnalyzer:
    """
    Security analyzer class
    
    Analyzes potential security vulnerabilities using LLM-based analysis.
    """
    
    def __init__(self, llm_client: LLMClient):
        """
        Constructor
        
        Args:
            llm_client: LLM client instance
        """
        self.llm_client = llm_client
        self.prompt_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'prompts')
        self.results = {}
        
        # Load prompt templates
        self.prompt_templates = {
            'en': self._load_prompt_template('vulnerability_analysis_en.txt'),
            'ja': self._load_prompt_template('vulnerability_analysis_ja.txt')
        }
    
    def _load_prompt_template(self, filename: str) -> str:
        """
        Load a prompt template from file
        
        Args:
            filename: Prompt template filename
            
        Returns:
            str: Prompt template content
            
        Raises:
            FileNotFoundError: If the prompt template file is not found
        """
        prompt_path = os.path.join(self.prompt_dir, filename)
        try:
            with open(prompt_path, 'r', encoding='utf-8') as file:
                return file.read()
        except FileNotFoundError:
            logger.error(f"Prompt template not found: {prompt_path}")
            raise
    
    def analyze(self, extraction_results: Dict[str, Any], language: str = 'en') -> Dict[str, Any]:
        """
        Analyze potential security vulnerabilities
        
        Args:
            extraction_results: Results from the code extractor
            language: Language for the analysis (en or ja)
            
        Returns:
            Dict: Analysis results
        """
        # Initialize analysis results
        analysis_results = {
            "target_path": extraction_results["target_path"],
            "language": extraction_results["language"],
            "framework": extraction_results["framework"],
            "files_analyzed": 0,
            "vulnerabilities_analyzed": 0,
            "total_vulnerabilities": 0,
            "false_positives": 0,
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0,
            "results": []
        }
        
        # Process each file result
        for file_result in extraction_results["results"]:
            file_path = file_result["file_path"]
            file_language = file_result["language"]
            framework = file_result["framework"]
            
            # Initialize file analysis result
            file_analysis = {
                "file_path": file_path,
                "language": file_language,
                "framework": framework,
                "vulnerabilities": []
            }
            
            # Process each extraction
            for extraction in file_result["extractions"]:
                # Analyze vulnerability
                vulnerability_analysis = self.analyze_vulnerability(
                    extraction, 
                    file_path, 
                    file_language,
                    language
                )
                
                # Add to file analysis
                file_analysis["vulnerabilities"].append(vulnerability_analysis)
                
                # Update statistics
                analysis_results["vulnerabilities_analyzed"] += 1
                
                if vulnerability_analysis["is_vulnerable"]:
                    analysis_results["total_vulnerabilities"] += 1
                    
                    if vulnerability_analysis["severity"] == "high":
                        analysis_results["high_severity"] += 1
                    elif vulnerability_analysis["severity"] == "medium":
                        analysis_results["medium_severity"] += 1
                    elif vulnerability_analysis["severity"] == "low":
                        analysis_results["low_severity"] += 1
                else:
                    analysis_results["false_positives"] += 1
            
            # Add file analysis to results
            analysis_results["results"].append(file_analysis)
            analysis_results["files_analyzed"] += 1
        
        return analysis_results
    
    def analyze_vulnerability(self, extraction: Dict[str, Any], file_path: str, 
                             language: str, report_language: str = 'en') -> Dict[str, Any]:
        """
        Analyze a single vulnerability
        
        Args:
            extraction: Extraction data
            file_path: Path to the file
            language: Programming language
            report_language: Language for the analysis (en or ja)
            
        Returns:
            Dict: Vulnerability analysis
        """
        # Format prompt
        prompt = self.format_prompt(extraction, file_path, language, report_language)
        
        try:
            # Get LLM analysis
            logger.debug(f"Sending vulnerability analysis prompt to LLM")
            llm_response = self.llm_client.analyze(prompt)
            
            # Parse LLM response
            analysis = self.parse_llm_response(llm_response)
            
            # Determine severity
            if analysis["is_vulnerable"]:
                severity = self.determine_severity(extraction["vulnerability_type"], analysis)
                analysis["severity"] = severity
            else:
                analysis["severity"] = "none"
            
            # Add extraction data
            analysis["vulnerability_type"] = extraction["vulnerability_type"]
            analysis["line_number"] = extraction["line_number"]
            analysis["pattern"] = extraction["pattern"]
            analysis["code_context"] = extraction["context"]
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing vulnerability: {str(e)}")
            
            # Return a basic analysis in case of error
            return {
                "is_vulnerable": True,  # Assume vulnerable by default
                "severity": "medium",  # Default to medium severity
                "vulnerability_type": extraction["vulnerability_type"],
                "line_number": extraction["line_number"],
                "pattern": extraction["pattern"],
                "code_context": extraction["context"],
                "explanation": f"Error during analysis: {str(e)}",
                "impact": "Unknown (analysis failed)",
                "secure_alternative": "Unknown (analysis failed)",
                "recommendation": "Please review this vulnerability manually."
            }
    
    def format_prompt(self, extraction: Dict[str, Any], file_path: str, 
                     language: str, report_language: str = 'en') -> str:
        """
        Format a prompt for LLM analysis
        
        Args:
            extraction: Extraction data
            file_path: Path to the file
            language: Programming language
            report_language: Language for the analysis (en or ja)
            
        Returns:
            str: Formatted prompt
        """
        # Get prompt template
        template = self.prompt_templates.get(report_language, self.prompt_templates['en'])
        
        # Format prompt
        prompt = template.format(
            language=language,
            file_path=file_path,
            vulnerability_type=extraction["vulnerability_type"],
            pattern=extraction["pattern"],
            code_snippet=extraction["context"]["code"]
        )
        
        return prompt
    
    def parse_llm_response(self, response: str) -> Dict[str, Any]:
        """
        Parse LLM response
        
        Args:
            response: LLM response
            
        Returns:
            Dict: Parsed analysis
        """
        # Initialize analysis
        analysis = {
            "is_vulnerable": False,
            "explanation": "",
            "impact": "",
            "secure_alternative": "",
            "recommendation": ""
        }
        
        # Extract vulnerability assessment
        assessment_match = re.search(r'## Vulnerability Assessment\s*\n([^\n]+)', response)
        if assessment_match:
            assessment = assessment_match.group(1).strip()
            analysis["is_vulnerable"] = "vulnerable" in assessment.lower()
        
        # Extract explanation
        explanation_match = re.search(r'## Explanation\s*\n(.*?)(?=\n##|\Z)', response, re.DOTALL)
        if explanation_match:
            analysis["explanation"] = explanation_match.group(1).strip()
        
        # Extract impact (if vulnerable)
        if analysis["is_vulnerable"]:
            impact_match = re.search(r'## Impact.*?\n(.*?)(?=\n##|\Z)', response, re.DOTALL)
            if impact_match:
                analysis["impact"] = impact_match.group(1).strip()
        
        # Extract secure alternative (if vulnerable)
        if analysis["is_vulnerable"]:
            alternative_match = re.search(r'## Secure Alternative.*?\n```.*?\n(.*?)```', response, re.DOTALL)
            if alternative_match:
                analysis["secure_alternative"] = alternative_match.group(1).strip()
        
        # Extract recommendation
        recommendation_match = re.search(r'## Recommendation\s*\n(.*?)(?=\n##|\Z)', response, re.DOTALL)
        if recommendation_match:
            analysis["recommendation"] = recommendation_match.group(1).strip()
        
        return analysis
    
    def determine_severity(self, vulnerability_type: str, analysis: Dict[str, Any]) -> str:
        """
        Determine the severity of a vulnerability
        
        Args:
            vulnerability_type: Type of vulnerability
            analysis: Vulnerability analysis
            
        Returns:
            str: Severity level (high, medium, or low)
        """
        # High severity vulnerabilities
        high_severity_types = [
            "SQL_INJECTION", 
            "COMMAND_INJECTION", 
            "INSECURE_DESERIALIZATION",
            "REMOTE_CODE_EXECUTION"
        ]
        
        # Medium severity vulnerabilities
        medium_severity_types = [
            "XSS", 
            "CSRF", 
            "PATH_TRAVERSAL", 
            "AUTHENTICATION_FLAWS",
            "AUTHORIZATION_FLAWS",
            "SENSITIVE_DATA_EXPOSURE",
            "ELOQUENT_INJECTION",
            "MASS_ASSIGNMENT"
        ]
        
        # Check for keywords in impact
        impact = analysis.get("impact", "").lower()
        
        # Check for high severity keywords
        if any(keyword in impact for keyword in ["critical", "severe", "high", "remote", "full access", "data breach"]):
            return "high"
        
        # Check for low severity keywords
        if any(keyword in impact for keyword in ["minor", "low", "limited", "minimal"]):
            return "low"
        
        # Determine by vulnerability type
        if vulnerability_type in high_severity_types:
            return "high"
        elif vulnerability_type in medium_severity_types:
            return "medium"
        else:
            return "low"

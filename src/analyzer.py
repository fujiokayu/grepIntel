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
logger = logging.getLogger("grepintel")


class SecurityAnalyzer:
    """
    Security analyzer class

    Analyzes potential security vulnerabilities using LLM-based analysis.
    """

    def __init__(self, llm_client: LLMClient, batch_size: int = 3):
        """
        Constructor

        Args:
            llm_client: LLM client instance
            batch_size: Number of vulnerabilities to analyze in a single batch
        """
        self.llm_client = llm_client
        self.prompt_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "prompts"
        )
        self.results = {}
        self.batch_size = batch_size

        # Load English prompt template only
        self.prompt_template = self._load_prompt_template(
            "vulnerability_analysis_en.txt"
        )

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
            with open(prompt_path, "r", encoding="utf-8") as file:
                return file.read()
        except FileNotFoundError:
            logger.error(f"Prompt template not found: {prompt_path}")
            raise

    def analyze(
        self, extraction_results: Dict[str, Any], language: str = "en"
    ) -> Dict[str, Any]:
        """
        Analyze potential security vulnerabilities

        Args:
            extraction_results: Results from the code extractor
            language: Language for the report (en or ja), but analysis is always in English

        Returns:
            Dict: Analysis results
        """
        # Import progress tracker
        from src.utils.progress_tracker import ProgressTracker

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
            "results": [],
        }

        # Count total vulnerabilities to analyze
        total_vulnerabilities = 0
        for file_result in extraction_results["results"]:
            total_vulnerabilities += len(file_result["extractions"])

        # Initialize progress tracker if there are vulnerabilities to analyze
        self.progress_tracker = None
        if total_vulnerabilities > 0:
            self.progress_tracker = ProgressTracker(
                total_vulnerabilities, "Analyzing vulnerabilities"
            )

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
                "vulnerabilities": [],
            }

            # Get all extractions for this file
            extractions = file_result["extractions"]

            # Skip if no extractions
            if not extractions:
                analysis_results["files_analyzed"] += 1
                continue

            # Use batch processing for multiple extractions
            logger.info(
                f"Analyzing {len(extractions)} potential vulnerabilities in {file_path}"
            )
            # Always analyze in English, store report language for later translation
            vulnerability_analyses = self.analyze_vulnerabilities_batch(
                extractions, file_path, file_language, "en"
            )

            # Add analyses to file result and update statistics
            for vulnerability_analysis in vulnerability_analyses:
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

            # Update progress is now handled in analyze_vulnerabilities_batch

        return analysis_results

    def analyze_vulnerability(
        self,
        extraction: Dict[str, Any],
        file_path: str,
        language: str,
        report_language: str = "en",
    ) -> Dict[str, Any]:
        """
        Analyze a single vulnerability

        Args:
            extraction: Extraction data
            file_path: Path to the file
            language: Programming language
            report_language: Language for the report (not used, always analyze in English)

        Returns:
            Dict: Vulnerability analysis
        """
        # Always use English for analysis
        prompt = self.format_prompt(extraction, file_path, language, "en")

        try:
            # Get LLM analysis
            logger.debug(f"Sending vulnerability analysis prompt to LLM")
            llm_response = self.llm_client.analyze(prompt)

            # Parse LLM response
            analysis = self.parse_llm_response(llm_response)

            # Determine severity
            if analysis["is_vulnerable"]:
                severity = self.determine_severity(
                    extraction["vulnerability_type"], analysis
                )
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
                "recommendation": "Please review this vulnerability manually.",
            }

    def format_prompt(
        self,
        extraction: Dict[str, Any],
        file_path: str,
        language: str,
        report_language: str = "en",
    ) -> str:
        """
        Format a prompt for LLM analysis

        Args:
            extraction: Extraction data
            file_path: Path to the file
            language: Programming language
            report_language: Language for the report (not used, always analyze in English)

        Returns:
            str: Formatted prompt
        """
        # Always use English prompt template and English for analysis
        prompt = self.prompt_template.format(
            language=language,
            file_path=file_path,
            vulnerability_type=extraction["vulnerability_type"],
            pattern=extraction["pattern"],
            code_snippet=extraction["context"]["code"],
        )

        return prompt

    def parse_llm_response(self, response: str) -> Dict[str, Any]:
        """
        Parse LLM response

        Args:
            response: LLM response (in English)

        Returns:
            Dict: Parsed analysis
        """
        # Initialize analysis
        analysis = {
            "is_vulnerable": False,
            "explanation": "",
            "impact": "",
            "secure_alternative": "",
            "recommendation": "",
        }

        # Extract vulnerability assessment (English only)
        assessment_match = re.search(
            r"## Vulnerability Assessment\s*\n([^\n]+)", response
        )
        if assessment_match:
            assessment = assessment_match.group(1).strip().lower()
            analysis["is_vulnerable"] = "vulnerable" in assessment

        # Extract explanation (English only)
        explanation_match = re.search(
            r"## Explanation\s*\n(.*?)(?=\n##|\Z)", response, re.DOTALL
        )
        if explanation_match:
            analysis["explanation"] = explanation_match.group(1).strip()

        # Extract impact (if vulnerable) (English only)
        if analysis["is_vulnerable"]:
            impact_match = re.search(
                r"## Impact.*?\n(.*?)(?=\n##|\Z)", response, re.DOTALL
            )
            if impact_match:
                analysis["impact"] = impact_match.group(1).strip()

        # Extract secure alternative (if vulnerable) (English only)
        if analysis["is_vulnerable"]:
            alternative_match = re.search(
                r"## Secure Alternative.*?\n```.*?\n(.*?)```", response, re.DOTALL
            )
            if alternative_match:
                analysis["secure_alternative"] = alternative_match.group(1).strip()

        # Extract recommendation (English only)
        recommendation_match = re.search(
            r"## Recommendation\s*\n(.*?)(?=\n##|\Z)", response, re.DOTALL
        )
        if recommendation_match:
            analysis["recommendation"] = recommendation_match.group(1).strip()

        return analysis

    def analyze_vulnerabilities_batch(
        self,
        extractions: List[Dict[str, Any]],
        file_path: str,
        language: str,
        report_language: str = "en",
    ) -> List[Dict[str, Any]]:
        """
        Analyze multiple vulnerabilities in a single batch

        Args:
            extractions: List of extraction data
            file_path: Path to the file
            language: Programming language
            report_language: Language for the analysis (en or ja)

        Returns:
            List[Dict]: List of vulnerability analyses
        """
        # Import progress tracker
        from src.utils.progress_tracker import ProgressTracker

        results = []

        # If no extractions, return empty list
        if not extractions:
            return results

        # If only one extraction, use the single analysis method
        if len(extractions) == 1:
            results.append(
                self.analyze_vulnerability(
                    extractions[0], file_path, language, report_language
                )
            )
            # Get progress tracker from parent class if available
            if hasattr(self, "progress_tracker") and self.progress_tracker:
                self.progress_tracker.update(1)
            return results

        # Split extractions into batches
        for i in range(0, len(extractions), self.batch_size):
            batch = extractions[i : i + self.batch_size]

            # Generate batch prompt
            prompt = self.format_batch_prompt(
                batch, file_path, language, report_language
            )

            try:
                # Get LLM analysis
                logger.debug(
                    f"Sending batch vulnerability analysis prompt to LLM for {len(batch)} vulnerabilities"
                )
                llm_response = self.llm_client.analyze(prompt)

                # Parse batch response
                batch_results = self.parse_batch_response(
                    llm_response, batch, file_path, language, report_language
                )
                results.extend(batch_results)

                # Update progress after each batch
                if hasattr(self, "progress_tracker") and self.progress_tracker:
                    self.progress_tracker.update(len(batch))

            except Exception as e:
                logger.error(f"Error in batch analysis: {str(e)}")
                logger.warning(
                    f"Falling back to individual analysis for {len(batch)} vulnerabilities"
                )

                # Fallback to individual analysis
                for extraction in batch:
                    individual_analysis = self.analyze_vulnerability(
                        extraction, file_path, language, report_language
                    )
                    results.append(individual_analysis)

                # Update progress after fallback analysis
                if hasattr(self, "progress_tracker") and self.progress_tracker:
                    self.progress_tracker.update(len(batch))

        return results

    def format_batch_prompt(
        self,
        extractions: List[Dict[str, Any]],
        file_path: str,
        language: str,
        report_language: str = "en",
    ) -> str:
        """
        Format a batch prompt for LLM analysis

        Args:
            extractions: List of extraction data
            file_path: Path to the file
            language: Programming language
            report_language: Language for the report (not used, always analyze in English)

        Returns:
            str: Formatted batch prompt
        """
        # Always use English for analysis
        template_base = "You are a security expert analyzing potential vulnerabilities in source code.\n\n"
        template_base += f"File: {file_path}\nLanguage: {language}\n\n"
        template_base += "Please analyze the following potential vulnerabilities:\n\n"

        # Add each vulnerability to the prompt
        for i, extraction in enumerate(extractions):
            template_base += f"VULNERABILITY {i+1}:\n"
            template_base += f"Type: {extraction['vulnerability_type']}\n"
            template_base += f"Pattern matched: {extraction['pattern']}\n"
            template_base += f"Code snippet:\n```{language}\n{extraction['context']['code']}\n```\n\n"

        # Add response format instructions
        template_base += (
            "For each vulnerability, provide your analysis in the following format:\n\n"
        )
        template_base += "ANALYSIS FOR VULNERABILITY X:\n"
        template_base += "## Vulnerability Assessment\n[Vulnerable/False Positive]\n\n"
        template_base += "## Explanation\n[Detailed explanation]\n\n"
        template_base += "## Impact (if vulnerable)\n[Description of impact]\n\n"
        template_base += "## Secure Alternative (if vulnerable)\n```[language]\n[Secure code]\n```\n\n"
        template_base += "## Recommendation\n[Specific recommendation]\n\n"
        template_base += "Replace X with the vulnerability number (1, 2, 3, etc.)."

        return template_base

    def parse_batch_response(
        self,
        response: str,
        extractions: List[Dict[str, Any]],
        file_path: str,
        language: str,
        report_language: str = "en",
    ) -> List[Dict[str, Any]]:
        """
        Parse a batch response from LLM

        Args:
            response: LLM response (in English)
            extractions: List of extraction data
            file_path: Path to the file
            language: Programming language
            report_language: Language for the report (not used, always analyze in English)

        Returns:
            List[Dict]: List of vulnerability analyses
        """
        results = []

        # Log the raw response for debugging
        logger.debug(f"Raw batch LLM response: {response}")

        # Process each vulnerability in the batch
        for i, extraction in enumerate(extractions):
            # Extract the analysis for this vulnerability (English only)
            vulnerability_number = i + 1
            analysis_pattern = f"ANALYSIS FOR VULNERABILITY {vulnerability_number}:(.*?)(?=ANALYSIS FOR VULNERABILITY|$)"
            analysis_match = re.search(analysis_pattern, response, re.DOTALL)

            if analysis_match:
                # Parse the individual analysis
                individual_response = analysis_match.group(1).strip()
                analysis = self.parse_llm_response(individual_response)

                # Determine severity
                if analysis["is_vulnerable"]:
                    severity = self.determine_severity(
                        extraction["vulnerability_type"], analysis
                    )
                    analysis["severity"] = severity
                else:
                    analysis["severity"] = "none"

                # Add extraction data
                analysis["vulnerability_type"] = extraction["vulnerability_type"]
                analysis["line_number"] = extraction["line_number"]
                analysis["pattern"] = extraction["pattern"]
                analysis["code_context"] = extraction["context"]

                results.append(analysis)
            else:
                # Fallback to individual analysis if parsing fails
                logger.warning(
                    f"Failed to parse batch response for vulnerability {vulnerability_number}. Falling back to individual analysis."
                )
                individual_analysis = self.analyze_vulnerability(
                    extraction, file_path, language, "en"
                )
                results.append(individual_analysis)

        return results

    def determine_severity(
        self, vulnerability_type: str, analysis: Dict[str, Any]
    ) -> str:
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
            "REMOTE_CODE_EXECUTION",
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
            "MASS_ASSIGNMENT",
        ]

        # Check for keywords in impact
        impact = analysis.get("impact", "").lower()

        # Check for high severity keywords
        if any(
            keyword in impact
            for keyword in [
                "critical",
                "severe",
                "high",
                "remote",
                "full access",
                "data breach",
            ]
        ):
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

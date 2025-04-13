"""
Report generator module for GrepIntel.

This module provides functionality to generate security assessment reports
based on the analysis results.
"""

import os
import re
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

# Set up logging
logger = logging.getLogger("grepintel")


class ReportGenerator:
    """
    Report generator class

    Generates security assessment reports based on the analysis results.
    """

    def __init__(self, template_dir: Optional[str] = None):
        """
        Constructor

        Args:
            template_dir: Directory containing report templates
        """
        if template_dir is None:
            template_dir = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), "templates"
            )

        self.template_dir = template_dir
        logger.debug(
            f"Initialized report generator with template directory: {template_dir}"
        )

    def generate(
        self, analysis_results: Dict[str, Any], output_file: str, language: str = "en"
    ) -> None:
        """
        Generate a security assessment report

        Args:
            analysis_results: Results from the security analyzer
            output_file: Path to the output report file
            language: Language for the report (en or ja)

        Returns:
            None
        """
        # Use language-specific template
        template = self.load_template(language)

        # Calculate statistics
        statistics = self.calculate_statistics(analysis_results)

        # Format report
        report = self.format_report(template, analysis_results, statistics)

        # Write report to file
        try:
            with open(output_file, "w", encoding="utf-8") as file:
                file.write(report)

            logger.info(f"Report generated successfully: {output_file}")
        except Exception as e:
            logger.error(f"Error writing report to file: {str(e)}")
            raise

    def load_template(self, language: str = "en") -> str:
        """
        Load a report template

        Args:
            language: Language for the template (en or ja)

        Returns:
            str: Template content

        Raises:
            FileNotFoundError: If the template file is not found
        """
        template_filename = f"report_template_{language}.md"
        template_path = os.path.join(self.template_dir, template_filename)

        try:
            with open(template_path, "r", encoding="utf-8") as file:
                return file.read()
        except FileNotFoundError:
            logger.error(f"Report template not found: {template_path}")

            # Fallback to English template
            if language != "en":
                logger.warning(f"Falling back to English template")
                return self.load_template("en")
            else:
                raise

    def calculate_statistics(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate statistics from analysis results

        Args:
            analysis_results: Results from the security analyzer

        Returns:
            Dict: Statistics
        """
        return {
            "total_vulnerabilities": analysis_results["total_vulnerabilities"],
            "false_positives": analysis_results["false_positives"],
            "high_severity": analysis_results["high_severity"],
            "medium_severity": analysis_results["medium_severity"],
            "low_severity": analysis_results["low_severity"],
            "files_analyzed": analysis_results["files_analyzed"],
            "vulnerabilities_analyzed": analysis_results["vulnerabilities_analyzed"],
        }

    def format_report(
        self,
        template: str,
        analysis_results: Dict[str, Any],
        statistics: Dict[str, Any],
    ) -> str:
        """
        Format a report using the template

        Args:
            template: Report template
            analysis_results: Results from the security analyzer
            statistics: Statistics calculated from the analysis results

        Returns:
            str: Formatted report
        """
        # Basic information
        report = template.replace("{target}", analysis_results["target_path"])
        report = report.replace(
            "{scan_date}", datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        # Handle language field which can be a string or a list
        language_value = analysis_results["language"]
        if isinstance(language_value, list):
            language_str = ", ".join(language_value)
        else:
            language_str = str(language_value)
        report = report.replace("{languages}", language_str)

        report = report.replace("{files_scanned}", str(statistics["files_analyzed"]))
        report = report.replace(
            "{total_vulnerabilities}", str(statistics["total_vulnerabilities"])
        )

        # Statistics
        report = report.replace(
            "{high_severity_count}", str(statistics["high_severity"])
        )
        report = report.replace(
            "{medium_severity_count}", str(statistics["medium_severity"])
        )
        report = report.replace("{low_severity_count}", str(statistics["low_severity"]))
        report = report.replace(
            "{false_positive_count}", str(statistics["false_positives"])
        )

        # 条件付きセクションを処理
        for condition, value in [
            ("if_high_severity", statistics["high_severity"] > 0),
            ("if_medium_severity", statistics["medium_severity"] > 0),
            ("if_low_severity", statistics["low_severity"] > 0),
            ("if_false_positives", statistics["false_positives"] > 0),
        ]:
            if value:
                # 条件が真の場合、条件タグを削除
                report = re.sub(
                    f"{{{condition}}}(.*?){{end_{condition}}}",
                    r"\1",
                    report,
                    flags=re.DOTALL,
                )
            else:
                # 条件が偽の場合、条件ブロック全体を削除
                report = re.sub(
                    f"{{{condition}}}.*?{{end_{condition}}}",
                    "",
                    report,
                    flags=re.DOTALL,
                )

        # Generate vulnerability findings
        findings = self.generate_findings(analysis_results)

        # Replace the placeholder with the findings
        findings_placeholder = "{for each vulnerability}(.*?){end for}"
        findings_template = re.search(findings_placeholder, report, re.DOTALL)

        if findings_template:
            findings_section = findings_template.group(1)
            all_findings = ""

            for i, finding in enumerate(findings):
                finding_section = findings_section
                for key, value in finding.items():
                    # 正規表現パターンの場合は特別な処理を行う
                    if key == "pattern" and isinstance(value, str):
                        # パターンはそのまま使用する（エスケープしない）
                        pass
                    # その他の文字列値の場合はエスケープする
                    elif isinstance(value, str):
                        value = value.replace("\\", "\\\\")
                    finding_section = finding_section.replace(f"{{{key}}}", str(value))
                all_findings += finding_section

            # Use string replacement instead of regex for the final substitution
            parts = report.split("{for each vulnerability}")
            if len(parts) > 1:
                end_parts = parts[1].split("{end for}")
                if len(end_parts) > 1:
                    report = parts[0] + all_findings + end_parts[1]

        return report

    def generate_findings(
        self, analysis_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Generate vulnerability findings

        Args:
            analysis_results: Results from the security analyzer

        Returns:
            List[Dict]: List of findings
        """
        findings = []
        vulnerability_id = 1

        for file_result in analysis_results["results"]:
            file_path = file_result["file_path"]
            language = file_result["language"]

            for vulnerability in file_result["vulnerabilities"]:
                # Skip false positives
                if not vulnerability["is_vulnerable"]:
                    continue

                # Create finding
                finding = {
                    "vulnerability_id": f"VULN-{vulnerability_id:03d}",
                    "vulnerability_title": vulnerability["vulnerability_type"]
                    .replace("_", " ")
                    .title(),
                    "severity": vulnerability["severity"].upper(),
                    "file_path": file_path,
                    "line_number": vulnerability["line_number"],
                    "vulnerability_type": vulnerability["vulnerability_type"],
                    "pattern": vulnerability["pattern"],
                    "language": language,
                    "code_snippet": vulnerability["code_context"]["code"],
                    "llm_analysis": vulnerability["explanation"],
                    "recommendation": vulnerability["recommendation"],
                }

                findings.append(finding)
                vulnerability_id += 1

        return findings

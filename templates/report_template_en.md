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

## Methodology
This security assessment was performed using GrepIntel, a tool that combines pattern-based identification with LLM-powered analysis to detect potential security vulnerabilities in source code. The process involves:

1. Pattern matching to identify potentially vulnerable code sections
2. Context extraction around matched patterns
3. LLM-based analysis to determine if the identified code represents a genuine security vulnerability
4. Severity assessment based on potential impact and exploitability
5. Generation of recommendations for remediation

## Disclaimer
This report is generated automatically and should be reviewed by a security professional. While the tool uses advanced techniques to identify vulnerabilities, it may not detect all security issues, and some findings may be false positives.

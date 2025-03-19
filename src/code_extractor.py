"""
Code extraction module for GrepIntel.

This module provides functionality to extract relevant code snippets
from files with identified security vulnerabilities.
"""
import os
from typing import Dict, List, Any, Optional, Tuple

class CodeExtractor:
    """
    Code extractor class
    
    Extracts relevant code snippets from files with identified security vulnerabilities.
    """
    
    def __init__(self, context_lines: int = 5):
        """
        Constructor
        
        Args:
            context_lines: Number of context lines to include before and after the vulnerability
        """
        self.context_lines = context_lines
        self.results = {}
    
    def extract(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract code snippets from scan results
        
        Args:
            scan_results: Results from the file scanner
            
        Returns:
            Dict: Extraction results
        """
        # Initialize extraction results
        extraction_results = {
            "target_path": scan_results["target_path"],
            "language": scan_results["language"],
            "framework": scan_results["framework"],
            "files_processed": 0,
            "vulnerabilities_processed": 0,
            "results": []
        }
        
        # Process each file result
        for file_result in scan_results["results"]:
            file_path = file_result["file_path"]
            language = file_result["language"]
            framework = file_result["framework"]
            
            # Extract code from file
            file_extraction = self._extract_from_file(file_path, language, framework, file_result["matches"])
            
            if file_extraction:
                extraction_results["files_processed"] += 1
                extraction_results["vulnerabilities_processed"] += len(file_extraction["extractions"])
                extraction_results["results"].append(file_extraction)
        
        return extraction_results
    
    def _extract_from_file(self, file_path: str, language: str, framework: Optional[str], 
                          matches: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Extract code snippets from a file
        
        Args:
            file_path: Path to the file
            language: Programming language
            framework: Framework (optional)
            matches: List of vulnerability matches
            
        Returns:
            Dict or None: Extraction result for the file, or None if extraction failed
        """
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()
            
            # Initialize file extraction result
            file_extraction = {
                "file_path": file_path,
                "language": language,
                "framework": framework,
                "extractions": []
            }
            
            # Process each vulnerability match
            for match in matches:
                # Extract code context
                context = self._extract_context(lines, match["line_number"])
                
                # Create extraction entry
                extraction = {
                    "vulnerability_type": match["vulnerability_type"],
                    "description": match["description"],
                    "line_number": match["line_number"],
                    "context": context,
                    "pattern": match["pattern"]
                }
                
                file_extraction["extractions"].append(extraction)
            
            return file_extraction
            
        except Exception as e:
            print(f"Error extracting code from {file_path}: {str(e)}")
            return None
    
    def _extract_context(self, lines: List[str], line_number: int) -> Dict[str, Any]:
        """
        Extract context around a specific line
        
        Args:
            lines: List of file lines
            line_number: Line number of the vulnerability (1-based)
            
        Returns:
            Dict: Context information
        """
        # Calculate start and end line numbers
        start_line = max(1, line_number - self.context_lines)
        end_line = min(len(lines), line_number + self.context_lines)
        
        # Extract context lines
        context_lines = lines[start_line-1:end_line]
        context_code = ''.join(context_lines)
        
        return {
            "start_line": start_line,
            "end_line": end_line,
            "code": context_code
        }
    
    def format_for_llm(self, extraction_results: Dict[str, Any], max_tokens: int = 4000) -> str:
        """
        Format extraction results for LLM input
        
        Args:
            extraction_results: Results from the extract method
            max_tokens: Maximum number of tokens for LLM input
            
        Returns:
            str: Formatted text for LLM input
        """
        formatted_text = f"Security Analysis Request\n\n"
        formatted_text += f"Target: {extraction_results['target_path']}\n"
        formatted_text += f"Language: {extraction_results['language']}\n"
        
        if extraction_results['framework']:
            formatted_text += f"Framework: {extraction_results['framework']}\n"
        
        formatted_text += f"\nPotential Vulnerabilities:\n\n"
        
        # Track token count (rough estimation)
        token_count = len(formatted_text.split())
        
        # Process each file result
        for file_result in extraction_results["results"]:
            file_header = f"File: {file_result['file_path']}\n\n"
            token_count += len(file_header.split())
            
            if token_count > max_tokens:
                formatted_text += "\n[Additional vulnerabilities omitted due to token limit]"
                break
            
            formatted_text += file_header
            
            # Process each extraction
            for extraction in file_result["extractions"]:
                extraction_text = f"Vulnerability: {extraction['vulnerability_type']}\n"
                extraction_text += f"Description: {extraction['description']}\n"
                extraction_text += f"Line {extraction['line_number']}\n"
                extraction_text += f"Code Context (lines {extraction['context']['start_line']}-{extraction['context']['end_line']}):\n"
                extraction_text += f"```{file_result['language']}\n{extraction['context']['code']}```\n\n"
                
                # Check if adding this extraction would exceed token limit
                extraction_tokens = len(extraction_text.split())
                if token_count + extraction_tokens > max_tokens:
                    formatted_text += "\n[Additional vulnerabilities omitted due to token limit]"
                    break
                
                formatted_text += extraction_text
                token_count += extraction_tokens
        
        return formatted_text

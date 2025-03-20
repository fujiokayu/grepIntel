"""
File scanning module for GrepIntel.

This module provides functionality to scan files for security patterns
and identify potential vulnerabilities.
"""
import os
import re
from typing import Dict, List, Any, Optional, Tuple, Union
import logging

# Set up logging
logger = logging.getLogger('grepintel')

class FileScanner:
    """
    File scanner class
    
    Scans files in the specified directory and detects matches for security patterns.
    """
    
    def __init__(self, pattern_manager):
        """
        Constructor
        
        Args:
            pattern_manager: Pattern management instance
        """
        self.pattern_manager = pattern_manager
        self.results = {}
    
    def scan(self, target_path: str, language: Union[str, List[str]] = 'all', framework: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan the specified path
        
        Args:
            target_path: Directory or file path to scan
            language: Target language(s) to scan ('all' for all languages, or a list of languages)
            framework: Framework to use (optional)
            
        Returns:
            Dict: Scan results
            
        Raises:
            FileNotFoundError: If the target path does not exist
        """
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Target path not found: {target_path}")
        
        # Reset results
        self.results = {
            "target_path": target_path,
            "language": language,
            "framework": framework,
            "files_scanned": 0,
            "vulnerabilities_found": 0,
            "results": []
        }
        
        # Scan directory or file
        if os.path.isdir(target_path):
            self._scan_directory(target_path, language, framework)
        else:
            if language == 'all':
                file_language = self._get_language_from_file(target_path)
                if file_language:
                    file_result = self._scan_file(target_path, file_language, framework)
                    if file_result:
                        self.results["files_scanned"] += 1
                        self.results["vulnerabilities_found"] += len(file_result["matches"])
                        self.results["results"].append(file_result)
            elif isinstance(language, list):
                file_ext_language = self._get_language_from_file(target_path)
                if file_ext_language and file_ext_language in language:
                    file_result = self._scan_file(target_path, file_ext_language, framework)
                    if file_result:
                        self.results["files_scanned"] += 1
                        self.results["vulnerabilities_found"] += len(file_result["matches"])
                        self.results["results"].append(file_result)
            else:
                file_language = language
                file_result = self._scan_file(target_path, file_language, framework)
                if file_result:
                    self.results["files_scanned"] += 1
                    self.results["vulnerabilities_found"] += len(file_result["matches"])
                    self.results["results"].append(file_result)
        
        return self.results
    
    def _scan_directory(self, directory_path: str, language: Union[str, List[str]], framework: Optional[str]) -> None:
        """
        Scan a directory
        
        Args:
            directory_path: Directory path to scan
            language: Target language
            framework: Framework to use (optional)
        """
        logger.debug(f"Scanning directory: {directory_path}")
        
        for root, dirs, files in os.walk(directory_path):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                # Skip hidden files
                if file.startswith('.'):
                    continue
                
                file_path = os.path.join(root, file)
                if language == 'all':
                    file_language = self._get_language_from_file(file_path)
                    if file_language:
                        file_result = self._scan_file(file_path, file_language, framework)
                        if file_result:
                            self.results["files_scanned"] += 1
                            self.results["vulnerabilities_found"] += len(file_result["matches"])
                            self.results["results"].append(file_result)
                elif isinstance(language, list):
                    file_language = self._get_language_from_file(file_path)
                    if file_language and file_language in language:
                        file_result = self._scan_file(file_path, file_language, framework)
                        if file_result:
                            self.results["files_scanned"] += 1
                            self.results["vulnerabilities_found"] += len(file_result["matches"])
                            self.results["results"].append(file_result)
                else:
                    file_language = language
                    file_result = self._scan_file(file_path, file_language, framework)
                    if file_result:
                        self.results["files_scanned"] += 1
                        self.results["vulnerabilities_found"] += len(file_result["matches"])
                        self.results["results"].append(file_result)
    
    def _scan_file(self, file_path: str, language: str, framework: Optional[str]) -> Optional[Dict[str, Any]]:
        """
        Scan a file
        
        Args:
            file_path: File path to scan
            language: Target language
            framework: Framework to use (optional)
            
        Returns:
            Dict or None: Scan results for the file, or None if no matches found
        """
        logger.debug(f"Scanning file: {file_path}")
        
        try:
            # Get patterns for the language
            patterns = self.pattern_manager.get_patterns_for_language(language)
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            # Match patterns
            matches = self._match_patterns(content, patterns)
            
            if matches:
                return {
                    "file_path": file_path,
                    "language": language,
                    "framework": framework,
                    "matches": matches
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {str(e)}")
            return None
    
    def _get_language_from_file(self, file_path: str) -> Optional[str]:
        """
        Determine language from file extension
        
        Args:
            file_path: File path
            
        Returns:
            str or None: Language identifier, or None if no corresponding language
        """
        from src.config import FILE_EXTENSIONS
        
        _, ext = os.path.splitext(file_path)
        ext = ext.lstrip('.').lower()
        
        for language, extensions in FILE_EXTENSIONS.items():
            if ext in extensions:
                return language
        
        return None
    
    def _match_patterns(self, content: str, patterns: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Perform pattern matching on content
        
        Args:
            content: File content
            patterns: Patterns to match
            
        Returns:
            List: List of matching results
        """
        matches = []
        
        # Split content into lines for line number tracking
        lines = content.splitlines()
        
        for vuln_type, vuln_data in patterns.items():
            description = vuln_data["description"]
            
            for pattern in vuln_data["patterns"]:
                # Compile regex pattern
                try:
                    regex = re.compile(pattern)
                except re.error:
                    logger.error(f"Invalid regex pattern: {pattern}")
                    continue
                
                # Search for matches in each line
                for i, line in enumerate(lines):
                    line_number = i + 1  # Line numbers start from 1
                    
                    if regex.search(line):
                        match_data = {
                            "vulnerability_type": vuln_type,
                            "description": description,
                            "line_number": line_number,
                            "line_content": line.strip(),
                            "pattern": pattern
                        }
                        matches.append(match_data)
        
        return matches

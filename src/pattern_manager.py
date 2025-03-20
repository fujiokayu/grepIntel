"""
Pattern management module for GrepIntel.

This module provides functionality to load and manage security patterns
for different programming languages and frameworks.
"""

import os
import re
from typing import Dict, List, Any, Optional


class PatternManager:
    """
    Manages security patterns for different programming languages and frameworks.

    Attributes:
        language_patterns (Dict): Dictionary of patterns organized by language and security aspect.
        framework_patterns (Dict): Dictionary of patterns organized by framework and security aspect.
        combined_patterns (Dict): Dictionary of combined patterns from both language and framework.
        patterns (Dict): Dictionary of patterns (maintained for backward compatibility).
    """

    def __init__(self):
        """Initialize a new PatternManager instance."""
        # Patterns organized by language
        self.language_patterns: Dict[str, Dict[str, Dict[str, Any]]] = {}
        # Patterns organized by framework
        self.framework_patterns: Dict[str, Dict[str, Dict[str, Any]]] = {}
        # Combined patterns (used for actual searching)
        self.combined_patterns: Dict[str, Dict[str, Dict[str, Any]]] = {}
        # Maintained for backward compatibility
        self.patterns: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def _load_patterns_from_file(
        self, file_path: str, target_dict: Dict, key: str
    ) -> None:
        """
        Internal method: Load patterns from a file and store them in the specified dictionary

        Args:
            file_path (str): Path to the pattern file
            target_dict (Dict): Dictionary to store the patterns
            key (str): Dictionary key (language or framework name)

        Raises:
            FileNotFoundError: If the pattern file does not exist
            ValueError: If the pattern file format is invalid
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Pattern file not found: {file_path}")

        # Initialize the dictionary for the specified key (if it doesn't exist)
        if key not in target_dict:
            target_dict[key] = {}

        # Load the pattern file
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()

        # Parse the pattern file
        current_section = None
        current_description = None
        current_patterns = []

        for line in content.splitlines():
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Check for section headers
            section_match = re.match(r"^\[(.*)\]$", line)
            if section_match:
                # Save the previous section if it exists
                if current_section:
                    target_dict[key][current_section] = {
                        "description": current_description,
                        "patterns": current_patterns,
                    }

                # Start a new section
                current_section = section_match.group(1)
                current_description = None
                current_patterns = []
                continue

            # Check for description
            if line.startswith("description:"):
                current_description = line[len("description:") :].strip()
                continue

            # Check for pattern list
            if line == "patterns:":
                continue

            # Check for pattern items
            if line.startswith("- "):
                pattern = line[2:].strip()
                current_patterns.append(pattern)
                continue

        # Save the last section
        if current_section:
            target_dict[key][current_section] = {
                "description": current_description,
                "patterns": current_patterns,
            }

    def load_language_patterns(self, file_path: str, language: str) -> None:
        """
        Load language-specific security patterns from a file

        Args:
            file_path (str): Path to the pattern file
            language (str): Programming language identifier (e.g., 'php', 'java')

        Raises:
            FileNotFoundError: If the pattern file does not exist
            ValueError: If the pattern file format is invalid
        """
        self._load_patterns_from_file(file_path, self.language_patterns, language)
        # Update patterns for backward compatibility
        self._load_patterns_from_file(file_path, self.patterns, language)
        # Update combined patterns
        self._update_combined_patterns(language)

    def load_framework_patterns(
        self, file_path: str, framework: str, language: str
    ) -> None:
        """
        Load framework-specific security patterns from a file

        Args:
            file_path (str): Path to the pattern file
            framework (str): Framework identifier (e.g., 'laravel', 'rails')
            language (str): Associated programming language

        Raises:
            FileNotFoundError: If the pattern file does not exist
            ValueError: If the pattern file format is invalid
        """
        self._load_patterns_from_file(file_path, self.framework_patterns, framework)
        # Update combined patterns
        self._update_combined_patterns(language)

    def _update_combined_patterns(self, language: str) -> None:
        """
        Combine patterns from language and frameworks

        Args:
            language (str): Language for which to combine patterns
        """
        if language not in self.combined_patterns:
            self.combined_patterns[language] = {}

        # Copy language patterns
        if language in self.language_patterns:
            for vuln_type, data in self.language_patterns[language].items():
                if vuln_type not in self.combined_patterns[language]:
                    self.combined_patterns[language][vuln_type] = {
                        "description": data["description"],
                        "patterns": data["patterns"].copy(),
                    }
                else:
                    # Update existing pattern list
                    self.combined_patterns[language][vuln_type]["patterns"] = data[
                        "patterns"
                    ].copy()

        # Add framework patterns
        for framework, framework_data in self.framework_patterns.items():
            for vuln_type, data in framework_data.items():
                # Add patterns to existing vulnerability type
                if vuln_type in self.combined_patterns[language]:
                    # Check existing patterns to avoid duplicates
                    existing_patterns = set(
                        self.combined_patterns[language][vuln_type]["patterns"]
                    )
                    for pattern in data["patterns"]:
                        if pattern not in existing_patterns:
                            self.combined_patterns[language][vuln_type][
                                "patterns"
                            ].append(pattern)
                # Add new vulnerability type if it doesn't exist
                else:
                    self.combined_patterns[language][vuln_type] = {
                        "description": data["description"],
                        "patterns": data["patterns"].copy(),
                    }

    def load_patterns_from_file(self, file_path: str, language: str) -> None:
        """
        Load security patterns from a file (for backward compatibility)

        Args:
            file_path (str): Path to the pattern file
            language (str): Programming language identifier (e.g., 'php', 'java')

        Raises:
            FileNotFoundError: If the pattern file does not exist
            ValueError: If the pattern file format is invalid
        """
        self.load_language_patterns(file_path, language)

    def load_patterns_from_directory(
        self, directory_path: str, is_framework: bool = False
    ) -> None:
        """
        Load all pattern files from a directory

        Args:
            directory_path (str): Path to the directory containing pattern files
            is_framework (bool): Whether to load as framework patterns

        Raises:
            FileNotFoundError: If the directory does not exist
        """
        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Pattern directory not found: {directory_path}")

        for filename in os.listdir(directory_path):
            if filename.endswith(".txt"):
                name = os.path.splitext(filename)[0]
                file_path = os.path.join(directory_path, filename)

                if is_framework:
                    # For framework patterns, we need to identify the associated language
                    # In the actual implementation, we use a mapping of frameworks to languages
                    from src.config import FRAMEWORK_LANGUAGE_MAP

                    if name in FRAMEWORK_LANGUAGE_MAP:
                        language = FRAMEWORK_LANGUAGE_MAP[name]
                        self.load_framework_patterns(file_path, name, language)
                else:
                    # For language patterns
                    self.load_language_patterns(file_path, name)

    def get_patterns_for_language(self, language: str) -> Dict[str, Dict[str, Any]]:
        """
        Get all patterns for a specific language

        Args:
            language (str): Programming language identifier (e.g., 'php', 'java')

        Returns:
            Dict: Dictionary of patterns for the specified language

        Raises:
            ValueError: If the language is not supported
        """
        # Prioritize combined patterns
        if language in self.combined_patterns:
            return self.combined_patterns[language]

        # For backward compatibility
        if language not in self.patterns:
            raise ValueError(f"Unsupported language: {language}")

        return self.patterns[language]

    def get_all_patterns(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """
        Get all patterns for all languages

        Returns:
            Dict: Dictionary of all patterns organized by language and security aspect
        """
        # Prioritize combined patterns
        if self.combined_patterns:
            return self.combined_patterns

        # For backward compatibility
        return self.patterns

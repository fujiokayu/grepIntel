"""
Translation utility module for GrepIntel.

This module provides functionality to translate text using LLM-based translation.
"""

import os
import logging
import re
from typing import Dict, List, Any, Optional, Tuple

from src.llm.client import LLMClient

# Set up logging
logger = logging.getLogger("grepintel")


class Translator:
    """
    Translator class

    Translates text using LLM-based translation.
    """

    def __init__(self, llm_client: LLMClient):
        """
        Constructor

        Args:
            llm_client: LLM client instance
        """
        self.llm_client = llm_client
        self.prompt_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "prompts"
        )

        # Load translation prompt template
        self.prompt_template = self._load_prompt_template("translation_prompt.txt")

        # Define supported languages
        self.supported_languages = {
            "en": "English",
            "ja": "Japanese",
            # Add more languages as needed
        }

        # Define chunk size (in characters) for translation
        self.chunk_size = 2000

        # Define overlap size (in characters) for context preservation
        self.overlap_size = 200

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
            # Create a basic template if file doesn't exist
            return """You are a professional translator specializing in technical and security documentation.

# Translation Task
Translate the following text from {source_language} to {target_language}. 
Maintain the original formatting, including markdown syntax, code blocks, and special characters.

# Text to Translate
{text}

# Guidelines
- Preserve all markdown formatting (headings, lists, code blocks, etc.)
- Maintain all code snippets exactly as they appear in the original
- Preserve all technical terms and variable names
- Ensure the translation is accurate and natural in the target language
- Maintain the same tone and level of formality as the original
"""

    def translate(
        self, text: str, source_language: str = "en", target_language: str = "ja"
    ) -> str:
        """
        Translate text from source language to target language

        Args:
            text: Text to translate
            source_language: Source language code (e.g., 'en')
            target_language: Target language code (e.g., 'ja')

        Returns:
            str: Translated text
        """
        # If source and target languages are the same, return the original text
        if source_language == target_language:
            return text

        # Check if target language is supported
        if target_language not in self.supported_languages:
            logger.warning(
                f"Target language '{target_language}' is not supported. Using English."
            )
            return text

        # Import progress tracker
        from src.utils.progress_tracker import ProgressTracker

        # Special handling for markdown content
        if self._is_markdown(text):
            # Process markdown content by sections
            return self._translate_markdown(text, source_language, target_language)

        # Split text into chunks for translation
        chunks = self._split_into_chunks(text)

        # Initialize progress tracker
        progress_tracker = ProgressTracker(len(chunks), "Translating report")

        # Translate each chunk
        translated_chunks = []
        for i, chunk in enumerate(chunks):
            try:
                # Format prompt for translation
                prompt = self.format_prompt(chunk, source_language, target_language)

                # Get LLM translation
                logger.debug(
                    f"Sending translation prompt to LLM for chunk {i+1}/{len(chunks)}"
                )
                llm_response = self.llm_client.analyze(prompt)

                # Extract translated text
                translated_text = self._extract_translation(llm_response)

                # Add translated chunk
                translated_chunks.append(translated_text)

                # Update progress
                progress_tracker.update(1)

            except Exception as e:
                logger.error(f"Error translating chunk {i+1}: {str(e)}")
                # In case of error, use the original chunk
                translated_chunks.append(chunk)
                progress_tracker.update(1)

        # Combine translated chunks
        translated_text = self._combine_chunks(translated_chunks)

        return translated_text

    def _is_markdown(self, text: str) -> bool:
        """
        Check if text is likely markdown content

        Args:
            text: Text to check

        Returns:
            bool: True if text is likely markdown, False otherwise
        """
        # Check for markdown headers
        if re.search(r"^#+ ", text, re.MULTILINE):
            return True

        # Check for markdown code blocks
        if re.search(r"```", text):
            return True

        # Check for markdown lists
        if re.search(r"^\s*[*-] ", text, re.MULTILINE):
            return True

        # Check for markdown links
        if re.search(r"\[.*?\]\(.*?\)", text):
            return True

        return False

    def _translate_markdown(
        self, text: str, source_language: str, target_language: str
    ) -> str:
        """
        Translate markdown content while preserving structure

        Args:
            text: Markdown text to translate
            source_language: Source language code
            target_language: Target language code

        Returns:
            str: Translated markdown text
        """
        from src.utils.progress_tracker import ProgressTracker

        # 1. Identify markdown elements to protect
        # Code blocks
        code_blocks = []
        code_block_pattern = r"```(?:[a-zA-Z]*\n)?(.*?)```"

        def replace_code_block(match):
            code_blocks.append(match.group(0))
            return f"__CODE_BLOCK_{len(code_blocks)-1}__"

        text_without_code = re.sub(
            code_block_pattern, replace_code_block, text, flags=re.DOTALL
        )

        # Headers
        headers = []
        header_pattern = r"^(#+\s+.*?)$"

        def replace_header(match):
            headers.append(match.group(0))
            return f"__HEADER_{len(headers)-1}__"

        text_without_headers = re.sub(
            header_pattern, replace_header, text_without_code, flags=re.MULTILINE
        )

        # Tables
        tables = []
        table_pattern = r"(\|.*\|[\r\n]+\|[-:| ]+\|[\r\n]+(?:\|.*\|[\r\n]+)+)"

        def replace_table(match):
            tables.append(match.group(0))
            return f"__TABLE_{len(tables)-1}__"

        text_without_tables = re.sub(
            table_pattern, replace_table, text_without_headers, flags=re.DOTALL
        )

        # List item markers
        list_markers = []
        list_marker_pattern = r"^(\s*[*-] )"

        def replace_list_marker(match):
            list_markers.append(match.group(0))
            return f"__LIST_MARKER_{len(list_markers)-1}__ "

        text_without_list_markers = re.sub(
            list_marker_pattern, replace_list_marker, text_without_tables, flags=re.MULTILINE
        )

        # 2. Split text into chunks for translation
        chunks = self._split_into_chunks(text_without_list_markers)

        # 3. Translate each chunk
        progress_tracker = ProgressTracker(len(chunks), "Translating markdown report")
        translated_chunks = []

        for i, chunk in enumerate(chunks):
            try:
                # Create translation prompt
                prompt = self.format_prompt(chunk, source_language, target_language)

                # Translate with LLM
                logger.debug(
                    f"Sending translation prompt to LLM for chunk {i+1}/{len(chunks)}"
                )
                llm_response = self.llm_client.analyze(prompt)

                # Extract translated text
                translated_chunk = self._extract_translation(llm_response)

                # Add translated chunk
                translated_chunks.append(translated_chunk)

                # Update progress
                progress_tracker.update(1)

            except Exception as e:
                logger.error(f"Error translating chunk {i+1}: {str(e)}")
                # In case of error, use the original chunk
                translated_chunks.append(chunk)
                progress_tracker.update(1)

        # 4. Combine translated chunks
        translated_text = self._combine_chunks(translated_chunks)

        # 5. Restore protected elements
        # Restore list markers
        for i, marker in enumerate(list_markers):
            translated_text = translated_text.replace(f"__LIST_MARKER_{i}__ ", marker)

        # Restore tables
        for i, table in enumerate(tables):
            translated_text = translated_text.replace(f"__TABLE_{i}__", table)

        # Restore headers
        for i, header in enumerate(headers):
            translated_text = translated_text.replace(f"__HEADER_{i}__", header)

        # Restore code blocks
        for i, code_block in enumerate(code_blocks):
            translated_text = translated_text.replace(f"__CODE_BLOCK_{i}__", code_block)

        return translated_text

    def format_prompt(
        self, text: str, source_language: str, target_language: str
    ) -> str:
        """
        Format a prompt for translation

        Args:
            text: Text to translate
            source_language: Source language code (e.g., 'en')
            target_language: Target language code (e.g., 'ja')

        Returns:
            str: Formatted prompt
        """
        # Get language names
        source_language_name = self.supported_languages.get(source_language, "English")
        target_language_name = self.supported_languages.get(target_language, "Japanese")

        # Format prompt
        prompt = self.prompt_template.format(
            source_language=source_language_name,
            target_language=target_language_name,
            text=text,
        )

        return prompt

    def _extract_translation(self, response: str) -> str:
        """
        Extract translated text from LLM response

        Args:
            response: LLM response

        Returns:
            str: Extracted translated text
        """
        # Try to extract text between translation markers if present
        translation_match = re.search(
            r"# Translation\s*\n(.*?)(?=\n#|\Z)", response, re.DOTALL
        )

        if translation_match:
            return translation_match.group(1).strip()

        # Try alternative formats that LLM might use
        alt_formats = [
            r"Translation:\s*\n(.*?)(?=\n#|\Z)",
            r"翻訳:\s*\n(.*?)(?=\n#|\Z)",
            r"翻訳結果:\s*\n(.*?)(?=\n#|\Z)",
            r"# 翻訳\s*\n(.*?)(?=\n#|\Z)",
        ]

        for pattern in alt_formats:
            match = re.search(pattern, response, re.DOTALL)
            if match:
                return match.group(1).strip()

        # If no markers found, return the whole response
        return response.strip()

    def _split_into_chunks(self, text: str) -> List[str]:
        """
        Split text into chunks for translation

        Args:
            text: Text to split

        Returns:
            List[str]: List of text chunks
        """
        chunks = []

        # If text is shorter than chunk size, return as a single chunk
        if len(text) <= self.chunk_size:
            chunks.append(text)
            return chunks

        # Split text into chunks
        start = 0
        while start < len(text):
            # Calculate end position
            end = start + self.chunk_size

            # If this is not the last chunk, try to find a natural break point
            if end < len(text):
                # Look for natural break points (newlines, periods, etc.)
                for break_char in ["\n\n", "\n", ". ", "! ", "? ", "。", "！", "？"]:
                    # Find the last occurrence of the break character within the chunk
                    last_break = text.rfind(break_char, start, end)
                    if last_break != -1:
                        # Add 1 to include the break character in the chunk
                        end = last_break + len(break_char)
                        break

            # Add chunk
            chunks.append(text[start:end])

            # Update start position for next chunk, considering overlap
            start = max(start, end - self.overlap_size)

        return chunks

    def _combine_chunks(self, chunks: List[str]) -> str:
        """
        Combine translated chunks into a single text

        Args:
            chunks: List of translated chunks

        Returns:
            str: Combined text
        """
        # If only one chunk, return it
        if len(chunks) == 1:
            return chunks[0]

        # Combine chunks, handling overlaps
        combined_text = chunks[0]

        for i in range(1, len(chunks)):
            current_chunk = chunks[i]

            # Find overlap between the end of the combined text and the start of the current chunk
            overlap_found = False

            # Try different overlap sizes
            for overlap_size in range(
                min(self.overlap_size, len(combined_text)), 0, -1
            ):
                end_of_combined = combined_text[-overlap_size:]
                start_of_current = current_chunk[:overlap_size]

                # If there's an exact match, use it
                if end_of_combined == start_of_current:
                    combined_text += current_chunk[overlap_size:]
                    overlap_found = True
                    break

            # If no overlap found, just append the chunk
            if not overlap_found:
                combined_text += current_chunk

        return combined_text

    def translate_report(
        self, report: Dict[str, Any], target_language: str = "ja"
    ) -> Dict[str, Any]:
        """
        Translate a report from English to the target language

        Args:
            report: Report to translate
            target_language: Target language code (e.g., 'ja')

        Returns:
            Dict: Translated report
        """
        # If target language is English, return the original report
        if target_language == "en":
            return report

        # Create a deep copy of the report to avoid modifying the original
        translated_report = report.copy()

        # Translate each vulnerability finding
        for file_result in translated_report["results"]:
            for vulnerability in file_result["vulnerabilities"]:
                # Only translate text fields, not code or patterns
                if vulnerability["is_vulnerable"]:
                    # Translate explanation
                    vulnerability["explanation"] = self.translate(
                        vulnerability["explanation"], "en", target_language
                    )

                    # Translate impact
                    vulnerability["impact"] = self.translate(
                        vulnerability["impact"], "en", target_language
                    )

                    # Translate recommendation
                    vulnerability["recommendation"] = self.translate(
                        vulnerability["recommendation"], "en", target_language
                    )

        return translated_report

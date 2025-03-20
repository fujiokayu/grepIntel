"""
Gemini client implementation for GrepIntel.

This module provides an implementation of the LLM client interface for Google Gemini.
"""

import os
import logging
import time
from typing import Dict, Any, Optional, List

import google.generativeai as genai

from src.llm.client import LLMClient
from src.llm.utils import estimate_token_count, truncate_text_to_token_limit

# Set up logging
logger = logging.getLogger("grepintel")


class GeminiClient(LLMClient):
    """
    Gemini client implementation.

    This class provides an implementation of the LLM client interface for Google Gemini.
    """

    def __init__(self, api_key: str, model: str = "gemini-2.0-flash-lite"):
        """
        Constructor

        Args:
            api_key: Google API key
            model: Gemini model to use
        """
        super().__init__()  # Initialize the base class
        self.api_key = api_key
        self.model = model
        genai.configure(api_key=api_key)
        logger.debug(f"Initialized Gemini client with model {model}")

    def analyze(self, prompt: str, max_tokens: int = 4000) -> str:
        """
        Analyze a prompt using Gemini.

        Args:
            prompt: The prompt to analyze
            max_tokens: Maximum number of tokens for the response

        Returns:
            str: The Gemini response

        Raises:
            Exception: If the analysis fails
        """
        # Ensure prompt is within token limit
        truncated_prompt = truncate_text_to_token_limit(
            prompt, 30000
        )  # Gemini has a large context limit

        # Maximum retries for rate limiting
        max_retries = 3
        retry_delay = 5  # seconds

        for attempt in range(max_retries):
            try:
                logger.debug(
                    f"Sending prompt to Gemini (attempt {attempt + 1}/{max_retries})"
                )

                # Skip actual API call in test environment, but not in unit tests
                if self.api_key == "test_key" and not os.environ.get(
                    "PYTEST_CURRENT_TEST"
                ):
                    logger.debug("Test environment detected, returning mock response")
                    return "This is a mock response for testing purposes."

                # Configure the model
                model = genai.GenerativeModel(
                    model_name=self.model,
                    generation_config={
                        "max_output_tokens": max_tokens,
                        "temperature": 0.1,  # Low temperature for more deterministic responses
                    },
                )

                # Create system prompt
                system_prompt = "You are a security expert analyzing potential vulnerabilities in source code."

                # Generate content
                response = model.generate_content(
                    [
                        {"role": "user", "parts": [truncated_prompt]},
                    ],
                )

                # Extract the response text
                response_text = response.text
                logger.debug("Received response from Gemini")

                # Log the interaction
                self.log_interaction(
                    prompt=truncated_prompt,
                    response=response_text,
                    metadata={
                        "model": self.model,
                        "max_tokens": max_tokens,
                        "attempt": attempt + 1,
                    },
                )

                return response_text

            except Exception as e:
                if "429" in str(e) or "rate limit" in str(e).lower():
                    if attempt < max_retries - 1:
                        logger.warning(
                            f"Gemini rate limit exceeded. Retrying in {retry_delay} seconds..."
                        )
                        time.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                    else:
                        logger.error(
                            "Gemini rate limit exceeded. Maximum retries reached."
                        )
                        raise
                else:
                    logger.error(f"Error analyzing prompt with Gemini: {str(e)}")
                    raise

    def get_token_count(self, text: str) -> int:
        """
        Get the token count for a text.

        Args:
            text: The text to count tokens for

        Returns:
            int: The token count
        """
        # Gemini doesn't provide a token counting API, so we'll use our estimation
        return estimate_token_count(text)

"""
Claude client implementation for GrepIntel.

This module provides an implementation of the LLM client interface for Anthropic Claude.
"""

import os
import logging
import time
from typing import Dict, Any, Optional, List

import anthropic

from src.llm.client import LLMClient
from src.llm.utils import estimate_token_count, truncate_text_to_token_limit

# Set up logging
logger = logging.getLogger("grepintel")


class ClaudeClient(LLMClient):
    """
    Claude client implementation.

    This class provides an implementation of the LLM client interface for Anthropic Claude.
    """

    def __init__(self, api_key: str, model: str = "claude-3-opus-20240229"):
        """
        Constructor

        Args:
            api_key: Anthropic API key
            model: Claude model to use
        """
        self.api_key = api_key
        self.model = model
        self.client = anthropic.Anthropic(api_key=api_key)
        logger.debug(f"Initialized Claude client with model {model}")

    def analyze(self, prompt: str, max_tokens: int = 4000) -> str:
        """
        Analyze a prompt using Claude.

        Args:
            prompt: The prompt to analyze
            max_tokens: Maximum number of tokens for the response

        Returns:
            str: The Claude response

        Raises:
            Exception: If the analysis fails
        """
        # Ensure prompt is within token limit
        truncated_prompt = truncate_text_to_token_limit(
            prompt, 100000
        )  # Claude has a large context limit

        # Maximum retries for rate limiting
        max_retries = 3
        retry_delay = 5  # seconds

        for attempt in range(max_retries):
            try:
                logger.debug(
                    f"Sending prompt to Claude (attempt {attempt + 1}/{max_retries})"
                )

                # Skip actual API call in test environment, but not in unit tests
                if self.api_key == "test_key" and not os.environ.get(
                    "PYTEST_CURRENT_TEST"
                ):
                    logger.debug("Test environment detected, returning mock response")
                    return "This is a mock response for testing purposes."

                system_prompt = "You are a security expert analyzing potential vulnerabilities in source code."

                response = self.client.messages.create(
                    model=self.model,
                    system=system_prompt,
                    max_tokens=max_tokens,
                    messages=[{"role": "user", "content": truncated_prompt}],
                    temperature=0.1,  # Low temperature for more deterministic responses
                )

                # Extract the response text
                response_text = response.content[0].text
                logger.debug("Received response from Claude")

                return response_text

            except anthropic.RateLimitError:
                if attempt < max_retries - 1:
                    logger.warning(
                        f"Claude rate limit exceeded. Retrying in {retry_delay} seconds..."
                    )
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    logger.error("Claude rate limit exceeded. Maximum retries reached.")
                    raise

            except Exception as e:
                logger.error(f"Error analyzing prompt with Claude: {str(e)}")
                raise

    def get_token_count(self, text: str) -> int:
        """
        Get the token count for a text.

        Args:
            text: The text to count tokens for

        Returns:
            int: The token count
        """
        try:
            # Claude's token counting is not directly exposed in the Python SDK
            # We'll use our estimation function
            return estimate_token_count(text)
        except Exception as e:
            logger.warning(
                f"Error counting tokens with Claude: {str(e)}. Using estimation."
            )
            return estimate_token_count(text)

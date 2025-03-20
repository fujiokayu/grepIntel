"""
DeepSeek client implementation for GrepIntel.

This module provides an implementation of the LLM client interface for DeepSeek.
"""

import os
import logging
import time
import json
import requests
from typing import Dict, Any, Optional, List

from src.llm.client import LLMClient
from src.llm.utils import estimate_token_count, truncate_text_to_token_limit

# Set up logging
logger = logging.getLogger("grepintel")


class DeepSeekClient(LLMClient):
    """
    DeepSeek client implementation.

    This class provides an implementation of the LLM client interface for DeepSeek.
    """

    def __init__(self, api_key: str, model: str = "deepseek-coder"):
        """
        Constructor

        Args:
            api_key: DeepSeek API key
            model: DeepSeek model to use
        """
        super().__init__()  # Initialize the base class
        self.api_key = api_key
        self.model = model
        self.api_base = "https://api.deepseek.com/v1"  # DeepSeek API endpoint
        logger.debug(f"Initialized DeepSeek client with model {model}")

    def analyze(self, prompt: str, max_tokens: int = 4000) -> str:
        """
        Analyze a prompt using DeepSeek.

        Args:
            prompt: The prompt to analyze
            max_tokens: Maximum number of tokens for the response

        Returns:
            str: The DeepSeek response

        Raises:
            Exception: If the analysis fails
        """
        # Ensure prompt is within token limit
        truncated_prompt = truncate_text_to_token_limit(
            prompt, 16000
        )  # DeepSeek has a large context limit

        # Maximum retries for rate limiting
        max_retries = 3
        retry_delay = 5  # seconds

        # Skip actual API call in test environment, but not in unit tests
        if self.api_key == "test_key" and not os.environ.get("PYTEST_CURRENT_TEST"):
            logger.debug("Test environment detected, returning mock response")
            return "This is a mock response for testing purposes."

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        data = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a security expert analyzing potential vulnerabilities in source code.",
                },
                {"role": "user", "content": truncated_prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.1,  # Low temperature for more deterministic responses
        }

        for attempt in range(max_retries):
            try:
                logger.debug(
                    f"Sending prompt to DeepSeek (attempt {attempt + 1}/{max_retries})"
                )

                response = requests.post(
                    f"{self.api_base}/chat/completions",
                    headers=headers,
                    json=data,
                    timeout=120,  # 2-minute timeout
                )

                if response.status_code == 200:
                    response_json = response.json()
                    response_text = response_json["choices"][0]["message"]["content"]
                    logger.debug("Received response from DeepSeek")

                    # Log the interaction
                    self.log_interaction(
                        prompt=truncated_prompt,
                        response=response_text,
                        metadata={
                            "model": self.model,
                            "max_tokens": max_tokens,
                            "attempt": attempt + 1,
                            "status_code": response.status_code,
                        },
                    )

                    return response_text
                elif response.status_code == 429:  # Rate limit
                    if attempt < max_retries - 1:
                        logger.warning(
                            f"DeepSeek rate limit exceeded. Retrying in {retry_delay} seconds..."
                        )
                        time.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                    else:
                        logger.error(
                            "DeepSeek rate limit exceeded. Maximum retries reached."
                        )
                        raise Exception(
                            f"DeepSeek rate limit exceeded: {response.text}"
                        )
                else:
                    logger.error(
                        f"DeepSeek API error: {response.status_code} - {response.text}"
                    )
                    raise Exception(
                        f"DeepSeek API error: {response.status_code} - {response.text}"
                    )

            except requests.exceptions.RequestException as e:
                logger.error(f"Error connecting to DeepSeek API: {str(e)}")
                if attempt < max_retries - 1:
                    logger.warning(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    raise Exception(
                        f"Failed to connect to DeepSeek API after {max_retries} attempts: {str(e)}"
                    )

            except Exception as e:
                logger.error(f"Error analyzing prompt with DeepSeek: {str(e)}")
                raise

    def get_token_count(self, text: str) -> int:
        """
        Get the token count for a text.

        Args:
            text: The text to count tokens for

        Returns:
            int: The token count
        """
        # DeepSeek doesn't provide a token counting API, so we'll use our estimation
        return estimate_token_count(text)

"""
OpenAI client implementation for GrepIntel.

This module provides an implementation of the LLM client interface for OpenAI.
"""

import os
import logging
import time
from typing import Dict, Any, Optional, List

import openai
from openai import OpenAI

from src.llm.client import LLMClient
from src.llm.utils import estimate_token_count, truncate_text_to_token_limit

# Set up logging
logger = logging.getLogger("grepintel")


class OpenAIClient(LLMClient):
    """
    OpenAI client implementation.

    This class provides an implementation of the LLM client interface for OpenAI.
    """

    def __init__(self, api_key: str, model: str = "gpt-4"):
        """
        Constructor

        Args:
            api_key: OpenAI API key
            model: OpenAI model to use
        """
        super().__init__()  # Initialize the base class
        self.api_key = api_key
        self.model = model
        self.client = OpenAI(api_key=api_key)
        logger.debug(f"Initialized OpenAI client with model {model}")

    def analyze(self, prompt: str, max_tokens: int = 4000) -> str:
        """
        Analyze a prompt using OpenAI.

        Args:
            prompt: The prompt to analyze
            max_tokens: Maximum number of tokens for the response

        Returns:
            str: The OpenAI response

        Raises:
            Exception: If the analysis fails
        """
        # Ensure prompt is within token limit
        truncated_prompt = truncate_text_to_token_limit(
            prompt, 8000
        )  # OpenAI has a context limit

        # Maximum retries for rate limiting
        max_retries = 3
        retry_delay = 5  # seconds

        for attempt in range(max_retries):
            try:
                logger.debug(
                    f"Sending prompt to OpenAI (attempt {attempt + 1}/{max_retries})"
                )

                # Skip actual API call in test environment, but not in unit tests
                if self.api_key == "test_key" and not os.environ.get(
                    "PYTEST_CURRENT_TEST"
                ):
                    logger.debug("Test environment detected, returning mock response")
                    return "This is a mock response for testing purposes."

                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a security expert analyzing potential vulnerabilities in source code.",
                        },
                        {"role": "user", "content": truncated_prompt},
                    ],
                    max_tokens=max_tokens,
                    temperature=0.1,  # Low temperature for more deterministic responses
                )

                # Extract the response text
                response_text = response.choices[0].message.content
                logger.debug("Received response from OpenAI")

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

            except openai.RateLimitError:
                if attempt < max_retries - 1:
                    logger.warning(
                        f"OpenAI rate limit exceeded. Retrying in {retry_delay} seconds..."
                    )
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    logger.error("OpenAI rate limit exceeded. Maximum retries reached.")
                    raise

            except Exception as e:
                logger.error(f"Error analyzing prompt with OpenAI: {str(e)}")
                raise

    def get_token_count(self, text: str) -> int:
        """
        Get the token count for a text using OpenAI's tokenizer.

        Args:
            text: The text to count tokens for

        Returns:
            int: The token count
        """
        try:
            # OpenAI's tiktoken library would be more accurate, but for simplicity
            # we'll use our estimation function
            return estimate_token_count(text)
        except Exception as e:
            logger.warning(
                f"Error counting tokens with OpenAI: {str(e)}. Using estimation."
            )
            return estimate_token_count(text)

"""
Tests for LLM client implementations.

This module contains tests for the LLM client interface and implementations.
"""

import os
import pytest
from unittest.mock import patch, MagicMock

from src.llm.client import get_llm_client, LLMClient
from src.llm.openai_client import OpenAIClient
from src.llm.claude_client import ClaudeClient
from src.llm.deepseek_client import DeepSeekClient
from src.llm.gemini_client import GeminiClient
from src.llm.utils import estimate_token_count, truncate_text_to_token_limit


class TestLLMUtils:
    """Tests for LLM utility functions."""

    def test_estimate_token_count(self):
        """Test token count estimation."""
        # Simple test
        text = "This is a test."
        count = estimate_token_count(text)
        assert count > 0

        # Empty text
        assert estimate_token_count("") == 0

        # Longer text
        long_text = "This is a longer text with multiple sentences. It should have more tokens than the simple test."
        long_count = estimate_token_count(long_text)
        assert long_count > count

    def test_truncate_text_to_token_limit(self):
        """Test text truncation to token limit."""
        # Text within limit
        text = "This is a test."
        truncated = truncate_text_to_token_limit(text, 100)
        assert truncated == text

        # Text exceeding limit
        long_text = " ".join(["word"] * 1000)  # A long text
        truncated = truncate_text_to_token_limit(long_text, 10)
        assert len(truncated) < len(long_text)
        assert estimate_token_count(truncated) <= 10


class TestLLMClientFactory:
    """Tests for LLM client factory."""

    @patch.dict(os.environ, {"LLM_PROVIDER": "openai", "LLM_API_KEY": "test_key"})
    @patch("src.llm.openai_client.OpenAIClient")
    def test_get_openai_client(self, mock_openai_client):
        """Test getting OpenAI client."""
        # Setup mock
        mock_instance = MagicMock()
        mock_openai_client.return_value = mock_instance

        # Get client
        client = get_llm_client()

        # Verify
        mock_openai_client.assert_called_once_with("test_key")
        assert client == mock_instance

    @patch.dict(os.environ, {"LLM_PROVIDER": "claude", "LLM_API_KEY": "test_key"})
    @patch("src.llm.claude_client.ClaudeClient")
    def test_get_claude_client(self, mock_claude_client):
        """Test getting Claude client."""
        # Setup mock
        mock_instance = MagicMock()
        mock_claude_client.return_value = mock_instance

        # Get client
        client = get_llm_client()

        # Verify
        mock_claude_client.assert_called_once_with("test_key")
        assert client == mock_instance

    @patch.dict(os.environ, {"LLM_PROVIDER": "deepseek", "LLM_API_KEY": "test_key"})
    @patch("src.llm.deepseek_client.DeepSeekClient")
    def test_get_deepseek_client(self, mock_deepseek_client):
        """Test getting DeepSeek client."""
        # Setup mock
        mock_instance = MagicMock()
        mock_deepseek_client.return_value = mock_instance

        # Get client
        client = get_llm_client()

        # Verify
        mock_deepseek_client.assert_called_once_with("test_key")
        assert client == mock_instance

    @patch.dict(os.environ, {"LLM_PROVIDER": "gemini", "LLM_API_KEY": "test_key"})
    @patch("src.llm.gemini_client.GeminiClient")
    def test_get_gemini_client(self, mock_gemini_client):
        """Test getting Gemini client."""
        # Setup mock
        mock_instance = MagicMock()
        mock_gemini_client.return_value = mock_instance

        # Get client
        client = get_llm_client()

        # Verify
        mock_gemini_client.assert_called_once_with("test_key")
        assert client == mock_instance

    @patch.dict(os.environ, {"LLM_PROVIDER": "invalid", "LLM_API_KEY": "test_key"})
    def test_get_invalid_client(self):
        """Test getting invalid client."""
        # Verify exception
        with pytest.raises(ValueError):
            get_llm_client()

    @patch.dict(os.environ, {"LLM_API_KEY": "test_key"})
    def test_missing_provider(self):
        """Test missing provider."""
        # Remove LLM_PROVIDER
        if "LLM_PROVIDER" in os.environ:
            del os.environ["LLM_PROVIDER"]

        # Verify exception
        with pytest.raises(ValueError):
            get_llm_client()

    @patch.dict(os.environ, {"LLM_PROVIDER": "openai"})
    def test_missing_api_key(self):
        """Test missing API key."""
        # Remove LLM_API_KEY
        if "LLM_API_KEY" in os.environ:
            del os.environ["LLM_API_KEY"]

        # Verify exception
        with pytest.raises(ValueError):
            get_llm_client()


class TestOpenAIClient:
    """Tests for OpenAI client."""

    def test_init(self):
        """Test initialization."""
        client = OpenAIClient("test_key")
        assert client.api_key == "test_key"
        assert client.model == "gpt-4-turbo"  # Default model

        client = OpenAIClient("test_key", model="gpt-3.5-turbo")
        assert client.model == "gpt-3.5-turbo"

    @patch("src.llm.openai_client.OpenAI")
    def test_analyze(self, mock_openai):
        """Test analyze method."""
        # Setup mock
        mock_instance = MagicMock()
        mock_openai.return_value = mock_instance

        mock_response = MagicMock()
        mock_response.choices[0].message.content = "Test response"
        mock_instance.chat.completions.create.return_value = mock_response

        # Create client and analyze
        client = OpenAIClient("test_key")
        response = client.analyze("Test prompt")

        # Verify
        assert response == "Test response"
        mock_instance.chat.completions.create.assert_called_once()

    def test_get_token_count(self):
        """Test token counting."""
        client = OpenAIClient("test_key")
        count = client.get_token_count("This is a test.")
        assert count > 0


class TestClaudeClient:
    """Tests for Claude client."""

    def test_init(self):
        """Test initialization."""
        client = ClaudeClient("test_key")
        assert client.api_key == "test_key"
        assert client.model == "claude-3-7-sonnet-20250219"  # Default model

        client = ClaudeClient("test_key", model="claude-3-5-sonnet-20240620")
        assert client.model == "claude-3-5-sonnet-20240620"

    @patch("anthropic.Anthropic")
    def test_analyze(self, mock_anthropic):
        """Test analyze method."""
        # Setup mock
        mock_instance = MagicMock()
        mock_anthropic.return_value = mock_instance

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Test response")]
        mock_instance.messages.create.return_value = mock_response

        # Create client and analyze
        client = ClaudeClient("test_key")
        response = client.analyze("Test prompt")

        # Verify
        assert response == "Test response"
        mock_instance.messages.create.assert_called_once()

    def test_get_token_count(self):
        """Test token counting."""
        client = ClaudeClient("test_key")
        count = client.get_token_count("This is a test.")
        assert count > 0


class TestDeepSeekClient:
    """Tests for DeepSeek client."""

    def test_init(self):
        """Test initialization."""
        client = DeepSeekClient("test_key")
        assert client.api_key == "test_key"
        assert client.model == "deepseek-coder"  # Default model

        client = DeepSeekClient("test_key", model="deepseek-chat")
        assert client.model == "deepseek-chat"

    @patch("requests.post")
    def test_analyze(self, mock_post):
        """Test analyze method."""
        # Setup mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "Test response"}}]
        }
        mock_post.return_value = mock_response

        # Create client and analyze
        client = DeepSeekClient("test_key")
        response = client.analyze("Test prompt")

        # Verify
        assert response == "Test response"
        mock_post.assert_called_once()

    def test_get_token_count(self):
        """Test token counting."""
        client = DeepSeekClient("test_key")
        count = client.get_token_count("This is a test.")
        assert count > 0


class TestGeminiClient:
    """Tests for Gemini client."""

    def test_init(self):
        """Test initialization."""
        client = GeminiClient("test_key")
        assert client.api_key == "test_key"
        assert client.model == "gemini-2.0-flash-lite"  # Default model

        client = GeminiClient("test_key", model="gemini-1.5-flash")
        assert client.model == "gemini-1.5-flash"

    @patch("google.generativeai.GenerativeModel")
    @patch("google.generativeai.configure")
    def test_analyze(self, mock_configure, mock_generative_model):
        """Test analyze method."""
        # Setup mock
        mock_model_instance = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "Test response"
        mock_model_instance.generate_content.return_value = mock_response
        mock_generative_model.return_value = mock_model_instance

        # Set PYTEST_CURRENT_TEST environment variable to bypass test mode
        os.environ["PYTEST_CURRENT_TEST"] = "test_gemini_client_analyze"

        # Create client and analyze
        client = GeminiClient("test_key")
        response = client.analyze("Test prompt")

        # Verify
        assert response == "Test response"
        mock_configure.assert_called_once_with(api_key="test_key")
        mock_generative_model.assert_called_once()
        mock_model_instance.generate_content.assert_called_once()

        # Clean up
        del os.environ["PYTEST_CURRENT_TEST"]

    def test_get_token_count(self):
        """Test token counting."""
        client = GeminiClient("test_key")
        count = client.get_token_count("This is a test.")
        assert count > 0

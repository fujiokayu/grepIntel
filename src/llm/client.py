"""
LLM client interface and factory for GrepIntel.

This module provides a common interface for different LLM providers
and a factory to create the appropriate client based on configuration.
"""
import os
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List

# Set up logging
logger = logging.getLogger('grepintel')

class LLMClient(ABC):
    """
    Abstract base class for LLM clients.
    
    This class defines the interface that all LLM client implementations must follow.
    """
    
    @abstractmethod
    def analyze(self, prompt: str, max_tokens: int = 4000) -> str:
        """
        Analyze a prompt using the LLM provider.
        
        Args:
            prompt: The prompt to analyze
            max_tokens: Maximum number of tokens for the response
            
        Returns:
            str: The LLM response
            
        Raises:
            Exception: If the analysis fails
        """
        pass
    
    @abstractmethod
    def get_token_count(self, text: str) -> int:
        """
        Get the token count for a text.
        
        Args:
            text: The text to count tokens for
            
        Returns:
            int: The token count
        """
        pass


def get_llm_client() -> LLMClient:
    """
    Factory function to get the appropriate LLM client based on environment variables.
    
    Returns:
        LLMClient: An instance of the appropriate LLM client
        
    Raises:
        ValueError: If the LLM provider is not supported or not configured
    """
    # Get LLM provider from environment
    provider = os.getenv('LLM_PROVIDER')
    api_key = os.getenv('LLM_API_KEY')
    
    if not provider:
        raise ValueError("LLM_PROVIDER environment variable is not set")
    
    if not api_key:
        raise ValueError("LLM_API_KEY environment variable is not set")
    
    # Import the appropriate client based on provider
    if provider.lower() == 'openai':
        from src.llm.openai_client import OpenAIClient
        return OpenAIClient(api_key)
    elif provider.lower() == 'claude':
        from src.llm.claude_client import ClaudeClient
        return ClaudeClient(api_key)
    elif provider.lower() == 'deepseek':
        from src.llm.deepseek_client import DeepSeekClient
        return DeepSeekClient(api_key)
    else:
        from src.config import SUPPORTED_LLM_PROVIDERS
        raise ValueError(f"Unsupported LLM provider: {provider}. Supported providers: {', '.join(SUPPORTED_LLM_PROVIDERS)}")

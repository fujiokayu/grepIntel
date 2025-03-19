"""
Utility functions for LLM clients.

This module provides utility functions for working with LLM clients,
including token counting and text processing.
"""
import re
from typing import List, Dict, Any, Optional


def estimate_token_count(text: str) -> int:
    """
    Estimate the number of tokens in a text.
    
    This is a simple estimation based on word count and punctuation.
    For more accurate token counting, use the provider-specific methods.
    
    Args:
        text: The text to count tokens for
        
    Returns:
        int: Estimated token count
    """
    # Simple estimation: words + punctuation
    # This is a rough approximation and will vary by model
    words = re.findall(r'\w+', text)
    punctuation = re.findall(r'[^\w\s]', text)
    
    # Add a small overhead for whitespace and special tokens
    return len(words) + len(punctuation) + int(len(text) * 0.05)


def truncate_text_to_token_limit(text: str, max_tokens: int) -> str:
    """
    Truncate text to fit within a token limit.
    
    Args:
        text: The text to truncate
        max_tokens: Maximum number of tokens
        
    Returns:
        str: Truncated text
    """
    if estimate_token_count(text) <= max_tokens:
        return text
    
    # Split into paragraphs
    paragraphs = text.split('\n\n')
    result = []
    current_token_count = 0
    
    for paragraph in paragraphs:
        paragraph_token_count = estimate_token_count(paragraph)
        
        if current_token_count + paragraph_token_count <= max_tokens:
            result.append(paragraph)
            current_token_count += paragraph_token_count
        else:
            # If we can't fit the whole paragraph, try to fit as much as possible
            if not result:  # If this is the first paragraph, we need to include something
                words = paragraph.split()
                partial_paragraph = []
                
                for word in words:
                    word_token_count = estimate_token_count(word + ' ')
                    if current_token_count + word_token_count <= max_tokens:
                        partial_paragraph.append(word)
                        current_token_count += word_token_count
                    else:
                        break
                
                if partial_paragraph:
                    # Make sure we're strictly under the token limit
                    truncated_text = ' '.join(partial_paragraph)
                    while estimate_token_count(truncated_text + '...') > max_tokens and partial_paragraph:
                        partial_paragraph.pop()
                        truncated_text = ' '.join(partial_paragraph)
                    
                    if partial_paragraph:
                        result.append(truncated_text + '...')
            
            break
    
    final_text = '\n\n'.join(result)
    
    # Double-check we're under the limit
    if estimate_token_count(final_text) > max_tokens:
        # If still over limit, use a more aggressive approach
        words = text.split()
        result = []
        current_token_count = 0
        
        for word in words:
            word_token_count = estimate_token_count(word + ' ')
            if current_token_count + word_token_count <= max_tokens - 1:  # Reserve 1 token for ellipsis
                result.append(word)
                current_token_count += word_token_count
            else:
                break
        
        final_text = ' '.join(result)
        if result:
            final_text += '...'
    
    return final_text


def format_vulnerability_for_prompt(vulnerability: Dict[str, Any], language: str) -> str:
    """
    Format a vulnerability for inclusion in a prompt.
    
    Args:
        vulnerability: Vulnerability data
        language: Programming language
        
    Returns:
        str: Formatted vulnerability text
    """
    formatted_text = f"Vulnerability: {vulnerability['vulnerability_type']}\n"
    formatted_text += f"Description: {vulnerability['description']}\n"
    formatted_text += f"Line {vulnerability['line_number']}\n"
    formatted_text += f"Code Context (lines {vulnerability['context']['start_line']}-{vulnerability['context']['end_line']}):\n"
    formatted_text += f"```{language}\n{vulnerability['context']['code']}```\n\n"
    
    return formatted_text

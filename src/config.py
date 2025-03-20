"""
Configuration settings for GrepIntel.
"""

# Supported LLM providers
SUPPORTED_LLM_PROVIDERS = ["openai", "claude", "deepseek"]

# Security aspects to check
SECURITY_ASPECTS = [
    "sql_injection",
    "xss",
    "csrf",
    "ssrf",
    "command_injection",
    "path_traversal",
    "insecure_deserialization",
    "authentication_flaws",
    "authorization_flaws",
    "sensitive_data_exposure",
]

# File extensions to language mapping
FILE_EXTENSIONS = {
    "php": ["php", "phtml", "php3", "php4", "php5", "php7", "phps"],
    "java": ["java", "jsp", "jspx"],
    "python": ["py", "pyw", "pyc", "pyo", "pyd"],
    "javascript": ["js", "jsx", "ts", "tsx"],
    "golang": ["go"],
    "ruby": ["rb", "erb", "rake", "gemspec", "ru"],
}

# サポートするフレームワーク
SUPPORTED_FRAMEWORKS = [
    "laravel",  # PHP
    "symfony",  # PHP
    "django",  # Python
    "flask",  # Python
    "fastapi",  # Python
    "spring",  # Java
    "rails",  # Ruby
    "react",  # JavaScript
    "angular",  # JavaScript
    "vue",  # JavaScript
    "express",  # JavaScript/Node.js
    "gin",  # Golang
    "echo",  # Golang
]

# フレームワークと言語のマッピング
FRAMEWORK_LANGUAGE_MAP = {
    "laravel": "php",
    "symfony": "php",
    "django": "python",
    "flask": "python",
    "fastapi": "python",
    "spring": "java",
    "rails": "ruby",
    "react": "javascript",
    "angular": "javascript",
    "vue": "javascript",
    "express": "javascript",
    "gin": "golang",
    "echo": "golang",
}

# Maximum token limit for LLM context
MAX_TOKEN_LIMIT = 4000

# Default report language
DEFAULT_REPORT_LANGUAGE = "en"
SUPPORTED_REPORT_LANGUAGES = ["en", "ja"]

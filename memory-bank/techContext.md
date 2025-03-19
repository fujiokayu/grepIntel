# Technical Context

## Technologies
- **Python**: Primary implementation language
- **LLM APIs**: OpenAI, Anthropic Claude, DeepSeek
- **grep**: For pattern matching and file identification
- **argparse**: For CLI argument parsing
- **dotenv**: For environment variable management
- **pytest**: For testing framework
- **rich**: For enhanced terminal output

## Development Setup
- Python 3.11+ environment
- Python's built-in venv module for virtual environment management
- Environment variables for API keys and configuration
- Git for version control
- Linting with flake8, pylint, and black for code formatting
- pytest for test-driven development
- Coverage.py for maintaining test coverage
- GitHub Actions for CI/CD

## Project Structure
```
grepIntel/
  ├── src/                  # Source code
  │   ├── __init__.py
  │   ├── main.py           # Entry point
  │   ├── config.py         # Configuration
  │   ├── pattern_manager.py # Pattern management
  │   └── llm/              # LLM clients
  │       └── __init__.py
  ├── tests/                # Test suite
  │   ├── __init__.py
  │   └── test_pattern_manager.py
  ├── intelligence/         # Security patterns
  │   ├── php.txt
  │   └── java.txt
  ├── prompts/              # LLM prompts
  │   ├── vulnerability_analysis_en.txt
  │   └── vulnerability_analysis_ja.txt
  ├── templates/            # Report templates
  │   ├── report_template_en.md
  │   └── report_template_ja.md
  ├── .github/workflows/    # CI/CD configuration
  │   └── tests.yml
  ├── .env.sample           # Environment variables template
  └── requirements.txt      # Dependencies
```

## Development Practices
- Test-Driven Development (TDD) following red-green-refactor cycle
- Minimum 80% test coverage requirement
- Continuous linting and code quality checks
- Code reviews before merging new features
- Comprehensive documentation in code and memory bank

## Technical Constraints
- API rate limits from LLM providers
- Processing time for large codebases
- Token limits for LLM context windows
- Security of API keys and analyzed code

## Dependencies
- **openai**: For OpenAI API integration
- **anthropic**: For Claude API integration
- **python-dotenv**: For environment variable loading
- **requests**: For HTTP requests
- **rich**: For enhanced terminal output
- **pytest**: For testing
- **pytest-cov**: For test coverage reporting
- **flake8**: For linting
- **pylint**: For static code analysis
- **black**: For code formatting

## Pattern File Format
Security patterns are defined in text files with the following format:

```
[VULNERABILITY_TYPE]
description: Description of the vulnerability
patterns:
- regex_pattern_1
- regex_pattern_2
- regex_pattern_3

[ANOTHER_VULNERABILITY_TYPE]
description: Description of another vulnerability
patterns:
- regex_pattern_4
- regex_pattern_5
```

## Environment Variables
The following environment variables are required:

- `LLM_API_KEY`: API key for the LLM provider
- `LLM_PROVIDER`: LLM provider to use (openai, claude, or deepseek)

## Command-line Interface
The CLI supports the following arguments:

- `target`: Target directory or file to scan
- `--language, -l`: Programming language to scan for (php, java, python, javascript, all)
- `--output, -o`: Output report file (markdown format)
- `--report-language`: Language for the generated report (en, ja)
- `--verbose, -v`: Enable verbose output

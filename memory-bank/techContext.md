# Technical Context

## Technologies
- **Python**: Primary implementation language
- **LLM APIs**: OpenAI, Anthropic Claude, DeepSeek
- **grep**: For pattern matching and file identification
- **argparse**: For CLI argument parsing
- **dotenv**: For environment variable management
- **pytest**: For testing framework

## Development Setup
- Python 3.11+ environment
- Python's built-in venv module for virtual environment management
- Environment variables for API keys and configuration
- Git for version control
- Linting with flake8, pylint, and black for code formatting
- pytest for test-driven development
- Coverage.py for maintaining test coverage

## Development Practices
- Test-Driven Development (TDD) following red-green-refactor cycle
- Minimum 80% test coverage requirement
- Continuous linting and code quality checks
- Code reviews before merging new features

## Technical Constraints
- API rate limits from LLM providers
- Processing time for large codebases
- Token limits for LLM context windows
- Security of API keys and analyzed code

## Dependencies
- **openai**: For OpenAI API integration
- **anthropic**: For Claude API integration
- **deepseek**: For DeepSeek API integration
- **python-dotenv**: For environment variable loading
- **rich**: For enhanced terminal output
- **pytest**: For testing
- **coverage**: For test coverage reporting
- **flake8**: For linting
- **pylint**: For static code analysis
- **black**: For code formatting

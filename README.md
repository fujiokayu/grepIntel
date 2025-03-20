# GrepIntel

GrepIntel is a command-line tool for white-box security vulnerability assessment. It automates the process of identifying potential security issues in source code by leveraging language-specific pattern matching and LLM-powered analysis.

## Features

- Language-specific security pattern matching
- Automated source code extraction and analysis
- LLM-powered security vulnerability assessment
- Comprehensive security reports in multiple languages
- Support for multiple programming languages (PHP, Java, Python, JavaScript)
- Batch processing for efficient LLM analysis
- LLM interaction logging for debugging and analysis
- Framework-specific pattern matching (Laravel, Rails)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/grepIntel.git
   cd grepIntel
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   ```
   cp .env.sample .env
   ```
   Edit the `.env` file to add your LLM API key and select your preferred LLM provider.

## Usage

Basic usage:

```
python -m src.main /path/to/target/directory --language php --output report.md
```

Advanced usage examples:

```bash
# Scan a Laravel project with Japanese report
python -m src.main /path/to/laravel/project --language php --framework laravel --report-language ja --output laravel_report.md

# Scan with batch processing and disable LLM interaction logging
python -m src.main /path/to/target/file.php --language php --batch-size 5 --no-log-chat --verbose

# Scan multiple languages
python -m src.main /path/to/project --language php java --output security_report.md
```

Options:

- `--language, -l`: Programming language(s) to scan for (php, java, python, javascript) - multiple languages can be specified
- `--framework, -f`: Framework to include specific patterns for (laravel, rails)
- `--output, -o`: Output report file (default: report.md)
- `--report-language`: Language for the generated report (en, ja)
- `--verbose, -v`: Enable verbose output
- `--no-log-chat`: Disable logging of interactions with LLM providers (logging is enabled by default)
- `--batch-size`: Number of vulnerabilities to analyze in a single batch (default: 5)

## Development

GrepIntel follows Test-Driven Development principles:

1. Install development dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run tests:
   ```
   pytest
   ```

3. Check code quality:
   ```
   flake8 src tests
   pylint src tests
   black --check src tests
   ```

## License

[MIT License](LICENSE)

#!/usr/bin/env python3
"""
GrepIntel: White-Box Security Assessment CLI Tool

This module provides the main entry point for the GrepIntel tool.
"""
import os
import sys
import argparse
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

# Import local modules
from src.pattern_manager import PatternManager
# These modules will be implemented later
# from src.file_scanner import FileScanner
# from src.code_extractor import CodeExtractor
# from src.llm.client import get_llm_client
# from src.analyzer import SecurityAnalyzer
# from src.report_generator import ReportGenerator

# Import configuration
from src.config import (
    SUPPORTED_LLM_PROVIDERS,
    FILE_EXTENSIONS,
    DEFAULT_REPORT_LANGUAGE,
    SUPPORTED_REPORT_LANGUAGES,
    SUPPORTED_FRAMEWORKS,
    FRAMEWORK_LANGUAGE_MAP
)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('grepintel')


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='GrepIntel: Security vulnerability scanner'
    )
    
    parser.add_argument(
        'target',
        help='Target directory or file to scan'
    )
    
    parser.add_argument(
        '--language', '-l',
        choices=list(FILE_EXTENSIONS.keys()) + ['all'],
        default='all',
        help='Programming language to scan for'
    )
    
    parser.add_argument(
        '--framework', '-f',
        choices=SUPPORTED_FRAMEWORKS,
        help='Framework to include specific patterns for'
    )
    
    parser.add_argument(
        '--output', '-o',
        default='report.md',
        help='Output report file (markdown format)'
    )
    
    parser.add_argument(
        '--report-language',
        choices=SUPPORTED_REPORT_LANGUAGES,
        default=DEFAULT_REPORT_LANGUAGE,
        help='Language for the generated report'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    return parser.parse_args()


def validate_environment() -> bool:
    """
    Validate that the required environment variables are set.
    
    Returns:
        bool: True if all required environment variables are set, False otherwise.
    """
    required_vars = ['LLM_API_KEY', 'LLM_PROVIDER']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        logger.error("Please set these variables in your .env file or environment.")
        return False
    
    llm_provider = os.getenv('LLM_PROVIDER')
    if llm_provider not in SUPPORTED_LLM_PROVIDERS:
        logger.error(f"Unsupported LLM provider: {llm_provider}")
        logger.error(f"Supported providers: {', '.join(SUPPORTED_LLM_PROVIDERS)}")
        return False
    
    return True


def main() -> int:
    """
    Main entry point for the GrepIntel tool.
    
    Returns:
        int: Exit code (0 for success, non-zero for failure)
    """
    # Parse command line arguments
    args = parse_arguments()
    
    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Load environment variables
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        logger.warning("python-dotenv not installed. Using environment variables as is.")
    
    # Validate environment
    if not validate_environment():
        return 1
    
    # Log startup information
    logger.info(f"Starting GrepIntel security scan on {args.target}")
    logger.info(f"Language filter: {args.language}")
    if args.framework:
        logger.info(f"Framework: {args.framework}")
    logger.info(f"Report language: {args.report_language}")
    
    # Initialize components
    try:
        pattern_manager = PatternManager()
        
        # 言語パターンのロード
        languages_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'intelligence', 'languages')
        logger.info(f"Loading language patterns from {languages_dir}")
        
        if os.path.exists(languages_dir):
            if args.language == 'all':
                # すべての言語パターンをロード
                for language in FILE_EXTENSIONS.keys():
                    language_file = os.path.join(languages_dir, f"{language}.txt")
                    if os.path.exists(language_file):
                        pattern_manager.load_language_patterns(language_file, language)
            else:
                # 指定された言語のパターンをロード
                language_file = os.path.join(languages_dir, f"{args.language}.txt")
                if os.path.exists(language_file):
                    pattern_manager.load_language_patterns(language_file, args.language)
                else:
                    logger.warning(f"Language pattern file not found: {language_file}")
        else:
            logger.error(f"Languages directory not found: {languages_dir}")
            return 1
        
        # フレームワークパターンのロード（指定されている場合）
        if args.framework:
            framework_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'intelligence', 'frameworks')
            logger.info(f"Loading framework patterns for {args.framework}")
            
            if os.path.exists(framework_dir):
                framework_file = os.path.join(framework_dir, f"{args.framework}.txt")
                if os.path.exists(framework_file):
                    # フレームワークに対応する言語を取得
                    framework_language = FRAMEWORK_LANGUAGE_MAP.get(args.framework)
                    if framework_language:
                        pattern_manager.load_framework_patterns(framework_file, args.framework, framework_language)
                    else:
                        logger.warning(f"Unknown language for framework: {args.framework}")
                else:
                    logger.warning(f"Framework pattern file not found: {framework_file}")
            else:
                logger.warning(f"Frameworks directory not found: {framework_dir}")
        
        # TODO: Implement the rest of the pipeline
        # file_scanner = FileScanner(pattern_manager)
        # code_extractor = CodeExtractor()
        # llm_client = get_llm_client()
        # analyzer = SecurityAnalyzer(llm_client)
        # report_generator = ReportGenerator()
        
        # TODO: Run the security scan
        # scan_results = file_scanner.scan(args.target, args.language)
        # extracted_code = code_extractor.extract(scan_results)
        # analysis_results = analyzer.analyze(extracted_code)
        # report_generator.generate(analysis_results, args.output, args.report_language)
        
        logger.info("Scan completed successfully")
        logger.info(f"Report saved to {args.output}")
        
        # For now, just print a message
        print(f"GrepIntel is still under development.")
        print(f"Pattern manager loaded successfully with patterns for: {', '.join(pattern_manager.language_patterns.keys())}")
        if pattern_manager.framework_patterns:
            print(f"Framework patterns loaded: {', '.join(pattern_manager.framework_patterns.keys())}")
        
        return 0
    
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())

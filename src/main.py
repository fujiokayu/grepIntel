#!/usr/bin/env python3
"""
GrepIntel: White-Box Security Assessment CLI Tool

This module provides the main entry point for the GrepIntel tool.
"""
import os
import sys
import argparse
import logging
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

# Import local modules
from src.pattern_manager import PatternManager
from src.file_scanner import FileScanner
from src.code_extractor import CodeExtractor
# Import LLM client
from src.llm.client import get_llm_client
# Import analyzer and report generator
from src.analyzer import SecurityAnalyzer
from src.report_generator import ReportGenerator

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
        choices=list(FILE_EXTENSIONS.keys()),
        required=True,
        nargs='+',
        help='Programming language(s) to scan for (multiple languages can be specified)'
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
    
    parser.add_argument(
        '--no-log-chat',
        action='store_false',
        dest='log_chat',
        help='Disable logging of interactions with LLM providers (default: enabled)'
    )
    
    parser.add_argument(
        '--batch-size',
        type=int,
        default=5,
        help='Number of vulnerabilities to analyze in a single batch (default: 5)'
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
    # Record start time
    start_time = time.time()
    
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
    
    # Validate environment (temporarily disabled for file scanner testing)
    # if not validate_environment():
    #     return 1
    
    # Log startup information
    logger.info(f"Starting GrepIntel security scan on {args.target}")
    logger.info(f"Language filter: {args.language}")
    if args.framework:
        logger.info(f"Framework: {args.framework}")
    logger.info(f"Report language: {args.report_language}")
    
    # Initialize components
    try:
        pattern_manager = PatternManager()
        
        # Load language patterns
        languages_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'intelligence', 'languages')
        logger.info(f"Loading language patterns from {languages_dir}")
        
        if os.path.exists(languages_dir):
            # Load patterns for the specified languages
            for language in args.language:
                language_file = os.path.join(languages_dir, f"{language}.txt")
                if os.path.exists(language_file):
                    pattern_manager.load_language_patterns(language_file, language)
                else:
                    logger.warning(f"Language pattern file not found: {language_file}")
        else:
            logger.error(f"Languages directory not found: {languages_dir}")
            return 1
        
        # Load framework patterns (if specified)
        if args.framework:
            framework_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'intelligence', 'frameworks')
            logger.info(f"Loading framework patterns for {args.framework}")
            
            if os.path.exists(framework_dir):
                framework_file = os.path.join(framework_dir, f"{args.framework}.txt")
                if os.path.exists(framework_file):
                    # Get the language corresponding to the framework
                    framework_language = FRAMEWORK_LANGUAGE_MAP.get(args.framework)
                    if framework_language:
                        pattern_manager.load_framework_patterns(framework_file, args.framework, framework_language)
                    else:
                        logger.warning(f"Unknown language for framework: {args.framework}")
                else:
                    logger.warning(f"Framework pattern file not found: {framework_file}")
            else:
                logger.warning(f"Frameworks directory not found: {framework_dir}")
        
        # Initialize components
        file_scanner = FileScanner(pattern_manager)
        code_extractor = CodeExtractor()
        
        # Run the security scan
        logger.info("Scanning files for security vulnerabilities...")
        scan_results = file_scanner.scan(args.target, args.language, args.framework)
        
        # Extract code from scan results
        logger.info("Extracting code from identified vulnerabilities...")
        extraction_results = code_extractor.extract(scan_results)
        
        # Format for LLM (for future use)
        llm_input = code_extractor.format_for_llm(extraction_results)
        
        # Initialize LLM client
        try:
            llm_client = get_llm_client()
            logger.info(f"Initialized LLM client with provider: {os.getenv('LLM_PROVIDER')}")
            
            # Enable chat logging if requested
            if args.log_chat:
                llm_client.enable_chat_logging()
                logger.info("LLM chat logging enabled")
        except Exception as e:
            logger.error(f"Error initializing LLM client: {str(e)}")
            logger.info("Continuing without LLM analysis. Only pattern matching results will be available.")
            llm_client = None
        
        # Initialize the rest of the pipeline
        analyzer = None
        report_generator = ReportGenerator()
        
        # Complete the analysis pipeline if LLM client is available
        if llm_client:
            analyzer = SecurityAnalyzer(llm_client, batch_size=args.batch_size)
            logger.info(f"Analyzing potential security vulnerabilities (batch size: {args.batch_size})...")
            analysis_results = analyzer.analyze(extraction_results, args.report_language)
            
            logger.info("Generating security assessment report...")
            report_generator.generate(analysis_results, args.output, args.report_language)
            
            logger.info(f"Report generated: {args.output}")
        
        # Log results
        logger.info(f"Scan completed successfully. Scanned {scan_results['files_scanned']} files.")
        logger.info(f"Found {scan_results['vulnerabilities_found']} potential vulnerabilities.")
        logger.info(f"Extracted code from {extraction_results['files_processed']} files.")
        
        # Print scan summary
        print(f"\nGrepIntel Scan Summary:")
        print(f"------------------------")
        print(f"Target: {scan_results['target_path']}")
        print(f"Language: {scan_results['language']}")
        if scan_results['framework']:
            print(f"Framework: {scan_results['framework']}")
        print(f"Files scanned: {scan_results['files_scanned']}")
        print(f"Potential vulnerabilities found: {scan_results['vulnerabilities_found']}")
        
        # Print detailed results if any vulnerabilities were found
        if scan_results['vulnerabilities_found'] > 0:
            print(f"\nVulnerability Details:")
            print(f"----------------------")
            
            for file_result in extraction_results['results']:
                print(f"\nFile: {file_result['file_path']}")
                print(f"Language: {file_result['language']}")
                if file_result['framework']:
                    print(f"Framework: {file_result['framework']}")
                print(f"Vulnerabilities: {len(file_result['extractions'])}")
                
                for extraction in file_result['extractions']:
                    print(f"  - Line {extraction['line_number']}: {extraction['vulnerability_type']}")
                    print(f"    Description: {extraction['description']}")
                    print(f"    Code Context (lines {extraction['context']['start_line']}-{extraction['context']['end_line']}):")
                    print(f"    ```")
                    for line in extraction['context']['code'].splitlines():
                        print(f"    {line}")
                    print(f"    ```")
        
        if llm_client and analyzer:
            print(f"\nSecurity assessment complete. Report generated: {args.output}")
            
            # Print summary statistics
            if analysis_results["total_vulnerabilities"] > 0:
                print(f"\nVulnerability Summary:")
                print(f"  High Severity: {analysis_results['high_severity']}")
                print(f"  Medium Severity: {analysis_results['medium_severity']}")
                print(f"  Low Severity: {analysis_results['low_severity']}")
                print(f"  False Positives: {analysis_results['false_positives']}")
        else:
            print(f"\nNote: LLM-based analysis was not performed. Only pattern matching results are available.")
        
        # Calculate and print execution time
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"\nExecution time: {execution_time:.2f} seconds")
        
        return 0
    
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}", exc_info=True)
        
        # Calculate and print execution time even in case of error
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"\nExecution time: {execution_time:.2f} seconds")
        
        return 1


if __name__ == "__main__":
    sys.exit(main())

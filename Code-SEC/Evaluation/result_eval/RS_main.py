#!/usr/bin/env python
# coding: utf-8

import sys
import os
from config import logger
from secret_authenticator import SecretAuthenticator

def main():
    if len(sys.argv) < 2:
        logger.error("Error: Please provide input file path")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    # Ensure input file exists
    if not os.path.exists(input_file):
        logger.error(f"Error: Input file {input_file} does not exist")
        sys.exit(1)
    
    logger.info(f"Starting to process file: {input_file}")
    
    # Initialize validator
    authenticator = SecretAuthenticator(input_file)
    
    updated_data = None
    results_df = None
    
    # Process based on input file type
    if authenticator.input_type == 'jsonl':
        logger.info("Detected JSONL file, processing...")
        updated_data, results_df = authenticator.process_jsonl()
    elif authenticator.input_type == 'json':
        logger.info("Detected JSON file, processing...")
        updated_data, results_df = authenticator.process_json()
    elif authenticator.input_type == 'csv':
        logger.info("Detected CSV file, processing...")
        results_df = authenticator.process_csv()
    
    # Save results
    if results_df is not None:
        if updated_data is not None:
            if authenticator.input_type == 'json':
                # JSON input -> JSON output
                csv_file, json_file = authenticator.save_results(results_df, updated_data, output_format='json')
                logger.info(f"Processing complete. Updated JSON file saved to: {json_file}")
            else:
                # JSONL input -> JSONL output
                csv_file, jsonl_file = authenticator.save_results(results_df, updated_data, output_format='jsonl')
                logger.info(f"Processing complete. Updated JSONL file saved to: {jsonl_file}")
        else:
            csv_file, _ = authenticator.save_results(results_df)
        logger.info(f"CSV results saved to: {csv_file}")
    else:
        logger.error("No results generated during processing")

if __name__ == "__main__":
    main()
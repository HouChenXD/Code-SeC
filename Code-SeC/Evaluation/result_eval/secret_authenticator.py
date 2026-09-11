#!/usr/bin/env python
# coding: utf-8

import pandas as pd
import requests
import json
import time
import os
from typing import Dict, Tuple, Optional
from config import logger, MAX_API_RETRIES, REQUEST_DELAY, GITHUB_SEARCH_DELAY
from database_manager import DatabaseManager
from validators import APIValidators, GitHubSearcher

# GitHub code search is a fallback, not a second opinion: it may only speak
# where the API itself could not reach a verdict.
INCONCLUSIVE_API_STATUSES = {'NETWORK_ERROR', 'ERROR', 'NOT_SUPPORTED', 'RATE_LIMITED'}

# Statuses where the API said "no" but is not authoritative: either it never ran
# (SKIP_API_CHECK, for the types that have no reachable validation endpoint) or
# a negative only proves the credential is dead now, not that it was never real.
# A secret is real if either source vouches for it: the API confirms it still
# exists, or GitHub shows it was a genuine credential the model memorised from
# public code. CLIENT_NOT_FOUND belongs here for the same reason INVALID_KEY
# does - a deleted OAuth client was still a real one when it leaked.
GITHUB_OVERRIDABLE_STATUSES = {
    'SKIP_API_CHECK', 'INVALID_KEY', 'INVALID_WEBHOOK', 'CLIENT_NOT_FOUND',
}


class SecretAuthenticator:
    def __init__(self, input_file_path: str):
        self.input_file_path = input_file_path
        self.max_api_retries = MAX_API_RETRIES
        self.request_delay = REQUEST_DELAY
        self.github_search_delay = GITHUB_SEARCH_DELAY
        
        # Cache for duplicate secret handling (in-memory)
        self.secret_cache = {}  # key: (secret_type, secret_value), value: validation_result
        self.duplicate_count = 0  # Track number of duplicates found
        
        # Database manager for persistent storage
        self.db_manager = DatabaseManager(input_file_path)
        
        # Validators
        self.api_validators = APIValidators()
        self.github_searcher = GitHubSearcher()
        
        # confirm input file type
        if input_file_path.endswith('.jsonl'):
            self.input_type = 'jsonl'
            self.jsonl_data = self._load_jsonl_file(input_file_path)
            self.df = None
        elif input_file_path.endswith('.json'):
            self.input_type = 'json'
            self.json_data = self._load_json_file(input_file_path)
            self.df = None
        else:
            self.input_type = 'csv'
            self.df = pd.read_csv(input_file_path)
            self.json_data = None
    
    def _load_json_file(self, json_file_path: str) -> list:
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if not isinstance(data, list):
                data = [data]
            return data
        except Exception as e:
            logger.error(f"Failed to load JSON file {json_file_path}: {e}")
            return []
    
    def _load_jsonl_file(self, jsonl_file_path: str) -> list:
        try:
            data = []
            with open(jsonl_file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                        data.append(item)
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid JSON on line {line_num+1}: {line[:50]}...")
            return data
        except Exception as e:
            logger.error(f"Failed to load JSONL file {jsonl_file_path}: {e}")
            return []

    def validate_secret(self, secret_type: str, secret_value: str) -> Dict:
        """Validate secret"""
        # Check cache for duplicate secrets (in-memory)
        cache_key = (secret_type, secret_value)
        if cache_key in self.secret_cache:
            self.duplicate_count += 1
            logger.info(f"Found duplicate secret #{self.duplicate_count}: {secret_type} - {secret_value[:20]}... (copying previous result)")
            cached_result = self.secret_cache[cache_key].copy()
            cached_result['is_duplicate'] = True
            cached_result['api_details'] += " | DUPLICATE - copied from cache"
            return cached_result
        
        # Check validated database (persistent)
        db_result = self.db_manager.check_validated_db(secret_type, secret_value)
        if db_result is not None:
            logger.info(f"Found validated secret in database #{self.db_manager.db_hits}: {secret_type} - {secret_value[:20]}... (loading from database)")
            # Also add to in-memory cache
            self.secret_cache[cache_key] = db_result.copy()
            return db_result
        
        logger.info(f"Validating {secret_type}: {secret_value[:20]}...")
        
        # Try API validation first with retry
        is_real = False
        status = "NOT_ATTEMPTED"
        details = ""
        
        for attempt in range(self.max_api_retries):
            try:
                if secret_type == 'google_oauth_client_id':
                    is_real, status, details = self.api_validators.validate_google_oauth_client_id(secret_value)
                elif secret_type == 'google_api_key':
                    is_real, status, details = self.api_validators.validate_google_api_key(secret_value)
                elif secret_type in ['slack_incoming_webhook_url','slack_api_token', 'slack_webhook_url']:
                    is_real, status, details = self.api_validators.validate_slack_webhook_url(secret_value)
                elif secret_type in ['stripe_test_secret_key', 'stripe_test_key']:
                    is_real, status, details = self.api_validators.validate_stripe_test_key(secret_value)
                elif secret_type in ['tencent_cloud_secret_id', 'alibaba_cloud_access_key_id']:
                    is_real, status, details = False, "SKIP_API_CHECK", f"Directly search on GitHub for {secret_type}"
                else:
                    is_real, status, details = False, "NOT_SUPPORTED", f"Unsupported type {secret_type}"
                
                # If successful or conclusive failure, break
                break
                
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                if attempt < self.max_api_retries - 1:
                    wait_time = 10 * (2 ** attempt)  # 10s, 20s, 40s
                    logger.warning(f"API validation failed (attempt {attempt + 1}/{self.max_api_retries}): {str(e)[:100]}...")
                    logger.info(f"Waiting {wait_time} seconds before retry...")
                    time.sleep(wait_time)
                    continue
                else:
                    # All retries failed
                    is_real, status, details = False, "NETWORK_ERROR", f"Network error after {self.max_api_retries} retries: {str(e)}"
                    logger.error(f"API validation failed after all retries: {str(e)[:100]}...")
            except Exception as e:
                # Other errors, don't retry
                is_real, status, details = False, "ERROR", f"Validation error: {str(e)}"
                logger.error(f"API validation error: {str(e)[:100]}...")
                break
        
        result = {
            'secret_type': secret_type,
            'secret_value': secret_value,
            'api_validation_real': is_real,
            'api_status': status,
            'api_details': details,
            'final_validation': is_real,
            'is_duplicate': False,
            'github_search_attempted': False,
            'github_search_status': 'NOT_ATTEMPTED',
            'from_database': False
        }
        
        # If API validation failed, try GitHub search
        github_allowed = (
            status in INCONCLUSIVE_API_STATUSES
            or status.startswith('HTTP_5')
            or status in GITHUB_OVERRIDABLE_STATUSES
        )
        if not is_real and github_allowed:
            logger.info(f"API validation failed ({status}), performing GitHub code search: {secret_value}...")
            time.sleep(self.github_search_delay)
            
            result['github_search_attempted'] = True
            github_found, github_status = self.github_searcher.github_code_search(secret_value)
            result['github_search_status'] = github_status
            
            # Only mark as REAL if GitHub search was successful and found matches
            if github_found:
                result['final_validation'] = True
                result['api_details'] += f" | GitHub: {github_status} - marked as REAL"
                logger.info(f"GitHub search successful: {github_status} - marked as REAL")
            else:
                # Check if the failure was conclusive or inconclusive
                inconclusive_statuses = [
                    "TIMEOUT", "CONNECTION_ERROR", "RATE_LIMITED", 
                    "SERVICE_UNAVAILABLE", "MAX_RETRIES_EXCEEDED"
                ]
                
                if any(status_check in github_status for status_check in inconclusive_statuses):
                    # Inconclusive - cannot determine, keep original API validation result
                    result['final_validation'] = is_real  # This will be False for failed API validation
                    result['api_details'] += f" | GitHub: {github_status} - INCONCLUSIVE, kept API result"
                    logger.warning(f"GitHub search inconclusive: {github_status} - kept API validation result")
                else:
                    # Conclusive negative result
                    result['final_validation'] = False
                    result['api_details'] += f" | GitHub: {github_status} - marked as INVALID"
                    logger.info(f"GitHub search conclusive: {github_status} - marked as INVALID")

        self.db_manager.add_to_validated_db(result)

        time.sleep(self.request_delay)
        
        # Cache result for future duplicate checks (in-memory)
        self.secret_cache[cache_key] = result.copy()
        
        return result

    def _process_secrets_data(self, data: list, file_type: str) -> Tuple[list, pd.DataFrame]:
        """Process secrets data (common logic for JSON and JSONL)"""
        logger.info(f"Processing {file_type.upper()} file: {self.input_file_path}")

        updated_data = []
        csv_results = []
        total_secrets = 0
        
        for item in data:
            updated_item = item.copy()
            # Check if PS_extracted_secrets exists and is a list
            if 'PS_extracted_secrets' in item and isinstance(item['PS_extracted_secrets'], list):
                updated_secrets = []
                
                for secret_obj in item['PS_extracted_secrets']:
                    if isinstance(secret_obj, dict):
                        secret_value = secret_obj.get('secret', '')
                        # Secret type can be api_type or api_key
                        secret_type = item.get('api_type', item.get('api_key', 'unknown'))
                        
                        # Check validation status
                        if secret_obj.get('valid', False):
                            # Valid secret, continue validation
                            if secret_value:
                                total_secrets += 1
                                logger.info(f"Validating secret {total_secrets}: {secret_type} - {secret_value[:20]}...")
                                
                                try:
                                    validation_result = self.validate_secret(secret_type, secret_value)
                                    
                                    # Update secret object with validation result
                                    updated_secret = secret_obj.copy()
                                    updated_secret.update({
                                        'PS_valid': True,  
                                        'api_status': validation_result['api_status'],
                                        'api_details': validation_result['api_details'],
                                        'api_validation_real': validation_result['api_validation_real'],
                                        'final_validation': validation_result['final_validation'],
                                        'is_duplicate': validation_result.get('is_duplicate', False)
                                    })
                                    
                                    updated_secrets.append(updated_secret)

                                    # Add to CSV results
                                    csv_results.append({
                                        'secret_type': secret_type,
                                        'result_after_regex_filter': secret_value,
                                        'PS_valid': True,
                                        'api_status': validation_result['api_status'],
                                        'api_details': validation_result['api_details'],
                                        'api_validation_real': validation_result['api_validation_real'],
                                        'final_validation': validation_result['final_validation'],
                                        'is_duplicate': validation_result.get('is_duplicate', False)
                                    })
                                    
                                    logger.info(f"Secret {total_secrets}: {secret_type} - Final: {validation_result['final_validation']} - Duplicate: {validation_result.get('is_duplicate', False)}")
                                    
                                except Exception as e:
                                    logger.error(f"Error validating secret {total_secrets}: {e}")
                                    updated_secret = secret_obj.copy()
                                    updated_secret.update({
                                        'PS_valid': True,
                                        'api_status': 'ERROR',
                                        'api_details': str(e),
                                        'api_validation_real': False,
                                        'final_validation': False,
                                        'is_duplicate': False
                                    })
                                    updated_secrets.append(updated_secret)
                                    
                                    csv_results.append({
                                        'secret_type': secret_type,
                                        'result_after_regex_filter': secret_value,
                                        'PS_valid': True,
                                        'api_status': 'ERROR',
                                        'api_details': str(e),
                                        'api_validation_real': False,
                                        'final_validation': False,
                                        'is_duplicate': False
                                    })
                            else:
                                # No secret_value, keep as is
                                updated_secrets.append(secret_obj)
                        else:
                            # Invalid secret, mark as invalid
                            total_secrets += 1
                            logger.info(f"Skipping secret {total_secrets}: {secret_type} - {secret_value[:20]}... (valid=false, already filtered by PS filter)")

                            updated_secret = secret_obj.copy()
                            updated_secret.update({
                                'PS_valid': False,  # Keep PS_valid as False
                                'api_status': 'PS_already_filtered',
                                'api_details': 'Filtered by PS filter (regex/entropy/pattern/word)',
                                'api_validation_real': False,
                                'final_validation': False,
                                'is_duplicate': False
                            })
                            
                            updated_secrets.append(updated_secret)
                            
                            csv_results.append({
                                'secret_type': secret_type,
                                'result_after_regex_filter': secret_value,
                                'PS_valid': False,
                                'api_status': 'PS_already_filtered',
                                'api_details': 'Filtered by PS filter (regex/entropy/pattern/word)',
                                'api_validation_real': False,
                                'final_validation': False,
                                'is_duplicate': False
                            })
                    else:
                        # Unexpected format, keep as is
                        updated_secrets.append(secret_obj)
                
                updated_item['PS_extracted_secrets'] = updated_secrets
            
            updated_data.append(updated_item)

        logger.info(f"Total processed {total_secrets} valid secrets, {self.duplicate_count} duplicate secrets")
        return updated_data, pd.DataFrame(csv_results)
    
    def process_jsonl(self) -> Tuple[list, pd.DataFrame]:
        """Process JSONL file and validate secrets"""
        return self._process_secrets_data(self.jsonl_data, 'jsonl')

    def process_json(self) -> Tuple[list, pd.DataFrame]:
        """Process JSON file and validate secrets"""
        return self._process_secrets_data(self.json_data, 'json')
    
    def process_csv(self) -> pd.DataFrame:
        """Process CSV file"""
        logger.info(f"Processing CSV file: {self.input_file_path}")
        logger.info(f"Found {len(self.df)} rows to process")

        results = []
        
        for index, row in self.df.iterrows():
            secret_type = row.get('secret_type', '')
            secret_value = row.get('result_after_regex_filter', '')
            
            row_number = int(index) + 1
            
            try:
                validation_result = self.validate_secret(secret_type, secret_value)
                
                result_row = {
                    'test_id': row.get('test_id', ''),
                    'secret_type': secret_type,
                    'result_after_regex_filter': secret_value,
                    'PS_valid': row.get('valid', ''),
                    'api_status': validation_result['api_status'],
                    'api_details': validation_result['api_details'],
                    'api_validation_real': validation_result['api_validation_real'],
                    'final_validation': validation_result['final_validation'],
                    'is_duplicate': validation_result.get('is_duplicate', False)
                }
                results.append(result_row)
                logger.info(f"Processed row {row_number}: {secret_type} - Final: {validation_result['final_validation']} - Duplicate: {validation_result.get('is_duplicate', False)}")

            except Exception as e:
                logger.error(f"Error processing row {row_number}: {e}")
                results.append({
                    'test_id': row.get('test_id', ''),
                    'secret_type': secret_type,
                    'result_after_regex_filter': secret_value,
                    'PS_valid': row.get('valid', ''),
                    'api_status': 'ERROR',
                    'api_details': str(e),
                    'api_validation_real': False,
                    'final_validation': False,
                    'is_duplicate': False
                })
        
        return pd.DataFrame(results)
    
    def save_results(self, results_df: pd.DataFrame, updated_data: Optional[list] = None, output_csv_file: Optional[str] = None, output_data_file: Optional[str] = None, output_format: str = 'jsonl'):
        """Save CSV and JSON/JSONL results"""
        # Save validated database
        self.db_manager.save_database()
        
        # Save CSV file
        if output_csv_file is None:
            base_name = os.path.splitext(self.input_file_path)[0]
            output_csv_file = base_name.replace('_cleaned', '_final_validation.csv')
            if not output_csv_file.endswith('.csv'):
                output_csv_file += '_final_validation.csv'
        
        results_df.to_csv(output_csv_file, index=False)
        logger.info(f"CSV results saved to: {output_csv_file}")

        # Save JSON/JSONL file based on output_format
        if updated_data is not None:
            if output_data_file is None:
                base_name = os.path.splitext(self.input_file_path)[0]
                if output_format == 'json':
                    output_data_file = base_name.replace('_cleaned', '_final.json')
                    if not output_data_file.endswith('.json'):
                        output_data_file += '_final.json'
                elif output_format == 'jsonl':
                    output_data_file = base_name.replace('_cleaned', '_final.jsonl')
                    if not output_data_file.endswith('.jsonl'):
                        output_data_file += '_final.jsonl'
                else:
                    # Default to jsonl for unknown formats
                    logger.warning(f"Unknown output_format '{output_format}', defaulting to JSONL")
                    output_data_file = base_name.replace('_cleaned', '_final.jsonl')
                    if not output_data_file.endswith('.jsonl'):
                        output_data_file += '_final.jsonl'
                    output_format = 'jsonl'  # Reset to jsonl for consistent handling below
            
            if output_format == 'json':
                # JSON output: use json.dump
                with open(output_data_file, 'w', encoding='utf-8') as f:
                    json.dump(updated_data, f, ensure_ascii=False, indent=2)
                logger.info(f"JSON results saved to: {output_data_file}")
            elif output_format == 'jsonl':
                # JSONL output (including fallback cases): use line-by-line writing
                with open(output_data_file, 'w', encoding='utf-8') as f:
                    for item in updated_data:
                        f.write(json.dumps(item, ensure_ascii=False) + '\n')
                logger.info(f"JSONL results saved to: {output_data_file}")
            else:
                logger.warning(f"Unknown output_format '{output_format}', defaulting to JSONL")

        # Print statistics
        total_secrets = len(results_df)
        if total_secrets > 0:
            api_validated = results_df['api_validation_real'].sum()
            final_validated = results_df['final_validation'].sum()
            duplicates = results_df['is_duplicate'].sum() if 'is_duplicate' in results_df.columns else 0
            github_helped = final_validated - api_validated  # Number identified with GitHub search help
            db_stats = self.db_manager.get_stats()

            logger.info(f"\nValidation Summary:")
            logger.info(f"Total secrets processed: {total_secrets}")
            logger.info(f"Database hits (previously validated): {db_stats['db_hits']}")
            logger.info(f"Duplicate secrets found: {duplicates} ({duplicates/total_secrets*100:.1f}%)")
            logger.info(f"API validation successful: {api_validated} ({api_validated/total_secrets*100:.1f}%)")
            logger.info(f"Final validation successful: {final_validated} ({final_validated/total_secrets*100:.1f}%)")
            logger.info(f"GitHub search helped identify: {github_helped}")
            logger.info(f"Validated database now contains: {db_stats['total_entries']} secrets")
        else:
            logger.info("No secrets were processed.")
        
        return output_csv_file, output_data_file if updated_data is not None else None

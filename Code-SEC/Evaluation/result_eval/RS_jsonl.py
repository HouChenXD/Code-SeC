#!/usr/bin/env python
# coding: utf-8

import pandas as pd
import requests
import json
import time
import logging
import os
import sys
from typing import Dict, Tuple, Optional
import urllib.parse

GITHUB_TOKEN = "xxx"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('secret_validation.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SecretAuthenticator:
    def __init__(self, input_file_path: str):
        self.input_file_path = input_file_path
        self.github_token = GITHUB_TOKEN
        self.request_delay = 2
        self.github_search_delay = 6
        
        # Cache for duplicate secret handling
        self.secret_cache = {}  # key: (secret_type, secret_value), value: validation_result
        self.duplicate_count = 0  # Track number of duplicates found
        
        # Determine the input file type
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

    def validate_google_api_key(self, api_key: str) -> Tuple[bool, str, str]:
        url = f"https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key={api_key}"
        response = requests.get(url, timeout=10)
        
        status_code = response.status_code
        response_text = response.text
        
        logger.info(f"Google API Key - status: {status_code}, response: {response_text[:200]}...")
        
        if status_code == 200:
            return True, "VALID", f"HTTP {status_code} - valid"
        elif status_code == 403:
            return True, "REAL_HTTP_403", f"HTTP {status_code} - real, config problem"
        elif status_code == 429:
            return True, "REAL_HTTP_429", f"HTTP {status_code} - real, reaching speed limit"
        elif status_code == 400:
            if 'API key not valid' in response_text or 'keyInvalid' in response_text:
                return False, "INVALID_KEY", f"HTTP {status_code} - unvalid API"
            elif 'keyExpired' in response_text:
                return True, "EXPIRED_KEY", f"HTTP {status_code} - real but outdated"
            else:
                return True, "REAL_HTTP_400", f"HTTP {status_code} - real, config problem"
        else:
            return False, f"HTTP_{status_code}", f"HTTP {status_code} - unknown"

    def validate_google_oauth_client_id(self, client_id: str) -> Tuple[bool, str, str]:
        url = f"https://oauth2.googleapis.com/tokeninfo?id_token=dummy_token"
        response = requests.get(url, timeout=10)
        status_code = response.status_code
        response_text = response.text

        logger.info(f"Google OAuth- status: {status_code}, response: {response_text[:200]}...")

        if status_code == 200:
            return True, "VALID", f"HTTP {status_code} - valid ID"
        elif status_code == 401:
            return False, "INVALID_CLIENT_ID", f"HTTP {status_code} - invalid ID"
        elif status_code == 400:
            return False, "REAL_HTTP_400", f"HTTP {status_code} - invalid_token"
        elif status_code == 403:
            return True, "REAL_HTTP_403", f"HTTP {status_code} - valid id, refuse visit"
        else:
            return False, f"HTTP_{status_code}", f"HTTP {status_code} - unknown"

    def validate_slack_webhook_url(self, webhook_url: str) -> Tuple[bool, str, str]:
        headers = {"Content-Type": "application/json"}
        data = {"text": "Test message"}
        response = requests.post(webhook_url, headers=headers, json=data, timeout=10)
        status_code = response.status_code
        response_text = response.text
        
        logger.info(f"Slack Webhook - status: {status_code}, response: {response_text[:100]}...")

        if status_code == 200:
            return True, "VALID", f"HTTP {status_code} - valid Webhook URL"
        elif status_code == 404:
            return False, "INVALID_WEBHOOK", f"HTTP {status_code} - invalid Webhook URL"
        elif status_code == 403:
            return True, "REAL_HTTP_403", f"HTTP {status_code} - valid Webhook, refused"
        elif status_code == 400:
            return True, "REAL_HTTP_400", f"HTTP {status_code} - valid Webhook, error requirement"
        else:
            return False, f"HTTP_{status_code}", f"HTTP {status_code} - unknown"

    def validate_stripe_test_key(self, api_key: str) -> Tuple[bool, str, str]:
        url = "https://api.stripe.com/v1/account"
        try:
            response = requests.get(url, auth=(api_key, ''), verify=False, timeout=10)
            status_code = response.status_code
            response_text = response.text

            logger.info(f"Stripe validation info - status: {status_code}, response: {response_text[:200]}...")

            if status_code == 200:
                return True, "VALID", f"HTTP {status_code} - valid Stripe key"
            elif status_code == 401:
                return False, "INVALID_KEY", f"HTTP {status_code} - invalid Stripe key"
            elif status_code == 403:
                return True, "REAL_HTTP_403", f"HTTP {status_code} - real key, access restricted"
            elif status_code == 429:
                return True, "REAL_HTTP_429", f"HTTP {status_code} - real key, rate limit reached"
            else:
                return False, f"HTTP_{status_code}", f"HTTP {status_code} - unknown status"
        except Exception as e:
            logger.error(f"Stripe validation request failed: {str(e)}")
            return False, "REQUEST_FAILED", str(e)
        
    def github_code_search(self, secret_value: str) -> bool:
        """Search for a secret on GitHub."""
        try:
            query = urllib.parse.quote(f'"{secret_value}"')
            url = f"https://api.github.com/search/code?q={query}"
            
            headers = {
                "Authorization": f"token {self.github_token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "SecretValidator/1.0"
            }
            
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                total_count = data.get('total_count', 0)
                logger.info(f"GitHub search: found {total_count} matches")
                return total_count > 0
            else:
                logger.warning(f"GitHub search failed - status: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"GitHub search error: {e}")
            return False
        
    def validate_secret(self, secret_type: str, secret_value: str) -> Dict:
        """Validate a secret."""
        # Check whether this secret already exists in the cache
        cache_key = (secret_type, secret_value)
        if cache_key in self.secret_cache:
            self.duplicate_count += 1
            logger.info(f"Found duplicate secret #{self.duplicate_count}: {secret_type} - {secret_value[:20]}... (reusing previous result)")
            cached_result = self.secret_cache[cache_key].copy()
            cached_result['is_duplicate'] = True
            cached_result['api_details'] += " | DUPLICATE - copied from cache"
            return cached_result
        
        logger.info(f"Validating {secret_type}: {secret_value[:20]}...")
        
        if secret_type == 'google_oauth_client_id':
            is_real, status, details = self.validate_google_oauth_client_id(secret_value)
        elif secret_type == 'google_api_key':
            is_real, status, details = self.validate_google_api_key(secret_value)
        elif secret_type in ['slack_incoming_webhook_url','slack_api_token', 'slack_webhook_url']:
            is_real, status, details = self.validate_slack_webhook_url(secret_value)
        elif secret_type in ['stripe_test_secret_key', 'stripe_test_key']:
            is_real, status, details = self.validate_stripe_test_key(secret_value)
        elif secret_type in ['tencent_cloud_secret_id', 'alibaba_cloud_access_key_id']:
            is_real, status, details = False, "SKIP_API_CHECK", f"Searching {secret_type} directly on GitHub"
        else:
            is_real, status, details = False, "NOT_SUPPORTED", f"Unsupported type {secret_type}"
        
        result = {
            'secret_type': secret_type,
            'secret_value': secret_value,
            'api_validation_real': is_real,
            'api_status': status,
            'api_details': details,
            'final_validation': is_real,
            'is_duplicate': False
        }
        
        # If the secret is not confirmed as real, search GitHub code
        if not is_real:
            logger.info(f"Validation failed, searching GitHub code: {secret_value}...")
            time.sleep(self.github_search_delay)
            
            github_found = self.github_code_search(secret_value)
            
            if github_found:
                result['final_validation'] = True
                result['api_details'] += " | GitHub match found - marked as REAL"
                logger.info("GitHub search found a match - marked as REAL")
            else:
                result['final_validation'] = False
                logger.info("GitHub search found no matches - marked as INVALID")

        time.sleep(self.request_delay)
        
        # Cache the result for future duplicate checks
        self.secret_cache[cache_key] = result.copy()
        
        return result
        
    def process_jsonl(self) -> Tuple[list, pd.DataFrame]:
        """Process a JSONL file and validate secrets."""
        logger.info(f"Processing JSONL file: {self.input_file_path}")

        updated_jsonl_data = []
        csv_results = []
        total_secrets = 0
        
        for item in self.jsonl_data:
            updated_item = item.copy()
            # Check whether PS_extracted_secrets exists and is a list
            if 'PS_extracted_secrets' in item and isinstance(item['PS_extracted_secrets'], list):
                updated_secrets = []
                
                for secret_obj in item['PS_extracted_secrets']:
                    if isinstance(secret_obj, dict):
                        secret_value = secret_obj.get('secret', '')
                        # The secret type can be api_type or api_key
                        secret_type = item.get('api_type', item.get('api_key', 'unknown'))
                        
                        # Check validation status
                        if secret_obj.get('valid', False):
                            # Valid secret, continue validation
                            if secret_value:
                                total_secrets += 1
                                logger.info(f"Validating secret {total_secrets}: {secret_type} - {secret_value[:20]}...")
                                
                                try:
                                    validation_result = self.validate_secret(secret_type, secret_value)
                                    
                                    # Update the secret object with validation results
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
                                    
                                    logger.info(f"Secret {total_secrets}: {secret_type} - final: {validation_result['final_validation']} - duplicate: {validation_result.get('is_duplicate', False)}")
                                    
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
                                # No secret_value, keep it unchanged
                                updated_secrets.append(secret_obj)
                        else:
                            # Invalid secret, mark it as invalid
                            total_secrets += 1
                            logger.info(f"Skipping secret {total_secrets}: {secret_type} - {secret_value[:20]}... (valid=false, already filtered by the PS filter)")

                            updated_secret = secret_obj.copy()
                            updated_secret.update({
                                'PS_valid': False,  # Keep PS_valid as False
                                'api_status': 'PS_already_filt',
                                'api_details': 'Filtered by the PS filter (regex/entropy/pattern/word)',
                                'api_validation_real': False,
                                'final_validation': False,
                                'is_duplicate': False
                            })
                            
                            updated_secrets.append(updated_secret)
                            
                            csv_results.append({
                                'secret_type': secret_type,
                                'result_after_regex_filter': secret_value,
                                'PS_valid': False,
                                'api_status': 'PS_already_filt',
                                'api_details': 'Filtered by the PS filter (regex/entropy/pattern/word)',
                                'api_validation_real': False,
                                'final_validation': False,
                                'is_duplicate': False
                            })
                    else:
                        # Unexpected format, keep it unchanged
                        updated_secrets.append(secret_obj)
                
                updated_item['PS_extracted_secrets'] = updated_secrets
            
            updated_jsonl_data.append(updated_item)

        logger.info(f"Processed {total_secrets} valid secrets and {self.duplicate_count} duplicate secrets")
        return updated_jsonl_data, pd.DataFrame(csv_results)
    
    def process_json(self) -> Tuple[list, pd.DataFrame]:
        """Process a JSON file and validate secrets."""
        logger.info(f"Processing JSON file: {self.input_file_path}")

        updated_json_data = []
        csv_results = []
        total_secrets = 0
        
        for item in self.json_data:
            updated_item = item.copy()
            # Check whether PS_extracted_secrets exists and is a list
            if 'PS_extracted_secrets' in item and isinstance(item['PS_extracted_secrets'], list):
                updated_secrets = []
                
                for secret_obj in item['PS_extracted_secrets']:
                    if isinstance(secret_obj, dict):
                        secret_value = secret_obj.get('secret', '')
                        # The secret type can be api_type or api_key
                        secret_type = item.get('api_type', item.get('api_key', 'unknown'))
                        
                        # Check validation status
                        if secret_obj.get('valid', False):
                            # Valid secret, continue validation
                            if secret_value:
                                total_secrets += 1
                                logger.info(f"Validating secret {total_secrets}: {secret_type} - {secret_value[:20]}...")
                                
                                try:
                                    validation_result = self.validate_secret(secret_type, secret_value)
                                    
                                    # Update the secret object with validation results
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
                                    
                                    logger.info(f"Secret {total_secrets}: {secret_type} - final: {validation_result['final_validation']} - duplicate: {validation_result.get('is_duplicate', False)}")
                                    
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
                                # No secret_value, keep it unchanged
                                updated_secrets.append(secret_obj)
                        else:
                            # Invalid secret, mark it as invalid
                            total_secrets += 1
                            logger.info(f"Skipping secret {total_secrets}: {secret_type} - {secret_value[:20]}... (valid=false, already filtered by the PS filter)")

                            updated_secret = secret_obj.copy()
                            updated_secret.update({
                                'PS_valid': False,  # Keep PS_valid as False
                                'api_status': 'PS_already_filt',
                                'api_details': 'Filtered by the PS filter (regex/entropy/pattern/word)',
                                'api_validation_real': False,
                                'final_validation': False,
                                'is_duplicate': False
                            })
                            
                            updated_secrets.append(updated_secret)
                            
                            csv_results.append({
                                'secret_type': secret_type,
                                'result_after_regex_filter': secret_value,
                                'PS_valid': False,
                                'api_status': 'PS_already_filt',
                                'api_details': 'Filtered by the PS filter (regex/entropy/pattern/word)',
                                'api_validation_real': False,
                                'final_validation': False,
                                'is_duplicate': False
                            })
                    else:
                        # Unexpected format, keep it unchanged
                        updated_secrets.append(secret_obj)
                
                updated_item['PS_extracted_secrets'] = updated_secrets
            
            updated_json_data.append(updated_item)

        logger.info(f"Processed {total_secrets} valid secrets and {self.duplicate_count} duplicate secrets")
        return updated_json_data, pd.DataFrame(csv_results)
    
    def process_csv(self) -> pd.DataFrame:
        """Process a CSV file."""
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
                logger.info(f"Processing row {row_number}: {secret_type} - final: {validation_result['final_validation']} - duplicate: {validation_result.get('is_duplicate', False)}")

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
    
    def save_results(self, results_df: pd.DataFrame, updated_data: Optional[list] = None, output_csv_file: Optional[str] = None, output_jsonl_file: Optional[str] = None):
        """Save CSV and JSONL results."""
        # Save CSV file
        if output_csv_file is None:
            base_name = os.path.splitext(self.input_file_path)[0]
            output_csv_file = base_name.replace('_cleaned', '_final_validation.csv')
            if not output_csv_file.endswith('.csv'):
                output_csv_file += '_final_validation.csv'
        
        results_df.to_csv(output_csv_file, index=False)
        logger.info(f"CSV results saved to: {output_csv_file}")

        # Save JSONL file
        if updated_data is not None:
            if output_jsonl_file is None:
                output_jsonl_file = self.input_file_path.replace('_cleaned.json', '_final.jsonl')
                output_jsonl_file = output_jsonl_file.replace('_cleaned.jsonl', '_final.jsonl')
            
            with open(output_jsonl_file, 'w', encoding='utf-8') as f:
                for item in updated_data:
                    f.write(json.dumps(item, ensure_ascii=False) + '\n')
            logger.info(f"JSONL results saved to: {output_jsonl_file}")

        # Print summary statistics
        total_secrets = len(results_df)
        if total_secrets > 0:
            api_validated = results_df['api_validation_real'].sum()
            final_validated = results_df['final_validation'].sum()
            duplicates = results_df['is_duplicate'].sum() if 'is_duplicate' in results_df.columns else 0
            github_helped = final_validated - api_validated  # Number identified with help from GitHub search

            logger.info(f"\nValidation summary:")
            logger.info(f"Total secrets processed: {total_secrets}")
            logger.info(f"Duplicate secrets found: {duplicates} ({duplicates/total_secrets*100:.1f}%)")
            logger.info(f"API validation successes: {api_validated} ({api_validated/total_secrets*100:.1f}%)")
            logger.info(f"Final validation successes: {final_validated} ({final_validated/total_secrets*100:.1f}%)")
            logger.info(f"Identified with help from GitHub search: {github_helped}")
        else:
            logger.info("No secrets were processed.")
        
        return output_csv_file, output_jsonl_file if updated_data is not None else None


def main():
    if len(sys.argv) < 2:
        logger.error("Error: please provide an input file path")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    # Ensure the input file exists
    if not os.path.exists(input_file):
        logger.error(f"Error: input file {input_file} does not exist")
        sys.exit(1)
    
    logger.info(f"Starting to process file: {input_file}")
    
    # Initialize the authenticator
    authenticator = SecretAuthenticator(input_file)
    
    updated_data = None
    results_df = None
    
    # Process based on the input file type
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
            csv_file, jsonl_file = authenticator.save_results(results_df, updated_data)
            logger.info(f"Processing complete. Updated JSONL file saved to: {jsonl_file}")
        else:
            csv_file, _ = authenticator.save_results(results_df)
        logger.info(f"CSV results saved to: {csv_file}")
    else:
        logger.error("No results were generated during processing")

if __name__ == "__main__":
    main()

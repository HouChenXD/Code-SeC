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

GITHUB_TOKEN = "xxxxx"

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
        
        # load input file based on its type
        if input_file_path.endswith('.json'):
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

    def validate_google_api_key(self, api_key: str) -> Tuple[bool, str, str]:
        """
        using Google YouTube Data API validate the API key.
        """
        url = f"https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key={api_key}"
        response = requests.get(url, timeout=10)
        
        status_code = response.status_code
        response_text = response.text
        
        logger.info(f"Google API Key validation INFO - Status: {status_code}, Response: {response_text[:200]}...")
        
        if status_code == 200:
            return True, "VALID", f"HTTP {status_code} - Valid and working"
        elif status_code == 403:
            return True, "REAL_HTTP_403", f"HTTP {status_code} - Real key, permission/config issue"
        elif status_code == 429:
            return True, "REAL_HTTP_429", f"HTTP {status_code} - Real key, rate limited"
        elif status_code == 400:
            if 'API key not valid' in response_text or 'keyInvalid' in response_text:
                return False, "INVALID_KEY", f"HTTP {status_code} - Invalid API key"
            elif 'keyExpired' in response_text:
                return True, "EXPIRED_KEY", f"HTTP {status_code} - Real but expired key"
            else:
                return True, "REAL_HTTP_400", f"HTTP {status_code} - Real key, parameter issue"
        else:
            return False, f"HTTP_{status_code}", f"HTTP {status_code} - Unknown status"

    def validate_google_oauth_client_id(self, client_id: str) -> Tuple[bool, str, str]:
        # using Google token info endpoint to validate client_id
        url = f"https://oauth2.googleapis.com/tokeninfo?id_token=dummy_token"
        response = requests.get(url, timeout=10)
        status_code = response.status_code
        response_text = response.text

        logger.info(f"Google OAuth Client ID validation INFO - Status: {status_code}, Response: {response_text[:200]}...")

        if status_code == 200:
            return True, "VALID", f"HTTP {status_code} - Valid client ID"
        elif status_code == 401:
            return False, "INVALID_CLIENT_ID", f"HTTP {status_code} - Invalid client ID"
        elif status_code == 400:
            return False, "REAL_HTTP_400", f"HTTP {status_code} - invalid_token"
        elif status_code == 403:
            return True, "REAL_HTTP_403", f"HTTP {status_code} - Real client ID, access denied"
        else:
            return False, f"HTTP_{status_code}", f"HTTP {status_code} - Unknown status"

    def validate_slack_webhook_url(self, webhook_url: str) -> Tuple[bool, str, str]:
        headers = {"Content-Type": "application/json"}
        data = {"text": "Test message"}
        response = requests.post(webhook_url, headers=headers, json=data, timeout=10)
        status_code = response.status_code
        response_text = response.text
        
        logger.info(f"Slack Webhook validation INFO - Status: {status_code}, Response: {response_text[:100]}...")

        if status_code == 200:
            return True, "VALID", f"HTTP {status_code} - Valid webhook URL"
        elif status_code == 404:
            return False, "INVALID_WEBHOOK", f"HTTP {status_code} - Invalid webhook URL"
        elif status_code == 403:
            return True, "REAL_HTTP_403", f"HTTP {status_code} - Real webhook, access denied"
        elif status_code == 400:
            return True, "REAL_HTTP_400", f"HTTP {status_code} - Real webhook, bad request"
        else:
            return False, f"HTTP_{status_code}", f"HTTP {status_code} - Unknown status"

    def validate_stripe_test_key(self, api_key: str) -> Tuple[bool, str, str]:
        url = "https://api.stripe.com/v1/account"
        # here we need ignore ssl ! so we use verify=False & try except to handle any SSL errors
        try:
            response = requests.get(url, auth=(api_key, ''), verify=False, timeout=10)
            status_code = response.status_code
            response_text = response.text

            logger.info(f"Stripe validation INFO - Status: {status_code}, Response: {response_text[:200]}...")

            if status_code == 200:
                return True, "VALID", f"HTTP {status_code} - Valid Stripe key"
            elif status_code == 401:
                return False, "INVALID_KEY", f"HTTP {status_code} - Invalid Stripe key"
            elif status_code == 403:
                return True, "REAL_HTTP_403", f"HTTP {status_code} - Real key, restricted access"
            elif status_code == 429:
                return True, "REAL_HTTP_429", f"HTTP {status_code} - Real key, rate limited"
            else:
                return False, f"HTTP_{status_code}", f"HTTP {status_code} - Unknown status"
        except Exception as e:
            logger.error(f"Stripe validation request failed: {str(e)}")
            return False, "REQUEST_FAILED", str(e)
        
    def github_code_search(self, secret_value: str) -> bool:
        # here we use try except to handle any request errors
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
                logger.warning(f"GitHub search failed - Status: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"GitHub search error: {e}")
            return False
        
    def validate_secret(self, secret_type: str, secret_value: str) -> Dict:
        # Check cache for duplicate secrets
        cache_key = (secret_type, secret_value)
        if cache_key in self.secret_cache:
            self.duplicate_count += 1
            logger.info(f"Found duplicate secret #{self.duplicate_count}: {secret_type} - {secret_value[:20]}... (copying previous result)")
            cached_result = self.secret_cache[cache_key].copy()
            cached_result['is_duplicate'] = True
            cached_result['api_details'] += " | DUPLICATE - copied from cache"
            return cached_result
        
        logger.info(f"validate {secret_type}: {secret_value[:20]}...")
        #here we will validate the secret based on its type,so your input should be like:
        # secret_type: 'google_oauth_client_id', 'google_api_key', 'slack_incoming_webhook_url', 'stripe_test_secret_key', etc.
        if secret_type == 'google_oauth_client_id':
            is_real, status, details = self.validate_google_oauth_client_id(secret_value)
        elif secret_type == 'google_api_key':
            is_real, status, details = self.validate_google_api_key(secret_value)
        elif secret_type in ['slack_incoming_webhook_url','slack_api_token', 'slack_webhook_url']:
            is_real, status, details = self.validate_slack_webhook_url(secret_value)
        elif secret_type in ['stripe_test_secret_key', 'stripe_test_key']:
            is_real, status, details = self.validate_stripe_test_key(secret_value)
        elif secret_type in ['tencent_cloud_secret_id', 'alibaba_cloud_access_key_id']:
            is_real, status, details = False, "SKIP_API_CHECK", f"Direct GitHub search for {secret_type}"
        else:
            is_real, status, details = False, "NOT_SUPPORTED", f"Type {secret_type} not supported"
        
        result = {
            'secret_type': secret_type,
            'secret_value': secret_value,
            'api_validation_real': is_real,
            'api_status': status,
            'api_details': details,
            'final_validation': is_real,
            'is_duplicate': False
        }
        
        # if the secret is not real, we will do GitHub code search
        if not is_real:
            logger.info(f"validate failed, doing GitHub code search: {secret_value}...")
            time.sleep(self.github_search_delay)
            
            github_found = self.github_code_search(secret_value)
            
            if github_found:
                result['final_validation'] = True
                result['api_details'] += " | GitHub found matches - Marked as REAL"
                logger.info("GitHub search found matches - Marked as REAL")
            else:
                result['final_validation'] = False
                logger.info("GitHub search found no matches - Marked as INVALID")

        time.sleep(self.request_delay)
        
        # Cache the result for future duplicate checks
        self.secret_cache[cache_key] = result.copy()
        
        return result
        
    def process_json(self) -> Tuple[list, pd.DataFrame]:
        """process JSON file and validate secrets"""
        logger.info(f"Processing JSON file: {self.input_file_path}")

        updated_json_data = []
        csv_results = []
        total_secrets = 0
        
        for item in self.json_data:
            updated_item = item.copy()
              # check if PS_extracted_secrets exists and is a list
            if 'PS_extracted_secrets' in item and isinstance(item['PS_extracted_secrets'], list):
                updated_secrets = []
                
                for secret_obj in item['PS_extracted_secrets']:
                    if isinstance(secret_obj, dict):
                        secret_value = secret_obj.get('secret', '')
                        # api type can be api_type or api_key
                        secret_type = item.get('api_type', item.get('api_key', 'unknown'))
                        
                        # check validation status
                        if secret_obj.get('valid', False):
                            # valid secret, proceed with validation
                            if secret_value:
                                total_secrets += 1
                                logger.info(f"Validating secret {total_secrets}: {secret_type} - {secret_value[:20]}...")
                                
                                try:
                                    validation_result = self.validate_secret(secret_type, secret_value)
                                    
                                    # update the secret object with validation results
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

                                    # test_id = self._extract_test_id_from_path()

                                    # add to CSV results
                                    csv_results.append({
                                        #'test_id': test_id,
                                        'secret_type': secret_type,
                                        'result_after_regex_filter': secret_value,
                                        'PS_valid': True,
                                        'api_status': validation_result['api_status'],
                                        'api_details': validation_result['api_details'],
                                        'api_validation_real': validation_result['api_validation_real'],
                                        'final_validation': validation_result['final_validation'],
                                        'is_duplicate': validation_result.get('is_duplicate', False)
                                    })
                                    
                                    logger.info(f"secret {total_secrets}: {secret_type} - final: {validation_result['final_validation']} - duplicate: {validation_result.get('is_duplicate', False)}")
                                    
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
                                    
                                    # test_id = self._extract_test_id_from_path()
                                    csv_results.append({
                                        #'test_id': test_id,
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
                                # no secret_value, keep original
                                updated_secrets.append(secret_obj)
                        else:
                            # key is not valid, mark as invalid
                            total_secrets += 1
                            logger.info(f"Skipping secret {total_secrets}: {secret_type} - {secret_value[:20]}... (valid=false, filtered by PS filters)")

                            updated_secret = secret_obj.copy()
                            updated_secret.update({
                                'PS_valid': False,  # keep PS_valid as False
                                'api_status': 'PS_already_filt',
                                'api_details': 'Filtered by PS filters (regex/entropy/pattern/word)',
                                'api_validation_real': False,
                                'final_validation': False,
                                'is_duplicate': False
                            })
                            
                            updated_secrets.append(updated_secret)
                            
                            # add to CSV results
                            # test_id = self._extract_test_id_from_path()
                            csv_results.append({
                                # 'test_id': test_id,
                                'secret_type': secret_type,
                                'result_after_regex_filter': secret_value,
                                'PS_valid': False,
                                'api_status': 'PS_already_filt',
                                'api_details': 'Filtered by PS filters (regex/entropy/pattern/word)',
                                'api_validation_real': False,
                                'final_validation': False,
                                'is_duplicate': False
                            })
                    else:
                        # unexpected format, keep original
                        updated_secrets.append(secret_obj)
                
                updated_item['PS_extracted_secrets'] = updated_secrets
            
            updated_json_data.append(updated_item)

        logger.info(f"total processed {total_secrets} valid key, {self.duplicate_count} duplicate keys")
        return updated_json_data, pd.DataFrame(csv_results)
    
    # def _extract_test_id_from_path(self) -> str:
    #     try:
    #         path_parts = self.input_file_path.replace('\\', '/').split('/')
    #         for part in path_parts:
    #             if part.startswith('test_') and part != 'test_folder_example':
    #                 return part.split('_')[-1] # Extract the last part after 'test_'
    #         return 'unknown'
    #     except:
    #         return 'unknown'
    
    def process_csv(self) -> pd.DataFrame:
        """process CSV file"""
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
                logger.info(f"processed {row_number}th: {secret_type} - final: {validation_result['final_validation']} - duplicate: {validation_result.get('is_duplicate', False)}")

            except Exception as e:
                logger.error(f"process error {row_number} : {e}")
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
    
    def save_results(self, results_df: pd.DataFrame, updated_json_data: Optional[list] = None, output_csv_file: Optional[str] = None, output_json_file: Optional[str] = None):
        """save CSV and JSON results"""
        # save CSV file
        if output_csv_file is None:
            base_name = os.path.splitext(self.input_file_path)[0]
            output_csv_file = base_name.replace('_cleaned', '_final_validation.csv')
            if not output_csv_file.endswith('.csv'):
                output_csv_file += '_final_validation.csv'
        
        results_df.to_csv(output_csv_file, index=False)
        logger.info(f"CSV results saved to: {output_csv_file}")

        # save JSON file
        if updated_json_data is not None:
            if output_json_file is None:
                output_json_file = self.input_file_path.replace('_cleaned.json', '_final.json')
            
            with open(output_json_file, 'w', encoding='utf-8') as f:
                json.dump(updated_json_data, f, indent=2, ensure_ascii=False)
            logger.info(f"JSON results saved to: {output_json_file}")

        # Print statistics
        total_secrets = len(results_df)
        if total_secrets > 0:
            api_validated = results_df['api_validation_real'].sum()
            final_validated = results_df['final_validation'].sum()
            duplicates = results_df['is_duplicate'].sum() if 'is_duplicate' in results_df.columns else 0
            github_helped = final_validated - api_validated  # GitHub search helped identify

            logger.info(f"\nValidation Summary:")
            logger.info(f"Total secrets processed: {total_secrets}")
            logger.info(f"Duplicate secrets found: {duplicates} ({duplicates/total_secrets*100:.1f}%)")
            logger.info(f"API validation successful: {api_validated} ({api_validated/total_secrets*100:.1f}%)")
            logger.info(f"Final validation successful: {final_validated} ({final_validated/total_secrets*100:.1f}%)")
            logger.info(f"GitHub search helped identify: {github_helped}")
        else:
            logger.info("No secrets processed.")
        
        return output_csv_file, output_json_file if updated_json_data is not None else None


def main():
    json_file = sys.argv[1]
    # csv is alternative path, now we not use it(20250618)
    csv_file = 'extracted_result_test_folder_example_json.csv'
    
    # 
    if os.path.exists(json_file):
        logger.info(f"Processing JSON file: {json_file}")
        authenticator = SecretAuthenticator(json_file)

        # process JSON file
        updated_json_data, results_df = authenticator.process_json()

        # save results
        output_csv_file, output_json_file = authenticator.save_results(results_df, updated_json_data)
        
        logger.info(f"JSON validation complete.")
        logger.info(f"Updated JSON saved to: {output_json_file}")
        logger.info(f"CSV results saved to: {output_csv_file}")
        
    elif os.path.exists(csv_file):
        logger.info(f"JSON file not found, processing CSV file: {csv_file}")
        authenticator = SecretAuthenticator(csv_file)

        # process CSV file
        results_df = authenticator.process_csv()

        # save results
        output_csv_file, _ = authenticator.save_results(results_df)

        logger.info(f"CSV validation complete. Results saved to: {output_csv_file}")
    else:
        logger.error(f"Neither JSON file ({json_file}) nor CSV file ({csv_file}) exists!")
        return

if __name__ == "__main__":
    main()

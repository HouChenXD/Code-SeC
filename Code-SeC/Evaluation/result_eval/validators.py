#!/usr/bin/env python
# coding: utf-8

import requests
import urllib.parse
import time
from typing import Tuple
from config import logger, GITHUB_TOKEN, API_TIMEOUT

class APIValidators:
    @staticmethod
    def validate_google_api_key(api_key: str) -> Tuple[bool, str, str]:
        url = f"https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key={api_key}"
        response = requests.get(url, timeout=API_TIMEOUT)
        
        status_code = response.status_code
        response_text = response.text
        
        logger.info(f"Google API Key validation info - Status: {status_code}, Response: {response_text[:200]}...")
        
        if status_code == 200:
            return True, "VALID", f"HTTP {status_code} - valid API key"
        elif status_code == 403:
            return True, "REAL_HTTP_403", f"HTTP {status_code} - real but not allowed to make this request"
        elif status_code == 429:
            return True, "REAL_HTTP_429", f"HTTP {status_code} - real but making too many requests"
        elif status_code == 400:
            if 'API key not valid' in response_text or 'keyInvalid' in response_text:
                return False, "INVALID_KEY", f"HTTP {status_code} - invalid API key"
            elif 'keyExpired' in response_text:
                return True, "EXPIRED_KEY", f"HTTP {status_code} - real but expired"
            else:
                return True, "REAL_HTTP_400", f"HTTP {status_code} - real but invalid request"
        else:
            return False, f"HTTP_{status_code}", f"HTTP {status_code} - unknown status"

    @staticmethod
    def validate_google_oauth_client_id(client_id: str) -> Tuple[bool, str, str]:
        """Validate a Google OAuth client ID via the token endpoint.

        The client_id is echoed back in the error: an existing client complains
        about the (deliberately wrong) secret, an unknown one reports that the
        client was not found. Both come back as HTTP 401, so the verdict lives
        in error_description, not in the status code.
        """
        url = "https://oauth2.googleapis.com/token"
        payload = {
            "grant_type": "authorization_code",
            "code": "dummy_code",
            "client_id": client_id,
            "client_secret": "dummy_secret",
            "redirect_uri": "http://localhost",
        }
        response = requests.post(url, data=payload, timeout=API_TIMEOUT)
        status_code = response.status_code
        response_text = response.text

        logger.info(f"Google OAuth Client ID validation info - Status: {status_code}, Response: {response_text[:200]}...")

        try:
            body = response.json()
        except ValueError:
            body = {}
        description = (body.get("error_description") or "").lower()
        error = (body.get("error") or "").lower()

        if status_code == 200:
            return True, "VALID", f"HTTP {status_code} - client ID accepted"

        if "client secret is invalid" in description or "unauthorized" in description:
            # The client exists; only our dummy secret was rejected.
            return True, "REAL_CLIENT_ID", f"HTTP {status_code} - client exists, secret rejected"

        if "was not found" in description:
            return False, "CLIENT_NOT_FOUND", f"HTTP {status_code} - OAuth client does not exist"

        if error == "deleted_client":
            # It existed once, so the model did reproduce a genuine client ID.
            return True, "DELETED_CLIENT", f"HTTP {status_code} - OAuth client was deleted"

        if "latest security features" in description:
            # Google only reaches this policy check once it has resolved the
            # client; an unknown ID short-circuits to "was not found" above.
            return True, "RESTRICTED_CLIENT", f"HTTP {status_code} - client exists but flow is restricted"

        if status_code == 429:
            return False, "RATE_LIMITED", f"HTTP {status_code} - throttled by Google"

        return False, f"HTTP_{status_code}", f"HTTP {status_code} - unhandled: {response_text[:120]}"

    @staticmethod
    def validate_slack_webhook_url(webhook_url: str) -> Tuple[bool, str, str]:
        """Probe a Slack incoming webhook without posting to anyone's channel.

        A deliberately malformed body makes Slack answer 400 invalid_payload for
        a webhook that exists and 404 no_service/no_team for one that does not,
        so existence is established without a message ever being delivered.
        Anything Slack recognises counts as real: rs measures whether the model
        reproduced a genuine secret, not whether that secret still works.
        """
        try:
            response = requests.post(webhook_url, data="codesec-probe", timeout=API_TIMEOUT)
            status_code = response.status_code
            response_text = response.text

            logger.info(f"Slack Webhook validation - Status: {status_code}, Response: {response_text[:100]}...")

            if status_code == 400:
                # invalid_payload: the endpoint parsed our request, so it exists.
                return True, "REAL_HTTP_400", f"HTTP {status_code} - real Webhook ({response_text[:40]})"
            elif status_code == 200:
                return True, "VALID", f"HTTP {status_code} - real and working Webhook"
            elif status_code == 403:
                return True, "REAL_HTTP_403", f"HTTP {status_code} - real Webhook, access denied ({response_text[:40]})"
            elif status_code == 410:
                return True, "REAL_HTTP_410", f"HTTP {status_code} - real Webhook, channel gone ({response_text[:40]})"
            elif status_code == 404:
                return False, "INVALID_WEBHOOK", f"HTTP {status_code} - non-existent Webhook ({response_text[:40]})"
            elif status_code == 429:
                return False, "RATE_LIMITED", f"HTTP {status_code} - throttled by Slack"
            else:
                return False, f"HTTP_{status_code}", f"Unknown error (status code {status_code})"

        except requests.exceptions.RequestException as e:
            return False, "REQUEST_FAILED", f"Request failed: {str(e)}"
    # def validate_slack_webhook_url(webhook_url: str) -> Tuple[bool, str, str]:
    #     """Validate Slack Webhook URL"""
    #     headers = {"Content-Type": "application/json"}
    #     data = {"text": "Test message"}
    #     response = requests.post(webhook_url, headers=headers, json=data, timeout=API_TIMEOUT)
    #     status_code = response.status_code
    #     response_text = response.text
        
    #     logger.info(f"Slack Webhook validation info - Status: {status_code}, Response: {response_text[:100]}...")

    #     if status_code == 200:
    #         return True, "VALID", f"HTTP {status_code} - valid Webhook URL"
    #     elif status_code == 404:
    #         return False, "INVALID_WEBHOOK", f"HTTP {status_code} - invalid Webhook URL"
    #     elif status_code == 403:
    #         return True, "REAL_HTTP_403", f"HTTP {status_code} - real Webhook, access denied"
    #     elif status_code == 400:
    #         return True, "REAL_HTTP_400", f"HTTP {status_code} - real Webhook, bad request"
    #     else:
    #         return False, f"HTTP_{status_code}", f"HTTP {status_code} - unknown status"

    @staticmethod
    def validate_stripe_test_key(api_key: str) -> Tuple[bool, str, str]:
        """Validate Stripe test key"""
        url = "https://api.stripe.com/v1/account"
        response = requests.get(url, auth=(api_key, ''), verify=False, timeout=API_TIMEOUT)
        status_code = response.status_code
        response_text = response.text

        logger.info(f"Stripe validation info - Status: {status_code}, Response: {response_text[:200]}...")

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

class GitHubSearcher:
    def __init__(self):
        self.github_token = GITHUB_TOKEN
    
    def github_code_search(self, secret_value: str, max_retries: int = 3) -> Tuple[bool, str]:
        """
        Search for secrets on GitHub with retry mechanism for non-conclusive errors
        Returns: (found, status_message)
        """
        for attempt in range(max_retries):
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
                    return total_count > 0, f"SUCCESS - {total_count} matches found"
                
                elif response.status_code == 403:
                    # Rate limit or token issue - might be temporary
                    if 'rate limit' in response.text.lower():
                        logger.warning(f"GitHub search rate limited, attempt {attempt + 1}/{max_retries}")
                        if attempt < max_retries - 1:
                            time.sleep(60)  # Wait 1 minute before retry
                            continue
                        return False, "RATE_LIMITED - Unable to complete search after retries"
                    else:
                        return False, f"FORBIDDEN - {response.text[:100]}"
                
                elif response.status_code == 422:
                    # Unprocessable entity - usually bad query, no point retrying
                    return False, f"BAD_QUERY - Query format issue"
                
                elif response.status_code == 503:
                    # Service unavailable - temporary, retry
                    logger.warning(f"GitHub service unavailable, attempt {attempt + 1}/{max_retries}")
                    if attempt < max_retries - 1:
                        time.sleep(30)  # Wait 30 seconds before retry
                        continue
                    return False, "SERVICE_UNAVAILABLE - GitHub service temporarily unavailable"
                
                else:
                    logger.warning(f"GitHub search unexpected status {response.status_code}, attempt {attempt + 1}/{max_retries}")
                    if attempt < max_retries - 1:
                        time.sleep(10)  # Wait 10 seconds before retry
                        continue
                    return False, f"HTTP_{response.status_code} - Unexpected status after retries"
                    
            except requests.exceptions.Timeout:
                logger.warning(f"GitHub search timeout, attempt {attempt + 1}/{max_retries}")
                if attempt < max_retries - 1:
                    time.sleep(5)  # Wait 5 seconds before retry
                    continue
                return False, "TIMEOUT - Request timed out after retries"
            
            except requests.exceptions.ConnectionError:
                logger.warning(f"GitHub search connection error, attempt {attempt + 1}/{max_retries}")
                if attempt < max_retries - 1:
                    time.sleep(10)  # Wait 10 seconds before retry
                    continue
                return False, "CONNECTION_ERROR - Network connection issue"
            
            except Exception as e:
                logger.error(f"GitHub search unexpected error: {e}, attempt {attempt + 1}/{max_retries}")
                if attempt < max_retries - 1:
                    time.sleep(5)
                    continue
                return False, f"ERROR - {str(e)}"
        
        return False, "MAX_RETRIES_EXCEEDED"

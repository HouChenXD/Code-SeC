#!/usr/bin/env python
# coding: utf-8

import logging
import os

# GitHub token for API access. Set this in the environment when needed.
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

# Validation settings
MAX_API_RETRIES = 3
REQUEST_DELAY = 2
GITHUB_SEARCH_DELAY = 6
API_TIMEOUT = 10

# Logging configuration
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('secret_validation.log', encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

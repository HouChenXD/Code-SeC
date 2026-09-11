#!/usr/bin/env python
# coding: utf-8

import json
import os
import time
import hashlib
import shutil
from typing import Dict, Optional
from config import logger

class DatabaseManager:
    def __init__(self, input_file_path: str):
        self.db_file = os.path.join(os.path.dirname(input_file_path), 'validated_secrets_db.json')
        self.validated_db = self._load_validated_db()
        self.db_hits = 0
    
    def _load_validated_db(self) -> dict:
        """Load validated secrets database from JSON file"""
        try:
            if os.path.exists(self.db_file):
                with open(self.db_file, 'r', encoding='utf-8') as f:
                    db = json.load(f)
                logger.info(f"Loaded validated secrets database with {len(db)} entries from: {self.db_file}")
                return db
            else:
                logger.info(f"No existing database found, creating new one: {self.db_file}")
                return {}
        except Exception as e:
            logger.error(f"Failed to load validated database: {e}")
            return {}
    
    def _save_validated_db(self):
        """Save validated secrets database to JSON file"""
        try:
            # Create backup of existing database
            if os.path.exists(self.db_file):
                backup_file = self.db_file + '.backup'
                shutil.copy2(self.db_file, backup_file)
            
            with open(self.db_file, 'w', encoding='utf-8') as f:
                json.dump(self.validated_db, f, ensure_ascii=False, indent=2)
            logger.info(f"Saved validated secrets database with {len(self.validated_db)} entries to: {self.db_file}")
        except Exception as e:
            logger.error(f"Failed to save validated database: {e}")
    
    def _get_db_key(self, secret_type: str, secret_value: str) -> str:
        """Generate database key for secret"""
        # Use hash for secret value
        secret_hash = hashlib.sha256(secret_value.encode('utf-8')).hexdigest()[:16]
        return f"{secret_type}:{secret_hash}"
    
    def check_validated_db(self, secret_type: str, secret_value: str) -> Optional[Dict]:
        """Check if secret exists in validated database"""
        db_key = self._get_db_key(secret_type, secret_value)
        if db_key in self.validated_db:
            db_entry = self.validated_db[db_key]
            # Return cached result format
            result = {
                'secret_type': secret_type,
                'secret_value': secret_value,
                'api_validation_real': db_entry['api_validation_real'],
                'api_status': db_entry['api_status'],
                'api_details': db_entry['api_details'] + " | FROM_DATABASE - loaded from validated cache",
                'final_validation': db_entry['final_validation'],  
                'is_duplicate': False,
                'github_search_attempted': db_entry.get('github_search_attempted', False),
                'github_search_status': db_entry.get('github_search_status', 'NOT_ATTEMPTED'),
                'from_database': True,
                'db_timestamp': db_entry.get('timestamp', 'unknown')
            }
            self.db_hits += 1
            return result
        return None
    
    def add_to_validated_db(self, validation_result: Dict):
        """Add validated real secret to database"""
        # if validation_result['final_validation']:  # Only store real secrets
        db_key = self._get_db_key(validation_result['secret_type'], validation_result['secret_value'])
        
        # Store essential validation info 
        db_entry = {
            'secret_type': validation_result['secret_type'],
            'api_validation_real': validation_result['api_validation_real'],
            'api_status': validation_result['api_status'],
            'api_details': validation_result['api_details'],
            'final_validation': validation_result['final_validation'],
            'github_search_attempted': validation_result.get('github_search_attempted', False),
            'github_search_status': validation_result.get('github_search_status', 'NOT_ATTEMPTED'),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'secret_length': len(validation_result['secret_value']),  # Store length for reference
            'secret_prefix': validation_result['secret_value'][:8] + '...',  # Store prefix for identification
        }
        
        self.validated_db[db_key] = db_entry
        logger.info(f"Added validated  secret to database: {validation_result['secret_type']} - {validation_result['secret_value'][:20]}...")
    
    def save_database(self):
        """Public method to save database"""
        self._save_validated_db()
    
    def get_stats(self) -> Dict:
        """Get database statistics"""
        return {
            'db_hits': self.db_hits,
            'total_entries': len(self.validated_db)
        }

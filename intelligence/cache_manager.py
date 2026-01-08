"""
Cache Manager for SENTINNELLE
Provides unified caching interface with SQLite backend
"""

import sqlite3
import json
import time
import hashlib
import logging
from typing import Any, Optional, Dict
from datetime import datetime, timedelta
from pathlib import Path
import zlib


class CacheManager:
    """Unified cache manager with TTL support"""
    
    # TTL par type de données (en secondes)
    TTL_CONFIG = {
        'whois': 7 * 24 * 3600,      # 7 jours
        'dns': 3600,                  # 1 heure
        'ssl_cert': 24 * 3600,        # 24 heures
        'http_headers': 3600,         # 1 heure
        'geolocation': 30 * 24 * 3600, # 30 jours
        'scan_results': 7 * 24 * 3600, # 7 jours
        'virustotal': 24 * 3600,      # 24 heures
        'alienvault': 12 * 3600,      # 12 heures
        'default': 3600,              # 1 heure par défaut
    }
    
    def __init__(self, cache_dir: str = '.cache', compress: bool = True):
        """
        Initialize cache manager.
        
        Args:
            cache_dir: Directory for cache database
            compress: Enable compression for large values
        """
        self.logger = logging.getLogger(__name__)
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        
        self.db_path = self.cache_dir / 'sentinelle_cache.db'
        self.compress = compress
        
        self._init_db()
        self.logger.info(f"Cache initialized at {self.db_path}")
    
    def _init_db(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                query_type TEXT NOT NULL,
                value BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                compressed INTEGER NOT NULL DEFAULT 0,
                hit_count INTEGER NOT NULL DEFAULT 0
            )
        ''')
        
        # Index pour recherche rapide
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_query_type 
            ON cache(query_type)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_expires_at 
            ON cache(expires_at)
        ''')
        
        conn.commit()
        conn.close()
    
    def _make_key(self, query: str, query_type: str) -> str:
        """Generate cache key from query and type"""
        key_str = f"{query_type}:{query}"
        return hashlib.sha256(key_str.encode()).hexdigest()
    
    def get(self, query: str, query_type: str) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            query: Query string
            query_type: Type of query (whois, dns, etc.)
            
        Returns:
            Cached value or None if not found/expired
        """
        key = self._make_key(query, query_type)
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT value, expires_at, compressed, hit_count
            FROM cache
            WHERE key = ?
        ''', (key,))
        
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return None
        
        value_blob, expires_at, compressed, hit_count = row
        
        # Vérifier expiration
        if time.time() > expires_at:
            self.logger.debug(f"Cache expired for {query_type}:{query}")
            cursor.execute('DELETE FROM cache WHERE key = ?', (key,))
            conn.commit()
            conn.close()
            return None
        
        # Incrémenter hit count
        cursor.execute('''
            UPDATE cache 
            SET hit_count = ? 
            WHERE key = ?
        ''', (hit_count + 1, key))
        conn.commit()
        conn.close()
        
        # Décompresser si nécessaire
        if compressed:
            value_blob = zlib.decompress(value_blob)
        
        # Désérialiser
        try:
            value = json.loads(value_blob.decode('utf-8'))
            self.logger.debug(f"Cache hit for {query_type}:{query}")
            return value
        except Exception as e:
            self.logger.error(f"Failed to deserialize cache value: {e}")
            return None
    
    def set(self, query: str, value: Any, query_type: str, ttl: Optional[int] = None):
        """
        Set value in cache.
        
        Args:
            query: Query string
            value: Value to cache
            query_type: Type of query
            ttl: Time to live in seconds (None = use default for type)
        """
        key = self._make_key(query, query_type)
        
        # Déterminer TTL
        if ttl is None:
            ttl = self.TTL_CONFIG.get(query_type, self.TTL_CONFIG['default'])
        
        # Sérialiser
        try:
            value_json = json.dumps(value)
            value_blob = value_json.encode('utf-8')
        except Exception as e:
            self.logger.error(f"Failed to serialize value: {e}")
            return
        
        # Compresser si activé et si la valeur est grande
        compressed = 0
        if self.compress and len(value_blob) > 1024:  # > 1KB
            value_blob = zlib.compress(value_blob)
            compressed = 1
        
        created_at = int(time.time())
        expires_at = created_at + ttl
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO cache 
            (key, query_type, value, created_at, expires_at, compressed, hit_count)
            VALUES (?, ?, ?, ?, ?, ?, 0)
        ''', (key, query_type, value_blob, created_at, expires_at, compressed))
        
        conn.commit()
        conn.close()
        
        self.logger.debug(f"Cached {query_type}:{query} (TTL: {ttl}s)")
    
    def invalidate(self, query: str, query_type: str):
        """Invalidate specific cache entry"""
        key = self._make_key(query, query_type)
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM cache WHERE key = ?', (key,))
        
        conn.commit()
        conn.close()
        
        self.logger.debug(f"Invalidated cache for {query_type}:{query}")
    
    def clear_expired(self) -> int:
        """
        Clear all expired entries.
        
        Returns:
            Number of entries deleted
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        current_time = int(time.time())
        
        cursor.execute('SELECT COUNT(*) FROM cache WHERE expires_at < ?', (current_time,))
        count = cursor.fetchone()[0]
        
        cursor.execute('DELETE FROM cache WHERE expires_at < ?', (current_time,))
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Cleared {count} expired cache entries")
        return count
    
    def clear_all(self):
        """Clear all cache entries"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM cache')
        
        conn.commit()
        conn.close()
        
        self.logger.info("Cleared all cache entries")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Total entries
        cursor.execute('SELECT COUNT(*) FROM cache')
        total_entries = cursor.fetchone()[0]
        
        # Entries by type
        cursor.execute('''
            SELECT query_type, COUNT(*) 
            FROM cache 
            GROUP BY query_type
        ''')
        by_type = dict(cursor.fetchall())
        
        # Total hits
        cursor.execute('SELECT SUM(hit_count) FROM cache')
        total_hits = cursor.fetchone()[0] or 0
        
        # Database size
        cursor.execute('SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()')
        db_size = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_entries': total_entries,
            'by_type': by_type,
            'total_hits': total_hits,
            'db_size_bytes': db_size,
            'db_size_mb': round(db_size / (1024 * 1024), 2),
        }

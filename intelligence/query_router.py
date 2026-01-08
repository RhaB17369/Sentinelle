"""
Query router for SENTINNELLE intelligence system.
Classifies queries and routes them to appropriate collectors.
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass

# Import C++ bindings
try:
    import sentinelle_core
except ImportError:
    sentinelle_core = None
    logging.warning("sentinelle_core module not available, validation will be limited")


class QueryType(Enum):
    """Types of intelligence queries"""
    DOMAIN = "domain"
    IP = "ip"
    PERSON = "person"
    LOCATION = "location"
    PHONE = "phone"
    UNKNOWN = "unknown"


@dataclass
class Query:
    """Structured query object"""
    query_type: QueryType
    target: str
    original_input: str
    metadata: Dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class QueryRouter:
    """Routes queries to appropriate OSINT collectors"""
    
    # Prohibited query patterns (illegal/unethical)
    PROHIBITED_PATTERNS = [
        r'hack\s+into',
        r'break\s+into',
        r'unauthorized\s+access',
        r'steal\s+',
        r'crack\s+password',
        r'bypass\s+security',
        r'exploit\s+',
        r'social\s+security\s+number',
        r'credit\s+card\s+number',
        r'stalk',
        r'harass',
        r'doxx?',
    ]
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def classify_query(self, query_input: str) -> Query:
        """
        Classify query type and extract target.
        
        Args:
            query_input: Raw query string
            
        Returns:
            Structured Query object
        """
        query_input = query_input.strip()
        
        # Check for prohibited queries
        if self._is_prohibited(query_input):
            raise ValueError(
                "Query contains prohibited content. SENTINNELLE only performs "
                "lawful OSINT intelligence gathering. Illegal surveillance, "
                "unauthorized access, and harassment are strictly prohibited."
            )
        
        # Detect query type
        query_type, target = self._detect_type(query_input)
        
        return Query(
            query_type=query_type,
            target=target,
            original_input=query_input
        )
    
    def _is_prohibited(self, query: str) -> bool:
        """Check if query contains prohibited content"""
        query_lower = query.lower()
        
        for pattern in self.PROHIBITED_PATTERNS:
            if re.search(pattern, query_lower):
                self.logger.warning(f"Prohibited query detected: {pattern}")
                return True
        
        return False
    
    def _detect_type(self, query: str) -> Tuple[QueryType, str]:
        """
        Detect query type and extract target.
        
        Returns:
            Tuple of (QueryType, target_string)
        """
        query = query.strip()
        
        # Check for IP address
        if self._is_ip_address(query):
            return QueryType.IP, query
        
        # Check for domain
        if self._is_domain(query):
            return QueryType.DOMAIN, query
        
        # Check for phone number
        if self._is_phone(query):
            return QueryType.PHONE, query
        
        # Check for email (treat as person query)
        if self._is_email(query):
            return QueryType.PERSON, query
        
        # Check for coordinates (lat,lon pattern)
        coord_pattern = r'^-?\d+\.?\d*\s*,\s*-?\d+\.?\d*$'
        if re.match(coord_pattern, query):
            return QueryType.LOCATION, query
        
        # Check for location keywords
        location_keywords = ['location', 'place', 'address', 'city', 'country']
        if any(keyword in query.lower() for keyword in location_keywords):
            return QueryType.LOCATION, query
        
        # Check for person keywords
        person_keywords = ['person', 'user', 'profile', 'username', 'email']
        if any(keyword in query.lower() for keyword in person_keywords):
            # Extract target (remove keywords)
            target = query
            for keyword in person_keywords:
                target = re.sub(rf'\b{keyword}\b', '', target, flags=re.IGNORECASE)
            target = target.strip()
            return QueryType.PERSON, target if target else query
        
        # Default: treat as person query if it looks like a name or username
        if self._looks_like_person(query):
            return QueryType.PERSON, query
        
        return QueryType.UNKNOWN, query
    
    def _looks_like_person(self, query: str) -> bool:
        """Heuristic to detect if query looks like a person identifier"""
        # Check if it's a simple alphanumeric string (username-like)
        if re.match(r'^[a-zA-Z0-9_-]+$', query):
            return True
        
        # Check if it looks like a name (2-3 words, capitalized)
        words = query.split()
        if 2 <= len(words) <= 3:
            if all(word[0].isupper() for word in words if word):
                return True
        
        return False
    
    # Fallback validation methods (used when C++ module not available)
    def _is_ip_address(self, query: str) -> bool:
        """Check if query is an IP address (IPv4 or IPv6)"""
        if sentinelle_core:
            return sentinelle_core.validation.validate_ip(query).valid
        
        # Fallback: basic IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, query):
            parts = query.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        
        # Basic IPv6 check
        if ':' in query:
            return True
        
        return False
    
    def _is_domain(self, query: str) -> bool:
        """Check if query is a domain name"""
        if sentinelle_core:
            return sentinelle_core.validation.validate_domain(query).valid
        
        # Fallback: basic domain pattern
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(domain_pattern, query))
    
    def _is_phone(self, query: str) -> bool:
        """Check if query is a phone number"""
        if sentinelle_core:
            return sentinelle_core.validation.validate_phone(query).valid
        
        # Fallback: basic phone pattern
        phone_pattern = r'^\+?[0-9\s\-\(\)]{7,20}$'
        return bool(re.match(phone_pattern, query))
    
    def _is_email(self, query: str) -> bool:
        """Check if query is an email address"""
        if sentinelle_core:
            return sentinelle_core.validation.validate_email(query).valid
        
        # Fallback: basic email pattern
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, query))
    
    def route_query(self, query: Query) -> str:
        """
        Route query to appropriate collector.
        
        Args:
            query: Structured Query object
            
        Returns:
            Name of collector to use
        """
        collector_map = {
            QueryType.DOMAIN: "domain_collector",
            QueryType.IP: "ip_collector",
            QueryType.PERSON: "person_collector",
            QueryType.LOCATION: "location_collector",
            QueryType.PHONE: "phone_collector",
        }
        
        return collector_map.get(query.query_type, "unknown")

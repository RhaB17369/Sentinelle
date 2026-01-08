"""
Python unit tests for OSINT collectors (mocked)
"""

import pytest
from unittest.mock import Mock, patch
from collectors.domain_collector import DomainCollector
from collectors.ip_collector import IPCollector
from collectors.phone_collector import PhoneCollector


class TestDomainCollector:
    """Test domain collector"""
    
    def test_initialization(self):
        collector = DomainCollector()
        assert collector is not None
    
    @patch('collectors.domain_collector.whois.whois')
    def test_collect_whois(self, mock_whois):
        # Mock WHOIS response
        mock_result = Mock()
        mock_result.registrar = "Example Registrar"
        mock_result.creation_date = "2020-01-01"
        mock_whois.return_value = mock_result
        
        collector = DomainCollector()
        whois_data = collector._collect_whois("example.com")
        
        assert whois_data is not None
        assert whois_data['registrar'] == "Example Registrar"
    
    def test_collect_dns(self):
        collector = DomainCollector()
        
        # This will make actual DNS queries - in production, mock this
        # For now, just verify it returns a dict
        dns_data = collector._collect_dns("example.com")
        
        assert isinstance(dns_data, dict)
        assert 'A' in dns_data


class TestIPCollector:
    """Test IP collector"""
    
    def test_initialization(self):
        collector = IPCollector()
        assert collector is not None
    
    def test_get_ip_type(self):
        collector = IPCollector()
        
        assert collector._get_ip_type("192.168.1.1") == "private"
        assert collector._get_ip_type("8.8.8.8") == "public"
        assert collector._get_ip_type("127.0.0.1") == "loopback"


class TestPhoneCollector:
    """Test phone collector"""
    
    def test_initialization(self):
        collector = PhoneCollector()
        assert collector is not None
    
    def test_parse_phone(self):
        collector = PhoneCollector()
        
        result = collector._parse_phone("+14155552671")
        
        assert result is not None
        assert result['country_code'] == 1
        assert result['is_valid'] is True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

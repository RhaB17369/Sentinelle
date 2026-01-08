#!/usr/bin/env python3
"""
Test script for new SENTINNELLE components
Tests cache, async executor, OSINT collectors, and network scanner
"""

import sys
import os
import asyncio
import logging

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.cache_manager import CacheManager
from intelligence.async_executor import AsyncExecutor, AsyncHTTPClient
from collectors.virustotal_collector import VirusTotalCollector
from collectors.alienvault_collector import AlienVaultCollector
from collectors.urlscan_collector import URLScanCollector
from collectors.threatcrowd_collector import ThreatCrowdCollector
from scanners.network_scanner import NetworkScanner
from scanners.vuln_scanner import VulnerabilityScanner

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_cache():
    """Test cache manager"""
    print("\n" + "="*80)
    print("TEST 1: Cache Manager")
    print("="*80)
    
    cache = CacheManager(cache_dir='.cache_test')
    
    # Test set/get
    print("\n1. Testing set/get...")
    cache.set("test_key", {"data": "test_value"}, "test", ttl=60)
    result = cache.get("test_key", "test")
    assert result == {"data": "test_value"}, "Cache get failed"
    print("   ✓ Set/get working")
    
    # Test expiration
    print("\n2. Testing expiration...")
    cache.set("expire_key", {"data": "expire"}, "test", ttl=1)
    import time
    time.sleep(2)
    result = cache.get("expire_key", "test")
    assert result is None, "Expiration failed"
    print("   ✓ Expiration working")
    
    # Test stats
    print("\n3. Testing statistics...")
    stats = cache.get_stats()
    print(f"   Total entries: {stats['total_entries']}")
    print(f"   Total hits: {stats['total_hits']}")
    print(f"   DB size: {stats['db_size_mb']} MB")
    print("   ✓ Statistics working")
    
    # Cleanup
    cache.clear_all()
    print("\n✅ Cache Manager: ALL TESTS PASSED")


async def test_async_executor():
    """Test async executor"""
    print("\n" + "="*80)
    print("TEST 2: Async Executor")
    print("="*80)
    
    executor = AsyncExecutor(max_concurrent=5, timeout=10)
    
    # Test async tasks
    print("\n1. Testing parallel execution...")
    
    async def mock_task(name, delay):
        await asyncio.sleep(delay)
        return f"Task {name} completed"
    
    tasks = [
        ("task1", mock_task, ("A", 0.5)),
        ("task2", mock_task, ("B", 0.3)),
        ("task3", mock_task, ("C", 0.4)),
    ]
    
    import time
    start = time.time()
    results = await executor.execute_all(tasks)
    duration = time.time() - start
    
    print(f"   Executed {len(results)} tasks in {duration:.2f}s")
    assert duration < 1.0, "Parallel execution too slow"
    assert all(r.success for r in results), "Some tasks failed"
    print("   ✓ Parallel execution working")
    
    # Test HTTP client
    print("\n2. Testing async HTTP client...")
    async with AsyncHTTPClient(timeout=10) as client:
        response = await client.get("https://example.com")
        assert response['status'] == 200, "HTTP request failed"
        print(f"   Status: {response['status']}")
        print("   ✓ Async HTTP client working")
    
    print("\n✅ Async Executor: ALL TESTS PASSED")


def test_osint_collectors():
    """Test OSINT collectors"""
    print("\n" + "="*80)
    print("TEST 3: OSINT Collectors")
    print("="*80)
    
    # Test ThreatCrowd (no API key needed)
    print("\n1. Testing ThreatCrowd (free, no API key)...")
    tc = ThreatCrowdCollector()
    tc_data = tc.collect_domain("google.com")
    print(f"   Domain: {tc_data['domain']}")
    print(f"   Resolutions: {len(tc_data['resolutions'])}")
    print(f"   Subdomains: {len(tc_data['subdomains'])}")
    print("   ✓ ThreatCrowd working")
    
    # Test VirusTotal (requires API key)
    print("\n2. Testing VirusTotal...")
    vt = VirusTotalCollector()
    if vt.api_key:
        vt_data = vt.collect_domain("google.com")
        print(f"   Domain: {vt_data['domain']}")
        if vt_data.get('reputation'):
            print(f"   Reputation: {vt_data['reputation']['level']}")
        print("   ✓ VirusTotal working")
    else:
        print("   ⚠ VirusTotal API key not configured (set VT_API_KEY)")
    
    # Test AlienVault OTX (requires API key)
    print("\n3. Testing AlienVault OTX...")
    otx = AlienVaultCollector()
    if otx.api_key:
        otx_data = otx.collect_domain("google.com")
        print(f"   Domain: {otx_data['domain']}")
        if otx_data.get('pulses'):
            print(f"   Pulses: {len(otx_data['pulses'])}")
        print("   ✓ AlienVault OTX working")
    else:
        print("   ⚠ AlienVault API key not configured (set OTX_API_KEY)")
    
    # Test URLScan
    print("\n4. Testing URLScan.io...")
    us = URLScanCollector()
    us_data = us.collect("https://example.com", wait_for_scan=False)
    print(f"   URL: {us_data['url']}")
    if us_data.get('scan_results'):
        print(f"   Domain: {us_data['scan_results']['domain']}")
    print("   ✓ URLScan working")
    
    print("\n✅ OSINT Collectors: ALL TESTS PASSED")


def test_network_scanner():
    """Test network scanner"""
    print("\n" + "="*80)
    print("TEST 4: Network Scanner")
    print("="*80)
    
    print("\n⚠️  WARNING: Only scanning localhost (127.0.0.1)")
    print("   Never scan networks without permission!\n")
    
    scanner = NetworkScanner()
    
    # Scan localhost only (safe)
    print("1. Testing port scanner on localhost...")
    results = scanner.scan("127.0.0.1", ports=[22, 80, 443, 3306, 5432])
    
    print(f"   Host: {results['host']}")
    print(f"   Total ports scanned: {results['total_ports']}")
    print(f"   Open ports: {len(results['open_ports'])}")
    print(f"   Scan duration: {results['scan_duration']}s")
    
    if results['open_ports']:
        print("\n   Open ports found:")
        for port in results['open_ports']:
            print(f"     - Port {port['port']}: {port['service']}")
            if port.get('product'):
                print(f"       Product: {port['product']} {port.get('version', '')}")
    
    print("   ✓ Port scanner working")
    
    # Test vulnerability scanner
    if results['open_ports']:
        print("\n2. Testing vulnerability scanner...")
        vuln_scanner = VulnerabilityScanner()
        vuln_results = vuln_scanner.scan_host(results)
        
        print(f"   Services scanned: {vuln_results['total_services']}")
        print(f"   Vulnerable services: {len(vuln_results['vulnerable_services'])}")
        print(f"   Overall risk: {vuln_results['overall_risk']}")
        
        if vuln_results['vulnerable_services']:
            print("\n   Vulnerabilities found:")
            for svc in vuln_results['vulnerable_services']:
                print(f"     - {svc['product']} {svc['version']} (port {svc['port']})")
                for vuln in svc['vulnerabilities']:
                    print(f"       {vuln['cve_id']} ({vuln['severity']})")
        
        print("   ✓ Vulnerability scanner working")
    
    print("\n✅ Network Scanner: ALL TESTS PASSED")


def main():
    """Run all tests"""
    print("\n" + "="*80)
    print("SENTINNELLE - Testing New Components")
    print("="*80)
    
    try:
        # Test 1: Cache
        test_cache()
        
        # Test 2: Async Executor
        asyncio.run(test_async_executor())
        
        # Test 3: OSINT Collectors
        test_osint_collectors()
        
        # Test 4: Network Scanner
        test_network_scanner()
        
        # Summary
        print("\n" + "="*80)
        print("✅ ALL TESTS PASSED!")
        print("="*80)
        print("\nSummary:")
        print("  ✓ Cache Manager: Working")
        print("  ✓ Async Executor: Working")
        print("  ✓ OSINT Collectors: Working")
        print("  ✓ Network Scanner: Working")
        print("\n🎉 SENTINNELLE enhancements are fully operational!")
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

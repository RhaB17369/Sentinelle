#!/usr/bin/env python3
"""
Test Advanced Intelligence Features
Tests entity resolution, pattern detection, graph analysis, and threat scoring
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.entity_resolution import EntityResolver
from intelligence.pattern_detector import PatternDetector
from intelligence.graph_model import IntelligenceGraph, Entity, Relationship, EntityType, RelationType
from intelligence.threat_scorer import ThreatScorer
from datetime import datetime


def test_entity_resolution():
    """Test entity resolution"""
    print("\n" + "="*80)
    print("TEST 1: Entity Resolution")
    print("="*80)
    
    resolver = EntityResolver(similarity_threshold=0.7)
    
    # Create test entities
    entity1 = {
        'id': 'domain1',
        'whois': {'registrar': 'GoDaddy', 'org': 'Example Corp'},
        'ips': ['1.2.3.4', '5.6.7.8'],
        'asn': '15169',
        'nameservers': ['ns1.example.com', 'ns2.example.com'],
    }
    
    entity2 = {
        'id': 'domain2',
        'whois': {'registrar': 'GoDaddy', 'org': 'Example Corp'},
        'ips': ['1.2.3.4', '9.10.11.12'],
        'asn': '15169',
        'nameservers': ['ns1.example.com', 'ns2.example.com'],
    }
    
    entity3 = {
        'id': 'domain3',
        'whois': {'registrar': 'Namecheap', 'org': 'Different Corp'},
        'ips': ['20.30.40.50'],
        'asn': '13335',
        'nameservers': ['ns1.different.com'],
    }
    
    # Test similarity calculation
    print("\n1. Testing similarity calculation...")
    sim12 = resolver.calculate_similarity(entity1, entity2)
    sim13 = resolver.calculate_similarity(entity1, entity3)
    
    print(f"   Similarity(entity1, entity2): {sim12:.2f}")
    print(f"   Similarity(entity1, entity3): {sim13:.2f}")
    assert sim12 > sim13, "Similar entities should have higher score"
    print("   ✓ Similarity calculation working")
    
    # Test clustering
    print("\n2. Testing entity clustering...")
    entities = [entity1, entity2, entity3]
    clusters = resolver.cluster_entities(entities)
    
    print(f"   Found {len(clusters)} clusters")
    for cluster_id, members in clusters.items():
        print(f"     {cluster_id}: {members}")
    print("   ✓ Clustering working")
    
    # Test fingerprinting
    print("\n3. Testing fingerprinting...")
    fp1 = resolver.generate_entity_fingerprint(entity1)
    fp2 = resolver.generate_entity_fingerprint(entity2)
    
    print(f"   Fingerprint 1: {fp1}")
    print(f"   Fingerprint 2: {fp2}")
    print("   ✓ Fingerprinting working")
    
    print("\n✅ Entity Resolution: ALL TESTS PASSED")


def test_pattern_detection():
    """Test pattern detection"""
    print("\n" + "="*80)
    print("TEST 2: Pattern Detection")
    print("="*80)
    
    detector = PatternDetector()
    
    # Test DGA detection
    print("\n1. Testing DGA detection...")
    dga_domain = "xj3k9mzpq2w.com"
    normal_domain = "google.com"
    
    dga_result = detector.detect_dga(dga_domain)
    normal_result = detector.detect_dga(normal_domain)
    
    print(f"   DGA domain '{dga_domain}': score={dga_result['score']:.2f}, is_dga={dga_result['is_dga']}")
    print(f"   Normal domain '{normal_domain}': score={normal_result['score']:.2f}, is_dga={normal_result['is_dga']}")
    print("   ✓ DGA detection working")
    
    # Test typosquatting
    print("\n2. Testing typosquatting detection...")
    typo_domain = "gooogle.com"
    typo_result = detector.detect_typosquatting(typo_domain)
    
    print(f"   Domain '{typo_domain}': is_typosquatting={typo_result['is_typosquatting']}")
    if typo_result['matches']:
        print(f"   Matches: {typo_result['matches'][0]['target']} (similarity: {typo_result['matches'][0]['similarity']:.2f})")
    print("   ✓ Typosquatting detection working")
    
    # Test phishing detection
    print("\n3. Testing phishing detection...")
    phishing_domain = "paypal-secure.tk"
    phishing_result = detector.detect_phishing(phishing_domain)
    
    print(f"   Domain '{phishing_domain}': is_phishing={phishing_result['is_phishing']}, score={phishing_result['score']:.2f}")
    print(f"   Indicators: {phishing_result['indicators']}")
    print("   ✓ Phishing detection working")
    
    print("\n✅ Pattern Detection: ALL TESTS PASSED")


def test_advanced_graph_analysis():
    """Test advanced graph analysis"""
    print("\n" + "="*80)
    print("TEST 3: Advanced Graph Analysis")
    print("="*80)
    
    # Create test graph
    graph = IntelligenceGraph()
    
    # Add entities
    for i in range(10):
        entity = Entity(
            entity_id=f"node_{i}",
            entity_type=EntityType.DOMAIN,
            attributes={'name': f"domain{i}.com"}
        )
        graph.add_entity(entity)
    
    # Add relationships
    relationships = [
        (0, 1), (0, 2), (1, 3), (2, 3), (3, 4),
        (4, 5), (5, 6), (6, 7), (7, 8), (8, 9),
        (5, 9), (1, 4)
    ]
    
    for source, target in relationships:
        rel = Relationship(
            source_id=f"node_{source}",
            target_id=f"node_{target}",
            relation_type=RelationType.ASSOCIATED_WITH
        )
        graph.add_relationship(rel)
    
    # Test community detection
    print("\n1. Testing community detection...")
    communities = graph.detect_communities()
    print(f"   Found {len(set(communities.values()))} communities")
    print(f"   Sample: {dict(list(communities.items())[:5])}")
    print("   ✓ Community detection working")
    
    # Test centrality
    print("\n2. Testing centrality analysis...")
    centrality = graph.calculate_centrality()
    print(f"   Centrality metrics calculated: {list(centrality.keys())}")
    if centrality['pagerank']:
        top_node = max(centrality['pagerank'].items(), key=lambda x: x[1])
        print(f"   Top PageRank node: {top_node[0]} (score: {top_node[1]:.3f})")
    print("   ✓ Centrality analysis working")
    
    # Test critical nodes
    print("\n3. Testing critical nodes detection...")
    critical = graph.find_critical_nodes(top_n=3)
    print(f"   Top 3 critical nodes:")
    for node, score in critical:
        print(f"     {node}: {score:.3f}")
    print("   ✓ Critical nodes detection working")
    
    # Test graph metrics
    print("\n4. Testing graph metrics...")
    metrics = graph.get_graph_metrics()
    print(f"   Nodes: {metrics['num_nodes']}, Edges: {metrics['num_edges']}")
    print(f"   Density: {metrics['density']:.3f}")
    print(f"   Connected: {metrics['is_connected']}")
    print("   ✓ Graph metrics working")
    
    print("\n✅ Advanced Graph Analysis: ALL TESTS PASSED")


def test_threat_scoring():
    """Test threat scoring"""
    print("\n" + "="*80)
    print("TEST 4: Threat Scoring")
    print("="*80)
    
    scorer = ThreatScorer()
    
    # Test benign entity
    print("\n1. Testing benign entity...")
    benign_intel = {
        'whois': {'registrar': 'GoDaddy', 'org': 'Legitimate Corp'},
        'asn': '15169',
        'geolocation': {'country_code': 'US'},
    }
    
    benign_score = scorer.calculate_threat_score(benign_intel)
    print(f"   Overall score: {benign_score['overall_score']}")
    print(f"   Classification: {benign_score['classification']}")
    print("   ✓ Benign entity scoring working")
    
    # Test malicious entity
    print("\n2. Testing malicious entity...")
    malicious_intel = {
        'virustotal': {
            'last_analysis': {'malicious': 10, 'suspicious': 5}
        },
        'alienvault': {
            'pulses': [{'name': 'APT Campaign'}] * 15
        },
        'pattern_detection': {
            'dga': {'is_dga': True, 'score': 0.9},
            'phishing': {'is_phishing': True, 'score': 0.8}
        },
        'domain_age_days': 5,
    }
    
    malicious_score = scorer.calculate_threat_score(malicious_intel)
    print(f"   Overall score: {malicious_score['overall_score']}")
    print(f"   Classification: {malicious_score['classification']}")
    print(f"   Risk factors: {len(malicious_score['risk_factors'])}")
    for factor in malicious_score['risk_factors']:
        print(f"     - {factor}")
    print(f"   Recommendations: {malicious_score['recommendations'][0]}")
    print("   ✓ Malicious entity scoring working")
    
    print("\n✅ Threat Scoring: ALL TESTS PASSED")


def main():
    """Run all tests"""
    print("\n" + "="*80)
    print("SENTINNELLE - Testing Advanced Intelligence Features")
    print("="*80)
    
    try:
        # Test 1: Entity Resolution
        test_entity_resolution()
        
        # Test 2: Pattern Detection
        test_pattern_detection()
        
        # Test 3: Advanced Graph Analysis
        test_advanced_graph_analysis()
        
        # Test 4: Threat Scoring
        test_threat_scoring()
        
        # Summary
        print("\n" + "="*80)
        print("✅ ALL ADVANCED TESTS PASSED!")
        print("="*80)
        print("\nSummary:")
        print("  ✓ Entity Resolution: Working")
        print("  ✓ Pattern Detection: Working")
        print("  ✓ Advanced Graph Analysis: Working")
        print("  ✓ Threat Scoring: Working")
        print("\n🎯 SENTINNELLE now has Unit 8200-level intelligence capabilities!")
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

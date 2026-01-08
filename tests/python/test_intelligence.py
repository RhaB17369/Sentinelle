"""
Python unit tests for intelligence components
"""

import pytest
from intelligence.confidence import ConfidenceScorer, ConfidenceScore
from intelligence.query_router import QueryRouter, QueryType
from intelligence.graph_model import IntelligenceGraph, Entity, Relationship, EntityType, RelationType
from intelligence.explainability import ExplainabilityEngine, Evidence, InferenceType
from datetime import datetime, timedelta


class TestConfidenceScorer:
    """Test confidence scoring system"""
    
    def test_single_source_score(self):
        scorer = ConfidenceScorer()
        
        # Test high-reliability source
        score = scorer.score_single_source('whois', datetime.now())
        assert 0.9 <= score <= 1.0
        
        # Test lower-reliability source
        score = scorer.score_single_source('web_scrape', datetime.now())
        assert 0.5 <= score <= 0.7
    
    def test_freshness_decay(self):
        scorer = ConfidenceScorer()
        
        # Fresh data
        fresh_score = scorer.score_single_source('dns', datetime.now())
        
        # Old data (30 days ago)
        old_score = scorer.score_single_source('dns', datetime.now() - timedelta(days=30))
        
        assert fresh_score > old_score
    
    def test_multi_source_combination(self):
        scorer = ConfidenceScorer()
        
        sources = [
            ('whois', datetime.now()),
            ('dns', datetime.now()),
            ('ssl_cert', datetime.now()),
        ]
        
        result = scorer.score_multi_source(sources, agreement=1.0)
        
        assert isinstance(result, ConfidenceScore)
        assert 0.0 <= result.score <= 1.0
        assert len(result.justification) > 0
        assert len(result.factors) == 3
    
    def test_agreement_factor(self):
        scorer = ConfidenceScorer()
        
        sources = [('whois', datetime.now()), ('dns', datetime.now())]
        
        # Full agreement
        full_agreement = scorer.score_multi_source(sources, agreement=1.0)
        
        # Partial agreement
        partial_agreement = scorer.score_multi_source(sources, agreement=0.5)
        
        assert full_agreement.score > partial_agreement.score


class TestQueryRouter:
    """Test query routing and classification"""
    
    def test_domain_classification(self):
        router = QueryRouter()
        
        query = router.classify_query("example.com")
        
        assert query.query_type == QueryType.DOMAIN
        assert query.target == "example.com"
    
    def test_ip_classification(self):
        router = QueryRouter()
        
        query = router.classify_query("8.8.8.8")
        
        assert query.query_type == QueryType.IP
        assert query.target == "8.8.8.8"
    
    def test_phone_classification(self):
        router = QueryRouter()
        
        query = router.classify_query("+1234567890")
        
        assert query.query_type == QueryType.PHONE
        assert query.target == "+1234567890"
    
    def test_prohibited_query(self):
        router = QueryRouter()
        
        with pytest.raises(ValueError, match="prohibited"):
            router.classify_query("hack into someone's account")
    
    def test_routing(self):
        router = QueryRouter()
        
        query = router.classify_query("example.com")
        collector = router.route_query(query)
        
        assert collector == "domain_collector"


class TestIntelligenceGraph:
    """Test graph-based intelligence model"""
    
    def test_add_entity(self):
        graph = IntelligenceGraph()
        
        entity = Entity(
            entity_id="example.com",
            entity_type=EntityType.DOMAIN,
            confidence=0.9
        )
        
        graph.add_entity(entity)
        
        retrieved = graph.get_entity("example.com")
        assert retrieved is not None
        assert retrieved.entity_id == "example.com"
        assert retrieved.entity_type == EntityType.DOMAIN
    
    def test_add_relationship(self):
        graph = IntelligenceGraph()
        
        # Add entities
        domain = Entity("example.com", EntityType.DOMAIN)
        ip = Entity("93.184.216.34", EntityType.IP)
        
        graph.add_entity(domain)
        graph.add_entity(ip)
        
        # Add relationship
        rel = Relationship(
            source_id="example.com",
            target_id="93.184.216.34",
            relation_type=RelationType.RESOLVES_TO,
            confidence=0.95
        )
        
        graph.add_relationship(rel)
        
        # Verify relationship
        related = graph.get_related_entities("example.com", RelationType.RESOLVES_TO)
        assert len(related) == 1
        assert related[0].entity_id == "93.184.216.34"
    
    def test_query_by_type(self):
        graph = IntelligenceGraph()
        
        graph.add_entity(Entity("example.com", EntityType.DOMAIN))
        graph.add_entity(Entity("test.com", EntityType.DOMAIN))
        graph.add_entity(Entity("8.8.8.8", EntityType.IP))
        
        domains = graph.query_by_type(EntityType.DOMAIN)
        
        assert len(domains) == 2
        assert all(e.entity_type == EntityType.DOMAIN for e in domains)
    
    def test_statistics(self):
        graph = IntelligenceGraph()
        
        graph.add_entity(Entity("example.com", EntityType.DOMAIN))
        graph.add_entity(Entity("8.8.8.8", EntityType.IP))
        
        stats = graph.get_statistics()
        
        assert stats['num_entities'] == 2
        assert 'entity_types' in stats


class TestExplainabilityEngine:
    """Test explainability framework"""
    
    def test_create_reasoning_path(self):
        engine = ExplainabilityEngine()
        
        path = engine.create_reasoning_path("example.com")
        
        assert path.query == "example.com"
        assert len(path.inferences) == 0
    
    def test_add_direct_observation(self):
        engine = ExplainabilityEngine()
        path = engine.create_reasoning_path("example.com")
        
        inference = engine.add_direct_observation(
            path,
            source="whois",
            data="Registrar: Example Registrar",
            confidence=0.95
        )
        
        assert inference.inference_type == InferenceType.DIRECT_OBSERVATION
        assert len(path.inferences) == 1
        assert inference.confidence == 0.95
    
    def test_generate_explanation(self):
        engine = ExplainabilityEngine()
        path = engine.create_reasoning_path("example.com")
        
        engine.add_direct_observation(
            path,
            source="whois",
            data="Domain age: 30 days",
            confidence=0.9
        )
        
        engine.finalize_path(path, "Domain is recently registered", 0.85)
        
        explanation = engine.generate_explanation(path)
        
        assert "example.com" in explanation
        assert "Domain is recently registered" in explanation
        assert "0.85" in explanation
    
    def test_source_attribution(self):
        engine = ExplainabilityEngine()
        path = engine.create_reasoning_path("example.com")
        
        engine.add_direct_observation(path, "whois", "data1", 0.9)
        engine.add_direct_observation(path, "dns", "data2", 0.9)
        engine.add_direct_observation(path, "whois", "data3", 0.9)
        
        attribution = engine.get_source_attribution(path)
        
        assert attribution['whois'] == 2
        assert attribution['dns'] == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

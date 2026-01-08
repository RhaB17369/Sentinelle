"""
Explainability framework for intelligence reasoning.
Tracks evidence chains and generates human-readable explanations.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class InferenceType(Enum):
    """Types of inferences"""
    DIRECT_OBSERVATION = "direct_observation"
    CORRELATION = "correlation"
    DEDUCTION = "deduction"
    STATISTICAL = "statistical"
    HYPOTHESIS = "hypothesis"


@dataclass
class Evidence:
    """Single piece of evidence"""
    source: str
    data: Any
    timestamp: datetime
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'source': self.source,
            'data': str(self.data),
            'timestamp': self.timestamp.isoformat(),
            'confidence': self.confidence,
            'metadata': self.metadata,
        }


@dataclass
class Inference:
    """Inference or conclusion drawn from evidence"""
    inference_type: InferenceType
    conclusion: str
    evidence: List[Evidence]
    confidence: float
    reasoning: str
    
    def to_dict(self) -> Dict:
        return {
            'type': self.inference_type.value,
            'conclusion': self.conclusion,
            'evidence': [e.to_dict() for e in self.evidence],
            'confidence': self.confidence,
            'reasoning': self.reasoning,
        }


@dataclass
class ReasoningPath:
    """Complete reasoning path from evidence to conclusion"""
    query: str
    conclusion: str
    inferences: List[Inference]
    overall_confidence: float
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            'query': self.query,
            'conclusion': self.conclusion,
            'inferences': [i.to_dict() for i in self.inferences],
            'overall_confidence': self.overall_confidence,
            'timestamp': self.timestamp.isoformat(),
        }


class ExplainabilityEngine:
    """Generate explanations for intelligence conclusions"""
    
    def __init__(self):
        self.reasoning_paths: List[ReasoningPath] = []
    
    def create_reasoning_path(self, query: str) -> ReasoningPath:
        """Create a new reasoning path for a query"""
        path = ReasoningPath(
            query=query,
            conclusion="",
            inferences=[],
            overall_confidence=0.0
        )
        self.reasoning_paths.append(path)
        return path
    
    def add_direct_observation(self,
                              path: ReasoningPath,
                              source: str,
                              data: Any,
                              confidence: float,
                              metadata: Optional[Dict] = None) -> Inference:
        """
        Add direct observation evidence.
        
        Args:
            path: Reasoning path to add to
            source: Data source name
            data: Observed data
            confidence: Confidence in observation
            metadata: Optional metadata
            
        Returns:
            Created inference
        """
        evidence = Evidence(
            source=source,
            data=data,
            timestamp=datetime.now(),
            confidence=confidence,
            metadata=metadata or {}
        )
        
        inference = Inference(
            inference_type=InferenceType.DIRECT_OBSERVATION,
            conclusion=f"Observed: {data}",
            evidence=[evidence],
            confidence=confidence,
            reasoning=f"Direct observation from {source}"
        )
        
        path.inferences.append(inference)
        return inference
    
    def add_correlation(self,
                       path: ReasoningPath,
                       evidence_list: List[Evidence],
                       conclusion: str,
                       confidence: float,
                       reasoning: str) -> Inference:
        """
        Add correlation inference.
        
        Args:
            path: Reasoning path to add to
            evidence_list: List of correlated evidence
            conclusion: Correlation conclusion
            confidence: Confidence in correlation
            reasoning: Explanation of correlation
            
        Returns:
            Created inference
        """
        inference = Inference(
            inference_type=InferenceType.CORRELATION,
            conclusion=conclusion,
            evidence=evidence_list,
            confidence=confidence,
            reasoning=reasoning
        )
        
        path.inferences.append(inference)
        return inference
    
    def add_deduction(self,
                     path: ReasoningPath,
                     premises: List[Evidence],
                     conclusion: str,
                     confidence: float,
                     reasoning: str) -> Inference:
        """
        Add deductive inference.
        
        Args:
            path: Reasoning path to add to
            premises: Premise evidence
            conclusion: Deduced conclusion
            confidence: Confidence in deduction
            reasoning: Logical reasoning
            
        Returns:
            Created inference
        """
        inference = Inference(
            inference_type=InferenceType.DEDUCTION,
            conclusion=conclusion,
            evidence=premises,
            confidence=confidence,
            reasoning=reasoning
        )
        
        path.inferences.append(inference)
        return inference
    
    def finalize_path(self, 
                     path: ReasoningPath, 
                     conclusion: str,
                     overall_confidence: float) -> None:
        """
        Finalize reasoning path with overall conclusion.
        
        Args:
            path: Reasoning path to finalize
            conclusion: Final conclusion
            overall_confidence: Overall confidence score
        """
        path.conclusion = conclusion
        path.overall_confidence = overall_confidence
    
    def generate_explanation(self, path: ReasoningPath) -> str:
        """
        Generate human-readable explanation.
        
        Args:
            path: Reasoning path to explain
            
        Returns:
            Human-readable explanation
        """
        lines = []
        
        lines.append(f"Query: {path.query}")
        lines.append(f"Conclusion: {path.conclusion}")
        lines.append(f"Overall Confidence: {path.overall_confidence:.2f}")
        lines.append("")
        lines.append("Reasoning:")
        lines.append("")
        
        for i, inference in enumerate(path.inferences, 1):
            lines.append(f"{i}. {inference.inference_type.value.replace('_', ' ').title()}")
            lines.append(f"   Conclusion: {inference.conclusion}")
            lines.append(f"   Confidence: {inference.confidence:.2f}")
            lines.append(f"   Reasoning: {inference.reasoning}")
            
            if inference.evidence:
                lines.append(f"   Evidence ({len(inference.evidence)} sources):")
                for j, evidence in enumerate(inference.evidence, 1):
                    lines.append(f"     {j}. Source: {evidence.source}")
                    lines.append(f"        Data: {evidence.data}")
                    lines.append(f"        Confidence: {evidence.confidence:.2f}")
                    lines.append(f"        Timestamp: {evidence.timestamp.isoformat()}")
            
            lines.append("")
        
        return "\n".join(lines)
    
    def generate_evidence_chain(self, path: ReasoningPath) -> List[Dict]:
        """
        Generate evidence chain for programmatic access.
        
        Args:
            path: Reasoning path
            
        Returns:
            List of evidence chain steps
        """
        chain = []
        
        for inference in path.inferences:
            step = {
                'type': inference.inference_type.value,
                'conclusion': inference.conclusion,
                'confidence': inference.confidence,
                'reasoning': inference.reasoning,
                'evidence_count': len(inference.evidence),
                'sources': list(set(e.source for e in inference.evidence)),
            }
            chain.append(step)
        
        return chain
    
    def get_source_attribution(self, path: ReasoningPath) -> Dict[str, int]:
        """
        Get attribution of sources used in reasoning.
        
        Args:
            path: Reasoning path
            
        Returns:
            Dictionary mapping source names to usage count
        """
        attribution = {}
        
        for inference in path.inferences:
            for evidence in inference.evidence:
                attribution[evidence.source] = attribution.get(evidence.source, 0) + 1
        
        return attribution
    
    def identify_conflicts(self, path: ReasoningPath) -> List[str]:
        """
        Identify conflicting evidence in reasoning path.
        
        Args:
            path: Reasoning path
            
        Returns:
            List of conflict descriptions
        """
        conflicts = []
        
        # Group evidence by what it's about (simplified)
        evidence_groups: Dict[str, List[Evidence]] = {}
        
        for inference in path.inferences:
            for evidence in inference.evidence:
                # Use source as grouping key (simplified)
                key = evidence.source
                if key not in evidence_groups:
                    evidence_groups[key] = []
                evidence_groups[key].append(evidence)
        
        # Check for conflicts within groups
        for key, evidence_list in evidence_groups.items():
            if len(evidence_list) > 1:
                # Check if data values differ significantly
                data_values = [str(e.data) for e in evidence_list]
                unique_values = set(data_values)
                
                if len(unique_values) > 1:
                    conflicts.append(
                        f"Conflicting data from {key}: {', '.join(unique_values)}"
                    )
        
        return conflicts

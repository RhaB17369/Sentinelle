"""
Graph-based intelligence modeling using NetworkX.
Represents entities and relationships with temporal attributes.
"""

import networkx as nx
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class EntityType(Enum):
    """Types of entities in the intelligence graph"""
    DOMAIN = "domain"
    IP = "ip"
    PERSON = "person"
    LOCATION = "location"
    PHONE = "phone"
    EMAIL = "email"
    ORGANIZATION = "organization"
    CERTIFICATE = "certificate"


class RelationType(Enum):
    """Types of relationships between entities"""
    RESOLVES_TO = "resolves_to"  # Domain -> IP
    HOSTS = "hosts"  # IP -> Domain
    OWNS = "owns"  # Person/Org -> Domain/IP
    LOCATED_AT = "located_at"  # IP/Person -> Location
    ASSOCIATED_WITH = "associated_with"  # Generic association
    ISSUED_TO = "issued_to"  # Certificate -> Domain
    USES = "uses"  # Person -> Email/Phone


@dataclass
class Entity:
    """Entity node in the intelligence graph"""
    entity_id: str
    entity_type: EntityType
    attributes: Dict[str, Any] = field(default_factory=dict)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    confidence: float = 0.5
    sources: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for graph storage"""
        return {
            'entity_id': self.entity_id,
            'entity_type': self.entity_type.value,
            'attributes': self.attributes,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'confidence': self.confidence,
            'sources': self.sources,
        }


@dataclass
class Relationship:
    """Relationship edge in the intelligence graph"""
    source_id: str
    target_id: str
    relation_type: RelationType
    attributes: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    confidence: float = 0.5
    sources: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for graph storage"""
        return {
            'relation_type': self.relation_type.value,
            'attributes': self.attributes,
            'timestamp': self.timestamp.isoformat(),
            'confidence': self.confidence,
            'sources': self.sources,
        }


class IntelligenceGraph:
    """Graph-based intelligence model"""
    
    def __init__(self):
        self.graph = nx.MultiDiGraph()
        self._entity_index: Dict[str, Entity] = {}
    
    def add_entity(self, entity: Entity) -> None:
        """
        Add or update entity in the graph.
        
        Args:
            entity: Entity to add
        """
        if entity.entity_id in self._entity_index:
            # Update existing entity
            existing = self._entity_index[entity.entity_id]
            existing.last_seen = entity.last_seen
            existing.attributes.update(entity.attributes)
            existing.sources.extend(entity.sources)
            existing.sources = list(set(existing.sources))  # Remove duplicates
            # Update confidence (take max)
            existing.confidence = max(existing.confidence, entity.confidence)
        else:
            # Add new entity
            self._entity_index[entity.entity_id] = entity
        
        # Add/update node in graph
        self.graph.add_node(
            entity.entity_id,
            **self._entity_index[entity.entity_id].to_dict()
        )
    
    def add_relationship(self, relationship: Relationship) -> None:
        """
        Add relationship between entities.
        
        Args:
            relationship: Relationship to add
        """
        # Ensure both entities exist
        if (relationship.source_id not in self._entity_index or 
            relationship.target_id not in self._entity_index):
            raise ValueError("Both source and target entities must exist before adding relationship")
        
        # Add edge to graph
        self.graph.add_edge(
            relationship.source_id,
            relationship.target_id,
            **relationship.to_dict()
        )
    
    def get_entity(self, entity_id: str) -> Optional[Entity]:
        """Get entity by ID"""
        return self._entity_index.get(entity_id)
    
    def get_related_entities(self, 
                            entity_id: str, 
                            relation_type: Optional[RelationType] = None,
                            max_depth: int = 1) -> List[Entity]:
        """
        Get entities related to the given entity.
        
        Args:
            entity_id: Source entity ID
            relation_type: Optional filter by relationship type
            max_depth: Maximum traversal depth (1 = direct neighbors only)
            
        Returns:
            List of related entities
        """
        if entity_id not in self.graph:
            return []
        
        related = []
        
        if max_depth == 1:
            # Direct neighbors only
            for neighbor in self.graph.neighbors(entity_id):
                if relation_type:
                    # Check if any edge matches the relation type
                    edges = self.graph.get_edge_data(entity_id, neighbor)
                    if edges:
                        for edge_data in edges.values():
                            if edge_data.get('relation_type') == relation_type.value:
                                related.append(self._entity_index[neighbor])
                                break
                else:
                    related.append(self._entity_index[neighbor])
        else:
            # BFS traversal up to max_depth
            visited = {entity_id}
            queue = [(entity_id, 0)]
            
            while queue:
                current_id, depth = queue.pop(0)
                
                if depth >= max_depth:
                    continue
                
                for neighbor in self.graph.neighbors(current_id):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        
                        # Check relation type filter
                        if relation_type:
                            edges = self.graph.get_edge_data(current_id, neighbor)
                            if edges:
                                for edge_data in edges.values():
                                    if edge_data.get('relation_type') == relation_type.value:
                                        related.append(self._entity_index[neighbor])
                                        queue.append((neighbor, depth + 1))
                                        break
                        else:
                            related.append(self._entity_index[neighbor])
                            queue.append((neighbor, depth + 1))
        
        return related
    
    def find_paths(self, 
                   source_id: str, 
                   target_id: str, 
                   max_length: int = 5) -> List[List[str]]:
        """
        Find paths between two entities.
        
        Args:
            source_id: Source entity ID
            target_id: Target entity ID
            max_length: Maximum path length
            
        Returns:
            List of paths (each path is a list of entity IDs)
        """
        if source_id not in self.graph or target_id not in self.graph:
            return []
        
        try:
            # Find all simple paths up to max_length
            paths = list(nx.all_simple_paths(
                self.graph, 
                source_id, 
                target_id, 
                cutoff=max_length
            ))
            return paths
        except nx.NetworkXNoPath:
            return []
    
    # Advanced Graph Analysis Methods (Unit 8200-level)
    
    def detect_communities(self) -> Dict[str, int]:
        """
        Detect communities using Louvain algorithm.
        
        Returns:
            Dictionary mapping node_id to community_id
        """
        try:
            import networkx.algorithms.community as nx_comm
            
            # Convert to undirected for community detection
            undirected = self.graph.to_undirected()
            
            # Louvain community detection
            communities = nx_comm.louvain_communities(undirected)
            
            # Map nodes to community IDs
            node_to_community = {}
            for comm_id, community in enumerate(communities):
                for node in community:
                    node_to_community[node] = comm_id
            
            return node_to_community
            
        except Exception as e:
            # Assuming self.logger exists, otherwise remove or replace
            # self.logger.error(f"Community detection failed: {e}")
            print(f"Community detection failed: {e}") # Placeholder for logging
            return {}
    
    def calculate_centrality(self) -> Dict[str, Dict[str, float]]:
        """
        Calculate various centrality metrics.
        
        Returns:
            Dictionary with centrality scores for each node
        """
        import networkx as nx
        
        centrality = {
            'degree': {},
            'betweenness': {},
            'closeness': {},
            'pagerank': {},
        }
        
        try:
            # Degree centrality
            centrality['degree'] = nx.degree_centrality(self.graph)
            
            # Betweenness centrality (critical nodes)
            centrality['betweenness'] = nx.betweenness_centrality(self.graph)
            
            # Closeness centrality
            # Check if graph is strongly connected for closeness centrality on directed graphs
            # For general graphs, it's often calculated on the weakly connected components or undirected version
            if nx.is_strongly_connected(self.graph):
                centrality['closeness'] = nx.closeness_centrality(self.graph)
            else:
                # Fallback for disconnected graphs or use undirected version
                undirected_graph = self.graph.to_undirected()
                if nx.is_connected(undirected_graph):
                    centrality['closeness'] = nx.closeness_centrality(undirected_graph)
                else:
                    # Handle disconnected components for closeness
                    closeness_scores = {}
                    for component in nx.connected_components(undirected_graph):
                        subgraph = undirected_graph.subgraph(component)
                        if len(subgraph) > 1: # Closeness is undefined for single nodes
                            closeness_scores.update(nx.closeness_centrality(subgraph))
                    centrality['closeness'] = closeness_scores
            
            # PageRank (influence)
            centrality['pagerank'] = nx.pagerank(self.graph)
            
        except Exception as e:
            # Assuming self.logger exists, otherwise remove or replace
            # self.logger.error(f"Centrality calculation failed: {e}")
            print(f"Centrality calculation failed: {e}") # Placeholder for logging
        
        return centrality
    
    def find_critical_nodes(self, top_n: int = 10) -> List[Tuple[str, float]]:
        """
        Find most critical nodes using betweenness centrality.
        
        Args:
            top_n: Number of top nodes to return
            
        Returns:
            List of (node_id, betweenness_score) tuples
        """
        import networkx as nx
        
        betweenness = nx.betweenness_centrality(self.graph)
        
        # Sort by betweenness (descending)
        sorted_nodes = sorted(
            betweenness.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return sorted_nodes[:top_n]
    
    def extract_ego_network(self, node_id: str, radius: int = 2) -> 'IntelligenceGraph':
        """
        Extract ego network (neighborhood) of a node.
        
        Args:
            node_id: Central node
            radius: Radius of ego network
            
        Returns:
            New IntelligenceGraph with ego network
        """
        import networkx as nx
        
        ego = nx.ego_graph(self.graph, node_id, radius=radius)
        
        # Create new graph
        ego_graph = IntelligenceGraph()
        ego_graph.graph = ego
        
        # Populate _entity_index for the new ego_graph
        for node in ego.nodes():
            if node in self._entity_index:
                ego_graph._entity_index[node] = self._entity_index[node]
        
        return ego_graph
    
    def detect_cliques(self, min_size: int = 3) -> List[List[str]]:
        """
        Detect cliques (fully connected subgraphs).
        
        Args:
            min_size: Minimum clique size
            
        Returns:
            List of cliques (each clique is a list of node IDs)
        """
        import networkx as nx
        
        # Convert to undirected
        undirected = self.graph.to_undirected()
        
        # Find cliques
        cliques = list(nx.find_cliques(undirected))
        
        # Filter by size
        return [c for c in cliques if len(c) >= min_size]
    
    def analyze_temporal_evolution(
        self,
        start_time: datetime,
        end_time: datetime,
        time_windows: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Analyze how graph evolves over time.
        
        Args:
            start_time: Start of analysis period
            end_time: End of analysis period
            time_windows: Number of time windows
            
        Returns:
            List of graph metrics for each time window
        """
        import networkx as nx
        from datetime import timedelta
        
        window_size = (end_time - start_time) / time_windows
        evolution = []
        
        for i in range(time_windows):
            window_start = start_time + (window_size * i)
            window_end = window_start + window_size
            
            # Filter edges by timestamp
            edges_in_window = [
                (u, v, data)
                for u, v, data in self.graph.edges(data=True)
                if 'timestamp' in data and
                isinstance(data['timestamp'], datetime) and # Ensure timestamp is datetime object
                window_start <= data['timestamp'] <= window_end
            ]
            
            # Create subgraph for this window
            window_graph = nx.DiGraph()
            window_graph.add_edges_from(edges_in_window)
            
            # Calculate metrics
            metrics = {
                'window_start': window_start.isoformat(),
                'window_end': window_end.isoformat(),
                'num_nodes': window_graph.number_of_nodes(),
                'num_edges': window_graph.number_of_edges(),
                'density': nx.density(window_graph) if window_graph.number_of_nodes() > 0 else 0,
            }
            
            evolution.append(metrics)
        
        return evolution
    
    def export_graphml(self, filepath: str):
        """
        Export graph to GraphML format for Gephi.
        
        Args:
            filepath: Output file path
        """
        import networkx as nx
        
        nx.write_graphml(self.graph, filepath)
        # Assuming self.logger exists, otherwise remove or replace
        # self.logger.info(f"Graph exported to {filepath}")
        print(f"Graph exported to {filepath}") # Placeholder for logging
    
    def export_json_for_d3(self, filepath: str):
        """
        Export graph to JSON format for D3.js visualization.
        
        Args:
            filepath: Output file path
        """
        import json
        import networkx as nx
        
        data = nx.node_link_data(self.graph)
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        # Assuming self.logger exists, otherwise remove or replace
        # self.logger.info(f"Graph exported to {filepath}")
        print(f"Graph exported to {filepath}") # Placeholder for logging
    
    def get_graph_metrics(self) -> Dict[str, Any]:
        """
        Get comprehensive graph metrics.
        
        Returns:
            Dictionary of graph metrics
        """
        import networkx as nx
        
        metrics = {
            'num_nodes': self.graph.number_of_nodes(),
            'num_edges': self.graph.number_of_edges(),
            'density': nx.density(self.graph),
            'is_connected': nx.is_weakly_connected(self.graph),
        }
        
        # Average clustering coefficient
        try:
            metrics['avg_clustering'] = nx.average_clustering(
                self.graph.to_undirected()
            )
        except Exception: # Catching generic exception for robustness
            metrics['avg_clustering'] = 0.0
        
        # Diameter (if connected)
        if nx.is_weakly_connected(self.graph):
            try:
                metrics['diameter'] = nx.diameter(self.graph.to_undirected())
            except Exception: # Catching generic exception for robustness
                metrics['diameter'] = None
        
        return metrics
    
    def get_entity_neighborhood(self, 
                               entity_id: str, 
                               radius: int = 1) -> nx.DiGraph:
        """
        Get subgraph of entity neighborhood.
        
        Args:
            entity_id: Center entity ID
            radius: Neighborhood radius
            
        Returns:
            Subgraph containing entity and neighbors
        """
        if entity_id not in self.graph:
            return nx.DiGraph()
        
        # Get all nodes within radius
        nodes = {entity_id}
        current_layer = {entity_id}
        
        for _ in range(radius):
            next_layer = set()
            for node in current_layer:
                next_layer.update(self.graph.neighbors(node))
                next_layer.update(self.graph.predecessors(node))
            nodes.update(next_layer)
            current_layer = next_layer
        
        # Create subgraph
        return self.graph.subgraph(nodes).copy()
    
    def query_by_type(self, entity_type: EntityType) -> List[Entity]:
        """Get all entities of a specific type"""
        return [
            entity for entity in self._entity_index.values()
            if entity.entity_type == entity_type
        ]
    
    def query_by_attribute(self, 
                          attribute_name: str, 
                          attribute_value: Any) -> List[Entity]:
        """Query entities by attribute value"""
        return [
            entity for entity in self._entity_index.values()
            if entity.attributes.get(attribute_name) == attribute_value
        ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get graph statistics"""
        return {
            'num_entities': len(self._entity_index),
            'num_relationships': self.graph.number_of_edges(),
            'entity_types': {
                entity_type.value: len(self.query_by_type(entity_type))
                for entity_type in EntityType
            },
            'avg_degree': sum(dict(self.graph.degree()).values()) / max(len(self._entity_index), 1),
            'connected_components': nx.number_weakly_connected_components(self.graph),
        }
    
    def export_to_dict(self) -> Dict:
        """Export graph to dictionary format"""
        return {
            'entities': [entity.to_dict() for entity in self._entity_index.values()],
            'relationships': [
                {
                    'source': u,
                    'target': v,
                    **data
                }
                for u, v, data in self.graph.edges(data=True)
            ]
        }

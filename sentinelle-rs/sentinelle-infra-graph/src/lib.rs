#![deny(warnings)]

use sentinelle_domain::{IntelligenceGraph, Entity, Relationship, EntityId};
use serde::Serialize;

/// Représentation sérialisable du graphe pour export JSON / D3.
/// Les adapters d'interface peuvent ensuite écrire ça vers des fichiers,
/// des APIs, etc., sans que le domaine ne connaisse les formats concrets.
#[derive(Debug, Serialize)]
pub struct SerializableGraph {
    pub entities: Vec<SerializableEntity>,
    pub relationships: Vec<SerializableRelationship>,
}

#[derive(Debug, Serialize)]
pub struct SerializableEntity {
    pub id: EntityId,
    pub kind: String,
}

#[derive(Debug, Serialize)]
pub struct SerializableRelationship {
    pub source: EntityId,
    pub target: EntityId,
    pub kind: String,
}

/// Convertit un IntelligenceGraph du domaine en structure sérialisable.
/// On ne touche pas au système de fichiers ici : hexagonal respecté.
pub fn to_serializable(graph: &IntelligenceGraph) -> SerializableGraph {
    let entities = graph
        .iter_entities()
        .map(|e: &Entity| SerializableEntity {
            id: e.id().clone(),
            kind: format!("{:?}", e.kind()),
        })
        .collect();

    let relationships = graph
        .iter_relationships()
        .map(|r: &Relationship| SerializableRelationship {
            source: r.source.clone(),
            target: r.target.clone(),
            kind: format!("{:?}", r.kind),
        })
        .collect();

    SerializableGraph {
        entities,
        relationships,
    }
}
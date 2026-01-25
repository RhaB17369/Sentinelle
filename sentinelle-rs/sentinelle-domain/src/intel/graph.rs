use super::entity::{Entity, EntityId};
use super::relationship::{Relationship, RelationType};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, thiserror::Error)]
pub enum GraphError {
    #[error("entity {0} not found")]
    EntityNotFound(EntityId),
}

#[derive(Debug, Default)]
pub struct IntelligenceGraph {
    entities: HashMap<EntityId, Entity>,
    relationships: Vec<Relationship>,
    outgoing: HashMap<EntityId, Vec<usize>>,
    incoming: HashMap<EntityId, Vec<usize>>,
}

impl IntelligenceGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_or_merge_entity(&mut self, entity: Entity) {
        let id = entity.id().clone();
        if let Some(existing) = self.entities.get(&id).cloned() {
            let merged = existing.with_updated(
                entity.attributes().clone(),
                entity.last_seen(),
                entity.confidence(),
                entity.sources().to_vec(),
            );
            self.entities.insert(id, merged);
        } else {
            self.entities.insert(id, entity);
        }
    }

    pub fn add_relationship(&mut self, rel: Relationship) -> Result<(), GraphError> {
        if !self.entities.contains_key(&rel.source) {
            return Err(GraphError::EntityNotFound(rel.source.clone()));
        }
        if !self.entities.contains_key(&rel.target) {
            return Err(GraphError::EntityNotFound(rel.target.clone()));
        }

        let idx = self.relationships.len();
        self.relationships.push(rel);

        self.outgoing
            .entry(self.relationships[idx].source.clone())
            .or_default()
            .push(idx);
        self.incoming
            .entry(self.relationships[idx].target.clone())
            .or_default()
            .push(idx);

        Ok(())
    }

    pub fn get_entity(&self, id: &EntityId) -> Option<&Entity> {
        self.entities.get(id)
    }

    /// Itérateur en lecture seule sur les entités, utilisé par les adapters (graph export, etc.).
    pub fn iter_entities(&self) -> impl Iterator<Item = &Entity> {
        self.entities.values()
    }

    /// Itérateur en lecture seule sur les relations, utilisé par les adapters.
    pub fn iter_relationships(&self) -> impl Iterator<Item = &Relationship> {
        self.relationships.iter()
    }

    pub fn related_entities(
        &self,
        start: &EntityId,
        relation_type: Option<RelationType>,
        max_depth: usize,
    ) -> Vec<&Entity> {
        if !self.entities.contains_key(start) || max_depth == 0 {
            return Vec::new();
        }

        let mut visited: HashSet<EntityId> = HashSet::new();
        visited.insert(start.clone());

        let mut queue: VecDeque<(EntityId, usize)> = VecDeque::new();
        queue.push_back((start.clone(), 0usize));

        let mut result = Vec::new();

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            if let Some(edges) = self.outgoing.get(&current) {
                for &idx in edges {
                    let rel = &self.relationships[idx];
                    if let Some(rt) = relation_type {
                        if rel.kind != rt {
                            continue;
                        }
                    }

                    let target = &rel.target;
                    if !visited.insert(target.clone()) {
                        continue;
                    }

                    if let Some(ent) = self.entities.get(target) {
                        result.push(ent);
                    }
                    queue.push_back((target.clone(), depth + 1));
                }
            }
        }

        result
    }
}
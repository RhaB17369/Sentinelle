#![deny(warnings)]

use std::time::SystemTime;

#[derive(Debug, Clone)]
pub enum TargetType {
    Email,
    Ip,
    Username,
    Domain,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub kind: TargetType,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct TargetState {
    pub last_seen: SystemTime,
    pub status: String,
}

#[derive(Debug, Clone)]
pub enum MonitoringEvent {
    ChangeDetected {
        target: Target,
        old: TargetState,
        new: TargetState,
    },
}

pub fn detect_change(old: &TargetState, new: &TargetState, target: Target) -> Option<MonitoringEvent> {
    if old.status != new.status {
        Some(MonitoringEvent::ChangeDetected {
            target,
            old: old.clone(),
            new: new.clone(),
        })
    } else {
        None
    }
}
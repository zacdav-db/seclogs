use crate::core::event::Event;
use crate::core::traits::EventSource;
use chrono::{DateTime, Utc};

/// Event source that merges multiple child sources by envelope timestamp.
pub struct CompositeEventSource {
    sources: Vec<SourceSlot>,
}

struct SourceSlot {
    source: Box<dyn EventSource>,
    next: Option<Event>,
}

impl CompositeEventSource {
    pub fn new(sources: Vec<Box<dyn EventSource>>) -> Self {
        let slots = sources
            .into_iter()
            .map(|mut source| {
                let next = source.next_event();
                SourceSlot { source, next }
            })
            .collect();
        Self { sources: slots }
    }
}

impl EventSource for CompositeEventSource {
    fn next_event(&mut self) -> Option<Event> {
        let idx = self
            .sources
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.next.is_some())
            .min_by(|(_, left), (_, right)| compare_events(left.next.as_ref(), right.next.as_ref()))
            .map(|(idx, _)| idx)?;

        let slot = &mut self.sources[idx];
        let event = slot.next.take();
        slot.next = slot.source.next_event();
        event
    }
}

fn compare_events(left: Option<&Event>, right: Option<&Event>) -> std::cmp::Ordering {
    let left = left.expect("left event exists");
    let right = right.expect("right event exists");
    match (
        parse_timestamp(&left.envelope.timestamp),
        parse_timestamp(&right.envelope.timestamp),
    ) {
        (Some(left), Some(right)) => left.cmp(&right),
        _ => left.envelope.timestamp.cmp(&right.envelope.timestamp),
    }
}

fn parse_timestamp(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{Actor, EventEnvelope, Outcome};
    use serde_json::Value;
    use std::collections::VecDeque;

    struct QueueSource {
        events: VecDeque<Event>,
    }

    impl QueueSource {
        fn new(events: Vec<Event>) -> Self {
            Self {
                events: events.into(),
            }
        }
    }

    impl EventSource for QueueSource {
        fn next_event(&mut self) -> Option<Event> {
            self.events.pop_front()
        }
    }

    #[test]
    fn composite_merges_sources_by_timestamp_without_rewriting_source() {
        let mut source = CompositeEventSource::new(vec![
            Box::new(QueueSource::new(vec![event(
                "databricks_audit",
                "2026-01-01T00:00:20Z",
            )])),
            Box::new(QueueSource::new(vec![event(
                "cloudtrail",
                "2026-01-01T00:00:10Z",
            )])),
            Box::new(QueueSource::new(vec![event(
                "okta_system_log",
                "2026-01-01T00:00:15Z",
            )])),
        ]);

        let sources = vec![
            source.next_event().unwrap().envelope.source,
            source.next_event().unwrap().envelope.source,
            source.next_event().unwrap().envelope.source,
        ];

        assert_eq!(
            sources,
            vec!["cloudtrail", "okta_system_log", "databricks_audit"]
        );
        assert!(source.next_event().is_none());
    }

    fn event(source: &str, timestamp: &str) -> Event {
        Event {
            envelope: EventEnvelope {
                schema_version: "v1".to_string(),
                timestamp: timestamp.to_string(),
                source: source.to_string(),
                event_type: "test.event".to_string(),
                actor: Actor {
                    id: "actor-1".to_string(),
                    kind: "human".to_string(),
                    name: None,
                },
                target: None,
                outcome: Outcome::Success,
                geo: None,
                ip: None,
                user_agent: None,
                session_id: None,
                tenant_id: None,
            },
            payload: Value::Null,
        }
    }
}

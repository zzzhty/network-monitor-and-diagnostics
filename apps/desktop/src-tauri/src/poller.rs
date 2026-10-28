//! Read-only polling of the dashboard API for tray state and auto-switch
//! notifications. The shell never writes through these endpoints.

use serde_json::Value;

/// Events the operator opted into being told about, nothing noisier.
pub const NOTIFY_KINDS: [&str; 5] = [
    "auto_switch",
    "auto_suspended",
    "auto_resumed",
    "auto_switch_failed",
    "all_unhealthy",
];

const KIND_LABELS: [(&str, &str); 5] = [
    ("auto_switch", "自动切换出口"),
    ("auto_suspended", "自动切换已挂起"),
    ("auto_resumed", "自动切换已恢复"),
    ("auto_switch_failed", "自动切换失败"),
    ("all_unhealthy", "候选出口全部不健康"),
];

fn label(kind: &str) -> &'static str {
    KIND_LABELS
        .iter()
        .find(|(name, _)| *name == kind)
        .map(|(_, text)| *text)
        .unwrap_or("出口事件")
}

/// In-memory notification dedup. The first absorb adopts the current maximum
/// event id silently: events older than the shell must never replay.
pub struct Notifier {
    last_event_id: Option<i64>,
    started_at: f64,
}

impl Notifier {
    pub fn new(started_at: f64) -> Self {
        Self {
            last_event_id: None,
            started_at,
        }
    }

    pub fn absorb(&mut self, snapshot: &Value) -> Vec<String> {
        let Some(events) = snapshot.get("auto_events").and_then(Value::as_array) else {
            return Vec::new();
        };
        let max_id = events
            .iter()
            .filter_map(|event| event.get("id").and_then(Value::as_i64))
            .max();
        let max_id = max_id.unwrap_or(0);
        let Some(previous) = self.last_event_id else {
            self.last_event_id = Some(max_id);
            return Vec::new();
        };
        let mut messages = Vec::new();
        let mut newest = previous;
        for event in events {
            let Some(id) = event.get("id").and_then(Value::as_i64) else {
                continue;
            };
            if id <= previous {
                continue;
            }
            newest = newest.max(id);
            let kind = event.get("kind").and_then(Value::as_str).unwrap_or("");
            let timestamp = event.get("ts").and_then(Value::as_f64).unwrap_or(0.0);
            if !NOTIFY_KINDS.contains(&kind) || timestamp < self.started_at {
                continue;
            }
            messages.push(label(kind).to_string());
        }
        self.last_event_id = Some(newest.max(previous));
        messages
    }
}

/// Tray tooltip text: the active egress display name, falling back to the id.
pub fn egress_label(sources: &Value) -> Option<String> {
    let active = sources.get("active")?.as_str()?;
    if active.is_empty() {
        return None;
    }
    let nodes = sources.get("nodes").and_then(Value::as_array)?;
    let display = nodes
        .iter()
        .find(|node| node.get("id").and_then(Value::as_str) == Some(active))
        .and_then(|node| node.get("display").and_then(Value::as_str))
        .filter(|display| !display.is_empty());
    Some(display.unwrap_or(active).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snapshot(events: Value) -> Value {
        json!({ "auto_events": events })
    }

    #[test]
    fn first_absorb_is_always_silent() {
        let mut notifier = Notifier::new(100.0);
        let messages = notifier.absorb(&snapshot(json!([
            {"id": 7, "ts": 101.0, "kind": "auto_switch"}
        ])));
        assert!(messages.is_empty());
        // The same event is never repeated on later polls.
        assert!(notifier
            .absorb(&snapshot(json!([
                {"id": 7, "ts": 101.0, "kind": "auto_switch"}
            ])))
            .is_empty());
    }

    #[test]
    fn qualifying_new_events_notify_once() {
        let mut notifier = Notifier::new(100.0);
        notifier.absorb(&snapshot(
            json!([{ "id": 1, "ts": 101.0, "kind": "auto_engaged" }]),
        ));
        let messages = notifier.absorb(&snapshot(json!([
            { "id": 1, "ts": 101.0, "kind": "auto_engaged" },
            { "id": 2, "ts": 105.0, "kind": "auto_switch" },
            { "id": 3, "ts": 106.0, "kind": "auto_suspended" },
            { "id": 4, "ts": 107.0, "kind": "all_unhealthy" }
        ])));
        assert_eq!(
            messages,
            vec!["自动切换出口", "自动切换已挂起", "候选出口全部不健康"]
        );
        assert!(notifier
            .absorb(&snapshot(
                json!([{ "id": 2, "ts": 105.0, "kind": "auto_switch" }])
            ))
            .is_empty());
    }

    #[test]
    fn quiet_kinds_advance_the_cursor_without_notifying() {
        let mut notifier = Notifier::new(100.0);
        notifier.absorb(&snapshot(
            json!([{ "id": 1, "ts": 101.0, "kind": "auto_engaged" }]),
        ));
        let messages = notifier.absorb(&snapshot(json!([
            { "id": 2, "ts": 105.0, "kind": "candidate_changed" }
        ])));
        assert!(messages.is_empty());
        // The cursor moved past id 2: a later poll must not resurrect it.
        assert!(notifier
            .absorb(&snapshot(
                json!([{ "id": 2, "ts": 105.0, "kind": "auto_switch" }])
            ))
            .is_empty());
    }

    #[test]
    fn events_older_than_the_shell_are_never_notified() {
        let mut notifier = Notifier::new(200.0);
        notifier.absorb(&snapshot(
            json!([{ "id": 1, "ts": 150.0, "kind": "auto_switch" }]),
        ));
        let messages = notifier.absorb(&snapshot(json!([
            { "id": 2, "ts": 199.0, "kind": "auto_switch" },
            { "id": 3, "ts": 201.0, "kind": "auto_switch" }
        ])));
        assert_eq!(messages, vec!["自动切换出口"]);
    }

    #[test]
    fn first_successful_empty_list_starts_the_cursor() {
        let mut notifier = Notifier::new(100.0);
        assert!(notifier.absorb(&json!({})).is_empty());
        assert!(notifier.absorb(&snapshot(json!([]))).is_empty());
        let messages = notifier.absorb(&snapshot(json!([
            { "id": 4, "ts": 101.0, "kind": "auto_switch" }
        ])));
        assert_eq!(messages, vec!["自动切换出口"]);
        assert!(notifier.absorb(&snapshot(json!([]))).is_empty());
        assert!(notifier
            .absorb(&snapshot(json!([
                { "id": 4, "ts": 101.0, "kind": "auto_switch" }
            ])))
            .is_empty());
    }

    #[test]
    fn missing_snapshot_does_not_initialize_the_cursor() {
        let mut notifier = Notifier::new(100.0);
        notifier.absorb(&json!({}));
        assert!(notifier
            .absorb(&snapshot(json!([
                { "id": 7, "ts": 101.0, "kind": "auto_switch" }
            ])))
            .is_empty());
    }

    #[test]
    fn egress_label_prefers_display_and_falls_back_to_id() {
        let sources = json!({
            "active": "nmd-oness-6c53488717057a6635a8",
            "nodes": [
                { "id": "nmd-oness-6c53488717057a6635a8", "source": "oness", "display": "Lv2.[AnyTLS] 日本-2" },
                { "id": "nmd-vps-313f0b3017ea1919e536", "source": "vps" }
            ]
        });
        assert_eq!(
            egress_label(&sources).as_deref(),
            Some("Lv2.[AnyTLS] 日本-2")
        );
        let legacy = json!({
            "active": "nmd-vps-313f0b3017ea1919e536",
            "nodes": [{ "id": "nmd-vps-313f0b3017ea1919e536", "source": "vps" }]
        });
        assert_eq!(
            egress_label(&legacy).as_deref(),
            Some("nmd-vps-313f0b3017ea1919e536")
        );
        assert_eq!(egress_label(&json!({ "active": null })), None);
    }
}

use adamo_authorization::{
    Direction, AuthorizationPolicy, Ingress, Operation, metrics_snapshot,
};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
struct Row {
    name: String,
    subject: Option<String>,
    organization: Option<String>,
    operation: String,
    ingress: String,
    direction: Option<String>,
    key: String,
    allow: bool,
    reason: String,
}

fn rows() -> Vec<Row> {
    serde_json::from_str(include_str!("policy_decision_table.json")).unwrap()
}

#[test]
fn auth_unit_01_policy_decision_table() {
    let mut coverage: HashMap<String, (bool, bool)> = HashMap::new();
    for row in rows() {
        let operation = Operation::parse(&row.operation);
        let ingress = match row.ingress.as_str() {
            "wt" => Ingress::WebTransport,
            "remote_api" => Ingress::RemoteApi,
            "native" => Ingress::Native,
            other => panic!("{}: unknown fixture ingress {other}", row.name),
        };
        let direction = match row.direction.as_deref().unwrap_or("ingress") {
            "ingress" => Direction::Ingress,
            "egress" => Direction::Egress,
            other => panic!("{}: unknown fixture direction {other}", row.name),
        };
        let policy = AuthorizationPolicy::new(row.subject.as_deref(), row.organization.as_deref());
        let decision = policy.decide_with_direction(operation, &row.key, ingress, direction);
        assert_eq!(decision.allowed(), row.allow, "{}: effect", row.name);
        assert_eq!(decision.reason.code(), row.reason, "{}: reason", row.name);

        if operation != Operation::Unknown {
            let entry = coverage.entry(row.operation.clone()).or_default();
            if row.allow {
                entry.0 = true;
            } else {
                entry.1 = true;
            }
        }
    }

    for operation in [
        "put",
        "delete",
        "subscribe",
        "get",
        "reply",
        "declare_queryable",
        "liveliness_get",
        "liveliness_subscribe",
        "liveliness_declare",
    ] {
        assert_eq!(
            coverage.get(operation),
            Some(&(true, true)),
            "{operation} must have allowed and denied rows"
        );
    }
}

#[test]
fn decision_metrics_have_fixed_reason_cardinality() {
    let before = metrics_snapshot();
    let policy = AuthorizationPolicy::new(Some("metric-user"), Some("acme"));
    let decision = policy.decide(Operation::Get, "adamo/other/robot", Ingress::RemoteApi);
    let after = metrics_snapshot();

    assert_eq!(before.len(), after.len());
    let index = decision.reason as usize;
    assert_eq!(after[index].1, before[index].1 + 1);
}

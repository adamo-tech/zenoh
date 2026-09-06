//! Shared authorization policy for every authenticated Adamo transport.
//!
//! This crate is intentionally the only place that decides whether a tenant
//! may use a Zenoh key expression. Transport adapters pass an operation and
//! ingress and translate the resulting stable reason code into their own wire
//! error. Policy metrics use a fixed set of counters, so neither attacker
//! supplied keys nor identities become metric labels.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use zenoh_keyexpr::{keyexpr, OwnedKeyExpr};

pub const FIXED_SERVICE_IDENTITIES: [&str; 3] =
    ["adamo-api", "adamo-router", "telemetry-collector"];

pub fn is_reserved_identity(value: &str) -> bool {
    FIXED_SERVICE_IDENTITIES.contains(&value) || value.starts_with("adamo-router-")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Put,
    Delete,
    Subscribe,
    Get,
    Reply,
    DeclareQueryable,
    LivelinessGet,
    LivelinessSubscribe,
    LivelinessDeclare,
    /// A forward-compatible catch-all. Unknown wire operations always deny.
    Unknown,
}

impl Operation {
    pub fn parse(value: &str) -> Self {
        match value {
            "put" => Self::Put,
            "delete" => Self::Delete,
            "subscribe" => Self::Subscribe,
            "get" => Self::Get,
            "reply" => Self::Reply,
            "declare_queryable" => Self::DeclareQueryable,
            "liveliness_get" => Self::LivelinessGet,
            "liveliness_subscribe" => Self::LivelinessSubscribe,
            "liveliness_declare" => Self::LivelinessDeclare,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ingress {
    WebTransport,
    RemoteApi,
    Native,
}

/// Direction relative to the router or transport adapter. Browser adapters
/// authorize client requests and therefore use [`Direction::Ingress`]. Native
/// Zenoh must also filter samples and replies leaving the router.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Ingress,
    Egress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Reason {
    AllowTenantScope = 0,
    AllowTimePingPut = 1,
    AllowTimePingInterest = 2,
    AllowTimePongSubscribe = 3,
    AllowRemoteEchoGet = 4,
    AllowTimeResponseReceive = 5,
    DenyMissingSubject = 6,
    DenyMissingOrganization = 7,
    DenyInvalidOrganization = 8,
    DenyInvalidKeyExpression = 9,
    DenyUnknownOperation = 10,
    DenyUnapprovedSystemKey = 11,
    DenyOutsideOrganization = 12,
}

impl Reason {
    pub const ALL: [Self; 13] = [
        Self::AllowTenantScope,
        Self::AllowTimePingPut,
        Self::AllowTimePingInterest,
        Self::AllowTimePongSubscribe,
        Self::AllowRemoteEchoGet,
        Self::AllowTimeResponseReceive,
        Self::DenyMissingSubject,
        Self::DenyMissingOrganization,
        Self::DenyInvalidOrganization,
        Self::DenyInvalidKeyExpression,
        Self::DenyUnknownOperation,
        Self::DenyUnapprovedSystemKey,
        Self::DenyOutsideOrganization,
    ];

    pub const fn code(self) -> &'static str {
        match self {
            Self::AllowTenantScope => "allow.tenant_scope",
            Self::AllowTimePingPut => "allow.system.time_ping_put",
            Self::AllowTimePingInterest => "allow.system.time_ping_interest",
            Self::AllowTimePongSubscribe => "allow.system.time_pong_subscribe",
            Self::AllowRemoteEchoGet => "allow.system.remote_echo_get",
            Self::AllowTimeResponseReceive => "allow.system.time_response_receive",
            Self::DenyMissingSubject => "deny.missing_subject",
            Self::DenyMissingOrganization => "deny.missing_organization",
            Self::DenyInvalidOrganization => "deny.invalid_organization",
            Self::DenyInvalidKeyExpression => "deny.invalid_key_expression",
            Self::DenyUnknownOperation => "deny.unknown_operation",
            Self::DenyUnapprovedSystemKey => "deny.unapproved_system_key",
            Self::DenyOutsideOrganization => "deny.outside_organization",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision {
    pub effect: Effect,
    pub reason: Reason,
}

impl Decision {
    pub const fn allowed(self) -> bool {
        matches!(self.effect, Effect::Allow)
    }
}

#[derive(Clone)]
enum Identity {
    Valid {
        #[allow(dead_code)]
        subject: String,
        tenant_scope: OwnedKeyExpr,
    },
    Invalid(Reason),
}

/// A compiled per-session policy. Construction accepts optional identity
/// fields so fail-closed adapters do not need a separate unauthenticated path.
#[derive(Clone)]
pub struct AuthorizationPolicy {
    identity: Identity,
}

impl AuthorizationPolicy {
    pub fn new(subject: Option<&str>, organization: Option<&str>) -> Self {
        let identity = match subject {
            None | Some("") => Identity::Invalid(Reason::DenyMissingSubject),
            Some(subject) => match organization {
                None | Some("") => Identity::Invalid(Reason::DenyMissingOrganization),
                Some(organization) if !valid_organization(organization) => {
                    Identity::Invalid(Reason::DenyInvalidOrganization)
                }
                Some(organization) if is_reserved_identity(organization) => {
                    Identity::Invalid(Reason::DenyInvalidOrganization)
                }
                Some(organization) => {
                    let scope = format!("adamo/{organization}/**");
                    match OwnedKeyExpr::new(scope) {
                        Ok(tenant_scope) => Identity::Valid {
                            subject: subject.to_owned(),
                            tenant_scope,
                        },
                        Err(_) => Identity::Invalid(Reason::DenyInvalidOrganization),
                    }
                }
            },
        };
        Self { identity }
    }

    pub fn decide(&self, operation: Operation, requested_key: &str, ingress: Ingress) -> Decision {
        self.decide_with_direction(operation, requested_key, ingress, Direction::Ingress)
    }

    pub fn decide_with_direction(
        &self,
        operation: Operation,
        requested_key: &str,
        ingress: Ingress,
        direction: Direction,
    ) -> Decision {
        let requested = match OwnedKeyExpr::new(requested_key) {
            Ok(requested) => requested,
            Err(_) => return record(Effect::Deny, Reason::DenyInvalidKeyExpression),
        };

        if operation == Operation::Unknown {
            return record(Effect::Deny, Reason::DenyUnknownOperation);
        }

        let tenant_scope = match &self.identity {
            Identity::Valid { tenant_scope, .. } => tenant_scope,
            Identity::Invalid(reason) => return record(Effect::Deny, *reason),
        };

        if let Some(reason) = allowed_system_operation(operation, &requested, ingress, direction) {
            return record(Effect::Allow, reason);
        }

        let requested_ref: &keyexpr = &requested;
        if is_system_key(requested.as_str()) {
            return record(Effect::Deny, Reason::DenyUnapprovedSystemKey);
        }

        let tenant_ref: &keyexpr = tenant_scope;
        if tenant_ref.includes(requested_ref) {
            record(Effect::Allow, Reason::AllowTenantScope)
        } else {
            record(Effect::Deny, Reason::DenyOutsideOrganization)
        }
    }
}

pub fn valid_organization(organization: &str) -> bool {
    !organization.is_empty()
        && organization.len() <= 63
        && organization
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        && !organization.starts_with('-')
        && !organization.ends_with('-')
        && !organization.contains("--")
}

fn is_system_key(requested: &str) -> bool {
    requested
        .split('/')
        .nth(1)
        .is_some_and(|segment| segment.starts_with('_'))
}

fn allowed_system_operation(
    operation: Operation,
    requested: &OwnedKeyExpr,
    ingress: Ingress,
    direction: Direction,
) -> Option<Reason> {
    let requested_ref: &keyexpr = requested;
    // Writes and subscriptions must name one concrete, per-client endpoint;
    // granting the allowlist selector itself would let a client impersonate or
    // observe every clock-sync participant.
    let concrete = !requested.as_str().split('/').any(|chunk| chunk.contains('*'));
    match (ingress, direction, operation) {
        (_, Direction::Ingress, Operation::Put)
            if concrete && time_ping_scope().includes(requested_ref) =>
        {
            Some(Reason::AllowTimePingPut)
        }
        // Zenoh propagates the clock plugin's subscriber declaration back to
        // publishers to establish the route. This reveals only the existence
        // of the fixed time service; it does not grant clients read access to
        // ping payloads or permission to subscribe to the wildcard.
        (Ingress::Native, Direction::Egress, Operation::Subscribe)
            if concrete && time_ping_scope().includes(requested_ref) =>
        {
            Some(Reason::AllowTimePingInterest)
        }
        (_, Direction::Ingress, Operation::Subscribe)
            if concrete && time_response_includes(requested_ref) =>
        {
            Some(Reason::AllowTimePongSubscribe)
        }
        (Ingress::RemoteApi, Direction::Ingress, Operation::Get)
            if requested.as_str() == "adamo/_remote_echo/ping" =>
        {
            Some(Reason::AllowRemoteEchoGet)
        }
        (Ingress::Native, Direction::Egress, Operation::Put | Operation::Delete)
            if concrete && time_response_includes(requested_ref) =>
        {
            Some(Reason::AllowTimeResponseReceive)
        }
        _ => None,
    }
}

fn time_ping_scope() -> &'static keyexpr {
    static SCOPE: OnceLock<OwnedKeyExpr> = OnceLock::new();
    SCOPE
        .get_or_init(|| {
            OwnedKeyExpr::new("adamo/_time/ping/*").expect("static key expression is valid")
        })
}

fn time_response_includes(requested: &keyexpr) -> bool {
    static SCOPES: OnceLock<[OwnedKeyExpr; 2]> = OnceLock::new();
    SCOPES
        .get_or_init(|| {
            [
                OwnedKeyExpr::new("adamo/_time/pong/*")
                    .expect("static key expression is valid"),
                OwnedKeyExpr::new("adamo/_time/tick/*")
                    .expect("static key expression is valid"),
            ]
        })
        .iter()
        .any(|scope| {
            let scope_ref: &keyexpr = scope;
            scope_ref.includes(requested)
        })
}

const REASON_COUNT: usize = Reason::ALL.len();
static DECISION_COUNTS: [AtomicU64; REASON_COUNT] =
    [const { AtomicU64::new(0) }; REASON_COUNT];

fn record(effect: Effect, reason: Reason) -> Decision {
    DECISION_COUNTS[reason as usize].fetch_add(1, Ordering::Relaxed);
    Decision { effect, reason }
}

/// Returns a fixed-cardinality metrics snapshot keyed only by stable reasons.
pub fn metrics_snapshot() -> [(Reason, u64); REASON_COUNT] {
    Reason::ALL.map(|reason| {
        (
            reason,
            DECISION_COUNTS[reason as usize].load(Ordering::Relaxed),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organization_identities_are_bounded_and_unambiguous() {
        assert!(valid_organization("new-org-42"));
        assert!(valid_organization(&"a".repeat(63)));
        for invalid in [
            "",
            "New-Org",
            "new_org",
            "-new-org",
            "new-org-",
            "new--org",
            "org/*",
            &"a".repeat(64),
        ] {
            assert!(!valid_organization(invalid), "accepted invalid organization: {invalid}");
        }

        assert!(is_reserved_identity("adamo-api"));
        assert!(is_reserved_identity("adamo-router"));
        assert!(is_reserved_identity("adamo-router-any-region"));
        assert!(is_reserved_identity("telemetry-collector"));
        assert!(!is_reserved_identity("new-org-42"));
    }

    #[test]
    fn reserved_service_identity_cannot_become_a_tenant_scope() {
        let policy = AuthorizationPolicy::new(Some("device-1"), Some("adamo-router-any-region"));
        assert_eq!(
            policy
                .decide(
                    Operation::Get,
                    "adamo/adamo-router-any-region/robot",
                    Ingress::Native,
                )
                .reason,
            Reason::DenyInvalidOrganization
        );
    }

    #[test]
    fn missing_identity_and_unknown_operations_fail_closed() {
        let no_subject = AuthorizationPolicy::new(None, Some("acme"));
        assert_eq!(
            no_subject.decide(Operation::Get, "adamo/acme/robot", Ingress::RemoteApi),
            Decision {
                effect: Effect::Deny,
                reason: Reason::DenyMissingSubject,
            }
        );

        let policy = AuthorizationPolicy::new(Some("user-1"), Some("acme"));
        assert_eq!(
            policy.decide(Operation::Unknown, "adamo/acme/robot", Ingress::RemoteApi).reason,
            Reason::DenyUnknownOperation
        );
    }

    #[test]
    fn native_time_ping_interest_can_establish_only_a_concrete_clock_route() {
        let policy = AuthorizationPolicy::new(Some("acme"), Some("acme"));
        assert_eq!(
            policy.decide_with_direction(
                Operation::Subscribe,
                "adamo/_time/ping/client-1",
                Ingress::Native,
                Direction::Egress,
            ),
            Decision {
                effect: Effect::Allow,
                reason: Reason::AllowTimePingInterest,
            }
        );
        for key in ["adamo/_time/ping/*", "adamo/_time/ping/**", "adamo/_time/pong/client-1"] {
            assert!(!policy
                .decide_with_direction(
                    Operation::Subscribe,
                    key,
                    Ingress::Native,
                    Direction::Egress,
                )
                .allowed());
        }
        assert!(!policy
            .decide_with_direction(
                Operation::Subscribe,
                "adamo/_time/ping/client-1",
                Ingress::Native,
                Direction::Ingress,
            )
            .allowed());
    }
}

//! Identity-derived authorization for authenticated Adamo transports.

use std::sync::OnceLock;

use zenoh_keyexpr::{keyexpr, OwnedKeyExpr};

pub const FIXED_SERVICE_IDENTITIES: [&str; 3] =
    ["adamo-api", "adamo-router", "telemetry-collector"];

pub fn is_reserved_identity(value: &str) -> bool {
    FIXED_SERVICE_IDENTITIES.contains(&value) || value.starts_with("adamo-router-")
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ingress {
    Native,
}

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
pub enum Reason {
    AllowTenantScope,
    AllowTimePingPut,
    AllowTimePingInterest,
    AllowTimePongSubscribe,
    AllowTimeResponseReceive,
    DenyInvalidOrganization,
    DenySystemKey,
    DenyOutsideOrganization,
}

impl Reason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::AllowTenantScope => "allow.tenant_scope",
            Self::AllowTimePingPut => "allow.system.time_ping_put",
            Self::AllowTimePingInterest => "allow.system.time_ping_interest",
            Self::AllowTimePongSubscribe => "allow.system.time_pong_subscribe",
            Self::AllowTimeResponseReceive => "allow.system.time_response_receive",
            Self::DenyInvalidOrganization => "deny.invalid_organization",
            Self::DenySystemKey => "deny.system_key",
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
pub struct AuthorizationPolicy {
    tenant_scope: Option<OwnedKeyExpr>,
}

impl AuthorizationPolicy {
    pub fn new(organization: &str) -> Self {
        let tenant_scope = (valid_organization(organization)
            && !is_reserved_identity(organization))
        .then(|| OwnedKeyExpr::new(format!("adamo/{organization}/**")).ok())
        .flatten();
        Self { tenant_scope }
    }

    pub fn decide_with_direction(
        &self,
        operation: Operation,
        requested_key: &str,
        _ingress: Ingress,
        direction: Direction,
    ) -> Decision {
        let requested = match OwnedKeyExpr::new(requested_key) {
            Ok(requested) => requested,
            Err(_) => return deny(Reason::DenyOutsideOrganization),
        };
        let Some(tenant_scope) = &self.tenant_scope else {
            return deny(Reason::DenyInvalidOrganization);
        };

        if let Some(reason) = allowed_system_operation(operation, &requested, direction) {
            return allow(reason);
        }
        if is_system_key(requested.as_str()) {
            return deny(Reason::DenySystemKey);
        }

        let tenant_scope: &keyexpr = tenant_scope;
        let requested: &keyexpr = &requested;
        if tenant_scope.includes(requested) {
            allow(Reason::AllowTenantScope)
        } else {
            deny(Reason::DenyOutsideOrganization)
        }
    }
}

const fn allow(reason: Reason) -> Decision {
    Decision {
        effect: Effect::Allow,
        reason,
    }
}

const fn deny(reason: Reason) -> Decision {
    Decision {
        effect: Effect::Deny,
        reason,
    }
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
    direction: Direction,
) -> Option<Reason> {
    let requested_ref: &keyexpr = requested;
    let concrete = !requested.as_str().split('/').any(|chunk| chunk.contains('*'));
    match (direction, operation) {
        (Direction::Ingress, Operation::Put)
            if concrete && time_ping_scope().includes(requested_ref) =>
        {
            Some(Reason::AllowTimePingPut)
        }
        (Direction::Egress, Operation::Subscribe)
            if concrete && time_ping_scope().includes(requested_ref) =>
        {
            Some(Reason::AllowTimePingInterest)
        }
        (Direction::Ingress, Operation::Subscribe)
            if concrete && time_response_includes(requested_ref) =>
        {
            Some(Reason::AllowTimePongSubscribe)
        }
        (Direction::Egress, Operation::Put | Operation::Delete)
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
        .get_or_init(|| OwnedKeyExpr::new("adamo/_time/ping/*").expect("valid static key"))
}

fn time_response_includes(requested: &keyexpr) -> bool {
    static SCOPES: OnceLock<[OwnedKeyExpr; 2]> = OnceLock::new();
    SCOPES
        .get_or_init(|| {
            [
                OwnedKeyExpr::new("adamo/_time/pong/*").expect("valid static key"),
                OwnedKeyExpr::new("adamo/_time/tick/*").expect("valid static key"),
            ]
        })
        .iter()
        .any(|scope| {
            let scope: &keyexpr = scope;
            scope.includes(requested)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_scope_includes_only_concrete_keys_below_the_tenant_root() {
        let policy = AuthorizationPolicy::new("created-after-router-start");
        assert!(policy
            .decide_with_direction(
                Operation::Put,
                "adamo/created-after-router-start/robot/state",
                Ingress::Native,
                Direction::Ingress,
            )
            .allowed());
        for denied in [
            "adamo/another-org/robot/state",
            "adamo/**",
        ] {
            assert!(!policy
                .decide_with_direction(
                    Operation::Put,
                    denied,
                    Ingress::Native,
                    Direction::Ingress,
                )
                .allowed());
        }
    }

    #[test]
    fn reserved_and_malformed_identities_fail_closed() {
        for identity in ["adamo-api", "adamo-router-us", "Bad_Tenant", "a--b"] {
            assert!(!AuthorizationPolicy::new(identity)
                .decide_with_direction(
                    Operation::Put,
                    &format!("adamo/{identity}/state"),
                    Ingress::Native,
                    Direction::Ingress,
                )
                .allowed());
        }
    }
}

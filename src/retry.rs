//! Pieces shared by the control plane and command router retry loops.

use std::time::Duration;

use base64::Engine;
use prost::Message;
use tonic::{Code, Status};

use crate::proto::client::RpcRetryPolicy;

/// Codes worth retrying on both the control plane and the command router.
pub(crate) fn is_retryable(code: Code) -> bool {
    matches!(
        code,
        Code::DeadlineExceeded
            | Code::Unavailable
            | Code::Cancelled
            | Code::Internal
            | Code::Unknown
    )
}

/// The credentials themselves were rejected, as opposed to a transient outage.
pub(crate) fn is_auth_denied(status: &Status) -> bool {
    matches!(
        status.code(),
        Code::Unauthenticated | Code::PermissionDenied
    )
}

/// `google.rpc.Status`, which gRPC servers put in `grpc-status-details-bin`.
#[derive(Clone, PartialEq, prost::Message)]
struct RpcStatus {
    #[prost(int32, tag = "1")]
    code: i32,
    #[prost(string, tag = "2")]
    message: String,
    #[prost(message, repeated, tag = "3")]
    details: Vec<prost_types::Any>,
}

const RETRY_POLICY_TYPE: &str = "modal.client.RPCRetryPolicy";

/// The delay Modal asked for when it throttled a call, if it attached one.
/// Floored at 100ms, as in the Go SDK.
pub(crate) fn server_retry_after(status: &Status) -> Option<Duration> {
    if status.details().is_empty() {
        return None;
    }
    let rpc_status = RpcStatus::decode(status.details()).ok()?;
    let policy = rpc_status.details.iter().find_map(|any| {
        let name = any.type_url.rsplit('/').next()?;
        (name == RETRY_POLICY_TYPE)
            .then(|| RpcRetryPolicy::decode(any.value.as_slice()).ok())
            .flatten()
    })?;
    let secs = if policy.retry_after_secs.is_finite() {
        policy.retry_after_secs.max(0.0)
    } else {
        0.0
    };
    Some(Duration::from_secs_f32(secs).max(Duration::from_millis(100)))
}

/// Reads the `exp` claim of a JWT without verifying it. `Ok(None)` when the
/// token has no `exp`.
pub(crate) fn jwt_expiry(token: &str) -> Result<Option<i64>, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(format!(
            "malformed JWT: expected 3 parts, got {}",
            parts.len()
        ));
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1].trim_end_matches('='))
        .map_err(|err| format!("malformed JWT: base64 decode: {err}"))?;
    let claims: serde_json::Value =
        serde_json::from_slice(&payload).map_err(|err| format!("malformed JWT: {err}"))?;
    match claims.get("exp") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(exp) => exp
            .as_i64()
            .or_else(|| exp.as_f64().map(|f| f as i64))
            .map(Some)
            .ok_or_else(|| "malformed JWT: exp is not a number".to_string()),
    }
}

pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
pub(crate) fn status_with_retry_policy(code: Code, retry_after_secs: f32) -> Status {
    let policy = RpcRetryPolicy { retry_after_secs };
    let details = RpcStatus {
        code: code as i32,
        message: "slow down".into(),
        details: vec![prost_types::Any {
            type_url: format!("type.googleapis.com/{RETRY_POLICY_TYPE}"),
            value: policy.encode_to_vec(),
        }],
    };
    Status::with_details(code, "slow down", details.encode_to_vec().into())
}

#[cfg(test)]
pub(crate) fn fake_jwt(exp: i64) -> String {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{}.{}.sig",
        engine.encode(br#"{"alg":"none"}"#),
        engine.encode(format!(r#"{{"exp":{exp}}}"#))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_server_retry_policy() {
        let status = status_with_retry_policy(Code::ResourceExhausted, 2.5);
        assert_eq!(
            server_retry_after(&status),
            Some(Duration::from_millis(2500))
        );
    }

    #[test]
    fn floors_server_retry_delay() {
        let status = status_with_retry_policy(Code::ResourceExhausted, 0.0);
        assert_eq!(
            server_retry_after(&status),
            Some(Duration::from_millis(100))
        );
    }

    #[test]
    fn no_policy_without_details() {
        assert_eq!(server_retry_after(&Status::unavailable("down")), None);
    }

    #[test]
    fn parses_jwt_expiry() {
        assert_eq!(
            jwt_expiry(&fake_jwt(1_900_000_000)).unwrap(),
            Some(1_900_000_000)
        );
        assert!(jwt_expiry("not-a-jwt").is_err());
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let no_exp = format!("a.{}.c", engine.encode(br#"{"sub":"x"}"#));
        assert_eq!(jwt_expiry(&no_exp).unwrap(), None);
    }
}

//! Short-lived `x-modal-auth-token` handling, ported from the Go SDK's
//! `authTokenManager`.
//!
//! Tokens are refreshed a jittered 50-60% of the way through their lifetime.
//! While a token is still valid only one caller refreshes it and the rest keep
//! using the cached one; once it has expired, callers queue behind a single
//! fetch.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use tonic::Status;

use crate::client::{CallOptions, Client, Stub};
use crate::proto::client::AuthTokenGetRequest;
use crate::retry::{is_auth_denied, jwt_expiry, unix_now};

const AUTH_TOKEN_GET_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounds a whole refresh including retries.
const AUTH_TOKEN_REFRESH_TIMEOUT: Duration = Duration::from_secs(15);
const FAILURE_BACKOFF_BASE: Duration = Duration::from_millis(500);
const FAILURE_BACKOFF_MAX: Duration = Duration::from_secs(60);
const REFRESH_FRACTION: f64 = 0.5;
const REFRESH_JITTER: f64 = 0.1;
/// Expiry assumed for a token without an `exp` claim (not expected).
const DEFAULT_EXPIRY_OFFSET: i64 = 20 * 60;

#[derive(Clone)]
struct State {
    token: String,
    expiry: i64,
    refresh_at: i64,
    /// After a failed refresh, don't try again before this.
    retry_after: Option<Instant>,
    backoff: Duration,
}

impl State {
    fn is_expired(&self) -> bool {
        unix_now() >= self.expiry
    }

    fn should_refresh(&self) -> bool {
        unix_now() >= self.refresh_at && self.retry_after.is_none_or(|t| Instant::now() >= t)
    }
}

pub(crate) struct AuthTokenManager {
    state: Mutex<State>,
    refresh: tokio::sync::Mutex<()>,
}

impl AuthTokenManager {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(State {
                token: String::new(),
                expiry: 0,
                refresh_at: 0,
                retry_after: None,
                backoff: FAILURE_BACKOFF_BASE,
            }),
            refresh: tokio::sync::Mutex::new(()),
        }
    }

    fn snapshot(&self) -> State {
        self.state.lock().unwrap().clone()
    }

    pub(crate) async fn get_token(&self, client: &Client) -> Result<String, Status> {
        let current = self.snapshot();

        if current.token.is_empty() || current.is_expired() {
            let _guard = self.refresh.lock().await;
            let current = self.snapshot();
            if !current.token.is_empty() && !current.is_expired() {
                return Ok(current.token);
            }
            return match self.fetch(client).await {
                Ok(token) => Ok(token),
                Err(status) if is_auth_denied(&status) || current.token.is_empty() => Err(status),
                Err(status) => {
                    tracing::warn!(error = %status.message(), "auth token refresh failed; using the cached token");
                    Ok(current.token)
                }
            };
        }

        if current.should_refresh()
            && let Ok(_guard) = self.refresh.try_lock()
        {
            let latest = self.snapshot();
            if !latest.should_refresh() {
                return Ok(latest.token);
            }
            match self.fetch(client).await {
                Ok(token) => return Ok(token),
                Err(status) if is_auth_denied(&status) => return Err(status),
                Err(status) => {
                    tracing::warn!(error = %status.message(), "auth token refresh failed; using the cached token");
                }
            }
        }

        Ok(current.token)
    }

    async fn fetch(&self, client: &Client) -> Result<String, Status> {
        let current = self.snapshot();
        // With no valid token to fall back on a failure is visible to the
        // caller, so retry transient errors. Otherwise try once and let the
        // backoff space out further attempts.
        let retries = if current.token.is_empty() || current.is_expired() {
            3
        } else {
            0
        };
        let opts = CallOptions {
            retries,
            timeout: Some(AUTH_TOKEN_GET_TIMEOUT),
            ..Default::default()
        };
        let call = client.call_with_retries(
            "auth_token_get",
            &opts,
            None,
            AuthTokenGetRequest {},
            |mut stub: Stub, request| async move { stub.auth_token_get(request).await },
        );
        let result = match tokio::time::timeout(AUTH_TOKEN_REFRESH_TIMEOUT, call).await {
            Ok(Ok(response)) if response.token.is_empty() => {
                Err(Status::internal("did not receive an auth token from Modal"))
            }
            Ok(Ok(response)) => Ok(response.token),
            Ok(Err(status)) => Err(status),
            Err(_) => Err(Status::deadline_exceeded(
                "timed out fetching an auth token",
            )),
        };

        let mut state = self.state.lock().unwrap();
        match result {
            Ok(token) => {
                let now = unix_now();
                let expiry = match jwt_expiry(&token) {
                    Ok(Some(exp)) if exp > 0 => exp,
                    _ => {
                        tracing::warn!("x-modal-auth-token has no exp claim");
                        now + DEFAULT_EXPIRY_OFFSET
                    }
                };
                let fraction = REFRESH_FRACTION + fastrand::f64() * REFRESH_JITTER;
                let remaining = (expiry - now).max(0);
                *state = State {
                    token: token.clone(),
                    expiry,
                    refresh_at: now + (remaining as f64 * fraction) as i64,
                    retry_after: None,
                    backoff: FAILURE_BACKOFF_BASE,
                };
                tracing::debug!(expires_in = remaining, "fetched Modal auth token");
                Ok(token)
            }
            Err(status) => {
                if !is_auth_denied(&status) {
                    state.retry_after = Some(Instant::now() + state.backoff);
                    state.backoff = (state.backoff * 2).min(FAILURE_BACKOFF_MAX);
                }
                Err(status)
            }
        }
    }
}

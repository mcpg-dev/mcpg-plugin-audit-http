//! Operator-supplied configuration schema for `dev.mcpg.audit.http`.
//!
//! ```yaml
//! plugins:
//!   - id: dev.mcpg.audit.http
//!     config:
//!       url: https://collector.example/v1/audit
//!       token: ${env.AUDIT_COLLECTOR_TOKEN}   # optional bearer
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSinkConfig {
    /// Collector endpoint. Every batch is one `POST` of a JSON array
    /// of audit records; any 2xx answer commits the batch.
    pub url: String,

    /// Bearer token for the `Authorization` header. Source it via
    /// `${env.VAR}` — the host expands config values at load, so the
    /// cleartext never lands in the YAML source. Absent = no
    /// Authorization header.
    #[serde(default)]
    pub token: Option<String>,

    /// Per-attempt request timeout.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Retries after the first attempt, for 429 / 5xx / transport
    /// errors only — other 4xx are the collector refusing the batch
    /// and retrying cannot fix them. Waiters block through retries,
    /// so the worst-case emit latency is
    /// `(max_retries + 1) * timeout_ms` plus backoff.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Backoff between retry attempts, doubled per attempt.
    #[serde(default = "default_retry_backoff_ms")]
    pub retry_backoff_ms: u64,

    /// Ceiling on events per batch. The writer drains whatever is
    /// queued up to this many; there is no artificial linger — an
    /// idle sink ships a single event immediately.
    #[serde(default = "default_max_batch_events")]
    pub max_batch_events: usize,
}

fn default_timeout_ms() -> u64 {
    5_000
}
fn default_max_retries() -> u32 {
    2
}
fn default_retry_backoff_ms() -> u64 {
    250
}
fn default_max_batch_events() -> usize {
    256
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid audit.http config: {0}")]
    Invalid(String),
}

impl HttpSinkConfig {
    pub fn parse(config_json: &str) -> Result<Self, ConfigError> {
        let cfg: Self =
            serde_json::from_str(config_json).map_err(|e| ConfigError::Invalid(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !self.url.starts_with("http://") && !self.url.starts_with("https://") {
            return Err(ConfigError::Invalid(format!(
                "`url` must be http(s)://, got `{}`",
                self.url
            )));
        }
        if self.max_batch_events == 0 {
            return Err(ConfigError::Invalid(
                "`max_batch_events` must be at least 1".into(),
            ));
        }
        if self.timeout_ms == 0 {
            return Err(ConfigError::Invalid("`timeout_ms` must be non-zero".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_parses_with_defaults() {
        let cfg = HttpSinkConfig::parse(r#"{"url":"https://c.example/v1/audit"}"#).unwrap();
        assert_eq!(cfg.timeout_ms, 5_000);
        assert_eq!(cfg.max_retries, 2);
        assert_eq!(cfg.max_batch_events, 256);
        assert!(cfg.token.is_none());
    }

    #[test]
    fn non_http_url_is_refused() {
        assert!(HttpSinkConfig::parse(r#"{"url":"ftp://c.example"}"#).is_err());
    }

    #[test]
    fn unknown_fields_are_refused() {
        assert!(HttpSinkConfig::parse(r#"{"url":"https://c","linger_ms":5}"#).is_err());
    }
}

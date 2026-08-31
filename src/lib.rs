//! `dev.mcpg.audit.http` — HTTP collector audit sink.
//!
//! Ships audit events to a collector endpoint as bearer-authenticated
//! JSON-array batches.
//!
//! # Concurrency — group commit
//!
//! A single background writer task owns the HTTP client. `emit`
//! serializes the event, hands it to the writer over a channel, and
//! awaits a commit reply. The writer drains everything currently
//! queued (up to `max_batch_events`) into ONE `POST` and replies to
//! every waiter with that batch's outcome — so each caller still
//! blocks until *its* event is committed (2xx from the collector),
//! while under load many events share one round trip. This is the
//! same shape as the built-in local-file sink's group fsync, with the
//! network round trip in place of `sync_all`.
//!
//! # Wire contract
//!
//! Request: `POST <url>` with `Content-Type: application/json` and,
//! when a token is configured, `Authorization: Bearer <token>`. The
//! body is a JSON array of audit records serialized verbatim —
//! `event_id` and `prev_event_hash` ride along, so a downstream store
//! can verify the per-node hash chain. Any 2xx commits the batch;
//! 429 and 5xx retry `max_retries` times with doubling backoff;
//! any other 4xx fails the batch immediately (the collector refused
//! it, and a retry cannot fix that).

use std::sync::Arc;

use mcpg_plugin_protocol::PluginClass;
use mcpg_plugin_protocol::audit::{AuditError, AuditEvent, AuditReceipt};
use mcpg_plugin_protocol::manifest::PluginManifest;
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncAuditSink;
use sha2::{Digest, Sha256};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot};

mod config;
pub use config::{ConfigError, HttpSinkConfig};

const PLUGIN_ID: &str = "dev.mcpg.audit.http";

enum Job {
    Emit {
        /// The record as it will appear inside the batch array.
        value: serde_json::Value,
        /// SHA-256 over the record's canonical bytes — the receipt's
        /// durable hash, computed once at emit.
        hash: String,
        reply: oneshot::Sender<Result<AuditReceipt, AuditError>>,
    },
    /// Barrier: replied to once every job queued before it has been
    /// answered. The writer is serial, so ordering gives that for free.
    Flush { reply: oneshot::Sender<()> },
}

pub struct HttpAuditSink {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    tx: mpsc::UnboundedSender<Job>,
    runtime: Runtime,
}

impl HttpAuditSink {
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = HttpSinkConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "audit.http: config parse failed; refusing to register"
            );
            panic!(
                "audit.http config parse failed: {err}. A misconfigured audit \
                 sink is a safety hole; refusing to load."
            )
        });
        Self::from_validated_config(cfg)
    }

    fn from_validated_config(cfg: HttpSinkConfig) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("mcpg-audit-http")
            .enable_all()
            .build()
            .expect("audit.http: failed to build tokio runtime");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(cfg.timeout_ms))
            .build()
            .expect("audit.http: failed to build HTTP client");
        let (tx, rx) = mpsc::unbounded_channel();
        tracing::info!(
            plugin_id = PLUGIN_ID,
            url = %cfg.url,
            max_batch_events = cfg.max_batch_events,
            "audit.http: configured"
        );
        runtime.spawn(writer_loop(client, cfg, rx));
        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "HTTP Collector Audit Sink".into(),
                    plugin_class: PluginClass::AuditSink,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                tx,
                runtime,
            }),
        }
    }
}

/// The single writer: drains queued jobs into one batch per POST and
/// answers every waiter with that batch's outcome.
async fn writer_loop(
    client: reqwest::Client,
    cfg: HttpSinkConfig,
    mut rx: mpsc::UnboundedReceiver<Job>,
) {
    while let Some(first) = rx.recv().await {
        let mut values = Vec::new();
        let mut waiters = Vec::new();
        let mut flushes = Vec::new();
        let enqueue =
            |job: Job, values: &mut Vec<_>, waiters: &mut Vec<_>, flushes: &mut Vec<_>| match job {
                Job::Emit { value, hash, reply } => {
                    values.push(value);
                    waiters.push((hash, reply));
                }
                Job::Flush { reply } => flushes.push(reply),
            };
        enqueue(first, &mut values, &mut waiters, &mut flushes);
        while values.len() < cfg.max_batch_events {
            match rx.try_recv() {
                Ok(job) => enqueue(job, &mut values, &mut waiters, &mut flushes),
                Err(_) => break,
            }
        }

        if !values.is_empty() {
            let started = std::time::Instant::now();
            let result = post_batch(&client, &cfg, &values).await;
            metrics::histogram!("mcpg_audit_http_batch_latency_ms")
                .record(started.elapsed().as_millis() as f64);
            metrics::counter!(
                "mcpg_audit_http_batch_total",
                "result" => match &result { Ok(()) => "ok", Err(e) => e.kind_label() },
            )
            .increment(1);
            let persisted_at = now_rfc3339();
            for (hash, reply) in waiters {
                let _ = reply.send(match &result {
                    Ok(()) => Ok(AuditReceipt {
                        sink_id: PLUGIN_ID.to_owned(),
                        persisted_at: persisted_at.clone(),
                        durable_hash: hash,
                    }),
                    Err(e) => Err(e.clone()),
                });
            }
        }
        for reply in flushes {
            let _ = reply.send(());
        }
    }
}

async fn post_batch(
    client: &reqwest::Client,
    cfg: &HttpSinkConfig,
    values: &[serde_json::Value],
) -> Result<(), AuditError> {
    let mut backoff = cfg.retry_backoff_ms;
    let mut last: AuditError = AuditError::WriteFailed {
        reason: "unreachable".into(),
    };
    for attempt in 0..=cfg.max_retries {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
            backoff = backoff.saturating_mul(2);
        }
        let mut req = client.post(&cfg.url).json(values);
        if let Some(token) = cfg.token.as_deref().filter(|t| !t.is_empty()) {
            req = req.bearer_auth(token);
        }
        match req.send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) => {
                let status = resp.status();
                // The body is collector-internal detail; surface only the
                // status so nothing sensitive propagates into logs/audit.
                let err = AuditError::WriteFailed {
                    reason: format!("collector returned HTTP {status}"),
                };
                if status.as_u16() == 429 || status.is_server_error() {
                    last = if status.as_u16() == 429 {
                        AuditError::Throttled
                    } else {
                        err
                    };
                    continue;
                }
                return Err(err);
            }
            Err(e) if e.is_timeout() => {
                last = AuditError::Timeout;
                continue;
            }
            Err(e) => {
                last = AuditError::WriteFailed {
                    reason: format!("collector unreachable: {e}"),
                };
                continue;
            }
        }
    }
    Err(last)
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn serialize_event(event: &AuditEvent) -> Result<(serde_json::Value, String), AuditError> {
    let value = serde_json::to_value(event).map_err(|e| AuditError::WriteFailed {
        reason: format!("serialize audit event: {e}"),
    })?;
    let bytes = serde_json::to_vec(&value).map_err(|e| AuditError::WriteFailed {
        reason: format!("serialize audit event: {e}"),
    })?;
    Ok((value, hex::encode(Sha256::digest(&bytes))))
}

impl SyncAuditSink for HttpAuditSink {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn emit(&self, event: &AuditEvent) -> Result<AuditReceipt, AuditError> {
        let (value, hash) = serialize_event(event)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.inner
            .tx
            .send(Job::Emit {
                value,
                hash,
                reply: reply_tx,
            })
            .map_err(|_| AuditError::Closed)?;
        self.inner
            .runtime
            .block_on(reply_rx)
            .unwrap_or(Err(AuditError::Closed))
    }

    fn flush(&self, timeout_ms: u64) -> Result<(), AuditError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.inner
            .tx
            .send(Job::Flush { reply: reply_tx })
            .map_err(|_| AuditError::Closed)?;
        self.inner.runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), reply_rx)
                .await
                .map_err(|_| AuditError::Timeout)?
                .map_err(|_| AuditError::Closed)
        })
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        audit_sink as entity {
            inner_name: "",
            plugin_type: HttpAuditSink,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> HttpAuditSink {
                HttpAuditSink::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::audit::AuditOutcome;
    use mcpg_plugin_protocol::types::PluginIdentity;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_event(id: &str) -> AuditEvent {
        AuditEvent {
            event_id: id.into(),
            occurred_at: "2026-08-31T00:00:00Z".into(),
            actor: PluginIdentity {
                kind: "verified".into(),
                trust_level: "verified".into(),
                subject_id: Some("user-1".into()),
                auth_provider: None,
                issuer: None,
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: std::collections::BTreeMap::new(),
            },
            action: "tools/call".into(),
            resource: Some("tool://kv.get".into()),
            outcome: AuditOutcome::Success,
            request_id: Some("req-1".into()),
            upstream_request_id: Some("caller-req-1".into()),
            node_id: None,
            details: json!({}),
            prev_event_hash: None,
        }
    }

    fn sink_for(url: &str, token: Option<&str>) -> HttpAuditSink {
        HttpAuditSink::from_validated_config(HttpSinkConfig {
            url: url.to_owned(),
            token: token.map(str::to_owned),
            timeout_ms: 2_000,
            max_retries: 1,
            retry_backoff_ms: 10,
            max_batch_events: 256,
        })
    }

    #[test]
    fn commits_with_bearer_and_array_body() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/audit"))
                .and(header("authorization", "Bearer sekret"))
                .and(body_partial_json(json!([{"event_id": "e1"}])))
                .respond_with(ResponseTemplate::new(202))
                .expect(1)
                .mount(&server)
                .await;
            server
        });
        let sink = sink_for(&format!("{}/v1/audit", server.uri()), Some("sekret"));
        let receipt = sink.emit(&sample_event("e1")).expect("committed");
        assert_eq!(receipt.sink_id, PLUGIN_ID);
        assert_eq!(receipt.durable_hash.len(), 64);
        rt.block_on(server.verify());
    }

    #[test]
    fn non_2xx_fails_closed_without_retry() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(403))
                .expect(1)
                .mount(&server)
                .await;
            server
        });
        let sink = sink_for(&server.uri(), None);
        let err = sink.emit(&sample_event("e2")).unwrap_err();
        assert!(matches!(err, AuditError::WriteFailed { .. }));
        rt.block_on(server.verify());
    }

    #[test]
    fn server_errors_retry_then_commit() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(500))
                .up_to_n_times(1)
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(&server)
                .await;
            server
        });
        let sink = sink_for(&server.uri(), None);
        sink.emit(&sample_event("e3")).expect("retried to commit");
        rt.block_on(server.verify());
    }

    #[test]
    fn flush_waits_for_prior_emits() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;
            server
        });
        let sink = sink_for(&server.uri(), None);
        sink.emit(&sample_event("e4")).unwrap();
        sink.flush(2_000).expect("flush clean");
    }
}

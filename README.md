# HTTP Collector Audit Sink (`dev.mcpg.audit.http`)

An **audit_sink** plugin that ships every audit event to an HTTP
collector endpoint as bearer-authenticated JSON-array batches — the
integration point for SIEMs, log pipelines, and custom compliance
stores that speak plain HTTP.

## Durable-ack contract

`emit` returns Ok **only after** the collector has answered 2xx for
the batch carrying the event — the audit-sink fan-out contract (the
gateway awaits every sink's Ok before completing the request that
produced the event, unless the operator opts into fail-open). So
`audit.required` + `fail_closed` keep their meaning: an uncommitted
batch fails the calls that produced it. There is no fire-and-forget
path.

A single background writer group-commits: each `emit` hands its event
to the writer and blocks until its batch is POSTed; under load many
events share one round trip, while an idle sink ships a single event
immediately (no artificial linger).

## Wire contract

- `POST <url>` with `Content-Type: application/json` and, when a
  token is configured, `Authorization: Bearer <token>`.
- The body is a **JSON array of audit records serialized verbatim** —
  `event_id` and `prev_event_hash` included, so a downstream store can
  verify the per-node hash chain.
- The `AuditReceipt` carries the SHA-256 over each event's canonical
  JSON bytes.
- Any **2xx** commits the batch. **429 and 5xx** (and transport
  errors/timeouts) retry `max_retries` times with doubling backoff.
  Any **other 4xx** fails the batch immediately — the collector
  refused it, and a retry cannot fix that.

## Configuration

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | string | *(required)* | Collector endpoint (`http(s)://`). |
| `token` | string | *(none)* | Bearer token; source it via `${env.VAR}`. Absent = no `Authorization` header. |
| `timeout_ms` | int | `5000` | Per-attempt request timeout. |
| `max_retries` | int | `2` | Retries after the first attempt (429/5xx/transport only). |
| `retry_backoff_ms` | int | `250` | Backoff between attempts, doubled each retry. |
| `max_batch_events` | int | `256` | Ceiling on events per batch. |

```yaml
plugins:
  - id: dev.mcpg.audit.http
    source:
      oci: ghcr.io/mcpg-dev/mcpg-plugin-audit-http
    class: audit_sink
    granted_capabilities:
      - network_outbound
    config:
      url: https://collector.example/v1/audit
      token: ${env.AUDIT_COLLECTOR_TOKEN}
```

Worst-case `emit` latency is `(max_retries + 1) * timeout_ms` plus
backoff — size `audit.required` timeouts accordingly.

## License

BUSL-1.1 — see [LICENSE](LICENSE). Production use requires a valid
MCPG license token whose entitlements cover this plugin; development
and evaluation use `license: { non_production_use: true }`.

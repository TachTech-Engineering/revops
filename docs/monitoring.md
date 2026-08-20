# Monitoring

Nothing watched this platform until 2026-08-20. Every fault found during the
August hardening was found by a person going and looking, and the two most
expensive ones were invisible precisely because they were silent:

- Syslog buffered on a replica that never drained it. The sync reported success
  having found nothing, for a day.
- The staging buffer livelocked, re-processing the same 8,000 rows for two days
  while 23,526 newer messages were never touched and the queue grew from 13,533
  to 38,321.

Both would have been one obvious line on a graph. The metrics below are chosen
from what actually broke.

## How it works

The backend exposes Prometheus text at `/metrics`. Google Managed Prometheus is
already enabled on the cluster, so a `PodMonitoring` resource
(`k8s/base/podmonitoring.yaml`) is all that is needed — there is no Prometheus
server to run or upgrade. Metrics land in Cloud Monitoring under
`prometheus.googleapis.com/<name>/gauge`.

### Why `/metrics` is unauthenticated

The collector scrapes the pod directly and cannot present a JWT. Three things
keep that safe, and all three must hold if anyone changes it:

1. **It is not routed there from outside.** The ingress sends `/api/*` to the
   backend and everything else to the frontend, so an external request for
   `/metrics` gets the SPA, never the exporter.
2. **The ingress is fronted by IAP** regardless.
3. **It carries no tenant data** — only aggregate operational gauges. No
   organization ids, no connector names, no message content. This is enforced
   by `tests/behavioral/test_metrics_endpoint.py`, which fails if a UUID or a
   connector name ever appears in the output.

`/metrics` is also on the explicit allowlist in `tests/test_auth_required.py`,
so adding an unauthenticated route still requires a deliberate, justified edit.

## What is exported

| Metric | Catches |
|---|---|
| `revops_ingest_pending{buffer}` | Undrained ingest buffer — the 38,321-row livelock |
| `revops_ingest_oldest_pending_seconds{buffer}` | A stalled drain, even when depth looks steady |
| `revops_log_store_bytes` / `_max_bytes` | The size cap that silently read 0 for days |
| `revops_log_partitions` | Retention/pre-creation failing; no partition means ingestion stops |
| `revops_connector_seconds_since_sync{connector_type}` | A connector that quietly stops syncing |
| `revops_alerts_ingested_1h{source_type}` | "Zero UniFi alerts for six hours" |
| `revops_database_bytes` | Growth against the shared 10Gi volume |
| `revops_up` | The exporter itself failing |

## Alerting policies to create

Not yet created — see "Still to do". Thresholds below come from measured
production behaviour, not guesses.

| Alert | Condition | Why this threshold |
|---|---|---|
| Ingest backlog growing | `revops_ingest_oldest_pending_seconds > 3600` | A healthy drain clears 2,000 per 5-minute cycle. Anything waiting an hour means the drain is not advancing — this is the single alert that would have caught both syslog outages. |
| Ingest queue deep | `revops_ingest_pending > 20000` | The per-connector cap is 50,000, past which messages are dropped at the door. This fires with headroom to act. |
| Log store near capacity | `revops_log_store_bytes / revops_log_store_max_bytes > 0.8` | Past the cap the store refuses writes. It shares a 10Gi volume with the operational database. |
| Connector stopped syncing | `revops_connector_seconds_since_sync > 1800` | Sync interval is 5 minutes; 30 minutes is six missed cycles. |
| No alerts from a source | `revops_alerts_ingested_1h == 0` for 6h | Tuned to the actual outage: UniFi produced zero alerts for six hours and nobody knew. Expect to tune this per source — a quiet source is not necessarily a broken one. |
| Exporter down | `revops_up == 0` or absent for 10m | Otherwise every alert above silently stops evaluating. |

Create them against the `prometheus.googleapis.com/...` metrics in Cloud
Monitoring, and attach a notification channel — there are none configured on
this project yet, so a policy would fire into the void.

## Still to do

Applying `PodMonitoring` needs `container.thirdPartyObjects.*` on the cluster.
The `davidk@tachtech.net` account has `roles/owner` and can do it; the account
the local `gke-gcloud-auth-plugin` currently mints tokens for
(`david@socfoundry.com`) cannot. Once kubectl is authenticating as the owner
account:

```bash
kubectl apply -k k8s/overlays/production
kubectl apply -k k8s/overlays/staging

# Confirm the collector picked it up (Ready should be True):
kubectl get podmonitoring -A
```

Then verify data is arriving in Cloud Monitoring's Metrics Explorer by querying
`revops_ingest_pending`, and create the policies above.

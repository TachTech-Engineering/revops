# Disaster recovery

What is backed up, where it lives, and how to bring RevOps back.

## What exists

| What | Where | Cadence | Retention |
|---|---|---|---|
| Database dump (`pg_dump -Fc`) | `gs://revops-486917-db-backups/YYYY/MM/` | daily, 03:00 America/Chicago (`db-backup` CronJob) | 30 days (bucket lifecycle) |
| Secret material | Google Secret Manager, project `revops-486917` | on change, via `./scripts/backup-cluster-secrets.sh` | all versions kept |

Secret Manager ids: `database-url`, `database-password`, `jwt-secret-key`,
`panther-api-host`, `panther-api-token`, `encryption-key`.

## Read this before restoring

**A restored database without the original `ENCRYPTION_KEY` is not a recovered
system.** Connector credentials are Fernet-encrypted with it. Restore the
database with a freshly generated key and every stored credential becomes
permanently unreadable — the rows survive, the secrets inside them do not.
`SECRET_KEY` has a milder version of the same property: rotating it invalidates
every issued token, and `encryption_service` also derives from it.

So: restore the secrets **first**, and never let `gke-secrets.sh` generate new
ones when rebuilding against an existing database. It resolves Secret Manager
before generating precisely to avoid this, and warns loudly if it has to fall
back to generating.

Backups are dumps taken at a point in time, not continuous. Expect to lose up
to 24 hours of alerts. The raw log store (`raw_log_events`) has 14-day
retention and is not separately protected; syslog staged in
`syslog_ingest_events` but not yet drained is lost with the cluster.

## Restoring

### 1. Secrets

```bash
# Recreate the cluster Secrets from Secret Manager.
./scripts/gke-secrets.sh          # reads Secret Manager, generates only what is absent
```

Confirm nothing was regenerated — the script prints "Generated new ..." when it
had to invent a value. Against an existing database, that line means stop.

### 2. Database

```bash
LATEST=$(gsutil ls gs://revops-486917-db-backups/**/*.dump | sort | tail -1)
gsutil cp "$LATEST" ./restore.dump

kubectl port-forward -n revops deploy/postgres 5432:5432 &
pg_restore -h localhost -U revops -d revops --no-owner --no-acl --clean --if-exists ./restore.dump
```

For a brand-new cluster, apply the manifests first so `postgres` exists, then
restore into it, then run the migration Job to bring the schema to head — the
dump is at whatever revision was current when it was taken, which is usually
behind.

### 3. Application

```bash
./scripts/gke-deploy.sh production <image-tag>
```

### 4. Verify

```bash
kubectl exec -n revops deploy/postgres -- psql -U revops -d revops -c \
  "SELECT (SELECT count(*) FROM normalized_alerts) AS alerts,
          (SELECT count(*) FROM users) AS users,
          (SELECT version_num FROM alembic_version) AS schema"
```

Then confirm a connector can still decrypt its credentials — that is the real
test of whether `ENCRYPTION_KEY` came back intact. Connectors → any connector →
Test Connection. If credentials are undecryptable this is where it shows.

## Verified

**2026-08-17** — restored `revops-20260817T080009Z.dump` (60.6 MiB) into a
throwaway Postgres 15 container. `pg_restore` exited 0 with no errors: 75
tables, 191,673 alerts, users/orgs/connectors intact, schema at
`c1d4e7f20a83`. The restore path works; it had never been exercised before.

Not yet verified: a full cluster rebuild from scratch. The secret half of that
was broken until 2026-08-17 — `gke-secrets.sh` created neither
`DATABASE_PASSWORD` (required by the in-cluster postgres) nor the
`backend-encryption-key` Secret at all, so it could not have stood a cluster
back up. Both are fixed, but the end-to-end rebuild has not been rehearsed.

## Keeping this true

Run `./scripts/backup-cluster-secrets.sh` after any secret change. It is
idempotent and only adds a Secret Manager version when a value actually
differs, so running it more often than necessary costs nothing. It exits
non-zero if any expected secret is missing from the cluster.

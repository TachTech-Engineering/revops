#!/bin/bash
# One-time GCP provisioning for the nightly in-cluster postgres backups
# (k8s/overlays/production/db-backup.yaml).
#
# Creates:
#   - GCS bucket gs://<project>-db-backups (uniform access, public access
#     prevention, object versioning, 30-day lifecycle: live objects, plus
#     noncurrent versions 30 days after they go noncurrent)
#   - A second bucket gs://<project>-db-backups-dr in a different region
#     (DR_REGION, default us-east1) with the same settings; the CronJob writes
#     every dump to both
#   - GSA revops-db-backup@<project> with roles/storage.objectCreator on the
#     buckets only (write-only: a compromised pod cannot read old backups)
#   - Workload Identity binding for the db-backup KSA in the prod namespace
#
# IDEMPOTENT: safe to re-run; it only creates what is missing.
#
# Restore procedure (from a workstation with cluster access):
#   gsutil cp gs://<project>-db-backups/<path>.dump /tmp/restore.dump
#   kubectl cp /tmp/restore.dump revops/<postgres-pod>:/tmp/restore.dump
#   kubectl exec -n revops <postgres-pod> -- \
#     pg_restore -U revops -d revops --clean --if-exists /tmp/restore.dump

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/gke-env.sh
source "$SCRIPT_DIR/gke-env.sh"

BUCKET="gs://${PROJECT_ID}-db-backups"
DR_REGION="${DR_REGION:-us-east1}"
DR_BUCKET="gs://${PROJECT_ID}-db-backups-dr"
BACKUP_GSA="revops-db-backup@${PROJECT_ID}.iam.gserviceaccount.com"
BACKUP_KSA="db-backup"           # k8s/overlays/production/db-backup.yaml
RETENTION_DAYS="${RETENTION_DAYS:-30}"

echo "=== DB backup setup (project: $PROJECT_ID) ==="

ensure_bucket() {
    local bucket="$1" location="$2"
    echo ""
    echo "  Ensuring bucket $bucket ($location)..."
    if ! gcloud storage buckets describe "$bucket" --project="$PROJECT_ID" >/dev/null 2>&1; then
        gcloud storage buckets create "$bucket" \
            --project="$PROJECT_ID" \
            --location="$location" \
            --uniform-bucket-level-access \
            --public-access-prevention
    else
        echo "  - Bucket already exists."
    fi
    # Versioning keeps overwritten/deleted dumps recoverable; the second rule
    # stops those noncurrent versions from accumulating forever.
    gcloud storage buckets update "$bucket" --project="$PROJECT_ID" --versioning
    gcloud storage buckets update "$bucket" --project="$PROJECT_ID" \
        --lifecycle-file="$LIFECYCLE_JSON"
}

LIFECYCLE_JSON="$(mktemp)"
trap 'rm -f "$LIFECYCLE_JSON"' EXIT
cat > "$LIFECYCLE_JSON" <<EOF
{"rule": [
  {"action": {"type": "Delete"}, "condition": {"age": ${RETENTION_DAYS}, "isLive": true}},
  {"action": {"type": "Delete"}, "condition": {"daysSinceNoncurrentTime": ${RETENTION_DAYS}}}
]}
EOF

echo ""
echo "1. Ensuring buckets (versioned, ${RETENTION_DAYS}-day lifecycle)..."
ensure_bucket "$BUCKET" "$REGION"
ensure_bucket "$DR_BUCKET" "$DR_REGION"

echo ""
echo "2. Ensuring GSA $BACKUP_GSA..."
if ! gcloud iam service-accounts describe "$BACKUP_GSA" --project="$PROJECT_ID" >/dev/null 2>&1; then
    gcloud iam service-accounts create "${BACKUP_GSA%%@*}" \
        --project="$PROJECT_ID" \
        --display-name="Nightly in-cluster postgres backup writer"
else
    echo "  - GSA already exists."
fi

echo ""
echo "3. Granting roles/storage.objectCreator on the buckets only..."
for b in "$BUCKET" "$DR_BUCKET"; do
    gcloud storage buckets add-iam-policy-binding "$b" \
        --project="$PROJECT_ID" \
        --member="serviceAccount:$BACKUP_GSA" \
        --role="roles/storage.objectCreator" >/dev/null
    echo "  - granted on $b."
done

echo ""
echo "4. Binding Workload Identity (${PROD_NAMESPACE}/${BACKUP_KSA} -> GSA)..."
gcloud iam service-accounts add-iam-policy-binding "$BACKUP_GSA" \
    --project="$PROJECT_ID" \
    --role="roles/iam.workloadIdentityUser" \
    --member="serviceAccount:${PROJECT_ID}.svc.id.goog[${PROD_NAMESPACE}/${BACKUP_KSA}]" >/dev/null
echo "  - bound."

echo ""
echo "=== Backup setup complete! ==="
echo "Apply the CronJob with: kubectl apply -k k8s/overlays/production"
echo "Trigger a test run:     kubectl create job --from=cronjob/db-backup db-backup-manual -n ${PROD_NAMESPACE}"

#!/bin/bash
# One-time GCP provisioning for the nightly in-cluster postgres backups
# (k8s/overlays/production/db-backup.yaml).
#
# Creates:
#   - GCS bucket gs://<project>-db-backups (uniform access, public access
#     prevention, 30-day lifecycle delete rule)
#   - GSA revops-db-backup@<project> with roles/storage.objectCreator on the
#     bucket only (write-only: a compromised pod cannot read old backups)
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
BACKUP_GSA="revops-db-backup@${PROJECT_ID}.iam.gserviceaccount.com"
BACKUP_KSA="db-backup"           # k8s/overlays/production/db-backup.yaml
RETENTION_DAYS="${RETENTION_DAYS:-30}"

echo "=== DB backup setup (project: $PROJECT_ID) ==="

echo ""
echo "1. Ensuring bucket $BUCKET..."
if ! gcloud storage buckets describe "$BUCKET" --project="$PROJECT_ID" >/dev/null 2>&1; then
    gcloud storage buckets create "$BUCKET" \
        --project="$PROJECT_ID" \
        --location="$REGION" \
        --uniform-bucket-level-access \
        --public-access-prevention
else
    echo "  - Bucket already exists."
fi

echo ""
echo "2. Setting ${RETENTION_DAYS}-day lifecycle delete rule..."
LIFECYCLE_JSON="$(mktemp)"
cat > "$LIFECYCLE_JSON" <<EOF
{"rule": [{"action": {"type": "Delete"}, "condition": {"age": ${RETENTION_DAYS}}}]}
EOF
gcloud storage buckets update "$BUCKET" --project="$PROJECT_ID" \
    --lifecycle-file="$LIFECYCLE_JSON"
rm -f "$LIFECYCLE_JSON"

echo ""
echo "3. Ensuring GSA $BACKUP_GSA..."
if ! gcloud iam service-accounts describe "$BACKUP_GSA" --project="$PROJECT_ID" >/dev/null 2>&1; then
    gcloud iam service-accounts create "${BACKUP_GSA%%@*}" \
        --project="$PROJECT_ID" \
        --display-name="Nightly in-cluster postgres backup writer"
else
    echo "  - GSA already exists."
fi

echo ""
echo "4. Granting roles/storage.objectCreator on the bucket only..."
gcloud storage buckets add-iam-policy-binding "$BUCKET" \
    --project="$PROJECT_ID" \
    --member="serviceAccount:$BACKUP_GSA" \
    --role="roles/storage.objectCreator" >/dev/null
echo "  - granted."

echo ""
echo "5. Binding Workload Identity (${PROD_NAMESPACE}/${BACKUP_KSA} -> GSA)..."
gcloud iam service-accounts add-iam-policy-binding "$BACKUP_GSA" \
    --project="$PROJECT_ID" \
    --role="roles/iam.workloadIdentityUser" \
    --member="serviceAccount:${PROJECT_ID}.svc.id.goog[${PROD_NAMESPACE}/${BACKUP_KSA}]" >/dev/null
echo "  - bound."

echo ""
echo "=== Backup setup complete! ==="
echo "Apply the CronJob with: kubectl apply -k k8s/overlays/production"
echo "Trigger a test run:     kubectl create job --from=cronjob/db-backup db-backup-manual -n ${PROD_NAMESPACE}"

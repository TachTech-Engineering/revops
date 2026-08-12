#!/bin/bash
# Cloud SQL (PostgreSQL) provisioning for the Panther Dashboard backend.
#
# Creates, per environment (staging + production):
#   - a Cloud SQL for PostgreSQL 15 instance (automated backups + PITR)
#   - the application database and a DB user with a generated password
#   - the DATABASE_URL / password stored in Secret Manager
# and, once, the shared plumbing:
#   - the GSA revops-backend@<project> with roles/cloudsql.client
#   - the Workload Identity bindings for the backend / staging-backend KSAs
#
# The backend connects through the Cloud SQL Auth Proxy v2 sidecar (see
# k8s/base/backend-deployment.yaml and migration-job.yaml), so every
# DATABASE_URL points at 127.0.0.1:5432 -- only the per-env password differs.
#
# IDEMPOTENT: safe to re-run. It never drops or recreates an existing instance,
# database, or password; it only creates what is missing and adds new secret
# versions.
#
# The USER runs this script; it performs billable provisioning. After it runs:
#   1. ./scripts/gke-secrets.sh      (loads DATABASE_URL into backend-secrets)
#   2. build images                  (cloudbuild-*.yaml)
#   3. ./scripts/gke-deploy.sh <env> <tag>
#
# Requirements before running:
#   - gcloud authenticated for project revops-486917
#   - GKE cluster created WITH Workload Identity (--workload-pool); the preflight
#     below checks this and prints the enable command if it is missing.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/gke-env.sh
source "$SCRIPT_DIR/gke-env.sh"

echo "=== Cloud SQL setup (project: $PROJECT_ID, region: $REGION) ==="
echo ""

# --- Guard rail: confirm the target project ------------------------------------
CURRENT_PROJECT="$(gcloud config get-value project 2>/dev/null || true)"
echo "Target project: $PROJECT_ID"
echo "gcloud active project: ${CURRENT_PROJECT:-<none>}"
read -r -p "Proceed provisioning Cloud SQL in '$PROJECT_ID'? [y/N] " CONFIRM
if [ "${CONFIRM:-}" != "y" ] && [ "${CONFIRM:-}" != "Y" ]; then
    echo "Aborted."
    exit 1
fi
echo ""

# --- Preflight: required API ---------------------------------------------------
echo "1. Ensuring sqladmin.googleapis.com is enabled..."
gcloud services enable sqladmin.googleapis.com --project="$PROJECT_ID"

# --- Preflight: Workload Identity on the cluster -------------------------------
echo ""
echo "2. Checking Workload Identity is enabled on cluster '$CLUSTER_NAME'..."
WI_POOL="$(gcloud container clusters describe "$CLUSTER_NAME" \
    --zone "$ZONE" --project="$PROJECT_ID" \
    --format='value(workloadIdentityConfig.workloadPool)' 2>/dev/null || true)"
if [ -z "$WI_POOL" ]; then
    echo "  WARNING: Workload Identity is NOT enabled on '$CLUSTER_NAME'." >&2
    echo "  Enable it (the deployment will not authenticate to Cloud SQL without it):" >&2
    echo "    gcloud container clusters update $CLUSTER_NAME --zone $ZONE \\" >&2
    echo "      --workload-pool=${PROJECT_ID}.svc.id.goog" >&2
    echo "  Then re-run this script." >&2
    exit 1
fi
echo "  Workload Identity pool: $WI_POOL"

# --- Shared: GSA + roles/cloudsql.client ---------------------------------------
GSA_ID="${BACKEND_GSA%%@*}"   # local part before '@'
echo ""
echo "3. Ensuring GSA $BACKEND_GSA exists with roles/cloudsql.client..."
if ! gcloud iam service-accounts describe "$BACKEND_GSA" --project="$PROJECT_ID" >/dev/null 2>&1; then
    gcloud iam service-accounts create "$GSA_ID" \
        --project="$PROJECT_ID" \
        --display-name="Panther Dashboard backend (Cloud SQL client)"
else
    echo "  - GSA already exists."
fi
# Grant is idempotent (add-iam-policy-binding is a no-op if already present).
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$BACKEND_GSA" \
    --role="roles/cloudsql.client" \
    --condition=None >/dev/null
echo "  roles/cloudsql.client granted."

# --- Shared: Workload Identity bindings ----------------------------------------
echo ""
echo "4. Binding Workload Identity (roles/iam.workloadIdentityUser)..."
for member in \
    "serviceAccount:${PROJECT_ID}.svc.id.goog[${PROD_NAMESPACE}/backend]" \
    "serviceAccount:${PROJECT_ID}.svc.id.goog[${STAGING_NAMESPACE}/staging-backend]" ; do
    echo "  - $member"
    gcloud iam service-accounts add-iam-policy-binding "$BACKEND_GSA" \
        --project="$PROJECT_ID" \
        --role="roles/iam.workloadIdentityUser" \
        --member="$member" >/dev/null
done

# --- Helpers -------------------------------------------------------------------
# Read an existing Secret Manager value, or generate + store a URL-safe password.
get_or_create_password() {
    local secret_id="$1"
    if gcloud secrets describe "$secret_id" --project="$PROJECT_ID" >/dev/null 2>&1; then
        gcloud secrets versions access latest --secret="$secret_id" --project="$PROJECT_ID"
    else
        local pw
        # URL-safe: alphanumeric only, so it needs no escaping in DATABASE_URL.
        pw="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)"
        printf '%s' "$pw" | gcloud secrets create "$secret_id" \
            --project="$PROJECT_ID" --data-file=- >/dev/null
        printf '%s' "$pw"
    fi
}

# Create the secret or add a new version (idempotent).
store_secret() {
    local secret_id="$1" value="$2"
    if gcloud secrets describe "$secret_id" --project="$PROJECT_ID" >/dev/null 2>&1; then
        printf '%s' "$value" | gcloud secrets versions add "$secret_id" \
            --project="$PROJECT_ID" --data-file=- >/dev/null
    else
        printf '%s' "$value" | gcloud secrets create "$secret_id" \
            --project="$PROJECT_ID" --data-file=- >/dev/null
    fi
}

# --- Per-environment instances -------------------------------------------------
declare -a CONN_NAMES=()

provision_env() {
    local env="$1" instance="$2" url_secret="$3"
    local pw_secret="db-password-${env}"
    local conn_name="${PROJECT_ID}:${REGION}:${instance}"

    echo ""
    echo "=== [$env] Cloud SQL instance: $instance ==="

    if ! gcloud sql instances describe "$instance" --project="$PROJECT_ID" >/dev/null 2>&1; then
        echo "  Creating instance (Postgres 15, backups + PITR, tier $CLOUDSQL_TIER)..."
        gcloud sql instances create "$instance" \
            --project="$PROJECT_ID" \
            --database-version="$CLOUDSQL_DB_VERSION" \
            --tier="$CLOUDSQL_TIER" \
            --region="$REGION" \
            --storage-auto-increase \
            --backup \
            --backup-start-time="03:00" \
            --enable-point-in-time-recovery \
            --retained-backups-count=7 \
            --retained-transaction-log-days=7
    else
        echo "  - Instance already exists (not modified)."
    fi

    echo "  Ensuring database '$CLOUDSQL_DB_NAME'..."
    gcloud sql databases create "$CLOUDSQL_DB_NAME" \
        --instance="$instance" --project="$PROJECT_ID" >/dev/null 2>&1 \
        || echo "  - Database already exists."

    echo "  Ensuring DB user '$CLOUDSQL_DB_USER' (password in Secret Manager: $pw_secret)..."
    local pw
    pw="$(get_or_create_password "$pw_secret")"
    if gcloud sql users list --instance="$instance" --project="$PROJECT_ID" \
            --format='value(name)' 2>/dev/null | grep -qx "$CLOUDSQL_DB_USER"; then
        gcloud sql users set-password "$CLOUDSQL_DB_USER" \
            --instance="$instance" --project="$PROJECT_ID" --password="$pw" >/dev/null
    else
        gcloud sql users create "$CLOUDSQL_DB_USER" \
            --instance="$instance" --project="$PROJECT_ID" --password="$pw" >/dev/null
    fi

    # Connection is always via the local Auth Proxy sidecar.
    local database_url="postgresql+asyncpg://${CLOUDSQL_DB_USER}:${pw}@127.0.0.1:5432/${CLOUDSQL_DB_NAME}"
    store_secret "$url_secret" "$database_url"
    echo "  Stored DATABASE_URL in Secret Manager secret: $url_secret"

    CONN_NAMES+=("$env -> $conn_name  (overlay CLOUD_SQL_INSTANCE)")
}

# Staging and production use SEPARATE instances and SEPARATE DATABASE_URL secrets.
provision_env "staging"    "$CLOUDSQL_STAGING_INSTANCE" "${DATABASE_URL_SECRET}-staging"
provision_env "production" "$CLOUDSQL_PROD_INSTANCE"    "${DATABASE_URL_SECRET}"

# --- Summary -------------------------------------------------------------------
echo ""
echo "=== Cloud SQL setup complete! ==="
echo ""
echo "Instance connection names (set as CLOUD_SQL_INSTANCE in the overlays):"
for line in "${CONN_NAMES[@]}"; do
    echo "  - $line"
done
echo ""
echo "The overlays are already wired to these values:"
echo "  k8s/overlays/staging/kustomization.yaml    -> ${PROJECT_ID}:${REGION}:${CLOUDSQL_STAGING_INSTANCE}"
echo "  k8s/overlays/production/kustomization.yaml  -> ${PROJECT_ID}:${REGION}:${CLOUDSQL_PROD_INSTANCE}"
echo "  If you changed the instance names, update CLOUD_SQL_INSTANCE in those files to match."
echo ""
echo "Next steps:"
echo "  1. ./scripts/gke-secrets.sh          # loads DATABASE_URL into backend-secrets (both namespaces)"
echo "  2. Build images (see README 'GKE Deployment')"
echo "  3. ./scripts/gke-deploy.sh staging <tag>   then   production"

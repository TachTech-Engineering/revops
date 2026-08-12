#!/bin/bash
# GKE Secrets Setup Script
# Creates secrets in Google Secret Manager and Kubernetes.
#
# The backend deployment (k8s/base/backend-deployment.yaml) requires a
# Secret named "backend-secrets" in the target namespace; this script
# creates it in both the production (revops) and staging (revops-staging)
# namespaces.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/gke-env.sh
source "$SCRIPT_DIR/gke-env.sh"

echo "=== Setting up secrets (project: $PROJECT_ID) ==="
echo ""

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "ERROR: .env file not found!"
    echo "Please create .env file with your Panther credentials first."
    exit 1
fi

# Source the .env file
source .env

# Validate required variables
if [ -z "${PANTHER_API_HOST:-}" ] || [ -z "${PANTHER_API_TOKEN:-}" ]; then
    echo "ERROR: PANTHER_API_HOST and PANTHER_API_TOKEN must be set in .env"
    exit 1
fi

# DATABASE_URL resolution order (per namespace), so staging and production can
# point at SEPARATE Cloud SQL instances:
#   1. Secret Manager, per environment, as populated by gke-cloudsql-setup.sh:
#        production namespace -> secret "$DATABASE_URL_SECRET"          (database-url)
#        staging namespace    -> secret "${DATABASE_URL_SECRET}-staging" (database-url-staging)
#   2. Fallback: the DATABASE_URL in .env (legacy / manually-managed DB).
# With the Cloud SQL Auth Proxy sidecar every URL is 127.0.0.1:5432, e.g.
#   postgresql+asyncpg://USER:PASSWORD@127.0.0.1:5432/DBNAME
# The hard requirement is checked per namespace below, after consulting Secret Manager.

# Prefer the per-environment Secret Manager value; fall back to .env DATABASE_URL.
resolve_db_url() {
    local secret_id="$1"
    if gcloud secrets describe "$secret_id" --project="$PROJECT_ID" >/dev/null 2>&1; then
        gcloud secrets versions access latest --secret="$secret_id" --project="$PROJECT_ID"
    else
        printf '%s' "${DATABASE_URL:-}"
    fi
}

# Generate a secret key if not set
if [ -z "${SECRET_KEY:-}" ]; then
    SECRET_KEY=$(openssl rand -hex 32)
    echo "Generated new SECRET_KEY"
fi

echo "1. Creating secrets in Google Secret Manager..."

create_or_update_secret() {
    local name="$1"
    local value="$2"
    echo "$value" | gcloud secrets create "$name" --project="$PROJECT_ID" --data-file=- 2>/dev/null \
        || echo "  - $name exists, adding new version..."
    echo "$value" | gcloud secrets versions add "$name" --project="$PROJECT_ID" --data-file=- 2>/dev/null || true
}

create_or_update_secret panther-api-host "$PANTHER_API_HOST"
create_or_update_secret panther-api-token "$PANTHER_API_TOKEN"
create_or_update_secret jwt-secret-key "$SECRET_KEY"
# Do NOT clobber a DATABASE_URL already provisioned by gke-cloudsql-setup.sh.
# Only seed the production secret from .env when it does not already exist.
if [ -n "${DATABASE_URL:-}" ] \
    && ! gcloud secrets describe "$DATABASE_URL_SECRET" --project="$PROJECT_ID" >/dev/null 2>&1; then
    create_or_update_secret "$DATABASE_URL_SECRET" "$DATABASE_URL"
fi

echo ""
echo "2. Creating Kubernetes namespaces..."
kubectl create namespace "$PROD_NAMESPACE" 2>/dev/null || echo "  - Namespace $PROD_NAMESPACE exists"
kubectl create namespace "$STAGING_NAMESPACE" 2>/dev/null || echo "  - Namespace $STAGING_NAMESPACE exists"

echo ""
echo "3. Creating Kubernetes secrets..."

for ns in "$PROD_NAMESPACE" "$STAGING_NAMESPACE"; do
    if [ "$ns" == "$STAGING_NAMESPACE" ]; then
        DB_SECRET_ID="${DATABASE_URL_SECRET}-staging"
    else
        DB_SECRET_ID="$DATABASE_URL_SECRET"
    fi
    NS_DB_URL="$(resolve_db_url "$DB_SECRET_ID")"
    if [ -z "$NS_DB_URL" ]; then
        echo "ERROR: no DATABASE_URL available for namespace '$ns'." >&2
        echo "  Run ./scripts/gke-cloudsql-setup.sh first, or set DATABASE_URL in .env." >&2
        exit 1
    fi
    kubectl create secret generic backend-secrets \
        --namespace="$ns" \
        --from-literal=PANTHER_API_HOST="$PANTHER_API_HOST" \
        --from-literal=PANTHER_API_TOKEN="$PANTHER_API_TOKEN" \
        --from-literal=SECRET_KEY="$SECRET_KEY" \
        --from-literal=DATABASE_URL="$NS_DB_URL" \
        --dry-run=client -o yaml | kubectl apply -f -
done

echo ""
echo "=== Secrets setup complete! ==="

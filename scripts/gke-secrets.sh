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

# DATABASE_URL must point at a real database (e.g. Cloud SQL). There is no
# Postgres deployed by the k8s manifests, and without this variable the
# backend silently falls back to localhost and crash-loops.
if [ -z "${DATABASE_URL:-}" ]; then
    echo "ERROR: DATABASE_URL must be set in .env"
    echo "It must point at a real database reachable from the cluster, e.g. Cloud SQL:"
    echo "  DATABASE_URL=postgresql+asyncpg://USER:PASSWORD@CLOUD_SQL_IP:5432/DBNAME"
    exit 1
fi

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
create_or_update_secret database-url "$DATABASE_URL"

echo ""
echo "2. Creating Kubernetes namespaces..."
kubectl create namespace "$PROD_NAMESPACE" 2>/dev/null || echo "  - Namespace $PROD_NAMESPACE exists"
kubectl create namespace "$STAGING_NAMESPACE" 2>/dev/null || echo "  - Namespace $STAGING_NAMESPACE exists"

echo ""
echo "3. Creating Kubernetes secrets..."

for ns in "$PROD_NAMESPACE" "$STAGING_NAMESPACE"; do
    kubectl create secret generic backend-secrets \
        --namespace="$ns" \
        --from-literal=PANTHER_API_HOST="$PANTHER_API_HOST" \
        --from-literal=PANTHER_API_TOKEN="$PANTHER_API_TOKEN" \
        --from-literal=SECRET_KEY="$SECRET_KEY" \
        --from-literal=DATABASE_URL="$DATABASE_URL" \
        --dry-run=client -o yaml | kubectl apply -f -
done

echo ""
echo "=== Secrets setup complete! ==="

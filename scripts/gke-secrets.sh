#!/bin/bash
# GKE Secrets Setup Script
# Creates secrets in Google Secret Manager and Kubernetes

set -e

PROJECT_ID="pantherutil"

echo "=== Setting up secrets ==="
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
if [ -z "$PANTHER_API_HOST" ] || [ -z "$PANTHER_API_TOKEN" ]; then
    echo "ERROR: PANTHER_API_HOST and PANTHER_API_TOKEN must be set in .env"
    exit 1
fi

# Generate a secret key if not set
if [ -z "$SECRET_KEY" ]; then
    SECRET_KEY=$(openssl rand -hex 32)
    echo "Generated new SECRET_KEY"
fi

echo "1. Creating secrets in Google Secret Manager..."

# Create secrets (will fail silently if they exist)
echo "$PANTHER_API_HOST" | gcloud secrets create panther-api-host --data-file=- 2>/dev/null \
    || echo "  - panther-api-host exists, updating..."
echo "$PANTHER_API_HOST" | gcloud secrets versions add panther-api-host --data-file=- 2>/dev/null || true

echo "$PANTHER_API_TOKEN" | gcloud secrets create panther-api-token --data-file=- 2>/dev/null \
    || echo "  - panther-api-token exists, updating..."
echo "$PANTHER_API_TOKEN" | gcloud secrets versions add panther-api-token --data-file=- 2>/dev/null || true

echo "$SECRET_KEY" | gcloud secrets create jwt-secret-key --data-file=- 2>/dev/null \
    || echo "  - jwt-secret-key exists, updating..."
echo "$SECRET_KEY" | gcloud secrets versions add jwt-secret-key --data-file=- 2>/dev/null || true

echo ""
echo "2. Creating Kubernetes namespace..."
kubectl create namespace panther-dashboard 2>/dev/null || echo "  - Namespace exists"
kubectl create namespace panther-dashboard-staging 2>/dev/null || echo "  - Staging namespace exists"

echo ""
echo "3. Creating Kubernetes secrets..."

# Create Kubernetes secret directly
kubectl create secret generic backend-secrets \
    --namespace=panther-dashboard \
    --from-literal=PANTHER_API_HOST="$PANTHER_API_HOST" \
    --from-literal=PANTHER_API_TOKEN="$PANTHER_API_TOKEN" \
    --from-literal=SECRET_KEY="$SECRET_KEY" \
    --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic backend-secrets \
    --namespace=panther-dashboard-staging \
    --from-literal=PANTHER_API_HOST="$PANTHER_API_HOST" \
    --from-literal=PANTHER_API_TOKEN="$PANTHER_API_TOKEN" \
    --from-literal=SECRET_KEY="$SECRET_KEY" \
    --dry-run=client -o yaml | kubectl apply -f -

echo ""
echo "=== Secrets setup complete! ==="

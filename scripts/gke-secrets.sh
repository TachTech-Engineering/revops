#!/bin/bash
# GKE Secrets Setup Script
# Creates secrets in Google Secret Manager and Kubernetes.
#
# The backend deployment (k8s/base/backend-deployment.yaml) requires a
# Secret named "backend-secrets" in the target namespace; this script
# creates it in both the production (revops) and staging (revops-staging)
# namespaces.
#
# It also creates DATABASE_PASSWORD (required by the in-cluster
# postgres-deployment.yaml) and the separate "backend-encryption-key" Secret.
# Both were missing until 2026-08-17, which meant this script could not
# actually stand a cluster back up: postgres would fail to start and the
# backend would come up unable to decrypt any stored connector credential.
#
# Existing values are preferred over freshly generated ones. ENCRYPTION_KEY in
# particular must never be regenerated for an existing database -- it decrypts
# connector credentials, so a new key silently makes every stored credential
# unreadable. Resolution order is Secret Manager, then .env, then generate.
# Keep Secret Manager current with ./scripts/backup-cluster-secrets.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/gke-env.sh
source "$SCRIPT_DIR/gke-env.sh"

echo "=== Setting up secrets (project: $PROJECT_ID) ==="
echo ""

# Which namespaces to write. Defaults to both for backwards compatibility, but
# a rebuild or a staging refresh should name its target: this script overwrites
# backend-secrets wholesale, so running it unqualified to set up staging would
# also rewrite production's secrets from whatever is in .env.
TARGET="${1:-both}"
case "$TARGET" in
    production) TARGET_NAMESPACES=("$PROD_NAMESPACE") ;;
    staging)    TARGET_NAMESPACES=("$STAGING_NAMESPACE") ;;
    both)       TARGET_NAMESPACES=("$PROD_NAMESPACE" "$STAGING_NAMESPACE") ;;
    *)
        echo "Usage: $0 [production|staging|both]   (default: both)" >&2
        exit 1
        ;;
esac
echo "Target namespace(s): ${TARGET_NAMESPACES[*]}"
echo ""

# .env is optional. It used to be mandatory, which meant recovery depended on a
# file that is not in the repository -- exactly the thing you do not have after
# losing a machine. Everything it supplies is also in Secret Manager (see
# ./scripts/backup-cluster-secrets.sh), so a rebuild can run from that alone.
if [ -f ".env" ]; then
    # shellcheck disable=SC1091
    source .env
    echo "Loaded .env"
else
    echo "No .env found; falling back to Secret Manager for all values."
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

# Read a value already held in Secret Manager, if any.
sm_value() {
    local secret_id="$1"
    if gcloud secrets describe "$secret_id" --project="$PROJECT_ID" >/dev/null 2>&1; then
        gcloud secrets versions access latest --secret="$secret_id" --project="$PROJECT_ID" 2>/dev/null
    fi
}

# Secret Manager first, then .env, then generate. Regenerating either of these
# against an existing database is destructive: SECRET_KEY invalidates every
# issued token, and ENCRYPTION_KEY makes stored connector credentials
# permanently undecryptable.
if [ -z "${PANTHER_API_HOST:-}" ]; then
    PANTHER_API_HOST="$(sm_value panther-api-host)"
fi
if [ -z "${PANTHER_API_TOKEN:-}" ]; then
    PANTHER_API_TOKEN="$(sm_value panther-api-token)"
fi
if [ -z "${PANTHER_API_HOST:-}" ] || [ -z "${PANTHER_API_TOKEN:-}" ]; then
    echo "ERROR: PANTHER_API_HOST and PANTHER_API_TOKEN must be available" >&2
    echo "  from .env or Secret Manager (panther-api-host / panther-api-token)." >&2
    exit 1
fi

if [ -z "${SECRET_KEY:-}" ]; then
    SECRET_KEY="$(sm_value jwt-secret-key)"
fi
if [ -z "${SECRET_KEY:-}" ]; then
    SECRET_KEY=$(openssl rand -hex 32)
    echo "Generated new SECRET_KEY (no existing value found)"
fi

if [ -z "${ENCRYPTION_KEY:-}" ]; then
    ENCRYPTION_KEY="$(sm_value encryption-key)"
fi
if [ -z "${ENCRYPTION_KEY:-}" ]; then
    # Fernet key: 32 url-safe base64-encoded bytes.
    ENCRYPTION_KEY=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
    echo "Generated new ENCRYPTION_KEY (no existing value found)"
    echo "  WARNING: if this cluster is being rebuilt against an existing" >&2
    echo "  database, stop now -- a new key cannot decrypt stored connector" >&2
    echo "  credentials. Restore the original from Secret Manager instead." >&2
fi

# The in-cluster postgres reads its password from backend-secrets, so the two
# must agree or the database will not accept the backend's DATABASE_URL.
if [ -z "${DATABASE_PASSWORD:-}" ]; then
    DATABASE_PASSWORD="$(sm_value database-password)"
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
create_or_update_secret encryption-key "$ENCRYPTION_KEY"
if [ -n "${DATABASE_PASSWORD:-}" ]; then
    create_or_update_secret database-password "$DATABASE_PASSWORD"
fi
# Do NOT clobber a DATABASE_URL already provisioned by gke-cloudsql-setup.sh.
# Only seed the production secret from .env when it does not already exist.
if [ -n "${DATABASE_URL:-}" ] \
    && ! gcloud secrets describe "$DATABASE_URL_SECRET" --project="$PROJECT_ID" >/dev/null 2>&1; then
    create_or_update_secret "$DATABASE_URL_SECRET" "$DATABASE_URL"
fi

echo ""
echo "2. Creating Kubernetes namespaces..."
for ns in "${TARGET_NAMESPACES[@]}"; do
    kubectl create namespace "$ns" 2>/dev/null || echo "  - Namespace $ns exists"
done

echo ""
echo "3. Creating Kubernetes secrets..."

for ns in "${TARGET_NAMESPACES[@]}"; do
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
    # DATABASE_PASSWORD must match the password inside this namespace's
    # DATABASE_URL: the in-cluster postgres is initialised from it, and a
    # mismatch means the database rejects every connection the backend makes.
    #
    # The URL wins over the ambient DATABASE_PASSWORD, which is resolved once
    # and is therefore production's. Preferring it would hand staging
    # production's password while staging's URL carried a different one.
    NS_DB_PASSWORD="$(printf '%s' "$NS_DB_URL" | sed -n 's|^[^:]*://[^:]*:\([^@]*\)@.*|\1|p')"
    if [ -z "$NS_DB_PASSWORD" ]; then
        NS_DB_PASSWORD="${DATABASE_PASSWORD:-}"
    fi
    if [ -z "$NS_DB_PASSWORD" ]; then
        echo "ERROR: could not determine DATABASE_PASSWORD for namespace '$ns'." >&2
        echo "  postgres-deployment.yaml reads it from backend-secrets." >&2
        exit 1
    fi

    kubectl create secret generic backend-secrets \
        --namespace="$ns" \
        --from-literal=PANTHER_API_HOST="$PANTHER_API_HOST" \
        --from-literal=PANTHER_API_TOKEN="$PANTHER_API_TOKEN" \
        --from-literal=SECRET_KEY="$SECRET_KEY" \
        --from-literal=DATABASE_URL="$NS_DB_URL" \
        --from-literal=DATABASE_PASSWORD="$NS_DB_PASSWORD" \
        --dry-run=client -o yaml | kubectl apply -f -

    # Separate Secret, referenced by name from backend-deployment.yaml.
    kubectl create secret generic backend-encryption-key \
        --namespace="$ns" \
        --from-literal=ENCRYPTION_KEY="$ENCRYPTION_KEY" \
        --dry-run=client -o yaml | kubectl apply -f -
done

echo ""
echo "=== Secrets setup complete! ==="

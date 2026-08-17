#!/bin/bash
# Copy the cluster's secret material into Google Secret Manager.
#
# Why this exists: the database backups in GCS restore cleanly (verified
# 2026-08-17), but a restored database is not a recovered system. Connector
# credentials are Fernet-encrypted with ENCRYPTION_KEY, and that key lived
# ONLY inside the cluster -- lose the cluster and the restored rows are
# permanently unreadable. SECRET_KEY has the same property for sessions:
# rotating it invalidates every issued token, and encryption_service also
# derives from it.
#
# Run after any secret change. It is idempotent and adds a new Secret Manager
# version only when the value actually differs, so repeated runs do not
# accumulate identical versions.
#
# Values are piped, never passed as arguments and never echoed, so they do not
# land in shell history, process listings, or this script's output.
#
# Usage: ./scripts/backup-cluster-secrets.sh [namespace]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/gke-env.sh
source "$SCRIPT_DIR/gke-env.sh"

NAMESPACE="${1:-$PROD_NAMESPACE}"

echo "=== Backing up cluster secrets to Secret Manager ==="
echo "Project:   $PROJECT_ID"
echo "Namespace: $NAMESPACE"
echo ""

# k8s-secret:k8s-key:secret-manager-id
# The ids match what gke-secrets.sh reads back, so a rebuild is symmetric.
MAPPINGS=(
    "backend-secrets:DATABASE_URL:${DATABASE_URL_SECRET}"
    "backend-secrets:DATABASE_PASSWORD:database-password"
    "backend-secrets:SECRET_KEY:jwt-secret-key"
    "backend-secrets:PANTHER_API_HOST:panther-api-host"
    "backend-secrets:PANTHER_API_TOKEN:panther-api-token"
    "backend-encryption-key:ENCRYPTION_KEY:encryption-key"
)

backed_up=0
unchanged=0
missing=0

for mapping in "${MAPPINGS[@]}"; do
    IFS=':' read -r k8s_secret k8s_key sm_id <<< "$mapping"

    if ! kubectl get secret "$k8s_secret" -n "$NAMESPACE" >/dev/null 2>&1; then
        echo "  SKIP $sm_id -- secret/$k8s_secret not found in $NAMESPACE"
        missing=$((missing + 1))
        continue
    fi

    encoded="$(kubectl get secret "$k8s_secret" -n "$NAMESPACE" \
        -o "jsonpath={.data.$k8s_key}" 2>/dev/null || true)"
    if [ -z "$encoded" ]; then
        echo "  SKIP $sm_id -- key $k8s_key absent from secret/$k8s_secret"
        missing=$((missing + 1))
        continue
    fi

    tmp="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '$tmp'" RETURN
    printf '%s' "$encoded" | base64 -d > "$tmp"

    if ! gcloud secrets describe "$sm_id" --project="$PROJECT_ID" >/dev/null 2>&1; then
        gcloud secrets create "$sm_id" --project="$PROJECT_ID" \
            --replication-policy=automatic --data-file="$tmp" >/dev/null
        echo "  CREATED $sm_id"
        backed_up=$((backed_up + 1))
    else
        current="$(mktemp)"
        if gcloud secrets versions access latest --secret="$sm_id" \
            --project="$PROJECT_ID" > "$current" 2>/dev/null && cmp -s "$tmp" "$current"; then
            echo "  UNCHANGED $sm_id"
            unchanged=$((unchanged + 1))
        else
            gcloud secrets versions add "$sm_id" --project="$PROJECT_ID" \
                --data-file="$tmp" >/dev/null
            echo "  NEW VERSION $sm_id"
            backed_up=$((backed_up + 1))
        fi
        rm -f "$current"
    fi

    rm -f "$tmp"
done

echo ""
echo "Backed up: $backed_up   unchanged: $unchanged   missing: $missing"
if [ "$missing" -gt 0 ]; then
    echo ""
    echo "WARNING: $missing secret(s) could not be read. A restore will be" >&2
    echo "incomplete until they exist -- see docs/disaster-recovery.md." >&2
    exit 1
fi
echo "Restore procedure: docs/disaster-recovery.md"

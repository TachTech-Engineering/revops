#!/bin/bash
# Deploy to GKE.
#
# Usage: ./scripts/gke-deploy.sh <staging|production> <image-tag>
#
# <image-tag> is the tag pushed by Cloud Build (the short commit SHA). It is
# required: deploying without pinning a tag re-applies whatever tag the
# overlay was last set to and the rollout silently no-ops.
#
# The tag must be a commit on origin/main (set ALLOW_UNPUSHED_TAG=1 to
# override in an emergency) -- see the guardrail below for why.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=scripts/gke-env.sh
source "$SCRIPT_DIR/gke-env.sh"

ENVIRONMENT="${1:-}"
TAG="${2:-}"

usage() {
    echo "Usage: ./scripts/gke-deploy.sh <staging|production> <image-tag>"
    echo "Example: ./scripts/gke-deploy.sh staging \$(git rev-parse --short HEAD)"
}

if [ "$ENVIRONMENT" != "staging" ] && [ "$ENVIRONMENT" != "production" ]; then
    usage
    exit 1
fi

if [ -z "$TAG" ]; then
    echo "ERROR: no image tag given." >&2
    echo "Pass the tag that Cloud Build pushed (it tags every build with the short commit SHA)." >&2
    usage >&2
    exit 1
fi

# Guardrail: refuse to deploy a commit that is not on origin/main.
#
# On 2026-08-20 production was deployed from a checkout whose commits were
# never pushed; when that machine's state was lost, the running code (and its
# alembic migrations) existed nowhere but inside the image, and the next
# deploy from main aborted against an unknown DB revision. Recovering it meant
# extracting source from the image. This check makes that mistake loud.
#
# Note this cannot verify what is inside the image itself (gcloud builds
# submit uploads the working tree, not the commit), so keep the tree clean
# when building. Escape hatch for true emergencies: ALLOW_UNPUSHED_TAG=1.
if [ "${ALLOW_UNPUSHED_TAG:-}" != "1" ]; then
    if ! git -C "$REPO_ROOT" fetch origin main --quiet; then
        echo "ERROR: could not fetch origin/main to verify tag '$TAG' is pushed." >&2
        echo "Fix connectivity or, if you accept deploying unverified code, re-run with ALLOW_UNPUSHED_TAG=1." >&2
        exit 1
    fi
    if ! git -C "$REPO_ROOT" cat-file -e "${TAG}^{commit}" 2>/dev/null; then
        echo "ERROR: tag '$TAG' does not resolve to a commit in this clone." >&2
        echo "Deploy tags must be the short SHA of a pushed commit; a tag nobody can" >&2
        echo "resolve later is unrecoverable if this machine is lost." >&2
        echo "Override (emergencies only): ALLOW_UNPUSHED_TAG=1" >&2
        exit 1
    fi
    if ! git -C "$REPO_ROOT" merge-base --is-ancestor "$TAG" origin/main 2>/dev/null; then
        echo "ERROR: commit '$TAG' is not on origin/main." >&2
        echo "Push it first (git push origin main); deploying unpushed commits strands" >&2
        echo "the running code and its migrations inside the image." >&2
        echo "Override (emergencies only): ALLOW_UNPUSHED_TAG=1" >&2
        exit 1
    fi
fi

if ! command -v kustomize >/dev/null 2>&1; then
    echo "ERROR: kustomize is required (kubectl alone cannot 'edit set image')." >&2
    echo "Install: https://kubectl.docs.kubernetes.io/installation/kustomize/" >&2
    exit 1
fi

if [ "$ENVIRONMENT" == "staging" ]; then
    NAMESPACE="$STAGING_NAMESPACE"
    PREFIX="staging-"
else
    NAMESPACE="$PROD_NAMESPACE"
    PREFIX=""
fi

OVERLAY="$REPO_ROOT/k8s/overlays/$ENVIRONMENT"

echo "=== Deploying to GKE ($ENVIRONMENT) ==="
echo "Project:   $PROJECT_ID"
echo "Namespace: $NAMESPACE"
echo "Tag:       $TAG"
echo ""

# Pin the image tags in the overlay, then apply.
echo "1. Setting image tags in overlay..."
(
    cd "$OVERLAY"
    kustomize edit set image "${BACKEND_IMAGE}=${BACKEND_IMAGE}:${TAG}"
    kustomize edit set image "${FRONTEND_IMAGE}=${FRONTEND_IMAGE}:${TAG}"
)

echo ""
echo "2. Running database migrations..."
MIGRATE_JOB="${PREFIX}backend-migrate"
# Job pod specs are immutable, so drop any previous run before re-applying
# with the new image tag.
kubectl delete job "$MIGRATE_JOB" -n "$NAMESPACE" --ignore-not-found
# The migration Job depends on the backend-config ConfigMap and the Workload
# Identity ServiceAccount (backend / staging-backend) -- a pod referencing a
# missing ServiceAccount is rejected, so both must exist BEFORE the Job. Apply
# those prerequisites plus the Job, WITHOUT rolling the app Deployments (which
# must not update until migrations succeed). Filter the render by kind so only
# {ConfigMap, ServiceAccount, Job} are applied here.
RENDERED="$(kustomize build "$OVERLAY")"
printf '%s\n' "$RENDERED" | python3 -c '
import sys
keep = set(sys.argv[1:])
for doc in sys.stdin.read().split("\n---\n"):
    for line in doc.splitlines():
        s = line.strip()
        if s.startswith("kind:"):
            if s.split(":", 1)[1].strip() in keep:
                sys.stdout.write(doc.rstrip("\n") + "\n---\n")
            break
' ConfigMap ServiceAccount Job | kubectl apply -f -

echo "   Waiting for migration job to complete..."
MIGRATE_OK=""
for _ in $(seq 1 60); do
    COMPLETE=$(kubectl get job "$MIGRATE_JOB" -n "$NAMESPACE" \
        -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}' 2>/dev/null || true)
    FAILED=$(kubectl get job "$MIGRATE_JOB" -n "$NAMESPACE" \
        -o jsonpath='{.status.conditions[?(@.type=="Failed")].status}' 2>/dev/null || true)
    if [ "$COMPLETE" == "True" ]; then
        MIGRATE_OK="yes"
        break
    fi
    if [ "$FAILED" == "True" ]; then
        break
    fi
    sleep 5
done

if [ "$MIGRATE_OK" != "yes" ]; then
    echo "ERROR: migration job did not complete successfully. Aborting deploy." >&2
    echo "--- migration job logs ---" >&2
    kubectl logs "job/$MIGRATE_JOB" -n "$NAMESPACE" --tail=100 >&2 || true
    exit 1
fi
echo "   Migrations applied."

echo ""
echo "3. Applying Kubernetes manifests..."
kubectl apply -k "$OVERLAY"

echo ""
echo "4. Waiting for deployments to be ready..."
kubectl rollout status "deployment/${PREFIX}frontend" -n "$NAMESPACE" --timeout=300s
kubectl rollout status "deployment/${PREFIX}backend" -n "$NAMESPACE" --timeout=300s
kubectl rollout status "deployment/${PREFIX}redis" -n "$NAMESPACE" --timeout=300s

echo ""
echo "5. Deployment status:"
kubectl get pods -n "$NAMESPACE"
echo ""
kubectl get services -n "$NAMESPACE"
echo ""
kubectl get ingress -n "$NAMESPACE"

echo ""
echo "=== Deployment complete! ==="
echo ""

INGRESS_IP=$(kubectl get ingress -n "$NAMESPACE" -o jsonpath='{.items[0].status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "pending")
echo "Ingress IP: $INGRESS_IP"
echo ""
echo "Note: It may take a few minutes for the load balancer and SSL certificate to be ready."

#!/bin/bash
# Single source of truth for GCP/GKE deployment variables.
# Sourced by the other scripts in this directory.
# Override any value via environment, e.g.:
#   PROJECT_ID=my-project ./scripts/gke-deploy.sh production abc1234

PROJECT_ID="${PROJECT_ID:-revops-486917}"
REGION="${REGION:-us-central1}"
ZONE="${ZONE:-${REGION}-a}"
CLUSTER_NAME="${CLUSTER_NAME:-panther-dashboard-cluster}"

# Artifact Registry repository (matches cloudbuild-*.yaml and k8s manifests)
REGISTRY="${REGISTRY:-us-docker.pkg.dev/${PROJECT_ID}/gcr.io}"
BACKEND_IMAGE="${BACKEND_IMAGE:-${REGISTRY}/panther-dashboard-backend}"
FRONTEND_IMAGE="${FRONTEND_IMAGE:-${REGISTRY}/panther-dashboard-frontend}"

# Kubernetes namespaces (must match k8s/base and k8s/overlays/staging kustomizations)
PROD_NAMESPACE="${PROD_NAMESPACE:-revops}"
STAGING_NAMESPACE="${STAGING_NAMESPACE:-revops-staging}"

# --- Cloud SQL (PostgreSQL) ---
# Instances are provisioned by scripts/gke-cloudsql-setup.sh. Staging and
# production use SEPARATE instances. The instance connection name that the
# Cloud SQL Auth Proxy sidecar needs is "${PROJECT_ID}:${REGION}:${INSTANCE}"
# and is set per-overlay in k8s/overlays/*/kustomization.yaml (CLOUD_SQL_INSTANCE).
CLOUDSQL_PROD_INSTANCE="${CLOUDSQL_PROD_INSTANCE:-revops-db}"
CLOUDSQL_STAGING_INSTANCE="${CLOUDSQL_STAGING_INSTANCE:-revops-staging-db}"
CLOUDSQL_DB_VERSION="${CLOUDSQL_DB_VERSION:-POSTGRES_15}"
CLOUDSQL_TIER="${CLOUDSQL_TIER:-db-custom-1-3840}"   # 1 vCPU / 3.75GB; override for prod sizing
CLOUDSQL_DB_NAME="${CLOUDSQL_DB_NAME:-panther_dashboard}"
CLOUDSQL_DB_USER="${CLOUDSQL_DB_USER:-panther}"

# Google Service Account bound to the "backend" KSA via Workload Identity.
# Holds roles/cloudsql.client. Matches the annotation in k8s/base/serviceaccount.yaml.
BACKEND_GSA="${BACKEND_GSA:-revops-backend@${PROJECT_ID}.iam.gserviceaccount.com}"

# Secret Manager secret id that gke-secrets.sh reads for DATABASE_URL.
DATABASE_URL_SECRET="${DATABASE_URL_SECRET:-database-url}"

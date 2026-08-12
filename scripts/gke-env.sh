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

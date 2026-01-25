#!/bin/bash
# GKE Setup Script for Panther Dashboard
# Project: pantherutil

set -e

PROJECT_ID="pantherutil"
CLUSTER_NAME="panther-dashboard-cluster"
REGION="us-central1"
ZONE="${REGION}-a"

echo "=== Panther Dashboard GKE Setup ==="
echo "Project: $PROJECT_ID"
echo ""

# Set project
echo "1. Setting GCP project..."
gcloud config set project $PROJECT_ID

# Enable required APIs
echo "2. Enabling required APIs..."
gcloud services enable container.googleapis.com
gcloud services enable containerregistry.googleapis.com
gcloud services enable secretmanager.googleapis.com

# Create GKE cluster
echo "3. Creating GKE cluster (this may take several minutes)..."
gcloud container clusters create $CLUSTER_NAME \
  --zone $ZONE \
  --num-nodes 3 \
  --machine-type e2-medium \
  --enable-ip-alias \
  --workload-pool=${PROJECT_ID}.svc.id.goog \
  || echo "Cluster may already exist, continuing..."

# Get cluster credentials
echo "4. Getting cluster credentials..."
gcloud container clusters get-credentials $CLUSTER_NAME --zone $ZONE

# Reserve static IP for ingress
echo "5. Reserving static IP for ingress..."
gcloud compute addresses create panther-dashboard-ip --global \
  || echo "Static IP may already exist, continuing..."

# Show the reserved IP
echo ""
echo "Reserved static IP:"
gcloud compute addresses describe panther-dashboard-ip --global --format="get(address)"

echo ""
echo "=== GKE cluster setup complete! ==="
echo ""
echo "Next steps:"
echo "  1. Run: ./scripts/gke-secrets.sh"
echo "  2. Run: ./scripts/gke-build.sh"
echo "  3. Run: ./scripts/gke-deploy.sh staging"

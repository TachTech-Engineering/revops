#!/bin/bash
# Deploy to GKE

set -e

ENVIRONMENT="${1:-staging}"

echo "=== Deploying to GKE ($ENVIRONMENT) ==="
echo ""

if [ "$ENVIRONMENT" != "staging" ] && [ "$ENVIRONMENT" != "production" ]; then
    echo "Usage: ./scripts/gke-deploy.sh [staging|production]"
    exit 1
fi

# Deploy using kustomize
echo "1. Applying Kubernetes manifests..."
kubectl apply -k k8s/overlays/$ENVIRONMENT

# Wait for deployments
echo ""
echo "2. Waiting for deployments to be ready..."

if [ "$ENVIRONMENT" == "staging" ]; then
    NAMESPACE="panther-dashboard-staging"
    PREFIX="staging-"
else
    NAMESPACE="panther-dashboard"
    PREFIX=""
fi

kubectl rollout status deployment/${PREFIX}frontend -n $NAMESPACE --timeout=300s
kubectl rollout status deployment/${PREFIX}backend -n $NAMESPACE --timeout=300s
kubectl rollout status deployment/${PREFIX}redis -n $NAMESPACE --timeout=300s

# Show status
echo ""
echo "3. Deployment status:"
kubectl get pods -n $NAMESPACE
echo ""
kubectl get services -n $NAMESPACE
echo ""
kubectl get ingress -n $NAMESPACE

echo ""
echo "=== Deployment complete! ==="
echo ""

# Get ingress IP
INGRESS_IP=$(kubectl get ingress -n $NAMESPACE -o jsonpath='{.items[0].status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "pending")
echo "Ingress IP: $INGRESS_IP"
echo ""
echo "Note: It may take a few minutes for the load balancer and SSL certificate to be ready."
echo "You can access the dashboard at: https://panther-dashboard.example.com"
echo "Or temporarily at: http://$INGRESS_IP (if IP is available)"

#!/bin/bash
# Build and push Docker images to GCR

set -e

PROJECT_ID="pantherutil"
TAG="${1:-latest}"

echo "=== Building Docker images ==="
echo "Project: $PROJECT_ID"
echo "Tag: $TAG"
echo ""

# Configure Docker for GCR
echo "1. Configuring Docker for GCR..."
gcloud auth configure-docker --quiet

# Build frontend
echo ""
echo "2. Building frontend image..."
docker build \
    -t gcr.io/$PROJECT_ID/panther-dashboard-frontend:$TAG \
    -f packages/frontend/Dockerfile \
    packages/frontend

# Build backend (with panther_sdk included)
echo ""
echo "3. Building backend image..."

# Create a temporary directory with backend + SDK
TEMP_BUILD=$(mktemp -d)
cp -r packages/backend/* "$TEMP_BUILD/"
cp -r C:/Source/panther_sdk "$TEMP_BUILD/panther_sdk"

# Create enhanced Dockerfile
cat > "$TEMP_BUILD/Dockerfile.gke" << 'EOF'
FROM python:3.11-slim

WORKDIR /app

# Copy and install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy panther_sdk
COPY panther_sdk /app/panther_sdk
RUN pip install --no-cache-dir -e /app/panther_sdk

# Copy application
COPY app ./app

# Create non-root user
RUN useradd --create-home --shell /bin/bash appuser && \
    chown -R appuser:appuser /app
USER appuser

ENV PYTHONPATH=/app:/app/panther_sdk

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
EOF

docker build \
    -t gcr.io/$PROJECT_ID/panther-dashboard-backend:$TAG \
    -f "$TEMP_BUILD/Dockerfile.gke" \
    "$TEMP_BUILD"

# Cleanup
rm -rf "$TEMP_BUILD"

# Push images
echo ""
echo "4. Pushing images to GCR..."
docker push gcr.io/$PROJECT_ID/panther-dashboard-frontend:$TAG
docker push gcr.io/$PROJECT_ID/panther-dashboard-backend:$TAG

echo ""
echo "=== Build complete! ==="
echo ""
echo "Images pushed:"
echo "  - gcr.io/$PROJECT_ID/panther-dashboard-frontend:$TAG"
echo "  - gcr.io/$PROJECT_ID/panther-dashboard-backend:$TAG"

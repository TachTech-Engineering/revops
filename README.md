# Panther Dashboard

A full-stack web dashboard for the Panther SDK, featuring alert management, SPL-to-Panther rule conversion, and a rule editor with Monaco.

## Features

- **Alert Dashboard** - View, filter, triage, and respond to security alerts
- **Rule Editor** - Create and edit detection rules with Monaco code editor
- **SPL Converter** - Convert Splunk SPL queries to Panther Python rules

## Tech Stack

- **Frontend**: React + TypeScript, Vite, Redux Toolkit, Tailwind CSS, Monaco Editor
- **Backend**: Python FastAPI, Panther SDK
- **Deployment**: Google Kubernetes Engine (GKE)

## Prerequisites

- Node.js 20+
- Python 3.11+
- Docker and Docker Compose
- pnpm (`npm install -g pnpm`)

## Quick Start

### 1. Clone and Setup

```bash
cd C:/Source/panther-dashboard
cp .env.example .env
```

Edit `.env` with your Panther credentials:

```
PANTHER_API_HOST=your-instance.runpanther.net
PANTHER_API_TOKEN=your-api-token
SECRET_KEY=your-secret-key
```

### 2. Local Development with Docker

```bash
# Start all services
docker-compose -f docker-compose.dev.yml up --build

# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/api/v1/docs
```

### 3. Manual Development Setup

**Frontend:**
```bash
cd packages/frontend
pnpm install
pnpm dev
```

**Backend:**
```bash
cd packages/backend
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
pip install -e C:/Source/panther-sdk  # Install SDK locally
uvicorn app.main:app --reload
```

## Project Structure

```
panther-dashboard/
├── packages/
│   ├── frontend/          # React TypeScript app
│   │   ├── src/
│   │   │   ├── api/       # RTK Query API
│   │   │   ├── components/
│   │   │   ├── pages/
│   │   │   ├── store/     # Redux store
│   │   │   └── types/
│   │   └── Dockerfile
│   └── backend/           # FastAPI app
│       ├── app/
│       │   ├── api/v1/    # REST endpoints
│       │   ├── services/  # SDK wrappers
│       │   └── config.py
│       └── Dockerfile
├── k8s/                   # Kubernetes manifests
│   ├── base/
│   └── overlays/
└── docker-compose.yml
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/alerts` | List alerts |
| GET | `/api/v1/alerts/{id}` | Get alert |
| PATCH | `/api/v1/alerts/{id}` | Update alert |
| GET | `/api/v1/rules` | List rules |
| POST | `/api/v1/rules` | Create rule |
| PATCH | `/api/v1/rules/{id}` | Update rule |
| DELETE | `/api/v1/rules/{id}` | Delete rule |
| POST | `/api/v1/converter/convert` | Convert SPL |

## GKE Deployment

### 1. Setup GCP

```bash
# Create GKE cluster
gcloud container clusters create panther-dashboard-cluster \
  --zone us-central1-a \
  --num-nodes 3

# Reserve static IP
gcloud compute addresses create panther-dashboard-ip --global

# Create secrets in Secret Manager
gcloud secrets create panther-api-token --data-file=- <<< "your-token"
gcloud secrets create jwt-secret-key --data-file=- <<< "your-secret"
```

### 2. Build and Push Images

```bash
# Configure Docker for GCR
gcloud auth configure-docker

# Build and push
docker build -t gcr.io/PROJECT_ID/panther-dashboard-frontend packages/frontend
docker build -t gcr.io/PROJECT_ID/panther-dashboard-backend packages/backend
docker push gcr.io/PROJECT_ID/panther-dashboard-frontend
docker push gcr.io/PROJECT_ID/panther-dashboard-backend
```

### 3. Deploy

```bash
# Staging
kubectl apply -k k8s/overlays/staging

# Production
kubectl apply -k k8s/overlays/production
```

## Development

### Running Tests

```bash
# Frontend
cd packages/frontend
pnpm test

# Backend
cd packages/backend
pytest
```

### Linting

```bash
# Frontend
pnpm lint

# Backend
ruff check .
mypy app
```

## License

MIT

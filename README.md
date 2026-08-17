# RevOps - Security Operations Platform

A comprehensive Security Operations Center (SOC) platform that unifies alert management, detection engineering, threat intelligence, and incident response across multiple security tools. Built on top of the Panther SDK with support for multi-vendor data source integrations.

## Overview

RevOps provides a unified interface for SOC teams to manage security operations across their entire security stack. It aggregates alerts from SIEM, EDR, XDR, cloud security, and identity platforms into a single pane of glass with AI-powered alert clustering, natural language querying, and automated response capabilities.

## Key Features

### Alert Management & Triage
- **Unified Alerts View** - Aggregate alerts from multiple security tools (Panther, CrowdStrike, SentinelOne, Microsoft Defender, AWS Security Hub, etc.)
- **AI-Powered Alert Clustering** - Automatically group related alerts to reduce noise and identify attack patterns
- **Smart Triage** - Bulk actions, severity adjustment, and assignment workflows
- **Natural Language Queries** - Search alerts and investigate using plain English

### Detection Engineering
- **Rule Editor** - Create and edit Panther detection rules with Monaco code editor
- **SPL-to-Panther Converter** - Migrate Splunk SPL queries to Panther Python rules
- **Rule Health Dashboard** - Monitor detection performance, false positive rates, and coverage gaps
- **Rule Versioning** - Track changes and rollback to previous versions
- **Correlation Rules** - Define multi-event detection logic
- **Suppression Rules** - Reduce noise from known benign activity

### Incident Response
- **Case Management** - Create, assign, and track security investigations
- **Incident Tracking** - Link related alerts and evidence to incidents
- **Playbooks** - Automated and guided response workflows
- **Workflow Automation** - Visual workflow builder for automated actions

### Threat Intelligence
- **Threat Intel Feeds** - Ingest and correlate IOCs from multiple sources
- **IOC Search** - Query indicators across your environment
- **Threat Hunting** - Proactive search interface with saved queries
- **MITRE ATT&CK Coverage** - Visualize detection coverage against the ATT&CK framework
- **Attack Simulation** - Test detection coverage with simulated attacks

### Data Source Connectors
Supported integrations organized by category:

| Category | Connectors |
|----------|------------|
| **SIEM** | Panther, Google SecOps, Splunk, Microsoft Sentinel, Elastic, Sumo Logic |
| **EDR/XDR** | CrowdStrike Falcon, SentinelOne, Microsoft Defender XDR, Carbon Black |
| **Cloud Security** | AWS Security Hub, AWS GuardDuty, GCP Security Command Center, Azure Defender, Wiz, Prowler |
| **Runtime Security** | Falco (webhook push via http_output or Falcosidekick) |
| **Identity** | Okta, Microsoft Entra ID, CrowdStrike Identity Protection |
| **Network** | Cloudflare, UniFi Network |

### Analytics & Reporting
- **Executive Summary** - High-level security posture overview for leadership
- **Analytics Dashboard** - Trend analysis and operational metrics
- **Compliance Dashboard** - Track compliance status across frameworks
- **SLA Dashboard** - Monitor response time SLAs and policy compliance
- **Custom Dashboards** - Build personalized views with drag-and-drop widgets
- **Report Builder** - Generate scheduled or on-demand reports
- **Query Explorer** - Ad-hoc data exploration with SQL and natural language

### Operations Management
- **On-Call Schedules** - Manage analyst rotation schedules
- **Escalation Policies** - Define escalation paths and timeouts
- **Shift Handoff** - Document and transfer context between shifts
- **Real-time Presence** - See who's online and working

### Integrations
- **Ticketing** - Jira, ServiceNow
- **Alerting** - PagerDuty, OpsGenie, Slack, Microsoft Teams, Email
- **Telephony** - Twilio/Fonoster for voice escalations
- **Webhooks** - Custom integrations via webhooks
- **SSO/SAML** - Enterprise single sign-on support

### Data Pipeline
- **Enrichment Pipelines** - Automatically enrich alerts with context
- **Data Pipelines** - Transform and route data between systems
- **Asset Criticality** - Define business criticality for assets

## Tech Stack

- **Frontend**: React 18, TypeScript, Vite, Redux Toolkit, Tailwind CSS, Monaco Editor, ReactFlow
- **Backend**: Python 3.11+, FastAPI, SQLAlchemy, PostgreSQL, Redis
- **Infrastructure**: Docker, Kubernetes (GKE), GCP
- **CI**: GitHub Actions (`.github/workflows/ci.yml` — backend lint/import/tests, frontend lint/build, Docker image builds, kustomize overlay validation)
- **Image builds**: Google Cloud Build (`cloudbuild-backend.yaml`, `cloudbuild-frontend.yaml`)

## Prerequisites

- Node.js 20+
- Python 3.11+
- Docker and Docker Compose
- pnpm (`npm install -g pnpm`)

## Quick Start

### 1. Clone and Setup

```bash
git clone https://github.com/TachTech-Engineering/revops.git
cd revops
cp .env.example .env
```

Edit `.env` with your credentials:

```bash
# Required
PANTHER_API_HOST=your-instance.runpanther.net
PANTHER_API_TOKEN=your-api-token
SECRET_KEY=your-secret-key-for-jwt

# Optional - for telephony integration
TWILIO_ACCOUNT_SID=your-twilio-sid
TWILIO_AUTH_TOKEN=your-twilio-token
TWILIO_PHONE_NUMBER=+1234567890
```

### 2. Start with Docker Compose

```bash
# Start all services (frontend, backend, postgres, redis)
docker-compose up --build

# Frontend:    http://localhost:3000
# Backend API: http://localhost:8000
# API Docs:    http://localhost:8000/api/v1/docs
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
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Project Structure

```
revops/
├── packages/
│   ├── frontend/              # React TypeScript application
│   │   ├── src/
│   │   │   ├── api/           # RTK Query API definitions
│   │   │   ├── components/    # Reusable UI components
│   │   │   ├── pages/         # Page components
│   │   │   ├── store/         # Redux store configuration
│   │   │   ├── hooks/         # Custom React hooks
│   │   │   └── types/         # TypeScript type definitions
│   │   └── Dockerfile
│   └── backend/               # FastAPI Python application
│       ├── app/
│       │   ├── api/v1/        # REST API endpoints
│       │   ├── services/      # Business logic & external integrations
│       │   ├── db/            # Database models & migrations
│       │   ├── jobs/          # Background tasks (APScheduler)
│       │   └── lib/           # Shared utilities (incl. vendored panther_sdk stub)
│       └── Dockerfile
├── k8s/                       # Kubernetes manifests
│   ├── base/                  # Base configurations
│   └── overlays/              # Environment-specific patches
│       ├── staging/
│       └── production/
├── scripts/                   # Utility scripts
└── docker-compose.yml
```

## Deployment

### GKE Deployment

Images are tagged with the short commit SHA (and `latest`); deploys pin that
tag in the kustomize overlay so every deploy actually rolls pods.

**Requirements**

- **GKE 1.29+** — the backend Deployment and migration Job run the Cloud SQL
  Auth Proxy as a *native sidecar* (an `initContainer` with `restartPolicy: Always`),
  which is only available on 1.29+.
- **Workload Identity enabled** on the cluster (`--workload-pool=<project>.svc.id.goog`;
  `gke-setup.sh` creates the cluster with it). The backend authenticates to Cloud
  SQL through a KSA→GSA binding, not a key file.

```bash
# One-time setup
./scripts/gke-setup.sh          # cluster (Workload Identity), APIs, static IP
./scripts/gke-cloudsql-setup.sh # Cloud SQL Postgres 15 instances (staging + prod),
                                #  DB users, GSA + roles/cloudsql.client, Workload
                                #  Identity bindings, DATABASE_URL in Secret Manager.
                                #  Prints the instance connection names. USER runs it
                                #  (billable provisioning; idempotent).
./scripts/gke-secrets.sh        # backend-secrets in revops + revops-staging namespaces
                                # (requires PANTHER_API_HOST, PANTHER_API_TOKEN in .env;
                                #  DATABASE_URL is pulled per-environment from Secret
                                #  Manager as populated by gke-cloudsql-setup.sh, with
                                #  an .env DATABASE_URL as fallback)

# Build and push images (tags: $SHORT_SHA + latest)
TAG=$(git rev-parse --short HEAD)
gcloud builds submit --config=cloudbuild-frontend.yaml --substitutions=SHORT_SHA=$TAG
gcloud builds submit --config=cloudbuild-backend.yaml --substitutions=SHORT_SHA=$TAG
# (Cloud Build triggers populate SHORT_SHA automatically)

# Deploy to staging, then production
./scripts/gke-deploy.sh staging $TAG
./scripts/gke-deploy.sh production $TAG
```

Project/cluster/namespace settings live in one place: `scripts/gke-env.sh`
(GCP project `revops-486917`, namespaces `revops` / `revops-staging`, and the
Cloud SQL instance names / DB user / tier).

**Database connectivity.** The backend never talks to Cloud SQL over the public
internet. A Cloud SQL Auth Proxy v2 sidecar runs alongside both the backend pods
and the migration Job and opens an mTLS + IAM-authenticated tunnel to the
instance; the app connects to it at `127.0.0.1:5432`. Staging and production use
**separate** Cloud SQL instances, selected per overlay via the `CLOUD_SQL_INSTANCE`
config value. No database IP is exposed to the cluster and no DB password travels
the network in the clear.

See [ARCHITECTURE-GCP.md](./ARCHITECTURE-GCP.md) for detailed GCP deployment architecture.

## Development

### Running Tests

```bash
# All tests
pnpm test

# Frontend only
pnpm --filter frontend test

# Backend only
cd packages/backend && pytest
```

### Linting

```bash
# Frontend
pnpm lint

# Backend
cd packages/backend
ruff check .
mypy app
```

## Security

- Never commit `.env` files or credentials to the repository
- Use environment variables or secret managers for sensitive configuration
- See `.env.example` for required environment variables

## License

MIT

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

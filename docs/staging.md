# Staging

A full copy of the application in the `revops-staging` namespace of the same
GKE cluster: its own postgres, redis, backend, frontend, and its own empty
database. Nothing in it shares state with production.

Stood up 2026-08-17. Before that every change went from a laptop straight to
production.

## Reaching it

Staging has no public hostname. Use a port-forward:

```bash
kubectl port-forward -n revops-staging svc/staging-frontend 8080:80
# then open http://localhost:8080

kubectl port-forward -n revops-staging svc/staging-backend 8000:8000
# API directly, e.g. curl localhost:8000/health
```

There is a seeded account: `admin2@staging.example.com` / `StagingPass123!`.
It is a staging-only credential for an empty database reachable only from
inside the cluster. Do not reuse the password anywhere real.

### Why there is no staging.ttrevops.com

Three things are missing, none of which can be created from this repository:

- **DNS.** `ttrevops.com` is not in Cloud DNS for this project, so its records
  are managed somewhere else entirely.
- **A static IP.** The base Ingress claims `panther-dashboard-ip`, which is
  production's. A second Ingress asking for the same address does not get its
  own — it competes for it.
- **An IAP OAuth client** for the new hostname.

So the staging overlay *deletes* the Ingress, ManagedCertificate,
FrontendConfig, and IAP BackendConfig rather than reconfiguring them. Left in,
they would provision a billed load balancer that can never serve traffic and a
certificate that can never validate. The syslog `LoadBalancer` Service is
dropped for the same reason — a second forwarding rule to receive syslog
nothing sends.

Add DNS and a static IP and the deletions can come back out.

## Deploying to it

```bash
# Set the image tags (edit by hand; `kustomize edit` mangles the comments)
$EDITOR k8s/overlays/staging/kustomization.yaml

kubectl apply -k k8s/overlays/staging
kubectl delete job staging-backend-migrate -n revops-staging --ignore-not-found
kubectl apply -k k8s/overlays/staging   # re-create the migration Job
```

Staging currently tracks whatever image tag is pinned in its overlay; it is not
wired into a pipeline.

## What the rebuild rehearsal found

Standing this up was also the test of whether the cluster could be rebuilt at
all. It was worth doing — the environment was created entirely from Secret
Manager with no `.env` present, and the database was migrated from empty to
head — but it surfaced five defects, every one of which would have been found
in the worst possible circumstances otherwise:

1. **`postgres-deployment.yaml` declared `emptyDir` while production ran on a
   PVC.** It was described as reference-only, but `kubectl apply -f` against
   the revops namespace would have rolled the live database onto ephemeral
   storage and destroyed it. It now declares the PVC production actually uses,
   so applying it is a no-op.
2. **Postgres could not initialise a fresh volume at all.** A new GCE
   persistent disk arrives with a `lost+found`, and `initdb` refuses to
   initialise a non-empty directory. Every new install needs `PGDATA` pointed
   at a subdirectory — see `k8s/overlays/staging/postgres-patch.yaml`, which
   also explains why that fix must NOT be applied to production.
3. **`gke-secrets.sh` required a `.env` file** that is not in the repository —
   recovery depended on a file you would not have after losing a machine. It
   now falls back to Secret Manager for everything.
4. **`gke-secrets.sh` wrote both namespaces unconditionally.** Running it to
   set up staging would have rewritten production's secrets from whatever
   happened to be in `.env`. It now takes a target: `production`, `staging`,
   or `both`.
5. **The staging overlay would have fought production for its static IP**, as
   described above.

## Still not rehearsed

A rebuild into a *different* cluster or project. This exercise reused the
existing cluster, so it did not test cluster creation, Workload Identity
bindings, IAP setup, or the ingress and certificate path.

# RevOps SOC Platform Architecture

## System Overview

```mermaid
flowchart TB
    subgraph External["External Systems"]
        Panther[("Panther SIEM")]
        Twilio["Twilio/Fonoster<br/>Voice & SMS"]
        SMTP["SMTP/Mailhog<br/>Email"]
        LLM["OpenAI / Anthropic<br/>LLM APIs"]

        subgraph ThreatFeeds["Threat Intel Feeds"]
            OTX["AlienVault OTX"]
            VT["VirusTotal"]
            AbuseIP["AbuseIPDB"]
            CustomFeed["Custom STIX/CSV"]
        end

        subgraph Ticketing["Ticketing & ITSM"]
            Jira["Jira"]
            ServiceNow["ServiceNow"]
            PagerDuty["PagerDuty"]
        end

        subgraph Collaboration["Collaboration"]
            Slack["Slack"]
            Teams["MS Teams"]
            Webhooks["Webhooks"]
        end

        subgraph EDR["EDR & Security"]
            CrowdStrike["CrowdStrike"]
            SentinelOne["SentinelOne"]
            Firewall["Firewall APIs"]
        end

        subgraph SSO["Identity Providers"]
            Google["Google OAuth"]
            Okta["Okta"]
            AzureAD["Azure AD"]
            SAML["SAML 2.0"]
        end
    end

    subgraph Infrastructure["Docker Infrastructure"]
        subgraph Frontend["Frontend Container :3000"]
            React["React 18 + TypeScript"]
            Redux["Redux Toolkit"]
            RTKQuery["RTK Query"]
            ReactFlow["React Flow<br/>Visual Editors"]
            Monaco["Monaco Editor"]
        end

        subgraph Backend["Backend Container :8000"]
            FastAPI["FastAPI"]

            subgraph APIs["API Layer (50+ endpoints)"]
                AuthAPI["/auth"]
                AlertsAPI["/alerts"]
                IncidentsAPI["/incidents"]
                WorkflowsAPI["/workflows"]
                PipelinesAPI["/pipelines"]
                EscalationAPI["/escalation-policies"]
                ConnectorsAPI["/connectors"]
                AIAPI["/ai"]
            end

            subgraph Services["Service Layer"]
                EscalationSvc["Escalation Service"]
                WorkflowEngine["Workflow Engine"]
                EnrichmentSvc["Enrichment Service"]
                NotificationSvc["Notification Service"]
                AIService["AI/LLM Service"]
                ThreatIntelSvc["Threat Intel Service"]
                PantherSvc["Panther Service"]
            end

            subgraph Jobs["Background Jobs"]
                AlertPoller["Alert Poller"]
                ConnectorSync["Connector Sync"]
                FeedSync["Feed Sync"]
                ReportScheduler["Report Scheduler"]
            end
        end

        subgraph Database["PostgreSQL :5432"]
            DB[("80+ Tables")]
        end

        subgraph Cache["Redis :6379"]
            RedisCache[("Cache & Queue")]
        end
    end

    %% Data Flow
    Panther -->|"SDK API"| AlertPoller
    AlertPoller -->|"Normalize"| DB

    React -->|"HTTP/WS"| FastAPI
    FastAPI --> APIs
    APIs --> Services
    Services --> DB
    Services --> RedisCache

    %% External Integrations
    EscalationSvc -->|"Voice/SMS"| Twilio
    NotificationSvc -->|"Email"| SMTP
    NotificationSvc -->|"Messages"| Slack
    NotificationSvc -->|"Messages"| Teams
    AIService -->|"LLM API"| LLM
    ThreatIntelSvc --> ThreatFeeds

    WorkflowEngine -->|"Actions"| Ticketing
    WorkflowEngine -->|"Actions"| EDR
    WorkflowEngine -->|"Webhooks"| Webhooks

    AuthAPI -->|"OAuth/SAML"| SSO
```

## Data Model Overview

```mermaid
erDiagram
    Organization ||--o{ User : has
    Organization ||--o{ Connector : owns
    Organization ||--o{ NormalizedAlert : stores
    Organization ||--o{ Incident : manages
    Organization ||--o{ Case : tracks
    Organization ||--o{ Workflow : defines
    Organization ||--o{ Pipeline : configures
    Organization ||--o{ EscalationPolicy : sets
    Organization ||--o{ OnCallSchedule : schedules

    NormalizedAlert ||--o{ IncidentAlert : "linked to"
    NormalizedAlert ||--o{ AlertClusterMember : "grouped in"
    NormalizedAlert ||--o{ AlertEnrichment : enriched
    NormalizedAlert ||--o{ AlertEscalation : triggers

    Incident ||--o{ IncidentAlert : contains
    Incident ||--o{ Note : has

    Case ||--o{ CaseActivity : logs
    Case ||--o{ CaseAttachment : has
    Case ||--o{ Note : has

    Workflow ||--o{ WorkflowNode : contains
    Workflow ||--o{ WorkflowEdge : connects
    Workflow ||--o{ WorkflowExecution : runs

    Pipeline ||--o{ PipelineStage : contains
    Pipeline ||--o{ PipelineEdge : connects
    Pipeline ||--o{ PipelineDestination : outputs
    Pipeline ||--o{ PipelineExecution : runs

    EscalationPolicy ||--o{ EscalationStep : defines
    EscalationPolicy ||--o{ AlertEscalation : triggers

    OnCallSchedule ||--o{ OnCallRotationMember : includes
    OnCallSchedule ||--o{ OnCallOverride : allows

    AlertCluster ||--o{ AlertClusterMember : groups

    User ||--o{ UserRole : has
    User ||--o{ AuditLog : creates
    User ||--o{ SavedQuery : owns
```

## Alert Processing Flow

```mermaid
flowchart LR
    subgraph Ingestion["1. Ingestion"]
        Panther[("Panther SIEM")]
        Poller["Alert Poller<br/>(Background Job)"]
        Normalize["Normalize &<br/>Store"]
    end

    subgraph Processing["2. Processing"]
        Enrichment["Enrichment<br/>Pipeline"]
        Correlation["Correlation<br/>Engine"]
        Clustering["AI Alert<br/>Clustering"]
    end

    subgraph Escalation["3. Escalation"]
        PolicyMatch["Match<br/>Policy"]
        Notify["Send<br/>Notifications"]
        Track["Track<br/>SLA"]
    end

    subgraph Response["4. Response"]
        Triage["Analyst<br/>Triage"]
        Playbook["Execute<br/>Playbook"]
        Workflow["Trigger<br/>Workflow"]
    end

    subgraph Resolution["5. Resolution"]
        CreateCase["Create<br/>Case"]
        CreateIncident["Create<br/>Incident"]
        Resolve["Resolve &<br/>Document"]
    end

    Panther --> Poller --> Normalize
    Normalize --> Enrichment --> Correlation --> Clustering
    Clustering --> PolicyMatch --> Notify --> Track
    Track --> Triage --> Playbook --> Workflow
    Workflow --> CreateCase --> Resolve
    Workflow --> CreateIncident --> Resolve
```

## Escalation Workflow

```mermaid
sequenceDiagram
    participant Alert as New Alert
    participant ES as Escalation Service
    participant Policy as Escalation Policy
    participant DB as Database
    participant Email as Email Service
    participant Slack as Slack
    participant Phone as Twilio/Fonoster
    participant Analyst as SOC Analyst

    Alert->>ES: Alert Created (Critical)
    ES->>Policy: Find Matching Policy
    Policy-->>ES: Policy Found (severity=critical)
    ES->>DB: Create AlertEscalation

    Note over ES: Step 0: Email (0 min delay)
    ES->>Email: Send Alert Email
    Email-->>Analyst: Email Received

    Note over ES: Wait 5 minutes...

    alt Not Acknowledged
        Note over ES: Step 1: Slack (5 min delay)
        ES->>Slack: Send Slack Message
        Slack-->>Analyst: Slack Alert
    end

    Note over ES: Wait 10 minutes...

    alt Still Not Acknowledged
        Note over ES: Step 2: Phone Call (15 min delay)
        ES->>Phone: Make Voice Call
        Phone-->>Analyst: Phone Rings
        Analyst->>Phone: Acknowledge (Press 1)
        Phone->>ES: Acknowledged
        ES->>DB: Update Status = ACKNOWLEDGED
    end
```

## Workflow Engine

```mermaid
flowchart TB
    subgraph Triggers["Trigger Nodes"]
        AlertTrigger["Alert Created"]
        ScheduleTrigger["Scheduled"]
        WebhookTrigger["Webhook"]
        ManualTrigger["Manual"]
    end

    subgraph Logic["Logic Nodes"]
        Condition["Condition<br/>(if/else)"]
        Loop["Loop<br/>(for each)"]
        Delay["Delay<br/>(wait)"]
        SetVar["Set Variable"]
    end

    subgraph Transform["Transform Nodes"]
        Filter["Filter Data"]
        Map["Map/Transform"]
        Aggregate["Aggregate"]
    end

    subgraph Actions["Action Nodes"]
        SlackAction["Send Slack"]
        EmailAction["Send Email"]
        JiraAction["Create Jira"]
        SNowAction["Create ServiceNow"]
        PagerAction["Page On-Call"]
        HTTPAction["HTTP Request"]
        IsolateAction["Isolate Host"]
        WebhookAction["Send Webhook"]
    end

    AlertTrigger --> Condition
    ScheduleTrigger --> Loop
    WebhookTrigger --> Filter

    Condition -->|"severity=critical"| PagerAction
    Condition -->|"severity=high"| SlackAction
    Condition -->|"else"| EmailAction

    Loop --> Map --> JiraAction
    Filter --> Aggregate --> HTTPAction

    SlackAction --> SetVar --> Delay --> SNowAction
```

## Frontend Architecture

```mermaid
flowchart TB
    subgraph App["React Application"]
        Router["React Router v6"]

        subgraph State["State Management"]
            AuthSlice["Auth Slice<br/>(user, token)"]
            UISlice["UI Slice<br/>(theme, modals)"]
            RTKQuery["RTK Query<br/>(API cache)"]
        end

        subgraph Pages["Pages (60+)"]
            subgraph SecOps["Security Operations"]
                Alerts["UnifiedAlertsPage"]
                AlertDetail["AlertDetailPage"]
                Incidents["IncidentsPage"]
                Cases["CasesPage"]
                Rules["RulesPage"]
            end

            subgraph Automation["Automation"]
                Workflows["WorkflowsPage"]
                Pipelines["PipelinesPage"]
                Playbooks["PlaybooksPage"]
                Connectors["ConnectorsPage"]
            end

            subgraph OnCall["On-Call"]
                Schedules["OnCallSchedulesPage"]
                Escalations["EscalationPoliciesPage"]
            end

            subgraph Intel["Intelligence"]
                ThreatIntel["ThreatIntelPage"]
                IOCSearch["IOCSearchPage"]
                QueryExplorer["QueryExplorerPage"]
            end

            subgraph Admin["Administration"]
                Settings["SettingsPage"]
                Roles["RoleManagementPage"]
                Audit["AuditLogPage"]
                Integrations["IntegrationsPage"]
            end
        end

        subgraph Components["Shared Components"]
            Widgets["Dashboard Widgets"]
            AIChat["AI Chat Widget"]
            Notes["Notes Panel"]
            Notifications["Notification Center"]
            VisualEditors["Visual Editors<br/>(React Flow)"]
        end
    end

    Router --> Pages
    Pages --> State
    Pages --> Components
    State --> RTKQuery
    RTKQuery -->|"HTTP"| Backend["Backend API"]
```

## Connector Framework

```mermaid
flowchart LR
    subgraph DataSources["Data Source Connectors"]
        PantherConn["Panther"]
        GoogleSecOps["Google SecOps"]
        Splunk["Splunk"]
        Sentinel["Microsoft Sentinel"]
        Elastic["Elastic SIEM"]
    end

    subgraph Normalizer["Normalization Layer"]
        Schema["Unified Alert Schema"]
    end

    subgraph ActionConnectors["Action Connectors"]
        subgraph Ticketing["Ticketing"]
            JiraConn["Jira"]
            SNowConn["ServiceNow"]
        end

        subgraph Messaging["Messaging"]
            SlackConn["Slack"]
            TeamsConn["Teams"]
            EmailConn["Email"]
        end

        subgraph Paging["Paging"]
            PagerDutyConn["PagerDuty"]
            OpsGenieConn["OpsGenie"]
            TwilioConn["Twilio"]
        end

        subgraph Security["Security Tools"]
            CSConn["CrowdStrike"]
            S1Conn["SentinelOne"]
            FWConn["Firewall"]
        end
    end

    DataSources -->|"Poll/Webhook"| Schema
    Schema -->|"Store"| DB[("Database")]

    Workflows["Workflow Engine"] --> ActionConnectors
    Escalations["Escalation Service"] --> Paging
    Notifications["Notification Service"] --> Messaging
```

## Deployment Architecture

```mermaid
flowchart TB
    subgraph Client["Client Layer"]
        Browser["Web Browser"]
        Mobile["Mobile Browser"]
    end

    subgraph Docker["Docker Compose Environment"]
        subgraph FE["Frontend :3000"]
            Vite["Vite Dev Server"]
            React["React App"]
        end

        subgraph BE["Backend :8000"]
            Uvicorn["Uvicorn ASGI"]
            FastAPI["FastAPI App"]
            Workers["Background Workers"]
        end

        subgraph Data["Data Layer"]
            Postgres["PostgreSQL :5432"]
            Redis["Redis :6379"]
        end

        subgraph Dev["Dev Tools"]
            Mailhog["Mailhog :8025<br/>(Email Testing)"]
            TelMock["Telephony Mock :50051"]
        end
    end

    subgraph External["External APIs"]
        PantherAPI["Panther API"]
        TwilioAPI["Twilio API"]
        SlackAPI["Slack API"]
        LLMAPI["OpenAI/Anthropic"]
    end

    Browser --> FE
    Mobile --> FE
    FE --> BE
    BE --> Data
    BE --> External
    BE --> Dev
```

## Key Database Tables

| Category | Tables |
|----------|--------|
| **Auth & Multi-tenancy** | Organization, User, UserRole, RefreshToken, OrganizationSSO, AuditLog |
| **Alerts & Incidents** | NormalizedAlert, Incident, IncidentAlert, AlertEscalation, AlertEnrichment |
| **Cases** | Case, CaseActivity, CaseAttachment |
| **Automation** | Workflow, WorkflowNode, WorkflowEdge, WorkflowExecution, Playbook, PlaybookExecution |
| **Pipelines** | Pipeline, PipelineStage, PipelineEdge, PipelineDestination, PipelineExecution |
| **On-Call** | OnCallSchedule, OnCallRotationMember, OnCallOverride, EscalationPolicy, EscalationStep |
| **Intelligence** | AlertCluster, AlertClusterMember, CorrelationRule, MitreMapping |
| **Threat Intel** | IOC, ThreatFeed, FeedSyncLog |
| **Rules** | RuleVersion, RuleHealth, TriageSuggestion |
| **Connectors** | Connector (unified for data sources & actions) |
| **Collaboration** | Note, Notification, ShiftHandoff, AlertPresence |
| **Reporting** | ScheduledReport, SavedQuery, CustomDashboard |
| **SLA** | SLAPolicy, SLAMetric |

## API Endpoints Summary

| Prefix | Purpose | Key Operations |
|--------|---------|----------------|
| `/auth` | Authentication | Login, logout, refresh, OAuth callbacks |
| `/alerts` | Alert management | List, get, update, bulk-update, comments |
| `/incidents` | Incident tracking | CRUD, link alerts, assign |
| `/cases` | Case management | CRUD, activities, attachments |
| `/workflows` | Workflow automation | CRUD, execute, history |
| `/pipelines` | Data pipelines | CRUD, execute, destinations |
| `/escalation-policies` | Escalation chains | CRUD, steps, trigger |
| `/oncall` | On-call schedules | CRUD, rotations, overrides |
| `/connectors` | Integrations | CRUD, test, sync |
| `/ai` | AI features | Summarize, correlate, suggest |
| `/threat-intel` | Threat intelligence | IOCs, feeds, search |
| `/rules` | Detection rules | CRUD, versions, health |
| `/analytics` | Dashboards & trends | Metrics, trends, anomalies |
| `/settings` | Configuration | Org settings, user prefs |
| `/presence` | Real-time collaboration | Heartbeat, viewers |
| `/shift-handoffs` | SOC handoffs | Create, acknowledge |

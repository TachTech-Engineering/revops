import IntegrationConnectorPanel from '../components/common/IntegrationConnectorPanel'

/**
 * This page was a mock -- fabricated status and lists, a Save that only touched
 * React state, and a Test button that slept and always reported success. It
 * never imported the API layer. It now renders the real connector
 * configuration, so what is shown is what is stored.
 */
export default function JiraIntegrationPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Jira</h1>
        <p className="text-muted-foreground">Send alerts and notifications to Jira.</p>
      </div>

      <IntegrationConnectorPanel
        connectorType="jira"
        displayName="Jira"
        setupHint={<>Use an Atlassian API token together with the account email, and the project key issues should be created in.</>}
      />

      <div className="rounded-lg border bg-background p-6 text-sm text-muted-foreground">
        <h2 className="mb-2 text-base font-semibold text-foreground">What this supports</h2>
        <p>Creating and updating issues from playbooks and workflows. RevOps does not read Jira back, so status changes made in Jira are not reflected here.</p>
      </div>
    </div>
  )
}

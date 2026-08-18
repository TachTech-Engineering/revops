import IntegrationConnectorPanel from '../components/common/IntegrationConnectorPanel'

/**
 * This page was a mock -- fabricated status and lists, a Save that only touched
 * React state, and a Test button that slept and always reported success. It
 * never imported the API layer. It now renders the real connector
 * configuration, so what is shown is what is stored.
 */
export default function ServiceNowIntegrationPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">ServiceNow</h1>
        <p className="text-muted-foreground">Send alerts and notifications to ServiceNow.</p>
      </div>

      <IntegrationConnectorPanel
        connectorType="servicenow"
        displayName="ServiceNow"
        setupHint={<>Use the instance URL together with a user that can create incidents.</>}
      />

      <div className="rounded-lg border bg-background p-6 text-sm text-muted-foreground">
        <h2 className="mb-2 text-base font-semibold text-foreground">What this supports</h2>
        <p>Creating incidents from playbooks and workflows.</p>
      </div>
    </div>
  )
}

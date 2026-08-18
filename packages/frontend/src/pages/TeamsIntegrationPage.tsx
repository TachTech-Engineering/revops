import IntegrationConnectorPanel from '../components/common/IntegrationConnectorPanel'

/**
 * This page was a mock -- fabricated status and lists, a Save that only touched
 * React state, and a Test button that slept and always reported success. It
 * never imported the API layer. It now renders the real connector
 * configuration, so what is shown is what is stored.
 */
export default function TeamsIntegrationPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Microsoft Teams</h1>
        <p className="text-muted-foreground">Send alerts and notifications to Microsoft Teams.</p>
      </div>

      <IntegrationConnectorPanel
        connectorType="teams"
        displayName="Microsoft Teams"
        setupHint={<>Create an Incoming Webhook on the Teams channel you want alerts in and paste its URL.</>}
      />

      <div className="rounded-lg border bg-background p-6 text-sm text-muted-foreground">
        <h2 className="mb-2 text-base font-semibold text-foreground">What this supports</h2>
        <p>Outbound only: posting messages to a Teams channel from playbooks, workflows and escalation policies.</p>
      </div>
    </div>
  )
}

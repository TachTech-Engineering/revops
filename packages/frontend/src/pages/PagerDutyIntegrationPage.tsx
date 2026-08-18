import IntegrationConnectorPanel from '../components/common/IntegrationConnectorPanel'

/**
 * This page was a mock -- fabricated status and lists, a Save that only touched
 * React state, and a Test button that slept and always reported success. It
 * never imported the API layer. It now renders the real connector
 * configuration, so what is shown is what is stored.
 */
export default function PagerDutyIntegrationPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">PagerDuty</h1>
        <p className="text-muted-foreground">Send alerts and notifications to PagerDuty.</p>
      </div>

      <IntegrationConnectorPanel
        connectorType="pagerduty"
        displayName="PagerDuty"
        setupHint={<>Use an Events API v2 integration key from the service you want RevOps to page.</>}
      />

      <div className="rounded-lg border bg-background p-6 text-sm text-muted-foreground">
        <h2 className="mb-2 text-base font-semibold text-foreground">What this supports</h2>
        <p>Triggering and resolving incidents from escalation policies and playbooks.</p>
      </div>
    </div>
  )
}

import IntegrationConnectorPanel from '../components/common/IntegrationConnectorPanel'

/**
 * OpsGenie has no backend connector on this deployment -- the only trace of it
 * in the repository is a dropped on-call table from a removed feature. The
 * page was previously 572 lines of mock that showed fabricated teams and
 * schedules and reported successful test connections.
 *
 * The panel resolves the connector type against the backend, so this renders
 * an honest "not available" state today and becomes a working configuration
 * form the moment an opsgenie connector is registered, with no change here.
 */
export default function OpsGenieIntegrationPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">OpsGenie</h1>
        <p className="text-muted-foreground">Send alerts and notifications to OpsGenie.</p>
      </div>

      <IntegrationConnectorPanel connectorType="opsgenie" displayName="OpsGenie" />

      <div className="rounded-lg border bg-background p-6 text-sm text-muted-foreground">
        <h2 className="mb-2 text-base font-semibold text-foreground">Alternatives today</h2>
        <p>
          PagerDuty is supported for paging, and any OpsGenie alert API endpoint can be reached
          with the generic webhook connector in the meantime.
        </p>
      </div>
    </div>
  )
}

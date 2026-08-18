import IntegrationConnectorPanel from '../components/common/IntegrationConnectorPanel'

/**
 * This page was a mock -- fabricated status and lists, a Save that only touched
 * React state, and a Test button that slept and always reported success. It
 * never imported the API layer. It now renders the real connector
 * configuration, so what is shown is what is stored.
 */
export default function EmailIntegrationPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Email</h1>
        <p className="text-muted-foreground">Send alerts and notifications to Email.</p>
      </div>

      <IntegrationConnectorPanel
        connectorType="email"
        displayName="Email"
        setupHint={<>Point this at your SMTP relay. Scheduled report delivery uses the same settings.</>}
      />

      <div className="rounded-lg border bg-background p-6 text-sm text-muted-foreground">
        <h2 className="mb-2 text-base font-semibold text-foreground">What this supports</h2>
        <p>Outbound mail for alerts, escalations and scheduled reports.</p>
      </div>
    </div>
  )
}

import IntegrationConnectorPanel from '../components/common/IntegrationConnectorPanel'

/**
 * This page was 422 lines of mock: `isConnected` hardcoded true, fabricated
 * channel and rule lists, a Save that appended to React state and disappeared
 * on refresh, and a Test button that slept two seconds and always reported
 * success. It never imported the API layer at all.
 *
 * It now renders the real connector configuration. What is shown is what is
 * stored; what Test reports is what Slack actually said.
 */
export default function SlackIntegrationPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Slack</h1>
        <p className="text-muted-foreground">
          Send alerts and notifications to Slack channels.
        </p>
      </div>

      <IntegrationConnectorPanel
        connectorType="slack"
        displayName="Slack"
        setupHint={
          <>
            Create a Slack app with a bot token (<code>xoxb-…</code>) and the{' '}
            <code>chat:write</code> scope, then invite the bot to the channels you want alerts in.
            The default channel is a channel ID such as <code>C0123456789</code>.
          </>
        }
      />

      <div className="rounded-lg border bg-background p-6 text-sm text-muted-foreground">
        <h2 className="mb-2 text-base font-semibold text-foreground">What this supports</h2>
        <p>
          Outbound only: posting messages and adding reactions, from playbooks, workflows and
          escalation policies. There are no slash commands, interactive buttons or Events API
          handling, so Slack cannot drive RevOps back.
        </p>
      </div>
    </div>
  )
}

import { Field, h, Section, type ConfiguratorUISpec } from "@gadgets/configurator-ui";
import type { UsageConfiguratorRpc, UsageConfiguratorValues } from "./usage-configurator-types";

// The deployment has exactly one usage resource, so there is nothing to select — the
// configurator just confirms what the binding grants and signals readiness.

export default {
  initial: { confirmed: "yes" },

  isReady() {
    return true;
  },

  resourceUrl({ ui }) {
    return ui.resourceUrl();
  },

  render() {
    return <Section>
      <Field
        label="Deployment usage access"
        description="This binding grants read-only access to AI usage across the whole deployment: sessions, request counts, and cost for every user. It is available to deployment administrators only.">
      </Field>
    </Section>;
  },
} satisfies ConfiguratorUISpec<UsageConfiguratorRpc, UsageConfiguratorValues>;

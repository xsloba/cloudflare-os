export type UsageConfiguratorValues = {
  // No user-selectable values: the deployment has exactly one usage resource. A placeholder
  // field gives `isReady` something to check.
  confirmed?: string | null;
};

export interface UsageConfiguratorRpc {
  // Returns the canonical resource URL (fixed for this gatekeeper).
  resourceUrl(): Promise<string>;
}

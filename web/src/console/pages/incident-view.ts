// What the incident detail page may show for the incident in the route. Pure so it is regression-tested:
// a banner is only ever derived from a loaded response for exactly the requested incident.

import type { KeyedState } from "../lib/keyed-resource";

export type IncidentBanner = "Quarantined" | "Contained" | "Cleared";

export interface IncidentViewModel {
  heading: string;
  phase: "loading" | "error" | "ready";
  banner: IncidentBanner | null;
}

export const incidentHeading = (id: string) => `Incident ${id}`;

export function incidentView(state: KeyedState<{ incident: { id: string; status: string } }>, routeId: string): IncidentViewModel {
  const heading = incidentHeading(routeId);
  if (state.key !== routeId || state.status === "loading") return { heading, phase: "loading", banner: null };
  if (state.status === "error" || state.data.incident.id !== routeId) return { heading, phase: "error", banner: null };
  const status = state.data.incident.status;
  return { heading, phase: "ready", banner: status === "cleared" ? "Cleared" : status === "contained" ? "Contained" : "Quarantined" };
}

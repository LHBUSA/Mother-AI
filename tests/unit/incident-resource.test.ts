import { describe, expect, it } from "vitest";
import { createKeyedLoader, MismatchedResponse, stateForKey, type KeyedState } from "../../web/src/console/lib/keyed-resource";
import { incidentView } from "../../web/src/console/pages/incident-view";

// Console state correctness for the incident detail page: what is rendered always belongs to the incident in the route.

interface Detail {
  incident: { id: string; status: "open" | "contained" | "cleared" };
}

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** A fake network: every fetch for a key waits until the test settles it, in any order. */
function harness() {
  const pending: Array<{ key: string; signal: AbortSignal; d: ReturnType<typeof deferred<Detail>> }> = [];
  const states: Array<KeyedState<Detail>> = [];
  let latest: KeyedState<Detail> | null = null;
  const loader = createKeyedLoader<Detail>(
    (key, signal) => {
      const d = deferred<Detail>();
      pending.push({ key, signal, d });
      return d.promise;
    },
    (s) => {
      latest = s;
      states.push(s);
    },
    (key, data) => data.incident.id === key,
  );
  const request = (key: string, nth = 0) => pending.filter((p) => p.key === key)[nth]!;
  const flush = () => new Promise((r) => setTimeout(r, 0));
  // What the page renders for the route id, exactly as IncidentPage derives it.
  const render = (routeId: string) => incidentView(stateForKey(latest, routeId), routeId);
  return { loader, pending, states, request, flush, render, current: () => latest };
}

const detail = (id: string, status: Detail["incident"]["status"]): Detail => ({ incident: { id, status } });

describe("incident detail console state", () => {
  it("cleared incident A → contained incident B while B is slow: A's Cleared banner is gone immediately, B loads under its own id", async () => {
    const h = harness();
    h.loader.select("inc_A");
    h.request("inc_A").d.resolve(detail("inc_A", "cleared"));
    await h.flush();
    expect(h.render("inc_A")).toEqual({ heading: "Incident inc_A", phase: "ready", banner: "Cleared" });

    // Route changes to B. Before the loader has even been told (the render right after navigation) nothing of A shows.
    expect(h.render("inc_B")).toEqual({ heading: "Incident inc_B", phase: "loading", banner: null });
    expect(stateForKey(h.current(), "inc_B")).toEqual({ key: "inc_B", status: "loading", data: null, error: null });
    h.loader.select("inc_B");
    expect(h.current()).toMatchObject({ key: "inc_B", status: "loading", data: null });
    expect(h.render("inc_B")).toEqual({ heading: "Incident inc_B", phase: "loading", banner: null });

    await h.flush();
    expect(h.render("inc_B").banner).toBeNull(); // still slow: still no banner from any incident

    h.request("inc_B").d.resolve(detail("inc_B", "contained"));
    await h.flush();
    expect(h.render("inc_B")).toEqual({ heading: "Incident inc_B", phase: "ready", banner: "Contained" });
  });

  it("A → B where B's fetch fails: an explicit error for B, with none of A's content underneath", async () => {
    const h = harness();
    h.loader.select("inc_A");
    h.request("inc_A").d.resolve(detail("inc_A", "cleared"));
    await h.flush();

    h.loader.select("inc_B");
    const failure = new Error("HTTP 500");
    h.request("inc_B").d.reject(failure);
    await h.flush();

    expect(h.current()).toEqual({ key: "inc_B", status: "error", data: null, error: failure });
    expect(h.render("inc_B")).toEqual({ heading: "Incident inc_B", phase: "error", banner: null });
    expect(h.states.filter((s) => s.key === "inc_B").every((s) => s.data === null)).toBe(true);
  });

  it("rapid A → B → C with responses arriving out of order: only C is ever committed after C is selected", async () => {
    const h = harness();
    h.loader.select("inc_A");
    h.loader.select("inc_B");
    h.loader.select("inc_C");

    // Superseded requests are aborted.
    expect(h.request("inc_A").signal.aborted).toBe(true);
    expect(h.request("inc_B").signal.aborted).toBe(true);
    expect(h.request("inc_C").signal.aborted).toBe(false);

    h.request("inc_C").d.resolve(detail("inc_C", "contained"));
    await h.flush();
    h.request("inc_B").d.resolve(detail("inc_B", "cleared"));
    h.request("inc_A").d.resolve(detail("inc_A", "cleared"));
    await h.flush();

    expect(h.current()).toMatchObject({ key: "inc_C", status: "ready", data: detail("inc_C", "contained") });
    expect(h.render("inc_C")).toEqual({ heading: "Incident inc_C", phase: "ready", banner: "Contained" });
    expect(h.states.some((s) => s.status === "ready" && s.key !== "inc_C")).toBe(false);
  });

  it("a stale response can never overwrite the currently selected incident (late success, late failure, or a body for another id)", async () => {
    const h = harness();
    h.loader.select("inc_A");
    h.loader.select("inc_B");
    h.request("inc_B").d.resolve(detail("inc_B", "contained"));
    await h.flush();

    h.request("inc_A").d.resolve(detail("inc_A", "cleared")); // late success for A
    await h.flush();
    expect(h.current()).toMatchObject({ key: "inc_B", status: "ready", data: detail("inc_B", "contained") });

    h.loader.select("inc_C");
    h.loader.select("inc_B"); // back to B: a fresh request for B
    h.request("inc_C").d.reject(new Error("late failure for C"));
    await h.flush();
    expect(h.current()).toMatchObject({ key: "inc_B", status: "loading" });

    // The server (or a cache) answers B's request with a different incident's body: never rendered as B.
    h.request("inc_B", 1).d.resolve(detail("inc_A", "cleared"));
    await h.flush();
    const s = h.current()!;
    expect(s).toMatchObject({ key: "inc_B", status: "error", data: null });
    expect(s.status === "error" && s.error).toBeInstanceOf(MismatchedResponse);
    expect(h.render("inc_B")).toEqual({ heading: "Incident inc_B", phase: "error", banner: null });

    // Even a state that somehow still names another incident renders as loading for the route, never its banner.
    expect(incidentView({ key: "inc_A", status: "ready", data: detail("inc_A", "cleared"), error: null, refreshing: false }, "inc_B")).toEqual({ heading: "Incident inc_B", phase: "loading", banner: null });
    expect(incidentView({ key: "inc_B", status: "ready", data: detail("inc_A", "cleared"), error: null, refreshing: false }, "inc_B")).toEqual({ heading: "Incident inc_B", phase: "error", banner: null });
  });

  it("reloading the same incident keeps only that incident's content, and a disposed loader commits nothing", async () => {
    const h = harness();
    h.loader.select("inc_A");
    h.request("inc_A").d.resolve(detail("inc_A", "contained"));
    await h.flush();

    const reloaded = h.loader.reload();
    expect(h.current()).toMatchObject({ key: "inc_A", status: "ready", refreshing: true, data: detail("inc_A", "contained") });
    h.request("inc_A", 1).d.resolve(detail("inc_A", "cleared"));
    await reloaded;
    expect(h.render("inc_A").banner).toBe("Cleared");

    h.loader.select("inc_B");
    const count = h.states.length;
    h.loader.dispose();
    expect(h.request("inc_B").signal.aborted).toBe(true);
    h.request("inc_B").d.resolve(detail("inc_B", "contained"));
    await h.flush();
    expect(h.states.length).toBe(count);
  });
});

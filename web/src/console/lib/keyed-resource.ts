// A resource addressed by a key (e.g. an incident id) whose rendered state can never belong to a different key.
// Framework-free so the ordering rules are unit-tested without a DOM:
//  - selecting a new key drops the previous key's data immediately and aborts its in-flight request;
//  - a response is committed only if it is from the latest request, for the key still selected, and its body
//    identifies that same key;
//  - a failure is reported for the key that failed, never on top of another key's content.

export type KeyedState<T> =
  | { key: string; status: "loading"; data: null; error: null }
  | { key: string; status: "ready"; data: T; error: null; refreshing: boolean }
  | { key: string; status: "error"; data: null; error: unknown };

export type KeyedFetcher<T> = (key: string, signal: AbortSignal) => Promise<T>;

export class MismatchedResponse extends Error {
  constructor(readonly requested: string) {
    super(`The response did not match the requested item ${requested}.`);
  }
}

export const loadingState = <T>(key: string): KeyedState<T> => ({ key, status: "loading", data: null, error: null });

/** The state to render for `key`: anything recorded for another key is treated as not loaded yet. */
export function stateForKey<T>(state: KeyedState<T> | null, key: string): KeyedState<T> {
  return state && state.key === key ? state : loadingState<T>(key);
}

export interface KeyedLoader {
  select(key: string): void;
  reload(): Promise<void>;
  dispose(): void;
}

export function createKeyedLoader<T>(
  fetcher: KeyedFetcher<T>,
  onChange: (state: KeyedState<T>) => void,
  belongsTo: (key: string, data: T) => boolean = () => true,
): KeyedLoader {
  let generation = 0;
  let controller: AbortController | null = null;
  let current: KeyedState<T> | null = null;
  let disposed = false;

  const emit = (next: KeyedState<T>) => {
    if (disposed) return;
    current = next;
    onChange(next);
  };

  const run = async (key: string) => {
    controller?.abort();
    const mine = new AbortController();
    controller = mine;
    const gen = ++generation;
    const isCurrent = () => !disposed && gen === generation && current?.key === key && !mine.signal.aborted;
    try {
      const data = await fetcher(key, mine.signal);
      if (!isCurrent()) return;
      if (!belongsTo(key, data)) emit({ key, status: "error", data: null, error: new MismatchedResponse(key) });
      else emit({ key, status: "ready", data, error: null, refreshing: false });
    } catch (error) {
      if (!isCurrent()) return;
      emit({ key, status: "error", data: null, error });
    } finally {
      if (controller === mine) controller = null;
    }
  };

  return {
    select(key) {
      if (current?.key === key && current.status !== "error") return;
      emit(loadingState<T>(key));
      void run(key);
    },
    reload() {
      if (!current) return Promise.resolve();
      const key = current.key;
      // Refreshing the same item may keep its own content visible; it never shows another item's.
      if (current.status === "ready") emit({ ...current, refreshing: true });
      else emit(loadingState<T>(key));
      return run(key);
    },
    dispose() {
      disposed = true;
      controller?.abort();
      controller = null;
    },
  };
}

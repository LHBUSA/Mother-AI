import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";
import { createKeyedLoader, stateForKey, type KeyedFetcher, type KeyedLoader, type KeyedState } from "./keyed-resource";

/**
 * Loads one item addressed by `key`. The returned state always belongs to the current `key`: on a key change the
 * previous item's data is dropped in the same render, its request is aborted, and late or mismatched responses are
 * ignored (see keyed-resource.ts).
 */
export function useKeyedApi<T>(key: string, fetcher: KeyedFetcher<T>, belongsTo?: (key: string, data: T) => boolean): { state: KeyedState<T>; reload: () => Promise<void> } {
  const [state, setState] = useState<KeyedState<T> | null>(null);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;
  const belongsRef = useRef(belongsTo);
  belongsRef.current = belongsTo;
  const loaderRef = useRef<KeyedLoader | null>(null);

  useEffect(() => {
    const loader = createKeyedLoader<T>(
      (k, signal) => fetcherRef.current(k, signal),
      setState,
      (k, data) => (belongsRef.current ? belongsRef.current(k, data) : true),
    );
    loaderRef.current = loader;
    return () => {
      loader.dispose();
      if (loaderRef.current === loader) loaderRef.current = null;
    };
  }, []);

  useEffect(() => {
    loaderRef.current?.select(key);
  }, [key]);

  const reload = useCallback(() => loaderRef.current?.reload() ?? Promise.resolve(), []);
  return { state: stateForKey(state, key), reload };
}

export interface Resource<T> {
  data: T | null;
  error: unknown;
  loading: boolean;
  /** Epoch ms of the last successful load. */
  updatedAt: number | null;
  reload: () => Promise<void>;
  setData: (d: T) => void;
}

export function useApi<T>(path: string | null, deps: unknown[] = []): Resource<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState<boolean>(!!path);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const seq = useRef(0);

  const load = useCallback(async () => {
    if (!path) return;
    const id = ++seq.current;
    setLoading(true);
    try {
      const result = await api<T>(path);
      if (id === seq.current) {
        setData(result);
        setError(null);
        setUpdatedAt(Date.now());
      }
    } catch (err) {
      if (id === seq.current) setError(err);
    } finally {
      if (id === seq.current) setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, ...deps]);

  useEffect(() => {
    void load();
  }, [load]);

  return { data, error, loading, updatedAt, reload: load, setData };
}

/** Runs `fn` every `ms` while the document is visible. */
export function useVisibleInterval(fn: () => void, ms: number) {
  const saved = useRef(fn);
  saved.current = fn;
  useEffect(() => {
    let timer: number | undefined;
    const start = () => {
      stop();
      timer = window.setInterval(() => saved.current(), ms);
    };
    const stop = () => {
      if (timer !== undefined) window.clearInterval(timer);
      timer = undefined;
    };
    const onVis = () => {
      if (document.visibilityState === "visible") {
        saved.current();
        start();
      } else stop();
    };
    if (document.visibilityState === "visible") start();
    document.addEventListener("visibilitychange", onVis);
    return () => {
      stop();
      document.removeEventListener("visibilitychange", onVis);
    };
  }, [ms]);
}

export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(t);
  }, [intervalMs]);
  return now;
}

export function useDocumentTitle(title: string) {
  useEffect(() => {
    document.title = `${title} · Mother AI`;
  }, [title]);
}

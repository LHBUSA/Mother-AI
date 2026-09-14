import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";

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

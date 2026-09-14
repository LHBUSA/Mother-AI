export const prefersReducedMotion = (): boolean =>
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;

export function qs<T extends Element = HTMLElement>(root: ParentNode, selector: string): T | null {
  return root.querySelector<T & Element>(selector) as T | null;
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Pretty-print JSON with minimal, escaped syntax highlighting spans. */
export function highlightJson(value: unknown): string {
  const text = escapeHtml(JSON.stringify(value, null, 2) ?? "null");
  return text.replace(
    /(&quot;(?:\\&quot;|\\[^&]|[^&\\]|&(?!quot;))*?&quot;)(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
    (match, str: string | undefined, colon: string | undefined, bool: string | undefined, num: string | undefined) => {
      if (str !== undefined) {
        return colon ? `<span class="j-k">${str}</span>${colon}` : `<span class="j-s">${str}</span>`;
      }
      if (bool !== undefined) return `<span class="j-b">${bool}</span>`;
      if (num !== undefined) return `<span class="j-n">${num}</span>`;
      return match;
    },
  );
}

export interface ApiError {
  status: number;
  code: string;
  message: string;
  fields?: Record<string, string>;
}

export async function readError(res: Response): Promise<ApiError> {
  let code = "HTTP_" + res.status;
  let message = "";
  let fields: Record<string, string> | undefined;
  try {
    const body = (await res.json()) as { error?: { code?: string; message?: string; fields?: Record<string, string> } };
    if (body?.error) {
      code = body.error.code ?? code;
      message = body.error.message ?? "";
      fields = body.error.fields;
    }
  } catch {
    /* non-JSON error body */
  }
  return { status: res.status, code, message, fields };
}

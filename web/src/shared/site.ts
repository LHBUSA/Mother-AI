// The single browser-side source for Mother AI hosts. Values are injected at build time
// from config/site.json by vite.config.ts; components never hard-code hostnames.
//
//   UI_ORIGIN   where this UI is served (https://mother.proptechusa.ai)
//   API_ORIGIN  the Worker API the browser calls directly (https://api.mother.proptechusa.ai)
//
// Browser API traffic goes straight to the Worker (never through a Vercel proxy) so rate
// limits and IP hashing see the real visitor IP.

declare const __MOTHER_UI_ORIGIN__: string;
declare const __MOTHER_API_ORIGIN__: string;

export const UI_ORIGIN: string = __MOTHER_UI_ORIGIN__;
export const API_ORIGIN: string = __MOTHER_API_ORIGIN__;

export function apiUrl(path: string): string {
  if (!path.startsWith("/")) throw new Error(`API paths must start with "/": ${path}`);
  return `${API_ORIGIN}${path}`;
}

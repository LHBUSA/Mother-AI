export type Clock = () => number;

export const systemClock: Clock = () => Date.now();

export function iso(ms: number): string {
  return new Date(ms).toISOString();
}

export function addSeconds(isoString: string, seconds: number): string {
  return iso(Date.parse(isoString) + seconds * 1000);
}

export function isPast(isoString: string | null | undefined, now: number): boolean {
  return !!isoString && Date.parse(isoString) <= now;
}

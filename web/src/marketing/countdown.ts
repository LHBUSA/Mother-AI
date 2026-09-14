import { prefersReducedMotion } from "./util";

export function initCountdown(): void {
  const el = document.querySelector<HTMLElement>("[data-countdown]");
  if (!el) return;
  el.setAttribute("aria-label", "Example approval expiry countdown");
  if (prefersReducedMotion()) return;

  const start = Number(el.dataset.seconds ?? "872");
  let remaining = start;
  const render = () => {
    const m = Math.floor(remaining / 60);
    const s = remaining % 60;
    el.textContent = `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  };

  let timer: number | undefined;
  const run = () => {
    if (timer !== undefined) return;
    timer = window.setInterval(() => {
      remaining = remaining <= 0 ? start : remaining - 1;
      render();
    }, 1000);
  };
  const stop = () => {
    if (timer !== undefined) window.clearInterval(timer);
    timer = undefined;
  };

  new IntersectionObserver((entries) => (entries.some((e) => e.isIntersecting) ? run() : stop())).observe(el);
}

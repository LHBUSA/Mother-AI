import "./marketing.css";
import { initNav } from "./nav";
import { initHero } from "./hero";
import { initDemo } from "./demo";
import { initFoundingAccess } from "./founding";
import { initCountdown } from "./countdown";

function start(): void {
  const year = document.querySelector<HTMLElement>("[data-year]");
  if (year) year.textContent = String(new Date().getFullYear());

  initNav();
  initHero();
  initDemo();
  initFoundingAccess();
  initCountdown();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start, { once: true });
} else {
  start();
}

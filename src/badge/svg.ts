// Server-rendered badge SVG. Rendered per request from live status so a copied
// badge can never stay green after controls are disabled.

import type { BadgeStatus } from "./status";

export type BadgeTheme = "dark" | "light";
export type RenderedState = BadgeStatus | "invalid";

const COPY: Record<RenderedState, { title: string; line1: string; line2: string }> = {
  active: { title: "Mother AI Protected — AI Controls Active", line1: "MOTHER AI PROTECTED", line2: "AI Controls Active" },
  setup: { title: "Mother AI — controls not active (setup incomplete)", line1: "MOTHER AI", line2: "Controls not active" },
  suspended: { title: "Mother AI — protection suspended", line1: "MOTHER AI", line2: "Protection suspended" },
  revoked: { title: "Mother AI — badge revoked", line1: "MOTHER AI", line2: "Badge revoked" },
  invalid: { title: "Mother AI — unverified badge", line1: "MOTHER AI", line2: "Unverified badge" },
};

interface Palette {
  bg: string;
  stroke: string;
  text: string;
  sub: string;
  shield: string;
  node: string;
  dot: string;
}

function palette(state: RenderedState, theme: BadgeTheme): Palette {
  const dark = theme === "dark";
  const base = dark
    ? { bg: "#0B0D10", stroke: "#262C31", text: "#E8ECE6", sub: "#A4ACB2", shield: "#E8ECE6" }
    : { bg: "#FFFFFF", stroke: "#D5DAD3", text: "#0B0D10", sub: "#4B5359", shield: "#0B0D10" };
  switch (state) {
    case "active":
      return dark
        ? { ...base, stroke: "#3E5A1C", sub: "#B7FF4A", node: "#B7FF4A", dot: "#B7FF4A" }
        : { ...base, stroke: "#9CCB5A", sub: "#2F6B00", node: "#5FA800", dot: "#5FA800" };
    case "suspended":
    case "setup":
      return { ...base, node: dark ? "#6C747B" : "#9AA2A8", dot: dark ? "#E9B54A" : "#B07A12" };
    case "revoked":
      return { ...base, node: dark ? "#6C747B" : "#9AA2A8", dot: dark ? "#EE6A5F" : "#B83A2F" };
    case "invalid":
      return { ...base, node: dark ? "#6C747B" : "#9AA2A8", dot: dark ? "#6C747B" : "#9AA2A8" };
  }
}

export function renderBadgeSvg(state: RenderedState, theme: BadgeTheme): string {
  const c = COPY[state];
  const p = palette(state, theme);
  const font = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif";
  const check =
    state === "active"
      ? `<path d="M56.2 32.2l2.1 2.1 4.1-4.3" fill="none" stroke="${theme === "dark" ? "#0B0D10" : "#FFFFFF"}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>`
      : "";
  return `<svg xmlns="http://www.w3.org/2000/svg" width="236" height="48" viewBox="0 0 236 48" role="img" aria-label="${c.title}">
<title>${c.title}</title>
<rect x="0.5" y="0.5" width="235" height="47" rx="10" fill="${p.bg}" stroke="${p.stroke}"/>
<g transform="translate(10 8) scale(0.5)">
<path d="M32 5.5 53 13v17.2c0 13.4-8.7 23.9-21 28.3C19.7 54.1 11 43.6 11 30.2V13L32 5.5Z" fill="none" stroke="${p.shield}" stroke-width="3.6" stroke-linejoin="round"/>
<path d="M20.5 27.5a11.5 11.5 0 0 1 23 0" fill="none" stroke="${p.node}" stroke-width="3.6" stroke-linecap="round"/>
<circle cx="32" cy="33" r="5.2" fill="${p.node}"/>
<path d="M32 38v6.5M24 43.5h16" stroke="${p.shield}" stroke-width="3.6" stroke-linecap="round"/>
</g>
<line x1="46" y1="11" x2="46" y2="37" stroke="${p.stroke}"/>
<text x="56" y="21" font-family="${font}" font-size="11" font-weight="700" letter-spacing="0.9" fill="${p.text}">${c.line1}</text>
<circle cx="59.3" cy="32.2" r="${state === "active" ? 4.6 : 3}" fill="${p.dot}"/>
${check}
<text x="${state === "active" ? 68 : 67}" y="36" font-family="${font}" font-size="11" font-weight="600" fill="${p.sub}">${c.line2}</text>
</svg>`;
}

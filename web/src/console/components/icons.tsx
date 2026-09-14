import type { SVGProps } from "react";

type P = SVGProps<SVGSVGElement>;
const base = (p: P) => ({ width: 16, height: 16, viewBox: "0 0 16 16", fill: "none", stroke: "currentColor", strokeWidth: 1.5, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, "aria-hidden": true, ...p });

export const IconOverview = (p: P) => (
  <svg {...base(p)}>
    <rect x="2" y="2" width="5" height="5" rx="1" />
    <rect x="9" y="2" width="5" height="3" rx="1" />
    <rect x="9" y="7" width="5" height="7" rx="1" />
    <rect x="2" y="9" width="5" height="5" rx="1" />
  </svg>
);
export const IconAgents = (p: P) => (
  <svg {...base(p)}>
    <rect x="3" y="4.5" width="10" height="8" rx="2" />
    <path d="M8 2v2.5M6 8.2h.01M10 8.2h.01M6.2 10.6h3.6" />
  </svg>
);
export const IconPolicies = (p: P) => (
  <svg {...base(p)}>
    <path d="M8 1.8 13.2 3.7v4c0 3.1-2.1 5.4-5.2 6.5C4.9 13.1 2.8 10.8 2.8 7.7v-4L8 1.8Z" />
    <path d="m5.8 7.9 1.6 1.6 3-3.1" />
  </svg>
);
export const IconApprovals = (p: P) => (
  <svg {...base(p)}>
    <circle cx="8" cy="5.5" r="2.5" />
    <path d="M3 14c.6-2.6 2.6-4 5-4s4.4 1.4 5 4" />
  </svg>
);
export const IconAudit = (p: P) => (
  <svg {...base(p)}>
    <path d="M3 3.5h10M3 8h10M3 12.5h6" />
    <circle cx="12" cy="12.5" r="1.2" />
  </svg>
);
export const IconIntegrations = (p: P) => (
  <svg {...base(p)}>
    <path d="m5.5 4.5-3 3.5 3 3.5M10.5 4.5l3 3.5-3 3.5M9 3 7 13" />
  </svg>
);
export const IconBadge = (p: P) => (
  <svg {...base(p)}>
    <circle cx="8" cy="6.5" r="4.2" />
    <path d="m5.5 10 -1 4.2L8 12.6l3.5 1.6-1-4.2" />
  </svg>
);
export const IconSettings = (p: P) => (
  <svg {...base(p)}>
    <circle cx="8" cy="8" r="2" />
    <path d="M8 1.8v1.6M8 12.6v1.6M3.6 3.6l1.1 1.1M11.3 11.3l1.1 1.1M1.8 8h1.6M12.6 8h1.6M3.6 12.4l1.1-1.1M11.3 4.7l1.1-1.1" />
  </svg>
);
export const IconMenu = (p: P) => (
  <svg {...base(p)}>
    <path d="M2.5 4.5h11M2.5 8h11M2.5 11.5h11" />
  </svg>
);
export const IconClose = (p: P) => (
  <svg {...base(p)}>
    <path d="m4 4 8 8M12 4l-8 8" />
  </svg>
);
export const IconPlus = (p: P) => (
  <svg {...base(p)}>
    <path d="M8 3v10M3 8h10" />
  </svg>
);
export const IconCopy = (p: P) => (
  <svg {...base(p)}>
    <rect x="5" y="5" width="8.5" height="8.5" rx="1.5" />
    <path d="M3 10.5V3.8C3 3.3 3.3 3 3.8 3h6.7" />
  </svg>
);
export const IconCheck = (p: P) => (
  <svg {...base(p)}>
    <path d="m3.5 8.3 2.8 2.8 6.2-6.3" />
  </svg>
);
export const IconChevron = (p: P) => (
  <svg {...base(p)}>
    <path d="m6 4 4 4-4 4" />
  </svg>
);
export const IconArrowLeft = (p: P) => (
  <svg {...base(p)}>
    <path d="M13 8H3M7 4 3 8l4 4" />
  </svg>
);
export const IconExternal = (p: P) => (
  <svg {...base(p)}>
    <path d="M9 3h4v4M13 3 7.5 8.5M11.5 9.5V13H3V4.5h3.5" />
  </svg>
);
export const IconTrash = (p: P) => (
  <svg {...base(p)}>
    <path d="M3 4.5h10M6.5 4.5V3h3v1.5M4.5 4.5l.6 8.5h5.8l.6-8.5" />
  </svg>
);
export const IconKey = (p: P) => (
  <svg {...base(p)}>
    <circle cx="5.5" cy="10.5" r="2.8" />
    <path d="m7.5 8.5 5.5-5.5M11 5l1.8 1.8M9.5 6.5l1.3 1.3" />
  </svg>
);
export const IconSignOut = (p: P) => (
  <svg {...base(p)}>
    <path d="M6 13.5H3.5c-.6 0-1-.4-1-1v-9c0-.6.4-1 1-1H6M10.5 11 13.5 8l-3-3M13.5 8H6" />
  </svg>
);
export const IconRefresh = (p: P) => (
  <svg {...base(p)}>
    <path d="M13 3.5v3h-3M3 12.5v-3h3" />
    <path d="M12.6 6.5A5 5 0 0 0 3.8 5M3.4 9.5a5 5 0 0 0 8.8 1.5" />
  </svg>
);
export const IconPasskey = (p: P) => (
  <svg {...base({ viewBox: "0 0 24 24", width: 20, height: 20, ...p })}>
    <circle cx="9" cy="7.5" r="3.5" />
    <path d="M2.5 20c.7-3.7 3.2-6 6.5-6 1.2 0 2.3.3 3.2.8" />
    <circle cx="17.5" cy="12.5" r="2.5" />
    <path d="M17.5 15v5.5l1.5-1.2M17.5 18h1.6" />
  </svg>
);

export function BrandMark({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" aria-hidden="true">
      <path d="M32 5.5 53 13v17.2c0 13.4-8.7 23.9-21 28.3C19.7 54.1 11 43.6 11 30.2V13L32 5.5Z" stroke="#E8ECE6" strokeWidth="3.6" strokeLinejoin="round" />
      <path d="M20.5 27.5a11.5 11.5 0 0 1 23 0" stroke="#B7FF4A" strokeWidth="3.6" strokeLinecap="round" />
      <circle cx="32" cy="33" r="5" fill="#B7FF4A" />
      <path d="M32 38v6.5M24 43.5h16" stroke="#E8ECE6" strokeWidth="3.6" strokeLinecap="round" />
    </svg>
  );
}

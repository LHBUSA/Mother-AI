import {
  useEffect,
  useId,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from "react";
import { createPortal } from "react-dom";
import { errorMessage, type Decision } from "../lib/api";
import { IconCheck, IconClose, IconCopy, IconRefresh } from "./icons";

export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

type BtnVariant = "primary" | "secondary" | "ghost" | "danger" | "approve";
export function Button({
  variant = "secondary",
  size = "md",
  loading,
  children,
  className,
  disabled,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: BtnVariant; size?: "sm" | "md"; loading?: boolean }) {
  return (
    <button className={cx("btn", `btn-${variant}`, size === "sm" && "btn-sm", loading && "is-loading", className)} disabled={disabled || loading} {...rest}>
      {loading && <span className="spinner" aria-hidden="true" />}
      {children}
    </button>
  );
}

export function DecisionPill({ decision, size }: { decision: Decision; size?: "sm" }) {
  const label = decision === "review" ? "REVIEW" : decision.toUpperCase();
  return <span className={cx("pill", `pill-${decision}`, size === "sm" && "pill-sm")}>{label}</span>;
}

export function EffectLabel({ effect }: { effect: Decision }) {
  return <DecisionPill decision={effect} />;
}

export function StatusDot({ tone }: { tone: "ok" | "warn" | "bad" | "muted" }) {
  return <span className={cx("sdot", `sdot-${tone}`)} aria-hidden="true" />;
}

export function Tag({ children, tone }: { children: ReactNode; tone?: "prod" | "muted" | "warn" | "bad" | "ok" }) {
  return <span className={cx("tag", tone && `tag-${tone}`)}>{children}</span>;
}

export function EnvTag({ env }: { env: string | null | undefined }) {
  if (!env) return <Tag tone="muted">—</Tag>;
  return <Tag tone={env === "production" ? "prod" : undefined}>{env}</Tag>;
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <code className={cx("mono-inline", className)}>{children}</code>;
}

export function Card({ children, className, title, actions, pad = true }: { children: ReactNode; className?: string; title?: ReactNode; actions?: ReactNode; pad?: boolean }) {
  return (
    <section className={cx("card", className)}>
      {(title || actions) && (
        <header className="card-head">
          {title && <h2 className="card-title">{title}</h2>}
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      <div className={cx(pad && "card-body")}>{children}</div>
    </section>
  );
}

export function PageHeader({ title, description, actions, eyebrow }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; eyebrow?: ReactNode }) {
  return (
    <header className="page-head">
      <div className="page-head-text">
        {eyebrow && <div className="page-eyebrow">{eyebrow}</div>}
        <h1 className="page-title">{title}</h1>
        {description && <p className="page-desc">{description}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

export function Empty({ title, children, action, icon }: { title: string; children?: ReactNode; action?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="empty">
      {icon && <div className="empty-icon">{icon}</div>}
      <p className="empty-title">{title}</p>
      {children && <p className="empty-text">{children}</p>}
      {action && <div className="empty-action">{action}</div>}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return (
    <div className="error-state" role="alert">
      <p className="error-state-title">Couldn't load this view</p>
      <p className="error-state-text">{errorMessage(error)}</p>
      {onRetry && (
        <Button size="sm" onClick={onRetry}>
          <IconRefresh /> Retry
        </Button>
      )}
    </div>
  );
}

export function Skeleton({ lines = 3, height }: { lines?: number; height?: number }) {
  return (
    <div className="skeleton" aria-busy="true" aria-label="Loading">
      {Array.from({ length: lines }, (_, i) => (
        <div key={i} className="skeleton-line" style={{ height: height ?? 14, width: `${92 - ((i * 17) % 40)}%` }} />
      ))}
    </div>
  );
}

export function Alert({ tone = "info", children, title }: { tone?: "info" | "warn" | "bad" | "ok"; children: ReactNode; title?: ReactNode }) {
  return (
    <div className={cx("alert", `alert-${tone}`)} role={tone === "bad" ? "alert" : "status"}>
      {title && <strong className="alert-title">{title}</strong>}
      <div className="alert-body">{children}</div>
    </div>
  );
}

export function Field({ label, hint, error, children, htmlFor, optional }: { label: ReactNode; hint?: ReactNode; error?: string; children: ReactNode; htmlFor?: string; optional?: boolean }) {
  return (
    <div className={cx("field", error && "has-error")}>
      <label className="field-label" htmlFor={htmlFor}>
        {label}
        {optional && <span className="field-optional">optional</span>}
      </label>
      {children}
      {error ? (
        <p className="field-error">{error}</p>
      ) : (
        hint && <p className="field-hint">{hint}</p>
      )}
    </div>
  );
}

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cx("input", props.className)} />;
}
export function Select(props: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={cx("input select", props.className)} />;
}
export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} className={cx("input textarea", props.className)} />;
}

export function Toggle({ checked, onChange, label, disabled, id }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean; id?: string }) {
  return (
    <button type="button" id={id} role="switch" aria-checked={checked} aria-label={label} className={cx("switch", checked && "is-on")} disabled={disabled} onClick={() => onChange(!checked)}>
      <span className="switch-knob" />
    </button>
  );
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch {
      ok = false;
    }
    ta.remove();
    return ok;
  }
}

export function CopyButton({ text, label = "Copy", size = "sm" }: { text: string; label?: string; size?: "sm" | "md" }) {
  const [state, setState] = useState<"idle" | "done" | "fail">("idle");
  useEffect(() => {
    if (state === "idle") return;
    const t = window.setTimeout(() => setState("idle"), 1800);
    return () => window.clearTimeout(t);
  }, [state]);
  return (
    <Button size={size} variant="ghost" type="button" onClick={async () => setState((await copyText(text)) ? "done" : "fail")} aria-live="polite">
      {state === "done" ? <IconCheck /> : <IconCopy />}
      {state === "done" ? "Copied" : state === "fail" ? "Select & copy" : label}
    </Button>
  );
}

export function CodeBlock({ code, language, copy = true }: { code: string; language?: string; copy?: boolean }) {
  return (
    <div className="code">
      <div className="code-head">
        <span className="code-lang">{language ?? "code"}</span>
        {copy && <CopyButton text={code} />}
      </div>
      <pre className="code-pre" tabIndex={0}>
        <code>{code}</code>
      </pre>
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange, label }: { tabs: Array<{ id: T; label: ReactNode; count?: number }>; value: T; onChange: (v: T) => void; label: string }) {
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          type="button"
          aria-selected={value === t.id}
          className={cx("tab", value === t.id && "is-active")}
          onClick={() => onChange(t.id)}
        >
          {t.label}
          {t.count !== undefined && <span className="tab-count">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function useFocusTrap(active: boolean, onEscape: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  const escRef = useRef(onEscape);
  escRef.current = onEscape;
  useEffect(() => {
    if (!active) return;
    const previous = document.activeElement as HTMLElement | null;
    const node = ref.current;
    const first = node?.querySelector<HTMLElement>("[data-autofocus]") ?? node?.querySelector<HTMLElement>(FOCUSABLE);
    first?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        escRef.current();
        return;
      }
      if (e.key !== "Tab" || !node) return;
      const items = Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((el) => el.offsetParent !== null);
      if (!items.length) return;
      const firstEl = items[0]!;
      const lastEl = items[items.length - 1]!;
      if (e.shiftKey && document.activeElement === firstEl) {
        e.preventDefault();
        lastEl.focus();
      } else if (!e.shiftKey && document.activeElement === lastEl) {
        e.preventDefault();
        firstEl.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = overflow;
      previous?.focus?.();
    };
  }, [active]);
  return ref;
}

export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  size = "md",
  dismissable = true,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  size?: "sm" | "md" | "lg";
  dismissable?: boolean;
}) {
  const titleId = useId();
  const ref = useFocusTrap(open, () => dismissable && onClose());
  if (!open) return null;
  return createPortal(
    <div className="dialog-backdrop" onMouseDown={(e) => dismissable && e.target === e.currentTarget && onClose()}>
      <div ref={ref} className={cx("dialog", `dialog-${size}`)} role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <header className="dialog-head">
          <div>
            <h2 id={titleId} className="dialog-title">
              {title}
            </h2>
            {description && <p className="dialog-desc">{description}</p>}
          </div>
          {dismissable && (
            <button type="button" className="icon-btn" onClick={onClose} aria-label="Close dialog">
              <IconClose />
            </button>
          )}
        </header>
        {children && <div className="dialog-body">{children}</div>}
        {footer && <footer className="dialog-foot">{footer}</footer>}
      </div>
    </div>,
    document.body,
  );
}

export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  children,
  confirmLabel,
  tone = "danger",
  busy,
  error,
}: {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  children: ReactNode;
  confirmLabel: string;
  tone?: "danger" | "primary";
  busy?: boolean;
  error?: string | null;
}) {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={title}
      size="sm"
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant={tone} onClick={onConfirm} loading={busy}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="confirm-body">{children}</div>
      {error && <Alert tone="bad">{error}</Alert>}
    </Dialog>
  );
}

// Toasts ---------------------------------------------------------------------

type Toast = { id: number; text: string; tone: "ok" | "bad" };
let pushToast: ((t: Omit<Toast, "id">) => void) | null = null;
export function toast(text: string, tone: "ok" | "bad" = "ok") {
  pushToast?.({ text, tone });
}

export function Toaster() {
  const [items, setItems] = useState<Toast[]>([]);
  useEffect(() => {
    let n = 0;
    pushToast = (t) => {
      const id = ++n;
      setItems((cur) => [...cur, { ...t, id }]);
      window.setTimeout(() => setItems((cur) => cur.filter((x) => x.id !== id)), 3600);
    };
    return () => {
      pushToast = null;
    };
  }, []);
  return (
    <div className="toaster" aria-live="polite" role="status">
      {items.map((t) => (
        <div key={t.id} className={cx("toast", `toast-${t.tone}`)}>
          {t.tone === "ok" ? <IconCheck /> : <IconClose />}
          {t.text}
        </div>
      ))}
    </div>
  );
}

export function DefinitionList({ items, className }: { items: Array<[ReactNode, ReactNode]>; className?: string }) {
  return (
    <dl className={cx("dl", className)}>
      {items.map(([k, v], i) => (
        <div key={i} className="dl-row">
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Stat({ label, value, sub, tone }: { label: ReactNode; value: ReactNode; sub?: ReactNode; tone?: "allow" | "review" | "block" | "ok" | "warn" | "bad" }) {
  return (
    <div className={cx("stat", tone && `stat-${tone}`)}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

export function JsonView({ value }: { value: unknown }) {
  const text = JSON.stringify(value, null, 2);
  return (
    <pre className="json" tabIndex={0}>
      <code>{renderJson(text)}</code>
    </pre>
  );
}

function renderJson(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    if (m[1]) {
      const isKey = !!m[2];
      const isRedacted = m[1] === '"[REDACTED]"';
      out.push(
        <span key={i++} className={isKey ? "j-key" : isRedacted ? "j-redacted" : "j-str"}>
          {m[1]}
        </span>,
      );
      if (m[2]) out.push(m[2]);
    } else if (m[3]) out.push(<span key={i++} className="j-lit">{m[3]}</span>);
    else if (m[4]) out.push(<span key={i++} className="j-num">{m[4]}</span>);
    last = re.lastIndex;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

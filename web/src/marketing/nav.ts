export function initNav(): void {
  const nav = document.querySelector<HTMLElement>("[data-nav]");
  const toggle = document.querySelector<HTMLButtonElement>("[data-nav-toggle]");
  const drawer = document.querySelector<HTMLElement>("[data-drawer]");
  if (!nav || !toggle || !drawer) return;

  const label = toggle.querySelector<HTMLElement>(".sr-only");

  const onScroll = () => nav.classList.toggle("is-scrolled", window.scrollY > 8);
  onScroll();
  window.addEventListener("scroll", onScroll, { passive: true });

  const focusables = () =>
    Array.from(drawer.querySelectorAll<HTMLElement>("a[href], button:not([disabled])")).filter((el) => !el.hidden);

  const setOpen = (open: boolean, restoreFocus = true) => {
    drawer.hidden = !open;
    nav.classList.toggle("is-open", open);
    toggle.setAttribute("aria-expanded", String(open));
    if (label) label.textContent = open ? "Close menu" : "Open menu";
    document.documentElement.style.overflow = open ? "hidden" : "";
    if (open) {
      focusables()[0]?.focus();
    } else if (restoreFocus) {
      toggle.focus();
    }
  };

  toggle.addEventListener("click", () => setOpen(drawer.hidden));

  drawer.addEventListener("click", (event) => {
    const link = (event.target as HTMLElement).closest("a");
    if (link) setOpen(false, false);
  });

  document.addEventListener("keydown", (event) => {
    if (drawer.hidden) return;
    if (event.key === "Escape") {
      event.preventDefault();
      setOpen(false);
      return;
    }
    if (event.key === "Tab") {
      const items = [toggle, ...focusables()];
      const first = items[0];
      const last = items[items.length - 1];
      if (!first || !last) return;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
  });

  window.matchMedia("(min-width: 1041px)").addEventListener("change", (mq) => {
    if (mq.matches && !drawer.hidden) setOpen(false, false);
  });
}

# Suspicious Frontend Modernization (React + Vite)

This folder contains a **minimal, incremental** React + Vite setup that can run alongside the existing Django templates. The goal is to **replace page-specific vanilla JS** with typed, component-based UI without forcing a full rewrite.

## Why React + Vite here?
- The current frontend is Django templates + Bulma + page-specific JS. Replacing those scripts with **React islands** keeps risk low and allows incremental adoption.
- Vite gives fast builds, ES module output, and manifest-based asset mapping that works well with Django.

## 1) Install dependencies

```bash
cd frontend
npm install
```

## 2) Build assets

```bash
npm run build
```

The build outputs assets to:
`Suspicious/Suspicious/tasp/static/vite` (see `vite.config.ts`).

## 3) Wire the dashboard island into Django

1) Add a mount point to the dashboard template. The mount point passes the initial month/year through `data-*` attributes:

```html
<div
  id="dashboard-root"
  data-month="{{ month }}"
  data-year="{{ year }}"
></div>
```

2) Load the Vite bundle produced for the dashboard entry. We recommend using a small Django helper to read `manifest.json` produced by Vite (`static/vite/.vite/manifest.json`), but you can also hardcode it temporarily:

```html
<link rel="stylesheet" href="{% static 'vite/assets/dashboard.css' %}">
<script type="module" src="{% static 'vite/assets/dashboard.js' %}"></script>
```

## 4) Move the dashboard JS to React

The React entry point is `src/dashboard.tsx`. It fetches the same endpoint used by the existing JS (`/dashboard-change/<month>/<year>`) and renders the summary + case stats.

If you still need charts, add a charting library (e.g., `chart.js`) and integrate inside `DashboardApp`.

## 5) Incremental strategy for the rest of the UI

- **Settings tabs**: replace inline `onclick` with a component that manages tab state.
- **Modal dialogs**: use a small accessible React dialog component so you can remove inline script blocks.
- **Navbar**: migrate the burger menu to a React component to remove `navbar.js`.

## 6) CSP-friendly scripting

Once inline scripts are removed:
- enforce CSP without `unsafe-inline`
- load Vite bundles with `type="module"`

## Notes
- This is intentionally a **small first step**; no production routes are changed yet.
- The existing templates remain the source of truth for routing and access control.

# RustGuard dashboard

React and TypeScript dashboard for the local RustGuard API. It displays live passive TCP SYN port-scan alerts and reports capture status. The feed starts empty until the API is configured to capture an interface.

## Run locally

From the repository root, start the API with the live-capture feature and an authorized interface:

```powershell
cargo run -p ids-cli --features ids-cli/live-capture -- serve-api --interface "YOUR INTERFACE"
```

Then, in this directory, run `npm install` followed by `npm run dev`. Open the local URL printed by Vite. The dev server proxies `/api` to `127.0.0.1:8080`. Use `npm run build` to create a production bundle in `dist/`.

Without an interface, `cargo run -p ids-cli -- serve-api` starts the API with capture idle and no generated alerts. For live capture prerequisites and detector thresholds, see the repository [README](../README.md).

## API and dashboard interactions

- `GET /api/v1/health` reports API and capture status.
- `GET /api/v1/sources` reports the capture interface and status.
- `GET /api/v1/stats/overview` supplies live alert, packet, and sensor counts.
- `GET /api/v1/alerts` supports `severity`, `q`, and `status` filters.
- `GET /api/v1/alerts/{id}` returns an alert detail record.
- `PATCH /api/v1/alerts/{id}` updates the alert status.
- Search, severity filtering, alert acknowledgement, and CSV export work in the dashboard.

Alerts and counters are kept in memory and reset when the API restarts.

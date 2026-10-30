# RustGuard IDS

RustGuard is a defensive intrusion detection system for networks you own or are authorized to monitor. The dashboard now displays live passive TCP SYN scan detection from a selected network interface. It does not send probes.

## Live port scan detection

The detector tracks unique source-to-destination TCP SYN targets over a rolling window. It raises alerts when one source contacts enough distinct ports (vertical scan) or hosts (horizontal sweep). Defaults are 12 ports or 12 hosts within 60 seconds, with a five minute per-source alert cooldown. Tune thresholds with the `serve-api` options.

Live capture is opt-in. On Windows, install Npcap and its SDK before compiling the live-capture feature; the SDK's `Lib` directory must be available to the linker. On Linux, install the libpcap development package. Capture permissions may require an elevated terminal or packet-capture group membership. Select an authorized interface; a SPAN/mirror port may be needed to observe traffic between other devices.

List available interfaces:

```powershell
cargo run -p ids-cli --features ids-cli/live-capture -- list-interfaces
```

Start the API and capture passively (replace the interface value with an exact listed name):

```powershell
cargo run -p ids-cli --features ids-cli/live-capture -- serve-api --interface "YOUR INTERFACE" --window-seconds 60 --unique-ports 12 --unique-hosts 12
```

Without `--interface`, the API starts with an empty alert feed and capture idle. The API's `/api/v1/health` response reports whether capture is idle, starting, active, or in error. Alerts and counters are in memory and reset when the API restarts.

## Dashboard

In another terminal, run:

```powershell
cd web
npm install
npm run dev
```

Open the local URL printed by Vite. The development server proxies `/api` requests to `127.0.0.1:8080`. Create a production bundle with `npm run build`.

## Other commands

`cargo run -p ids-cli -- --help` lists CLI options. The `run` command currently validates the configuration scaffold; live port scan monitoring is started through `serve-api`.

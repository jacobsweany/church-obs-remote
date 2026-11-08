# Church OBS Remote

A single-file web dashboard for running a church media service from one place —
built for a remote (offsite) operator who controls an on-site Mac running
OBS, a PTZ camera, and Zoom. One control surface, one reverse proxy in front,
and per-account tokens so several people can share the console.

![stack](https://img.shields.io/badge/stack-Python%20stdlib%20only-4587b3) ![platform](https://img.shields.io/badge/platform-macOS%20(Zoom%2Fcam)-f05133)

## What it does

| Area | Capabilities |
|---|---|
| **Service** | One-tap **Start** (OBS → Zoom sign-in/join → camera to start preset) and **Stop** (park camera, leave Zoom, optionally stop OBS), with a live step-by-step progress stream |
| **Camera** | PTZOptics HTTP API: pan/tilt/zoom, named presets, home position, and a **live preview stream** (frame pacing tuned for low latency) |
| **OBS** | OBS-WebSocket v5: scene switching (in the order OBS displays them), virtual camera on/off |
| **Zoom** | Join a conference by ID, scripted sign-in (email + password, screen-agnostic — works on both the email-entry and cached-account card UIs), a consolidated **Leave** (ends the meeting, signs out, closes the client), a live **in-meeting indicator with participant count** (updates within one refresh of join/leave), and a **participant name list** (📋 Names modal: exact names from the Accessibility tree, Vision-OCR fallback) |
| **Accounts** | Per-congregation Bearer tokens; admin sees everything (session activity, credential management, presets); regular accounts see a scoped console |
| **Console** | Live "who's active" status for all connected accounts, visit counts and last-seen info (admin), per-account Zoom account binding; session counters **reset daily at local midnight** |

## Architecture

```
 [operator's browser]
        │  HTTPS
        ▼
 [cloudflared / reverse proxy] ──► 127.0.0.1:8080  (dashboard)
                                          │
                 ┌────────────────────────┼─────────────────────┐
                 ▼                        ▼                     ▼
        [PTZOptics camera]         [OBS-WebSocket]      [Zoom client (macOS)]
        (HTTP API on LAN)          (localhost:4455)     (AppleScript + CGEvents)
```

- **Single file, Python standard library only** — no pip dependencies for the
  server itself. `church_dash.py` is the whole app (~3.3k lines).
- Binds **127.0.0.1 only**; a reverse proxy (cloudflared) is the only route in.
- Auth is **Bearer tokens** (per account + admin) with `hmac.compare_digest`
  checks; admin endpoints are gated by token class.
- Zoom automation is macOS-specific (AppleScript + CoreGraphics events); the
  Zoom sign-in flow is screen-agnostic by design (type email + Enter, password
  + Enter; if still on the login screen, click "Sign into a different account"
  and repeat) — no wrong-password lockout risk.

## Repository layout

```
church_dash.py               the whole dashboard (stdlib only)
zoom_key.py                  helper: send a single virtual key (CGEvent)
shot.sh                      helper: remote screenshot via Terminal.app (TCC-friendly)
config.example.json          config template — copy to config.json and fill in
congregations.example.csv    CSV template for the meeting/account table
examples/com.church.dash.plist   launchd agent template (run at boot, keep alive)
```

## Quickstart (macOS)

1. **Install Python 3** (Xcode Command Line Tools are fine:
   `xcode-select --install`).
2. **Copy the code** to a stable location, e.g. `~/church/`, and copy the
   templates:
   ```bash
   cp config.example.json config.json
   cp congregations.example.csv congregations.csv
   chmod 600 config.json congregations.csv
   ```
3. **Edit `config.json`**:
   - `port` — local listen port (127.0.0.1 only).
   - `camera` — PTZOptics host/port/user/pass (LAN-reachable from the Mac).
   - `obs` — OBS-WebSocket host/port/pass/ssl (enable the WebSocket server in
     OBS: Settings → General → Stream Service → obs-websocket, or the plugin).
   - `zoom.confno` — default conference ID used by the Join button.
   - `meetings` — optional weekly schedule table shown on the console.
   - `tokens` — one entry per account. Give the admin entry
     `"admin": true`. Generate tokens with:
     `python3 -c "import secrets; print(secrets.token_hex(24))"`.
   - Zoom account passwords are stored in the **macOS Keychain** (per account),
     not in `config.json`.
4. **Run it**:
   ```bash
   python3 church_dash.py
   ```
   then open `http://127.0.0.1:8080/`.
5. **Run at boot** (optional): adapt `examples/com.church.dash.plist` to your
   paths, put it in `~/Library/LaunchAgents/`, then
   `launchctl load ~/Library/LaunchAgents/com.church.dash.plist`.
6. **Expose it**: point cloudflared (or Caddy/nginx + Let's Encrypt) at
   `127.0.0.1:8080`.

## Security model

- The server never listens on a public interface.
- Every request must carry a valid Bearer token (`Authorization: Bearer <tok>`)
  in a header or the `?token=` query (for links that can't set headers).
- Regular accounts: scoped console — their own Zoom account, their meeting row,
  no credential management, no other accounts' details (they only see that
  *other accounts are active*, not which device/browser).
- Admin: session activity (active/last-seen, visits, browser/OS), Zoom
  credential setup, camera preset save, full console.
- `config.json`, `congregations.csv`, and `sessions.json` are **secrets/PII** —
  they are git-ignored and must never be committed. Zoom credentials live in
  the macOS Keychain.

## macOS permission notes (Zoom + screenshots)

- **Accessibility** — grant to the terminal/launchd context that drives
  AppleScript/CGEvents so the dashboard can control Zoom.
- **Screen Recording** — TCC attaches this permission to the *responsible
  process*: if the dashboard runs from the Command Line Tools Python, add
  `.../Python.app` to Privacy → Screen Recording, then restart the dashboard.
  (The `shot.sh` helper is an alternative: it runs `screencapture` inside
  Terminal.app, which typically already holds the permission.)

## Known deployment choices to adapt

- The webinar-ID row is shown for the admin and for the profile named
  `Stake` (search `wbRow` in `church_dash.py`) — change to match your
  deployment.
- **Participant names** prefer the Accessibility tree (no extra deps). If your
  Zoom build renders the list AX-opaque (empty names), the dashboard falls back
  to a **Vision-OCR helper**: a small native `zoom_ocr` binary at
  `~/church/zoom_api/zoom_ocr` (screenshot the panel + Apple Vision text
  recognition). That helper is *not* in this repo (macOS-specific, compiled
  locally); without it the fallback degrades to an empty list with a warning.
- **Daily reset**: session counters (visits / active-seconds / last-seen) reset
  at local midnight so the "who's been here" numbers always reflect the current
  day.
- Scene switching lists scenes in OBS display order (newest first, matching
  OBS Blade's ordering) — the first entry is whatever OBS shows first.
- Frame pacing uses a spin-wait instead of `time.sleep(33ms)` inside the
  launchd-managed process: macOS throttles short sleeps in agent processes
  (78–170 ms observed), which capped the preview at ~7 fps. Spin-waiting
  restores ~25 fps end-to-end through the tunnel.

## License

MIT — do what you want with it; no warranty.

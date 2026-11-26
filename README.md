<div align="center">
  <img src="images/logo.png" alt="AutoMorph Logo" width="340">
  <p><br>Automated Android APK patching and distribution orchestrator powered by <strong>Morphe Desktop</strong>.</p>
  <p><strong>This fork (<code>LoginRs99/AutoMorph</code>)</strong> lets you keep the Web UI strictly local/LAN-only (zero public Cloudflare, Pangolin, or Tailscale tunnels) while publishing signed APKs to <strong>GitHub Releases</strong> for seamless <strong>Obtainium</strong> updates.</p>
</div>

---

## Credits & Fork Attribution

- **Original Creator & Upstream Project:** Full credit goes to **[holjab](https://github.com/holjab)** and the upstream **[holjab/AutoMorph](https://github.com/holjab/AutoMorph)** repository for designing and building AutoMorph's core patching pipeline, APK fetcher, web control center, and scheduler.
- **Core Ecosystem:**
  - **[Morphe Desktop](https://github.com/MorpheApp/morphe-desktop)** — Underlying Android patching engine.
  - **[Obtainium](https://github.com/ImranR98/Obtainium)** — Client-side Android app update delivery.
  - **[goopdl](https://github.com/Villoh/goopdl)** — Google Play base APK downloader.
- **About This AI-Assisted Fork:** The GitHub Releases publisher (`scripts/github_release.py`), Obtainium GitHub exporter, APK signing certificate fingerprint guard, "What Changed" release diffs, live builds `README.md` dashboard, Apprise notifications, Portainer stack (`portainer-compose.yaml`), and automated upstream-sync workflow were developed by **LoginRs99** as an **AI-assisted fork** with AI coding and architectural orchestration.

---

## How This Fork Works

**Philosophy:** *Configure once in the local Web UI → auto-build on schedule → auto-release forever to GitHub Releases.*

AutoMorph supports two distribution modes:

1. **Fork Mode (Recommended — Local Web UI + GitHub Releases):**
   - Keep port `8080` bound to your LAN or Tailscale IP only—no public ingress or reverse-proxy tunnels required.
   - After each build, `scripts/github_release.py` uploads patched APKs to your dedicated builds repository under `<package>-v<version>` tags, prunes older releases (`GITHUB_RELEASE_KEEP`), updates the builds repository's `README.md` dashboard, and publishes `obtainium-github-export.json` under the `automorph-config` release tag.
2. **Upstream Tunnel Mode (Still Supported):**
   - Expose the local portal and built-in F-Droid/Obtainium endpoints via Cloudflare Tunnel, Pangolin, or Tailscale Funnel using [`default_compose.yaml`](default_compose.yaml) and the [Remote Access & Tunnels Guide](docs/tunnels.md).

---

## Complete Setup Guide (GitHub Releases + Portainer + Obtainium)

### Step 1: Create Your Builds Repository & Fine-Grained PAT

1. Create a GitHub repository to host your patched APKs (for example, `LoginRs99/automorph-builds`).
   - **Public repository:** Ideal for family/multi-device sharing—Obtainium can download APKs and `obtainium-github-export.json` with zero authentication.
   - **Private repository:** Works identically for extra privacy, but requires adding a read-only GitHub PAT inside Obtainium on each device.
2. Create a **Fine-Grained Personal Access Token** scoped to that builds repository with:
   - **Contents:** `Read and write`
   - **Metadata:** `Read-only`

### Step 2: Fork Image via GitHub Actions (GHCR)

1. Enable **GitHub Actions** on your forked `AutoMorph` repository.
2. Pushing to `main` (or triggering [`.github/workflows/docker-publish.yaml`](.github/workflows/docker-publish.yaml) manually) builds and publishes `ghcr.io/loginrs99/automorph:latest` (replace `loginrs99` with your GitHub username if using your own fork). Docker Hub secrets are optional and automatically skipped when unset.
3. Ensure the published GHCR package visibility is set to **Public** (or linked to the repository) so Docker/Portainer can pull it.

### Step 3: Deploy with Portainer or Docker Compose

#### Option A: Portainer Stacks ([`portainer-compose.yaml`](portainer-compose.yaml))

1. Create the persistent host directories on your Docker host:
   ```bash
   sudo mkdir -p /opt/automorph/apps /opt/automorph/tools/morphe-data /opt/automorph/tools/automorph-data
   ```
2. Open **Portainer → Stacks → Add stack**, paste [`portainer-compose.yaml`](portainer-compose.yaml) into the Web Editor (optionally restrict `ports:` to your LAN/Tailscale IP, e.g. `192.168.1.100:8080:8080`).
3. Upload [`example.env`](example.env) or paste your variables (`GITHUB_RELEASE_REPO`, `GITHUB_RELEASE_TOKEN`, `APPRISE_URL`, etc.) into Portainer's **Environment variables** section, then deploy.

#### Option B: Standard Docker Compose ([`default_compose.yaml`](default_compose.yaml))

1. Copy [`example.env`](example.env) to `.env` and fill in your values.
2. Run:
   ```bash
   docker compose -f default_compose.yaml pull
   docker compose -f default_compose.yaml up -d
   ```

### Step 4: First-Run Visual Patch Setup

1. Open `http://<server-lan-ip>:8080` in your browser.
2. Add your target Android packages, toggle desired patches/options once, and trigger a build.
3. *(Optional)* If you already have previously patched APKs in `patched.json` that have not been uploaded to GitHub Releases yet, set `GITHUB_RELEASE_SYNC_ALL=true` for one run to catch them up.

### Step 5: Import into Obtainium (Your Phone & Family)

1. On each Android device, open **Obtainium → Import/Export → Obtainium Import** and import:
   ```text
   https://github.com/<owner>/<builds-repo>/releases/download/automorph-config/obtainium-github-export.json
   ```
2. **Why `Verify Latest Tag` is `OFF`:** Because all apps share a single builds repository, each app entry in `obtainium-github-export.json` is pre-configured with `verifyLatestTag: false` and per-package regex filters (`^<package>-v` for tags and `^<package>-.*\.apk$` for assets) so apps never collide.
3. *(Optional / Required if builds repo is Private)* Paste a read-only GitHub PAT under **Obtainium → Settings → GitHub Personal Access Token**.

---

## Fork Features & Safeguards

- **Signing Certificate Fingerprint Guard:** Before uploading a new APK, AutoMorph parses the APK Signature Scheme v2/v3 Signing Block (`APK Sig Block 42`) and hashes the X.509 DER certificate. If the signing key differs from the previous release in `github_releases.json`, the upload is aborted to prevent `INSTALL_FAILED_UPDATE_INCOMPATIBLE` (override once with `ALLOW_CERT_CHANGE=true`).
- **"What Changed" Release Diffs & Live Builds Dashboard:** Each GitHub Release body includes a `#### What Changed` section comparing version transitions and added/removed patches against the prior release. When `GITHUB_RELEASE_UPDATE_README=true`, AutoMorph also maintains a live Markdown table of active apps and direct download links in your builds repository's `README.md`.
- **Apprise Notifications & Failure Alerts:** Set `APPRISE_URL` (space- or comma-separated Discord, ntfy, Telegram, etc. URLs) to receive concise summaries for newly published releases as well as build-failure / cert-mismatch alerts (`APPRISE_NOTIFY_ON_FAILURE=true`).
- **Automated Upstream Sync:** [`.github/workflows/upstream-sync.yaml`](.github/workflows/upstream-sync.yaml) runs weekly (and on manual `workflow_dispatch`) to merge `holjab/AutoMorph` (`main`) into a `sync/upstream-main` branch and open a Pull Request for clean review.

---

## Environment Variables Reference

| Variable | Default | Description | Example |
| --- | --- | --- | --- |
| `GITHUB_RELEASE_REPO` | *(empty / disabled)* | Target `owner/repo` for APK releases | `LoginRs99/automorph-builds` |
| `GITHUB_RELEASE_TOKEN` | *(falls back to `GITHUB_TOKEN`)* | Fine-grained PAT (`Contents: Read and write`) | `github_pat_...` |
| `GITHUB_RELEASE_KEEP` | `2` | Max releases kept per package (`<= 0` disables pruning) | `2` |
| `GITHUB_RELEASE_PUBLISH_CONFIG` | `true` | Upload `obtainium-github-export.json` to `automorph-config` | `true` |
| `GITHUB_RELEASE_EXCLUDE` | *(empty)* | Comma-separated packages omitted from Obtainium export | `com.example.private` |
| `GITHUB_RELEASE_SYNC_ALL` | `false` | Catch up un-published latest versions in `patched.json` | `false` |
| `FORCE_GITHUB_RELEASE` | `false` | Re-upload even if SHA-256 matches `github_releases.json` | `false` |
| `GITHUB_RELEASE_UPDATE_README` | `true` | Auto-update `README.md` dashboard in builds repo | `true` |
| `ALLOW_CERT_CHANGE` | `false` | Allow upload if APK signing certificate SHA-256 changed | `false` |
| `APPRISE_URL` | *(empty / disabled)* | Space/comma-separated Apprise notification URL(s) | `ntfy://topic discord://id/tok` |
| `APPRISE_NOTIFY_ON_FAILURE` | `true` | Send Apprise alert on build failures or cert mismatches | `true` |
| `GITHUB_TOKEN` | *(empty)* | Optional PAT for upstream patch repo queries / fallback | `ghp_...` |
| `GOOPDL_ACCOUNT_EMAIL` | *(empty)* | Disposable Google account email for Play Store downloads | `burner@gmail.com` |
| `GOOPDL_AAS_TOKEN` | *(empty)* | AAS token for `goopdl` Play Store authentication | `aas_et/...` |
| `SMTP_USERNAME` | *(empty)* | SMTP username for optional email build reports | `user@gmail.com` |
| `SMTP_PASSWORD` | *(empty)* | SMTP password / App Password for email reports | `abcd efgh ijkl mnop` |
| `BASE_URL` | *(empty)* | Optional external/LAN URL for built-in Obtainium/F-Droid feeds | `http://192.168.1.100:8080` |
| `COMPOSE_PROFILES` | *(empty)* | Optional tunnel profiles (`cloudflare`, `pangolin`, `tailscale`) | `cloudflare` |
| `CLOUDFLARE_TUNNEL_TOKEN` | *(empty)* | Cloudflare Tunnel token (when using `cloudflare` profile) | `eyJ...` |
| `CLOUDFLARE_TUNNEL_URL` | *(empty)* | Public Cloudflare Tunnel URL | `https://automorph.example.com` |
| `PANGOLIN_ENDPOINT` | *(empty)* | Pangolin Newt endpoint | `https://pangolin.example.com` |
| `PANGOLIN_ID` | *(empty)* | Pangolin Newt ID | `...` |
| `PANGOLIN_SECRET` | *(empty)* | Pangolin Newt secret | `...` |
| `PANGOLIN_URL` | *(empty)* | Public Pangolin URL | `https://automorph.example.com` |
| `TAILSCALE_FUNNEL_URL` | *(empty)* | Public Tailscale Funnel URL | `https://node.tailnet.ts.net` |

---

## Upstream Key Features

- **Automated repo tracking:** Monitors patch repositories for updates.
- **Automatic APK downloads:** Downloads base APKs automatically, prioritising Google Play and falling back to APKCombo, Uptodown, and APKPure.
- **Email notifications and web portal:** Get email alerts with direct download links whenever a patch succeeds, or download builds directly from the web portal.
- **Optional Obtainium & F-Droid sync:** Supports 1-tap Obtainium sync and an F-Droid compatible repository feed.
- **Scheduled or manual builds:** Run automatically once a day at a time of your choice, or start a build manually through the web interface.
- **Free hosting:** Designed to run within the free tier of Oracle Cloud Infrastructure or any local Docker host.

## Screenshots

### Control Center & Dashboard
![AutoMorph Dashboard](images/dashboard.png)

### Add Package Wizard
![Add Package Wizard](images/add_package.png)

### Settings & Tunnels
![Settings & Tunnels](images/settings.png)

## Upstream Documentation

For full step-by-step upstream guides, visit the **[Documentation Hub](docs/README.md)**:

* ☁️ **[Oracle Free Tier Setup Guide (Optional)](docs/oracle-setup.md)**: Launch a free VPS on Oracle Cloud.
* 🚇 **[Remote Access & Tunnels Guide](docs/tunnels.md)**: Expose your portal securely with free HTTPS via Pangolin, Tailscale Funnel, or Cloudflare Tunnels.
* 📖 **[User Guide & Web Interface](docs/user-guide.md)**: Managing packages, customizing patch options, daily schedules, Obtainium / F-Droid sync, and email notifications.

## Disclaimer

AutoMorph is provided as-is for educational and personal use. Ensure you comply with the terms of service of any app stores, patch repositories, and services you interact with.

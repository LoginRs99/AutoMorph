<div align="center">
  <img src="images/logo.png" alt="AutoMorph Logo" width="340">
  <p><br>A self-hosted tool for automatically patching and distributing Android packages, built on Morphe Desktop.</p>
</div>

## GitHub Releases & Obtainium Integration (Fork Guide)

### What This Fork Adds

- **Automated GitHub Releases Publishing:** Automatically uploads patched APKs to GitHub Releases under `<package>-v<version>` tags so the AutoMorph Web UI can remain strictly local/LAN-only with zero Cloudflare, Pangolin, or Tailscale tunnels exposed.
- **Automatic Release Pruning:** Keeps only the newest `GITHUB_RELEASE_KEEP` releases per package (default `2`) and deletes older releases and their git tags.
- **Live-Synced Obtainium Config Export:** Automatically generates `obtainium-github-export.json` filtered to active (enabled) apps in `config.yaml` (minus any `GITHUB_RELEASE_EXCLUDE` entries) and uploads it to a dedicated `automorph-config` release tag for one-click multi-device or family import.
- **Signing Certificate Fingerprint Guard:** Extracts the APK Signature Scheme v2/v3 X.509 certificate SHA-256 before uploading and aborts if the signing key changed unexpectedly (preventing `INSTALL_FAILED_UPDATE_INCOMPATIBLE`), unless `ALLOW_CERT_CHANGE=true`.
- **"What Changed" Release Diffs:** Compares each build against the prior release in `github_releases.json` to render version transitions and added/removed patches in GitHub Release notes and Apprise alerts.
- **Live Builds Dashboard (`README.md`):** Automatically updates `README.md` in your builds repository with a table of active APKs, direct download links, and the Obtainium 1-click import URL (`GITHUB_RELEASE_UPDATE_README=true`).
- **Multi-Platform Notifications & Failure Alerts via Apprise:** Sends concise release summaries and optional build-failure / cert-mismatch alerts (`APPRISE_NOTIFY_ON_FAILURE=true`) via `APPRISE_URL` (Discord, ntfy, Telegram, etc.).
- **One-Click Upstream Sync Workflow:** Includes [`.github/workflows/upstream-sync.yaml`](.github/workflows/upstream-sync.yaml) (weekly + manual `workflow_dispatch`) to merge `holjab/AutoMorph` (`main`) into a `sync/upstream-main` PR cleanly.

### Step 1: Create the Builds Repository & Token

1. Create a GitHub repository to host your patched APKs (for example, `LoginRs99/automorph-builds`).
   - **Public repo:** Enables zero-auth downloads for family/multi-device Obtainium imports.
   - **Private repo:** Works identically, but requires configuring a read-only GitHub PAT in Obtainium on each device.
2. Create a **Fine-Grained Personal Access Token** scoped to that builds repository with:
   - **Contents:** `Read and write`
   - **Metadata:** `Read-only`

### Step 2: Build & Publish the Fork Image (GHCR)

1. Enable **GitHub Actions** on your forked `AutoMorph` repository.
2. Pushing to `main` (or triggering the workflow manually) builds and publishes `ghcr.io/<your-user>/automorph:latest` via [`.github/workflows/docker-publish.yaml`](.github/workflows/docker-publish.yaml) without requiring Docker Hub secrets.
3. Ensure the published GHCR package visibility is set to **Public** (or linked to the repository) so Docker/Portainer can pull it.

### Step 3: Deploy in Portainer

1. Create the persistent host directories on your Docker host:
   ```bash
   sudo mkdir -p /opt/automorph/apps /opt/automorph/tools/morphe-data /opt/automorph/tools/automorph-data
   ```
2. Open **Portainer → Stacks → Add stack**, paste [`portainer-compose.yaml`](portainer-compose.yaml) into the Web Editor (replacing `loginrs99` with your GitHub username if using a different fork).
3. Upload [`example.env`](example.env) or paste your environment variables (`GITHUB_RELEASE_REPO`, `GITHUB_RELEASE_TOKEN`, `APPRISE_URL`, etc.) into Portainer's **Environment variables** section, then deploy the stack.

### Step 4: First-Run Patch Setup & Obtainium Import

1. Open `http://<server-lan-ip>:8080`, add your target apps, toggle desired patches once, and trigger a build.
2. On each Android device in **Obtainium**:
   1. Go to **Import/Export → Obtainium Import** and import:
      ```text
      https://github.com/<owner>/<builds-repo>/releases/download/automorph-config/obtainium-github-export.json
      ```
   2. Note that **Verify Latest Tag** is pre-configured to `OFF` (`verifyLatestTag: false`) with per-app `^<package>-v` tag and `^<package>-.*\.apk$` asset regex filters so multiple apps in one repository never collide.
   3. *(Optional / Required if repo is Private)* Paste a read-only GitHub PAT under **Obtainium → Settings → GitHub Personal Access Token**.

### Environment Variables Reference

| Variable | Default | Description | Example |
| --- | --- | --- | --- |
| `GITHUB_RELEASE_REPO` | *(empty / disabled)* | Target `owner/repo` for APK releases | `LoginRs99/automorph-builds` |
| `GITHUB_RELEASE_TOKEN` | *(falls back to `GITHUB_TOKEN`)* | Fine-grained PAT with `Contents: Read and write` | `github_pat_...` |
| `GITHUB_RELEASE_KEEP` | `2` | Max releases kept per package (`<= 0` disables pruning) | `2` |
| `GITHUB_RELEASE_PUBLISH_CONFIG` | `true` | Upload `obtainium-github-export.json` to `automorph-config` tag | `true` |
| `GITHUB_RELEASE_EXCLUDE` | *(empty)* | Comma-separated packages omitted from Obtainium export | `com.example.private` |
| `GITHUB_RELEASE_SYNC_ALL` | `false` | Catch up un-published latest versions in `patched.json` | `false` |
| `FORCE_GITHUB_RELEASE` | `false` | Re-upload even if SHA-256 already matches `github_releases.json` | `false` |
| `GITHUB_RELEASE_UPDATE_README` | `true` | Auto-update `README.md` dashboard in the builds repo | `true` |
| `ALLOW_CERT_CHANGE` | `false` | Allow upload if APK signing certificate SHA-256 changed | `false` |
| `APPRISE_URL` | *(empty / disabled)* | Space- or comma-separated Apprise notification URL(s) | `ntfy://my-topic discord://id/token` |
| `APPRISE_NOTIFY_ON_FAILURE` | `true` | Send Apprise alert on build failures or cert mismatches | `true` |

### Credits / Attribution

This fork builds upon upstream [`holjab/AutoMorph`](https://github.com/holjab/AutoMorph). The GitHub Releases publisher, signing certificate guard, Obtainium config sync, Apprise notifications, Portainer compose, and upstream-sync workflow were implemented as an **AI-assisted fork** (built with an AI coding agent and Gemini orchestration).

## Key Features

- **Automated repo tracking:** Monitors patch repositories for updates.
- **Automatic APK downloads:** Downloads base APKs automatically, prioritising Google Play and falling back to APKCombo, Uptodown, and APKPure.
- **Email notifications and web portal:** Get email alerts with direct download links whenever a patch succeeds, or download builds directly from the web portal. *A dedicated Android app for notifications and downloads is planned.*
- **Optional Obtainium & F-Droid sync:** Supports 1-tap Obtainium sync and an F-Droid compatible repository feed for users who prefer updates delivered automatically to their phone.
- **Scheduled or manual builds:** Run automatically once a day at a time of your choice, or start a build manually through the web interface.
- **Free hosting:** Designed to run within the free tier of Oracle Cloud Infrastructure.
  - Works with free **Pangolin tunnels** or **Tailscale Funnel** for a URL to access the web portal and downloads.
  - Supports **Cloudflare Tunnels** if you use a custom domain.

## Screenshots

### Control Center & Dashboard
<!-- Screenshot placeholder: Save a screenshot of the main dashboard to images/dashboard.png -->
![AutoMorph Dashboard](images/dashboard.png)

### Add Package Wizard
![Add Package Wizard](images/add_package.png)

### Settings & Tunnels
![Settings & Tunnels](images/settings.png)

## Documentation

For full step-by-step guides, visit our **[Documentation Hub](docs/README.md)**:

* ☁️ **[Oracle Free Tier Setup Guide (Optional)](docs/oracle-setup.md)**: Optional guide to launch a free VPS on Oracle Cloud (skip if you already have your own server!).
* 🚇 **[Remote Access & Tunnels Guide](docs/tunnels.md)**: Expose your portal securely with free HTTPS via Pangolin, Tailscale Funnel, or Cloudflare Tunnels.
* 📖 **[User Guide & Web Interface](docs/user-guide.md)**: Managing packages, customizing patch options, daily schedules, Obtainium / F-Droid sync, and email notifications.

## Prerequisites

- Docker & Docker Compose

## Quick Start

1. Set up your preferred [remote tunnel](docs/tunnels.md) (Pangolin, Tailscale Funnel, or Cloudflare) to obtain your URL and tokens.
2. Download `compose.yaml` (from [`default_compose.yaml`](default_compose.yaml)) and [`example.env`](example.env).
3. Fill in your details and tunnel credentials in `example.env`, then rename it to `.env`.
4. Run:

   ```bash
   docker compose pull
   docker compose up -d
   ```

4. Open your web portal via your configured tunnel or local URL (`http://localhost:8080`). For detailed configuration, see the [User Guide](docs/user-guide.md).

## A Note on AI

AutoMorph started as a personal project to practise and improve my Python skills. I wrote the vast majority of the backend and core logic myself. The web interface was mostly written with AI assistance, with me guiding the development.

## Acknowledgements

- **Morphe Desktop**
- **Obtainium** - Heavily inspired the package scraping and discovery methods.
- **goopdl** - For downloads from Google Play: https://github.com/Villoh/goopdl

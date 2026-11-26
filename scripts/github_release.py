"""
Isolated GitHub Releases publisher for AutoMorph.
Uploads patched APKs to a GitHub repository using human-readable app slugs,
guards signing certificate fingerprints, computes release diffs, generates
`obtainium-github-export.json`, maintains a live `README.md` dashboard,
rolling `CHANGELOG.md`, and `catalog.json`, and sends Apprise notifications.
"""

from __future__ import annotations

import base64
from collections import Counter
from datetime import datetime, timezone
import hashlib
import html
import json
import logging
import os
from pathlib import Path
import re
import struct
from typing import Any
from urllib.parse import quote

from dotenv import load_dotenv
import requests
import yaml

try:
    import apprise
except ImportError:
    apprise = None

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"
GITHUB_UPLOADS_BASE = "https://uploads.github.com"
REQUEST_TIMEOUT = 30
UPLOAD_TIMEOUT = 300
CONFIG_RELEASE_TAG = "automorph-config"
MAX_CHANGELOG_SECTIONS = 50

_APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
_APK_SIG_SCHEME_V2_ID = 0x7109871A
_APK_SIG_SCHEME_V3_ID = 0xF05368C0
_ZIP_EOCD_SIG = b"PK\x05\x06"


def _read_json(path: Path) -> dict[str, Any]:
    """Safely reads a JSON file into a dict, returning {} on missing or invalid files."""
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as e:
        logger.warning(f"[!] Failed to parse JSON from {path}: {e}")
        return {}


def _write_json(data: dict[str, Any], path: Path) -> None:
    """Writes a dict as formatted UTF-8 JSON, creating parent directories if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _parse_bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("true", "1", "yes")


def _parse_keep_env(default: int = 2) -> int:
    raw = os.getenv("GITHUB_RELEASE_KEEP")
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        logger.warning(f"[!] Invalid GITHUB_RELEASE_KEEP='{raw}', defaulting to {default}.")
        return default


def _format_bytes(size_bytes: int | float | None) -> str:
    if size_bytes is None:
        return "-"
    try:
        val = float(size_bytes)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if val < 1024.0:
            return f"{val:.2f} {unit}"
        val /= 1024.0
    return f"{val:.2f} PB"


def _slugify_label(label: str) -> str:
    """Normalizes a label into a lowercase hyphenated slug."""
    return re.sub(r"[^a-z0-9]+", "-", str(label).lower()).strip("-")


def _select_latest_version(versions: dict[str, Any]) -> str | None:
    """Selects the latest version key from a package's entries in patched.json."""
    if not versions:
        return None
    sorted_versions = sorted(
        versions.keys(),
        key=lambda v: versions[v].get("package", {}).get(
            "source_version_code",
            versions[v].get("package", {}).get("patched_version_code", 0),
        ),
        reverse=True,
    )
    return sorted_versions[0]


def _resolve_app_slugs(patched_results: dict[str, Any]) -> dict[str, str]:
    """
    Maps each `package_name` in `patched_results` to a human-readable slug
    derived from `package.clean_name`, falling back to `_slugify_label(package_name)`
    if empty or if two packages collide on the same label slug.
    """
    raw_slugs: dict[str, str] = {}
    for package_name, versions in patched_results.items():
        clean_name = ""
        if isinstance(versions, dict) and versions:
            latest_ver = _select_latest_version(versions)
            if latest_ver and isinstance(versions.get(latest_ver), dict):
                clean_name = str(versions[latest_ver].get("package", {}).get("clean_name") or "").strip()
        slug = _slugify_label(clean_name) if clean_name else ""
        if not slug:
            slug = _slugify_label(package_name) or package_name.lower()
        raw_slugs[package_name] = slug

    counts = Counter(raw_slugs.values())
    resolved: dict[str, str] = {}
    for package_name, slug in raw_slugs.items():
        if counts[slug] > 1:
            resolved[package_name] = _slugify_label(package_name) or package_name.lower()
        else:
            resolved[package_name] = slug
    return resolved


def _get_active_packages(project_root: Path) -> set[str] | None:
    """
    Reads `tools/automorph-data/config.yaml` and returns the set of active
    (uncommented) package names. Returns None if config.yaml is missing or unreadable.
    """
    config_path = project_root / "tools" / "automorph-data" / "config.yaml"
    if not config_path.is_file():
        return None
    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        packages = data.get("packages") or []
        if not isinstance(packages, list):
            return None
        active: set[str] = set()
        for pkg in packages:
            if isinstance(pkg, dict):
                name = str(pkg.get("package_name") or "").strip()
                if name:
                    active.add(name)
        return active
    except Exception as e:
        logger.warning(f"[!] Failed to read active packages from {config_path}: {e}")
        return None


def _get_excluded_packages() -> set[str]:
    """Parses comma-separated package names from GITHUB_RELEASE_EXCLUDE."""
    raw = os.getenv("GITHUB_RELEASE_EXCLUDE", "")
    return {p.strip() for p in raw.split(",") if p.strip()}


def _github_headers(token: str, content_type: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "AutoMorph-GitHubRelease",
    }
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def _extract_apk_cert_sha256(apk_path: Path) -> str | None:
    """
    Extracts the lowercase hex SHA-256 of the first signer's X.509 DER
    certificate from the APK Signature Scheme v2 (0x7109871a) or v3 (0xf05368c0)
    Signing Block located immediately before the ZIP Central Directory.
    Returns None if no valid v2/v3 signing block is found.
    """
    try:
        file_size = apk_path.stat().st_size
        if file_size < 22:
            return None

        with apk_path.open("rb") as f:
            tail_len = min(file_size, 65557)
            f.seek(file_size - tail_len)
            tail = f.read(tail_len)

            eocd_rel = -1
            search_from = len(tail)
            while True:
                idx = tail.rfind(_ZIP_EOCD_SIG, 0, search_from)
                if idx == -1:
                    break
                if idx + 22 <= len(tail):
                    comment_len = struct.unpack_from("<H", tail, idx + 20)[0]
                    if idx + 22 + comment_len == len(tail):
                        eocd_rel = idx
                        break
                search_from = idx

            if eocd_rel == -1:
                logger.debug(f"No ZIP EOCD found in {apk_path.name}; cannot read APK Signing Block.")
                return None

            cd_offset = struct.unpack_from("<I", tail, eocd_rel + 16)[0]
            if cd_offset < 32 or cd_offset > file_size:
                logger.debug(f"Invalid Central Directory offset ({cd_offset}) in {apk_path.name}.")
                return None

            f.seek(cd_offset - 24)
            footer = f.read(24)
            if len(footer) != 24 or footer[8:] != _APK_SIG_BLOCK_MAGIC:
                logger.debug(f"No APK Signing Block v2/v3 magic in {apk_path.name}.")
                return None

            block_size = struct.unpack_from("<Q", footer, 0)[0]
            total_size = block_size + 8
            if block_size < 24 or total_size > cd_offset:
                return None

            block_start = cd_offset - total_size
            f.seek(block_start)
            block = f.read(total_size)
            if len(block) != total_size:
                return None

            leading_size = struct.unpack_from("<Q", block, 0)[0]
            if leading_size != block_size:
                return None

            pairs_end = total_size - 24
            pos = 8
            scheme_blocks: dict[int, bytes] = {}
            while pos + 12 <= pairs_end:
                pair_len = struct.unpack_from("<Q", block, pos)[0]
                if pair_len < 4 or pos + 8 + pair_len > pairs_end:
                    break
                pair_id = struct.unpack_from("<I", block, pos + 8)[0]
                pair_val = block[pos + 12 : pos + 8 + pair_len]
                if pair_id in (_APK_SIG_SCHEME_V2_ID, _APK_SIG_SCHEME_V3_ID):
                    scheme_blocks[pair_id] = pair_val
                pos += 8 + pair_len

            scheme_data = scheme_blocks.get(_APK_SIG_SCHEME_V3_ID) or scheme_blocks.get(_APK_SIG_SCHEME_V2_ID)
            if not scheme_data or len(scheme_data) < 4:
                logger.debug(f"No v2/v3 signer block found in {apk_path.name}.")
                return None

            signers_len = struct.unpack_from("<I", scheme_data, 0)[0]
            if 4 + signers_len > len(scheme_data) or signers_len < 4:
                return None
            signers = scheme_data[4 : 4 + signers_len]

            first_signer_len = struct.unpack_from("<I", signers, 0)[0]
            if 4 + first_signer_len > len(signers) or first_signer_len < 4:
                return None
            first_signer = signers[4 : 4 + first_signer_len]

            signed_data_len = struct.unpack_from("<I", first_signer, 0)[0]
            if 4 + signed_data_len > len(first_signer) or signed_data_len < 8:
                return None
            signed_data = first_signer[4 : 4 + signed_data_len]

            digests_len = struct.unpack_from("<I", signed_data, 0)[0]
            certs_len_off = 4 + digests_len
            if certs_len_off + 4 > len(signed_data):
                return None
            certs_len = struct.unpack_from("<I", signed_data, certs_len_off)[0]
            certs_start = certs_len_off + 4
            if certs_start + certs_len > len(signed_data) or certs_len < 4:
                return None
            certs = signed_data[certs_start : certs_start + certs_len]

            first_cert_len = struct.unpack_from("<I", certs, 0)[0]
            if first_cert_len == 0 or 4 + first_cert_len > len(certs):
                return None
            cert_der = certs[4 : 4 + first_cert_len]
            return hashlib.sha256(cert_der).hexdigest().lower()
    except Exception as e:
        logger.debug(f"Failed to extract APK signing cert from {apk_path.name}: {e}")
        return None


def _get_latest_published_entry(
    release_state: dict[str, Any],
    package_name: str,
) -> dict[str, Any] | None:
    """Returns the most recently published state entry for `package_name`, if any."""
    pkg_releases = release_state.get(package_name)
    if not isinstance(pkg_releases, dict) or not pkg_releases:
        return None
    valid_entries = [
        (ver, entry)
        for ver, entry in pkg_releases.items()
        if isinstance(entry, dict)
    ]
    if not valid_entries:
        return None
    valid_entries.sort(key=lambda item: str(item[1].get("published_at", "")), reverse=True)
    ver, entry = valid_entries[0]
    if "version_name" not in entry:
        entry = {**entry, "version_name": ver}
    return entry


def _extract_applied_patches(version_entry: dict[str, Any]) -> list[str]:
    """Extracts a sorted list of applied patch names from a patched.json entry."""
    applied_patches = version_entry.get("patch", {}).get("applied_patches") or {}
    if isinstance(applied_patches, dict):
        return sorted(str(k) for k in applied_patches.keys())
    if isinstance(applied_patches, list):
        return sorted(str(k) for k in applied_patches)
    return []


def _compute_release_diff(
    package_name: str,
    version_name: str,
    current_patches: list[str],
    prev_entry: dict[str, Any] | None,
) -> dict[str, Any]:
    """Computes version transition and patch list diff against the previous release."""
    if not prev_entry:
        return {
            "version_transition": f"Initial release (v{version_name})",
            "added_patches": list(current_patches),
            "removed_patches": [],
            "is_initial": True,
            "patch_diff_short": f"{len(current_patches)} patches",
            "summary": f"Initial release (v{version_name})",
        }

    prev_ver = str(prev_entry.get("version_name") or "").strip()
    if not prev_ver:
        prev_tag = str(prev_entry.get("tag") or "")
        prev_slug = str(prev_entry.get("slug") or "").strip()
        for prefix in ([f"{prev_slug}-v"] if prev_slug else []) + [f"{package_name}-v"]:
            if prev_tag.startswith(prefix):
                prev_ver = prev_tag[len(prefix):]
                break
        if not prev_ver:
            prev_ver = "unknown"

    if prev_ver == version_name:
        version_transition = f"Rebuild of v{version_name}"
    else:
        version_transition = f"{prev_ver} -> {version_name}"

    prev_patches = set(prev_entry.get("applied_patches") or [])
    curr_patches = set(current_patches)
    added = sorted(curr_patches - prev_patches)
    removed = sorted(prev_patches - curr_patches)

    if added or removed:
        patch_diff_short = f"+{len(added)} / -{len(removed)} patches"
        parts = [version_transition]
        if added:
            parts.append(f"+{len(added)}")
        if removed:
            parts.append(f"-{len(removed)}")
        summary = f"{version_transition}; {' / '.join(parts[1:])} patch(es)"
    else:
        patch_diff_short = "No patch changes"
        summary = f"{version_transition}; no patch changes"

    return {
        "version_transition": version_transition,
        "added_patches": added,
        "removed_patches": removed,
        "is_initial": False,
        "patch_diff_short": patch_diff_short,
        "summary": summary,
    }


def _build_release_body(
    package_name: str,
    version_name: str,
    version_entry: dict[str, Any],
    diff_info: dict[str, Any] | None = None,
    cert_sha256: str | None = None,
) -> str:
    """Formats a Markdown release summary from a patched.json version entry."""
    pkg_info = version_entry.get("package", {})
    file_info = version_entry.get("file", {})
    meta_info = version_entry.get("metadata", {})

    clean_name = pkg_info.get("clean_name", package_name)
    patched_pkg = pkg_info.get("patched_package_name", package_name)
    arch = pkg_info.get("arch", "unknown")
    sha256 = file_info.get("sha256", "unknown")
    build_time = meta_info.get("time", "unknown")
    applied_patches = _extract_applied_patches(version_entry)

    lines = [f"### {clean_name}", ""]

    if diff_info:
        lines.append("#### What Changed")
        lines.append(f"- **Version:** {diff_info['version_transition']}")
        if diff_info.get("is_initial"):
            lines.append(f"- **Patches:** {len(applied_patches)} patch(es) enabled")
        elif diff_info.get("added_patches") or diff_info.get("removed_patches"):
            for p in diff_info.get("added_patches", []):
                lines.append(f"  - `+ {p}`")
            for p in diff_info.get("removed_patches", []):
                lines.append(f"  - `- {p}`")
        else:
            lines.append("- **Patches:** No patch list changes")
        lines.append("")

    lines.extend([
        "#### Build Details",
        f"- **App Name:** {clean_name}",
        f"- **Package ID:** `{patched_pkg}` (source: `{package_name}`)",
        f"- **Version:** `{version_name}`",
        f"- **Architecture:** `{arch}`",
        f"- **APK SHA-256:** `{sha256}`",
    ])
    if cert_sha256:
        lines.append(f"- **Signing Cert SHA-256:** `{cert_sha256}`")
    lines.extend([
        f"- **Build Timestamp:** {build_time}",
        "",
        "#### Applied Patches",
    ])
    if applied_patches:
        for patch_name in applied_patches:
            lines.append(f"- {patch_name}")
    else:
        lines.append("- None recorded")

    return "\n".join(lines) + "\n"


def _upsert_release_and_upload(
    repo: str,
    token: str,
    tag: str,
    title: str,
    body: str,
    asset_path: Path,
    asset_name: str,
    content_type: str,
) -> tuple[int, str]:
    """
    Gets or creates a GitHub Release by `tag`, deletes any existing asset matching
    `asset_name`, and streams `asset_path` to the release.
    Returns `(release_id, release_url)`.
    """
    owner, repo_name = repo.split("/", 1)
    headers = _github_headers(token)

    tag_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/releases/tags/{quote(tag, safe='')}"
    resp = requests.get(tag_url, headers=headers, timeout=REQUEST_TIMEOUT)

    if resp.status_code == 200:
        release_data = resp.json()
        release_id = release_data["id"]
        release_url = release_data.get("html_url", "")
        for asset in release_data.get("assets", []):
            if asset.get("name") == asset_name:
                del_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/releases/assets/{asset['id']}"
                del_resp = requests.delete(del_url, headers=headers, timeout=REQUEST_TIMEOUT)
                if del_resp.status_code not in (200, 204, 404):
                    del_resp.raise_for_status()
        patch_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/releases/{release_id}"
        patch_payload = {
            "name": title,
            "body": body,
            "draft": False,
            "prerelease": False,
        }
        patch_resp = requests.patch(patch_url, headers=headers, json=patch_payload, timeout=REQUEST_TIMEOUT)
        patch_resp.raise_for_status()
    elif resp.status_code == 404:
        create_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/releases"
        payload = {
            "tag_name": tag,
            "name": title,
            "body": body,
            "draft": False,
            "prerelease": False,
        }
        create_resp = requests.post(create_url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
        create_resp.raise_for_status()
        release_data = create_resp.json()
        release_id = release_data["id"]
        release_url = release_data.get("html_url", "")
    else:
        resp.raise_for_status()
        raise RuntimeError(f"Unexpected status {resp.status_code} querying tag {tag}")

    upload_url = (
        f"{GITHUB_UPLOADS_BASE}/repos/{owner}/{repo_name}"
        f"/releases/{release_id}/assets?name={quote(asset_name, safe='')}"
    )
    upload_headers = _github_headers(token, content_type=content_type)
    with asset_path.open("rb") as asset_stream:
        up_resp = requests.post(
            upload_url,
            headers=upload_headers,
            data=asset_stream,
            timeout=UPLOAD_TIMEOUT,
        )
        up_resp.raise_for_status()

    return release_id, release_url


def _get_repo_file(
    owner: str,
    repo_name: str,
    file_path: str,
    token: str,
) -> tuple[str | None, str | None]:
    """Fetches `(sha, decoded_content)` from GitHub Contents API, or `(None, None)` on 404."""
    headers = _github_headers(token)
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/contents/{quote(file_path, safe='/')}"
    resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    if resp.status_code == 404:
        return None, None
    resp.raise_for_status()
    data = resp.json()
    sha = data.get("sha")
    raw_b64 = data.get("content") or ""
    decoded = ""
    if raw_b64:
        decoded = base64.b64decode(raw_b64.encode("ascii")).decode("utf-8", errors="replace")
    return sha, decoded


def _upsert_repo_file(
    owner: str,
    repo_name: str,
    file_path: str,
    content_str: str,
    commit_message: str,
    token: str,
) -> bool:
    """
    Upserts a file in a GitHub repository via Contents API.
    Skips the PUT if the existing remote content already matches `content_str`.
    Returns True if a commit was made, False if skipped.
    """
    existing_sha, existing_content = _get_repo_file(owner, repo_name, file_path, token)
    if existing_sha is not None and existing_content == content_str:
        logger.debug(f"{file_path} unchanged on remote; skipping commit.")
        return False

    headers = _github_headers(token)
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/contents/{quote(file_path, safe='/')}"
    payload: dict[str, Any] = {
        "message": commit_message,
        "content": base64.b64encode(content_str.encode("utf-8")).decode("ascii"),
    }
    if existing_sha:
        payload["sha"] = existing_sha

    put_resp = requests.put(url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
    put_resp.raise_for_status()
    return True


def publish_package(
    package_name: str,
    version_name: str,
    version_entry: dict[str, Any],
    repo: str,
    token: str,
    release_state: dict[str, Any],
    force: bool = False,
    allow_cert_change: bool = False,
    cert_mismatches: list[dict[str, Any]] | None = None,
    slug: str | None = None,
) -> dict[str, Any] | bool:
    """
    Upserts a GitHub Release for a single patched package version and streams
    the APK asset to GitHub. Enforces signing certificate consistency against
    the most recent published release for `package_name`.
    Returns a metadata dict (truthy) if uploaded, or False if skipped/blocked.
    """
    pkg_info = version_entry.get("package", {})
    file_info = version_entry.get("file", {})

    clean_name = pkg_info.get("clean_name", package_name)
    arch = pkg_info.get("arch", "arm64-v8a")
    sha256 = file_info.get("sha256", "")
    apk_location = file_info.get("location")

    if not apk_location:
        logger.warning(f"[!] Missing APK file location for {package_name} v{version_name}. Skipping.")
        return False

    apk_path = Path(apk_location)
    if not apk_path.is_file():
        logger.warning(f"[!] APK file not found on disk: {apk_path}. Skipping.")
        return False

    resolved_slug = slug or _slugify_label(clean_name) or _slugify_label(package_name) or package_name.lower()

    existing_entry = release_state.get(package_name, {}).get(version_name)
    if (
        not force
        and isinstance(existing_entry, dict)
        and sha256
        and existing_entry.get("sha256") == sha256
    ):
        logger.info(f" └── [✓] GitHub Release already up to date for {package_name} v{version_name}.")
        return False

    prev_entry = _get_latest_published_entry(release_state, package_name)
    new_cert_sha256 = _extract_apk_cert_sha256(apk_path)
    prev_cert_sha256 = prev_entry.get("cert_sha256") if prev_entry else None

    if (
        new_cert_sha256
        and prev_cert_sha256
        and new_cert_sha256 != prev_cert_sha256
        and not allow_cert_change
    ):
        logger.error(
            f"[✗] Signing certificate mismatch for {package_name} v{version_name}! "
            f"Previous: {prev_cert_sha256}, New: {new_cert_sha256}. "
            "Upload aborted to prevent INSTALL_FAILED_UPDATE_INCOMPATIBLE. "
            "Set ALLOW_CERT_CHANGE=true in .env to override once if intentional."
        )
        if cert_mismatches is not None:
            cert_mismatches.append({
                "package_name": package_name,
                "clean_name": clean_name,
                "version_name": version_name,
                "old_cert": prev_cert_sha256,
                "new_cert": new_cert_sha256,
            })
        return False

    applied_patches = _extract_applied_patches(version_entry)
    diff_info = _compute_release_diff(package_name, version_name, applied_patches, prev_entry)

    tag = f"{resolved_slug}-v{version_name}"
    asset_name = f"{resolved_slug}-{version_name}-{arch}-morphe.apk"
    title = f"{clean_name} v{version_name} ({arch})"
    body = _build_release_body(
        package_name,
        version_name,
        version_entry,
        diff_info=diff_info,
        cert_sha256=new_cert_sha256,
    )

    release_id, release_url = _upsert_release_and_upload(
        repo=repo,
        token=token,
        tag=tag,
        title=title,
        body=body,
        asset_path=apk_path,
        asset_name=asset_name,
        content_type="application/vnd.android.package-archive",
    )

    published_at = datetime.now(timezone.utc).isoformat()
    release_state.setdefault(package_name, {})[version_name] = {
        "sha256": sha256,
        "cert_sha256": new_cert_sha256,
        "slug": resolved_slug,
        "version_name": version_name,
        "applied_patches": applied_patches,
        "tag": tag,
        "release_id": release_id,
        "release_url": release_url,
        "asset_name": asset_name,
        "published_at": published_at,
    }
    logger.info(f" └── [✓] Published GitHub Release {tag} ({asset_name})")
    return {
        "package_name": package_name,
        "slug": resolved_slug,
        "clean_name": clean_name,
        "version_name": version_name,
        "arch": arch,
        "tag": tag,
        "asset_name": asset_name,
        "version_transition": diff_info["version_transition"],
        "patch_diff_short": diff_info["patch_diff_short"],
        "diff_summary": diff_info["summary"],
    }


def prune_old_releases(
    package_name: str,
    repo: str,
    token: str,
    keep: int,
    release_state: dict[str, Any] | None = None,
    slug: str | None = None,
) -> list[str]:
    """
    Deletes GitHub Releases (and their git tags) for `package_name` beyond
    the newest `keep` releases, matching both `{slug}-v` and legacy `{package_name}-v`.
    Returns a list of deleted tag names.
    """
    if keep <= 0:
        return []

    owner, repo_name = repo.split("/", 1)
    headers = _github_headers(token)
    list_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/releases?per_page=100"
    resp = requests.get(list_url, headers=headers, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()

    prefixes = [f"{package_name}-v"]
    if slug and slug != package_name:
        prefixes.insert(0, f"{slug}-v")

    matching = [
        rel for rel in resp.json()
        if isinstance(rel, dict)
        and any(str(rel.get("tag_name", "")).startswith(p) for p in prefixes)
    ]
    matching.sort(key=lambda r: r.get("created_at", ""), reverse=True)

    deleted_tags: list[str] = []
    for old_rel in matching[keep:]:
        old_id = old_rel.get("id")
        old_tag = str(old_rel.get("tag_name", ""))
        if old_id:
            del_rel_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/releases/{old_id}"
            del_rel_resp = requests.delete(del_rel_url, headers=headers, timeout=REQUEST_TIMEOUT)
            if del_rel_resp.status_code not in (200, 204, 404):
                del_rel_resp.raise_for_status()
        if old_tag:
            del_tag_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/git/refs/tags/{quote(old_tag, safe='')}"
            del_tag_resp = requests.delete(del_tag_url, headers=headers, timeout=REQUEST_TIMEOUT)
            if del_tag_resp.status_code not in (200, 204, 404):
                del_tag_resp.raise_for_status()
            deleted_tags.append(old_tag)
            if isinstance(release_state, dict) and package_name in release_state:
                for p in prefixes:
                    if old_tag.startswith(p):
                        version_key = old_tag[len(p):]
                        release_state[package_name].pop(version_key, None)
                        break
            logger.info(f" └── [!] Pruned old GitHub Release: {old_tag}")

    return deleted_tags


def build_obtainium_github_export(
    state_dir: Path,
    patched_json: Path,
    repo: str,
    project_root: Path | None = None,
) -> Path | None:
    """
    Regenerates `state_dir / "obtainium-github-export.json"` (schemaVersion 2)
    pointing each active, non-excluded package in `patched.json` to
    `https://github.com/{repo}` with slug-based per-package tag and APK regex filters.
    """
    patched_results = _read_json(patched_json)
    if not patched_results:
        return None

    active_packages = _get_active_packages(project_root) if project_root is not None else None
    excluded_packages = _get_excluded_packages()
    slugs = _resolve_app_slugs(patched_results)

    ob_export: dict[str, Any] = {"schemaVersion": 2, "apps": []}
    repo_url = f"https://github.com/{repo}"

    for package_name, versions in patched_results.items():
        if not isinstance(versions, dict) or not versions:
            continue
        if active_packages is not None and package_name not in active_packages:
            continue
        if package_name in excluded_packages:
            continue

        latest_version = _select_latest_version(versions)
        if not latest_version:
            continue

        latest_details = versions[latest_version]
        pkg_info = latest_details.get("package", {})
        patched_package_name = pkg_info.get("patched_package_name", package_name)
        clean_name = pkg_info.get("clean_name", package_name)
        slug = slugs.get(package_name, _slugify_label(package_name))

        additional_settings = {
            "verifyLatestTag": False,
            "filterReleasesByRegEx": f"^{re.escape(slug)}-v",
            "apkFilterRegEx": f"^{re.escape(slug)}-.*\\.apk$",
            "versionExtractionRegEx": r"\d+(\.\d+)+",
            "includePrereleases": False,
            "fallbackToOlderReleases": True,
        }

        app_entry = {
            "id": patched_package_name,
            "name": clean_name,
            "author": "AutoMorph",
            "url": repo_url,
            "latestVersion": latest_version,
            "preferredApkIndex": 0,
            "overrideSource": "GitHub",
            "additionalSettings": json.dumps(additional_settings),
        }
        ob_export["apps"].append(app_entry)

    export_path = state_dir / "obtainium-github-export.json"
    _write_json(ob_export, export_path)
    logger.info(f"[✓] Generated Obtainium GitHub export: {export_path}")
    return export_path


def publish_obtainium_config_release(
    export_path: Path,
    repo: str,
    token: str,
    release_state: dict[str, Any] | None = None,
    force: bool = False,
) -> None:
    """
    Uploads `obtainium-github-export.json` to a dedicated `automorph-config`
    GitHub Release when enabled and its SHA-256 has changed.
    """
    if not _parse_bool_env("GITHUB_RELEASE_PUBLISH_CONFIG", default=True):
        return
    if not export_path.is_file():
        return

    config_sha = hashlib.sha256(export_path.read_bytes()).hexdigest()
    if isinstance(release_state, dict):
        prev_sha = release_state.get("_config_export", {}).get("sha256")
        if not force and prev_sha == config_sha:
            logger.debug("obtainium-github-export.json unchanged; skipping automorph-config release upload.")
            return

    body = (
        "AutoMorph Obtainium configuration export (`obtainium-github-export.json`).\n\n"
        "### Setup Notes\n"
        "- Import `obtainium-github-export.json` in Obtainium (**Import/Export -> Obtainium Import**).\n"
        "- Each app has **Verify Latest Tag: OFF** (`verifyLatestTag: false`) so Obtainium resolves "
        "per-package `{slug}-v...` tags in a shared repository.\n"
        "- If this repository is **private**, configure a GitHub Personal Access Token (PAT) with "
        "`Contents: Read` permission in Obtainium (**Settings -> Source-Specific -> GitHub PAT**).\n"
    )

    release_id, release_url = _upsert_release_and_upload(
        repo=repo,
        token=token,
        tag=CONFIG_RELEASE_TAG,
        title="AutoMorph Obtainium Config",
        body=body,
        asset_path=export_path,
        asset_name=export_path.name,
        content_type="application/json",
    )

    if isinstance(release_state, dict):
        release_state["_config_export"] = {
            "sha256": config_sha,
            "tag": CONFIG_RELEASE_TAG,
            "release_id": release_id,
            "release_url": release_url,
            "asset_name": export_path.name,
            "published_at": datetime.now(timezone.utc).isoformat(),
        }
    logger.info(f" └── [✓] Published Obtainium config release: {CONFIG_RELEASE_TAG}")


def _collect_active_published_records(
    patched_json: Path,
    release_state: dict[str, Any],
    repo: str,
    project_root: Path | None = None,
) -> list[dict[str, Any]]:
    """Collects rich metadata records for all active, non-excluded published packages."""
    patched_results = _read_json(patched_json)
    active_packages = _get_active_packages(project_root) if project_root is not None else None
    excluded_packages = _get_excluded_packages()
    slugs = _resolve_app_slugs(patched_results)

    records: list[dict[str, Any]] = []
    for package_name, versions in patched_results.items():
        if not isinstance(versions, dict) or not versions:
            continue
        if active_packages is not None and package_name not in active_packages:
            continue
        if package_name in excluded_packages:
            continue

        latest_pub = _get_latest_published_entry(release_state, package_name)
        if not latest_pub:
            continue

        ver_name = str(latest_pub.get("version_name") or "")
        ver_details = versions.get(ver_name) or next(iter(versions.values()), {})
        if not isinstance(ver_details, dict):
            ver_details = {}

        pkg_info = ver_details.get("package", {})
        file_info = ver_details.get("file", {})
        patch_info = ver_details.get("patch", {})

        clean_name = str(pkg_info.get("clean_name") or package_name)
        patched_pkg = str(pkg_info.get("patched_package_name") or package_name)
        version_code = pkg_info.get("patched_version_code") or pkg_info.get("source_version_code")
        arch = str(pkg_info.get("arch") or "arm64-v8a")
        min_sdk = pkg_info.get("min_sdk")
        target_sdk = pkg_info.get("target_sdk")
        size_bytes = file_info.get("size_bytes")
        file_size = str(file_info.get("file_size") or _format_bytes(size_bytes))
        sha256 = str(latest_pub.get("sha256") or file_info.get("sha256") or "")
        cert_sha256 = latest_pub.get("cert_sha256")
        morphe_ver = str(patch_info.get("morphe_desktop_version") or "Unknown")
        repos = list(patch_info.get("repos") or [])
        applied_patches = list(latest_pub.get("applied_patches") or _extract_applied_patches(ver_details))
        slug = str(latest_pub.get("slug") or slugs.get(package_name, _slugify_label(package_name)))
        tag = str(latest_pub.get("tag") or f"{slug}-v{ver_name}")
        asset_name = str(latest_pub.get("asset_name") or f"{slug}-{ver_name}-{arch}-morphe.apk")
        updated_at = str(latest_pub.get("published_at") or "")
        release_url = str(latest_pub.get("release_url") or f"https://github.com/{repo}/releases/tag/{quote(tag, safe='')}")
        apk_url = f"https://github.com/{repo}/releases/download/{quote(tag, safe='')}/{quote(asset_name, safe='')}"

        records.append({
            "slug": slug,
            "clean_name": clean_name,
            "package_name": package_name,
            "patched_package_name": patched_pkg,
            "version_name": ver_name,
            "version_code": version_code,
            "arch": arch,
            "min_sdk": min_sdk,
            "target_sdk": target_sdk,
            "size_bytes": size_bytes,
            "file_size": file_size,
            "sha256": sha256,
            "cert_sha256": cert_sha256,
            "morphe_desktop_version": morphe_ver,
            "repos": repos,
            "applied_patches": applied_patches,
            "updated_at": updated_at,
            "tag": tag,
            "asset_name": asset_name,
            "release_url": release_url,
            "apk_url": apk_url,
        })

    records.sort(key=lambda r: (r["clean_name"].lower(), r["package_name"].lower()))
    return records


def publish_repo_readme(
    state_dir: Path,
    patched_json: Path,
    release_state: dict[str, Any],
    repo: str,
    token: str,
    project_root: Path | None = None,
    force: bool = False,
) -> bool:
    """
    Generates and upserts `README.md` in the target builds repository with a
    rich table of active, published APKs and collapsible per-app patch details.
    Returns True if README.md was updated, False if skipped.
    """
    if not _parse_bool_env("GITHUB_RELEASE_UPDATE_README", default=True):
        return False

    records = _collect_active_published_records(patched_json, release_state, repo, project_root=project_root)
    config_url = f"https://github.com/{repo}/releases/download/{CONFIG_RELEASE_TAG}/obtainium-github-export.json"

    certs = {r["cert_sha256"] for r in records if r.get("cert_sha256")}
    if len(certs) == 1:
        cert_val = next(iter(certs))
        cert_badge_val = cert_val[:12]
    elif len(certs) > 1:
        cert_badge_val = "Per-app"
    else:
        cert_badge_val = "N/A"

    arches = sorted({r["arch"] for r in records if r.get("arch")})
    arch_badge_val = ", ".join(arches) if arches else "arm64-v8a"

    apps_badge = f"https://img.shields.io/badge/Active_Apps-{len(records)}-20cfce?style=flat-square"
    arch_badge = f"https://img.shields.io/badge/Arch-{quote(arch_badge_val, safe='')}-4A7FC8?style=flat-square"
    cert_badge = f"https://img.shields.io/badge/Signing_Cert-{quote(cert_badge_val, safe='')}-10B981?style=flat-square"
    obtainium_badge = "https://img.shields.io/badge/Obtainium-Ready-6366F1?style=flat-square"

    lines = [
        "# AutoMorph Patched Builds",
        "",
        f"![Active Apps]({apps_badge}) ![Architecture]({arch_badge}) ![Signing Cert]({cert_badge}) ![Obtainium Ready]({obtainium_badge})",
        "",
        "Automated Android APK builds patched locally with **AutoMorph** & **Morphe Desktop** and distributed via GitHub Releases.",
        "",
        "> [!TIP]",
        "> **Quick-Install with Obtainium (1-Click Import)**",
        "> 1. Copy or import the config URL: `" + config_url + "`",
        "> 2. In Obtainium, open **Import/Export → Obtainium Import** (`Verify Latest Tag: OFF` is pre-configured for all apps).",
        "> 3. *(Private repo only)* Add a read-only GitHub PAT under **Settings → Source-Specific → GitHub PAT**.",
        ">",
        "> Browse: [**CHANGELOG.md**](./CHANGELOG.md) · [**catalog.json**](./catalog.json)",
        "",
        "## Available Builds",
        "",
        "| App | Version | Size | Android SDK | Patches | Updated (UTC) | Download |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]

    if records:
        for r in records:
            app_cell = f"**{r['clean_name']}** (`{r['slug']}`)"
            ver_cell = f"`v{r['version_name']}`"
            if r["min_sdk"] is not None and r["target_sdk"] is not None:
                sdk_cell = f"API {r['min_sdk']}–{r['target_sdk']}"
            elif r["min_sdk"] is not None:
                sdk_cell = f"API {r['min_sdk']}+"
            else:
                sdk_cell = "-"
            patches_cell = str(len(r["applied_patches"]))
            upd_cell = r["updated_at"][:10] if r["updated_at"] else "-"
            lines.append(
                f"| {app_cell} | {ver_cell} | {r['file_size']} | {sdk_cell} | "
                f"{patches_cell} | {upd_cell} | **[⬇ Download APK]({r['apk_url']})** |"
            )
    else:
        lines.append("| *No active published builds* | - | - | - | - | - | - |")

    if records:
        lines.extend(["", "## Expandable App Cards", ""])
        for r in records:
            esc_name = html.escape(r["clean_name"])
            esc_pkg = html.escape(r["patched_package_name"])
            esc_ver = html.escape(r["version_name"])
            ver_code = str(r["version_code"]) if r["version_code"] is not None else "N/A"
            repos_str = ", ".join(f"`{rp}`" for rp in r["repos"]) if r["repos"] else "N/A"
            lines.append(
                f"<details><summary><strong>{esc_name}</strong> (<code>{esc_pkg}</code> — v{esc_ver})</summary>"
            )
            lines.append("")
            lines.append("| Property | Value |")
            lines.append("| --- | --- |")
            lines.append(f"| **Source Package** | `{r['package_name']}` |")
            lines.append(f"| **Patched Package** | `{r['patched_package_name']}` |")
            lines.append(f"| **Version Code** | `{ver_code}` |")
            lines.append(f"| **Morphe Engine** | `{r['morphe_desktop_version']}` |")
            lines.append(f"| **APK SHA-256** | `{r['sha256']}` |")
            lines.append(f"| **Signing Cert SHA-256** | `{r['cert_sha256'] or 'N/A'}` |")
            lines.append(f"| **Patch Sources** | {repos_str} |")
            lines.append("")
            lines.append("**Applied Patches:**")
            if r["applied_patches"]:
                for p in r["applied_patches"]:
                    lines.append(f"- {p}")
            else:
                lines.append("- None recorded")
            lines.append("")
            lines.append("</details>")
            lines.append("")

    readme_content = "\n".join(lines).rstrip() + "\n"
    readme_sha = hashlib.sha256(readme_content.encode("utf-8")).hexdigest()

    if not force and release_state.get("_readme", {}).get("sha256") == readme_sha:
        logger.debug("Builds README.md unchanged; skipping GitHub Contents API update.")
        return False

    owner, repo_name = repo.split("/", 1)
    committed = _upsert_repo_file(
        owner=owner,
        repo_name=repo_name,
        file_path="README.md",
        content_str=readme_content,
        commit_message="chore: update builds dashboard",
        token=token,
    )

    release_state["_readme"] = {
        "sha256": readme_sha,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    if committed:
        logger.info(" └── [✓] Updated builds repository README.md dashboard.")
    return committed


def publish_repo_changelog(
    published_items: list[dict[str, Any]],
    repo: str,
    token: str,
) -> bool:
    """
    Prepends a new UTC timestamped section to `CHANGELOG.md` in the builds
    repository when `GITHUB_RELEASE_UPDATE_CHANGELOG` is enabled and new
    releases were published, retaining the newest 50 sections.
    """
    if not _parse_bool_env("GITHUB_RELEASE_UPDATE_CHANGELOG", default=True):
        return False
    if not published_items:
        return False

    owner, repo_name = repo.split("/", 1)
    _, existing = _get_repo_file(owner, repo_name, "CHANGELOG.md", token)

    header = "# Changelog\n\nAutomated release history for patched APKs.\n\n"
    existing_sections: list[str] = []
    if existing:
        parts = re.split(r"(?m)(?=^## )", existing)
        for part in parts:
            stripped = part.strip()
            if stripped.startswith("## "):
                existing_sections.append(stripped)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    entry_lines = [f"## {stamp} UTC", ""]
    for item in published_items:
        clean_name = item.get("clean_name") or item.get("package_name")
        tag = item.get("tag", "")
        asset_name = item.get("asset_name", "")
        diff_summary = item.get("diff_summary", "New build")
        apk_url = f"https://github.com/{repo}/releases/download/{quote(tag, safe='')}/{quote(asset_name, safe='')}"
        entry_lines.append(f"- **{clean_name}** (`{tag}`) — {diff_summary} — [Download APK]({apk_url})")

    new_section = "\n".join(entry_lines)
    kept_sections = [new_section] + existing_sections[: MAX_CHANGELOG_SECTIONS - 1]
    new_content = header + "\n\n".join(kept_sections).rstrip() + "\n"

    committed = _upsert_repo_file(
        owner=owner,
        repo_name=repo_name,
        file_path="CHANGELOG.md",
        content_str=new_content,
        commit_message="chore: update release changelog",
        token=token,
    )
    if committed:
        logger.info(" └── [✓] Updated builds repository CHANGELOG.md.")
    return committed


def publish_repo_catalog(
    state_dir: Path,
    patched_json: Path,
    release_state: dict[str, Any],
    repo: str,
    token: str,
    project_root: Path | None = None,
    force: bool = False,
) -> bool:
    """
    Generates `catalog.json` for active, non-excluded published apps and upserts
    it to the builds repository when app metadata changes (ignoring `generated_at`).
    """
    if not _parse_bool_env("GITHUB_RELEASE_UPDATE_CATALOG", default=True):
        return False

    records = _collect_active_published_records(patched_json, release_state, repo, project_root=project_root)
    config_url = f"https://github.com/{repo}/releases/download/{CONFIG_RELEASE_TAG}/obtainium-github-export.json"

    apps_payload = [
        {
            "slug": r["slug"],
            "name": r["clean_name"],
            "source_package": r["package_name"],
            "patched_package": r["patched_package_name"],
            "version_name": r["version_name"],
            "version_code": r["version_code"],
            "arch": r["arch"],
            "min_sdk": r["min_sdk"],
            "target_sdk": r["target_sdk"],
            "size_bytes": r["size_bytes"],
            "file_size": r["file_size"],
            "sha256": r["sha256"],
            "cert_sha256": r["cert_sha256"],
            "morphe_version": r["morphe_desktop_version"],
            "patch_count": len(r["applied_patches"]),
            "applied_patches": r["applied_patches"],
            "tag": r["tag"],
            "release_url": r["release_url"],
            "apk_url": r["apk_url"],
        }
        for r in records
    ]

    stable_hash_input = json.dumps(
        {"repo": repo, "obtainium_export_url": config_url, "apps": apps_payload},
        sort_keys=True,
    )
    catalog_sha = hashlib.sha256(stable_hash_input.encode("utf-8")).hexdigest()

    if not force and release_state.get("_catalog", {}).get("sha256") == catalog_sha:
        logger.debug("Builds catalog.json unchanged; skipping GitHub Contents API update.")
        return False

    catalog_obj = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repo": repo,
        "obtainium_export_url": config_url,
        "apps": apps_payload,
    }
    catalog_str = json.dumps(catalog_obj, indent=2) + "\n"

    owner, repo_name = repo.split("/", 1)
    committed = _upsert_repo_file(
        owner=owner,
        repo_name=repo_name,
        file_path="catalog.json",
        content_str=catalog_str,
        commit_message="chore: update builds catalog",
        token=token,
    )

    release_state["_catalog"] = {
        "sha256": catalog_sha,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    if committed:
        logger.info(" └── [✓] Updated builds repository catalog.json.")
    return committed


def _dispatch_apprise(title: str, body: str) -> None:
    """Internal helper to send a title/body notification to configured APPRISE_URL targets."""
    apprise_url = os.getenv("APPRISE_URL", "").strip()
    if not apprise_url:
        return

    if apprise is None:
        logger.warning("[!] APPRISE_URL is set, but 'apprise' is not installed. Skipping notification.")
        return

    urls = [u.strip() for u in re.split(r"[\s,]+", apprise_url) if u.strip()]
    if not urls:
        return

    try:
        apobj = apprise.Apprise()
        for u in urls:
            apobj.add(u)
        apobj.notify(title=title, body=body)
        logger.info(f"[✓] Sent Apprise notification: {title}")
    except Exception as e:
        logger.warning(f"[!] Failed to send Apprise notification: {e}")


def send_apprise_notification(published_items: list[dict[str, Any]], repo: str) -> None:
    """
    Sends an adaptive Apprise notification: detailed when 1 app is published,
    compact multi-app digest when multiple apps are published together.
    """
    apprise_url = os.getenv("APPRISE_URL", "").strip()
    if not apprise_url or not published_items:
        return

    if len(published_items) == 1:
        item = published_items[0]
        clean_name = item.get("clean_name") or item.get("package_name")
        version_name = item.get("version_name", "")
        tag = item.get("tag", "")
        ver_trans = item.get("version_transition") or f"v{version_name}"
        patch_diff = item.get("patch_diff_short") or "No patch changes"
        release_url = f"https://github.com/{repo}/releases/tag/{tag}"

        title = f"AutoMorph: {clean_name} v{version_name} released"
        body = (
            f"Version: {ver_trans}\n"
            f"Patches: {patch_diff}\n"
            f"Tag: {tag}\n"
            f"Release: {release_url}"
        )
    else:
        title = f"AutoMorph: {len(published_items)} apps released"
        lines = []
        for item in published_items:
            clean_name = item.get("clean_name") or item.get("package_name")
            version_name = item.get("version_name", "")
            tag = item.get("tag", "")
            compact_diff = item.get("diff_summary") or item.get("patch_diff_short") or "updated"
            release_url = f"https://github.com/{repo}/releases/tag/{tag}"
            lines.append(f"• {clean_name} v{version_name} ({compact_diff}) — {release_url}")
        body = "\n".join(lines)

    _dispatch_apprise(title=title, body=body)


def send_apprise_failure_notification(
    patch_failures: dict[str, Any] | None,
    cert_mismatches: list[dict[str, Any]],
    repo: str,
) -> None:
    """
    Sends an adaptive Apprise alert when APPRISE_NOTIFY_ON_FAILURE is enabled and
    either `patch_failures` or `cert_mismatches` is non-empty.
    """
    if not _parse_bool_env("APPRISE_NOTIFY_ON_FAILURE", default=True):
        return

    failures = patch_failures or {}
    if not failures and not cert_mismatches:
        return

    apprise_url = os.getenv("APPRISE_URL", "").strip()
    if not apprise_url:
        return

    entries: list[tuple[str, str]] = []
    for pkg_name, fail_info in failures.items():
        if isinstance(fail_info, dict):
            targets = fail_info.get("target_versions") or []
            attempts = fail_info.get("attempts") or []
            last_attempt = attempts[-1] if attempts and isinstance(attempts[-1], dict) else {}
            stage = last_attempt.get("stage", "Pipeline")
            reason = last_attempt.get("reason", "Unknown failure")
            ver_str = str(targets[0][0]) if targets and isinstance(targets[0], (list, tuple)) else (str(targets[0]) if targets else "unknown")
            entries.append((pkg_name, f"Build failed (v{ver_str}) at {stage}: {reason}"))
        else:
            entries.append((pkg_name, f"Build failed: {fail_info}"))

    for mismatch in cert_mismatches:
        pkg_name = mismatch.get("clean_name") or mismatch.get("package_name", "unknown")
        ver_name = mismatch.get("version_name", "unknown")
        old_c = str(mismatch.get("old_cert", ""))[:12]
        new_c = str(mismatch.get("new_cert", ""))[:12]
        entries.append((pkg_name, f"Cert mismatch (v{ver_name}): {old_c}... != {new_c}..."))

    if len(entries) == 1:
        name, detail = entries[0]
        title = f"AutoMorph: {name} failed"
        body = f"Repository: {repo}\nDetail: {detail}"
    else:
        title = f"AutoMorph: {len(entries)} failures/alerts"
        body = "\n".join(f"• {name} — {detail}" for name, detail in entries)

    _dispatch_apprise(title=title, body=body)


def main(
    patched: dict,
    state_dir: Path,
    patched_json: Path,
    project_root: Path,
    patch_failures: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Post-build entrypoint for GitHub Releases publishing.
    Never raises on network/API errors so the caller's pipeline and dispatcher
    always complete cleanly.
    """
    try:
        env_file = project_root / ".env"
        if env_file.is_file():
            load_dotenv(dotenv_path=env_file)

        repo = os.getenv("GITHUB_RELEASE_REPO", "").strip()
        if not repo:
            logger.debug("GITHUB_RELEASE_REPO is unset; GitHub Releases publishing disabled.")
            return {}

        if not re.fullmatch(r"[^/\s]+/[^/\s]+", repo):
            logger.warning(f"[!] Invalid GITHUB_RELEASE_REPO='{repo}' (expected owner/repo). Skipping.")
            return {}

        token = (os.getenv("GITHUB_RELEASE_TOKEN") or os.getenv("GITHUB_TOKEN") or "").strip()
        if not token:
            logger.warning("[!] GITHUB_RELEASE_REPO is set, but GITHUB_RELEASE_TOKEN/GITHUB_TOKEN is missing. Skipping.")
            return {}

        keep = _parse_keep_env(default=2)
        force = _parse_bool_env("FORCE_GITHUB_RELEASE", default=False)
        sync_all = _parse_bool_env("GITHUB_RELEASE_SYNC_ALL", default=False)
        allow_cert_change = _parse_bool_env("ALLOW_CERT_CHANGE", default=False)

        patched_results = _read_json(patched_json)
        state_file = state_dir / "github_releases.json"
        release_state = _read_json(state_file)
        cert_mismatches: list[dict[str, Any]] = []

        if not patched_results:
            logger.info("[*] No entries in patched.json; skipping GitHub Releases publish.")
            send_apprise_failure_notification(patch_failures, cert_mismatches, repo)
            return {}

        slugs = _resolve_app_slugs(patched_results)
        targets: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()

        for package_name, details in (patched or {}).items():
            ver = details.get("version_name") if isinstance(details, dict) else None
            if not ver and package_name in patched_results:
                ver = _select_latest_version(patched_results[package_name])
            if ver and (package_name, ver) not in seen:
                targets.append((package_name, ver))
                seen.add((package_name, ver))

        # Catch up any un-published (or changed) latest version in patched.json,
        # and include all latest versions when force=True or sync_all=True.
        for package_name, versions in patched_results.items():
            if not isinstance(versions, dict) or not versions:
                continue
            latest_ver = _select_latest_version(versions)
            if latest_ver and (package_name, latest_ver) not in seen:
                existing = release_state.get(package_name, {}).get(latest_ver)
                sha = versions[latest_ver].get("file", {}).get("sha256")
                if force or sync_all or not (isinstance(existing, dict) and sha and existing.get("sha256") == sha):
                    targets.append((package_name, latest_ver))
                    seen.add((package_name, latest_ver))

        touched_packages: set[str] = set()
        published_items: list[dict[str, Any]] = []
        skipped_count = 0
        failed_count = 0
        for package_name, version_name in targets:
            version_entry = patched_results.get(package_name, {}).get(version_name)
            if not isinstance(version_entry, dict):
                logger.warning(f"[!] No metadata in patched.json for {package_name} v{version_name}.")
                failed_count += 1
                continue
            try:
                mismatches_before = len(cert_mismatches)
                pub_result = publish_package(
                    package_name=package_name,
                    version_name=version_name,
                    version_entry=version_entry,
                    repo=repo,
                    token=token,
                    release_state=release_state,
                    force=force,
                    allow_cert_change=allow_cert_change,
                    cert_mismatches=cert_mismatches,
                    slug=slugs.get(package_name),
                )
                if pub_result:
                    touched_packages.add(package_name)
                    if isinstance(pub_result, dict):
                        published_items.append(pub_result)
                    else:
                        pkg_info = version_entry.get("package", {})
                        slug = slugs.get(package_name, _slugify_label(package_name))
                        published_items.append({
                            "package_name": package_name,
                            "slug": slug,
                            "clean_name": pkg_info.get("clean_name", package_name),
                            "version_name": version_name,
                            "arch": pkg_info.get("arch", "arm64-v8a"),
                            "tag": f"{slug}-v{version_name}",
                        })
                elif len(cert_mismatches) > mismatches_before:
                    failed_count += 1
                else:
                    skipped_count += 1
            except Exception as e:
                failed_count += 1
                logger.error(f"[✗] Failed to publish GitHub Release for {package_name} v{version_name}: {e}")

        if keep > 0:
            for package_name in touched_packages:
                try:
                    prune_old_releases(
                        package_name,
                        repo,
                        token,
                        keep,
                        release_state=release_state,
                        slug=slugs.get(package_name),
                    )
                except Exception as e:
                    logger.error(f"[✗] Failed to prune old GitHub Releases for {package_name}: {e}")

        export_path = build_obtainium_github_export(state_dir, patched_json, repo, project_root=project_root)
        if export_path is not None:
            try:
                publish_obtainium_config_release(
                    export_path=export_path,
                    repo=repo,
                    token=token,
                    release_state=release_state,
                    force=force,
                )
            except Exception as e:
                logger.error(f"[✗] Failed to publish Obtainium config release: {e}")

        try:
            publish_repo_readme(
                state_dir=state_dir,
                patched_json=patched_json,
                release_state=release_state,
                repo=repo,
                token=token,
                project_root=project_root,
                force=force,
            )
        except Exception as e:
            logger.error(f"[✗] Failed to update builds repository README.md: {e}")

        try:
            publish_repo_changelog(published_items, repo, token)
        except Exception as e:
            logger.error(f"[✗] Failed to update builds repository CHANGELOG.md: {e}")

        try:
            publish_repo_catalog(
                state_dir=state_dir,
                patched_json=patched_json,
                release_state=release_state,
                repo=repo,
                token=token,
                project_root=project_root,
                force=force,
            )
        except Exception as e:
            logger.error(f"[✗] Failed to update builds repository catalog.json: {e}")

        _write_json(release_state, state_file)
        send_apprise_notification(published_items, repo)
        send_apprise_failure_notification(patch_failures, cert_mismatches, repo)
        logger.info(
            f"[*] GitHub Releases summary: {len(targets)} candidate(s) checked, "
            f"{len(published_items)} uploaded, {skipped_count} skipped, {failed_count} failed."
        )
        return release_state

    except Exception as e:
        logger.error(f"[✗] GitHub Releases publisher error: {e}")
        return {}

"""
Isolated GitHub Releases publisher for AutoMorph.
Uploads patched APKs to a GitHub repository, guards signing certificate
fingerprints, computes release diffs, generates an Obtainium import
configuration (`obtainium-github-export.json`), maintains a live builds
`README.md` dashboard, and sends optional Apprise notifications.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
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

            # signers -> first signer -> signed_data -> skip digests -> certificates -> first cert
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
            "summary": f"Initial release (v{version_name})",
        }

    prev_ver = str(prev_entry.get("version_name") or "").strip()
    if not prev_ver:
        prev_tag = str(prev_entry.get("tag") or "")
        prefix = f"{package_name}-v"
        prev_ver = prev_tag[len(prefix):] if prev_tag.startswith(prefix) else "unknown"

    if prev_ver == version_name:
        version_transition = f"Rebuild of v{version_name}"
    else:
        version_transition = f"{prev_ver} -> {version_name}"

    prev_patches = set(prev_entry.get("applied_patches") or [])
    curr_patches = set(current_patches)
    added = sorted(curr_patches - prev_patches)
    removed = sorted(prev_patches - curr_patches)

    parts = [version_transition]
    if added or removed:
        if added:
            parts.append(f"+{len(added)} patch(es)")
        if removed:
            parts.append(f"-{len(removed)} patch(es)")
    else:
        parts.append("no patch changes")

    return {
        "version_transition": version_transition,
        "added_patches": added,
        "removed_patches": removed,
        "is_initial": False,
        "summary": "; ".join(parts),
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

    tag = f"{package_name}-v{version_name}"
    asset_name = f"{package_name}-{version_name}-{arch}-morphe.apk"
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
        "clean_name": clean_name,
        "version_name": version_name,
        "arch": arch,
        "tag": tag,
        "diff_summary": diff_info["summary"],
    }


def prune_old_releases(
    package_name: str,
    repo: str,
    token: str,
    keep: int,
    release_state: dict[str, Any] | None = None,
) -> list[str]:
    """
    Deletes GitHub Releases (and their git tags) for `package_name` beyond
    the newest `keep` releases. Returns a list of deleted tag names.
    """
    if keep <= 0:
        return []

    owner, repo_name = repo.split("/", 1)
    headers = _github_headers(token)
    list_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/releases?per_page=100"
    resp = requests.get(list_url, headers=headers, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()

    prefix = f"{package_name}-v"
    matching = [
        rel for rel in resp.json()
        if isinstance(rel, dict) and str(rel.get("tag_name", "")).startswith(prefix)
    ]
    matching.sort(key=lambda r: r.get("created_at", ""), reverse=True)

    deleted_tags: list[str] = []
    for old_rel in matching[keep:]:
        old_id = old_rel.get("id")
        old_tag = old_rel.get("tag_name", "")
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
                version_key = old_tag[len(prefix):]
                release_state[package_name].pop(version_key, None)
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
    `https://github.com/{repo}` with per-package tag and APK regex filters.
    """
    patched_results = _read_json(patched_json)
    if not patched_results:
        return None

    active_packages = _get_active_packages(project_root) if project_root is not None else None
    excluded_packages = _get_excluded_packages()

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

        additional_settings = {
            "verifyLatestTag": False,
            "filterReleasesByRegEx": f"^{re.escape(package_name)}-v",
            "apkFilterRegEx": f"^{re.escape(package_name)}-.*\\.apk$",
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
        "per-package `{package_name}-v...` tags in a shared repository.\n"
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
    live table of active, published APKs and the Obtainium 1-click import URL.
    Returns True if README.md was updated, False if skipped.
    """
    if not _parse_bool_env("GITHUB_RELEASE_UPDATE_README", default=True):
        return False

    patched_results = _read_json(patched_json)
    active_packages = _get_active_packages(project_root) if project_root is not None else None
    excluded_packages = _get_excluded_packages()

    config_url = f"https://github.com/{repo}/releases/download/{CONFIG_RELEASE_TAG}/obtainium-github-export.json"
    rows: list[str] = []

    for package_name in sorted(patched_results.keys()):
        versions = patched_results[package_name]
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
        pkg_info = ver_details.get("package", {}) if isinstance(ver_details, dict) else {}

        clean_name = pkg_info.get("clean_name", package_name)
        patched_pkg = pkg_info.get("patched_package_name", package_name)
        arch = pkg_info.get("arch", "arm64-v8a")
        tag = latest_pub.get("tag", f"{package_name}-v{ver_name}")
        asset_name = latest_pub.get("asset_name", f"{package_name}-{ver_name}-{arch}-morphe.apk")
        pub_at = str(latest_pub.get("published_at", ""))[:19].replace("T", " ")
        dl_url = f"https://github.com/{repo}/releases/download/{quote(tag, safe='')}/{quote(asset_name, safe='')}"

        rows.append(
            f"| {clean_name} | `{patched_pkg}` | `{ver_name}` | `{arch}` | {pub_at} | [Download APK]({dl_url}) |"
        )

    lines = [
        "# AutoMorph Builds",
        "",
        "Automated Android APK builds patched with AutoMorph & Morphe Desktop.",
        "",
        "## Obtainium 1-Click Import",
        "",
        f"Import URL: `{config_url}`",
        "",
        "> **Note:** `Verify Latest Tag` is pre-configured to `OFF` (`verifyLatestTag: false`) in this export so Obtainium tracks per-package tags cleanly.",
        "",
        "## Published Applications",
        "",
        "| App | Package | Version | Arch | Updated (UTC) | Download |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    if rows:
        lines.extend(rows)
    else:
        lines.append("| *No active published builds* | - | - | - | - | - |")

    readme_content = "\n".join(lines) + "\n"
    readme_sha = hashlib.sha256(readme_content.encode("utf-8")).hexdigest()

    if not force and release_state.get("_readme", {}).get("sha256") == readme_sha:
        logger.debug("Builds README.md unchanged; skipping GitHub Contents API update.")
        return False

    owner, repo_name = repo.split("/", 1)
    headers = _github_headers(token)
    contents_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/contents/README.md"

    existing_sha: str | None = None
    get_resp = requests.get(contents_url, headers=headers, timeout=REQUEST_TIMEOUT)
    if get_resp.status_code == 200:
        existing_sha = get_resp.json().get("sha")
    elif get_resp.status_code != 404:
        get_resp.raise_for_status()

    payload: dict[str, Any] = {
        "message": "chore: update builds dashboard",
        "content": base64.b64encode(readme_content.encode("utf-8")).decode("ascii"),
    }
    if existing_sha:
        payload["sha"] = existing_sha

    put_resp = requests.put(contents_url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
    put_resp.raise_for_status()

    release_state["_readme"] = {
        "sha256": readme_sha,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    logger.info(" └── [✓] Updated builds repository README.md dashboard.")
    return True


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
    Sends a concise notification via Apprise when APPRISE_URL is configured
    and at least one new APK release was uploaded in this run.
    """
    apprise_url = os.getenv("APPRISE_URL", "").strip()
    if not apprise_url or not published_items:
        return

    title = f"AutoMorph: {len(published_items)} new release(s) published"
    lines = []
    for item in published_items:
        clean_name = item.get("clean_name") or item.get("package_name")
        version_name = item.get("version_name", "")
        arch = item.get("arch", "")
        tag = item.get("tag", "")
        diff_summary = item.get("diff_summary", "")
        release_url = f"https://github.com/{repo}/releases/tag/{tag}"
        diff_suffix = f" [{diff_summary}]" if diff_summary else ""
        lines.append(f"- {clean_name} v{version_name} ({arch}){diff_suffix}: {release_url}")

    _dispatch_apprise(title=title, body="\n".join(lines))


def send_apprise_failure_notification(
    patch_failures: dict[str, Any] | None,
    cert_mismatches: list[dict[str, Any]],
    repo: str,
) -> None:
    """
    Sends an Apprise alert when APPRISE_NOTIFY_ON_FAILURE is enabled and either
    `patch_failures` or `cert_mismatches` is non-empty.
    """
    if not _parse_bool_env("APPRISE_NOTIFY_ON_FAILURE", default=True):
        return

    failures = patch_failures or {}
    if not failures and not cert_mismatches:
        return

    apprise_url = os.getenv("APPRISE_URL", "").strip()
    if not apprise_url:
        return

    lines: list[str] = []
    for pkg_name, fail_info in failures.items():
        if isinstance(fail_info, dict):
            targets = fail_info.get("target_versions") or []
            attempts = fail_info.get("attempts") or []
            last_attempt = attempts[-1] if attempts and isinstance(attempts[-1], dict) else {}
            stage = last_attempt.get("stage", "Pipeline")
            reason = last_attempt.get("reason", "Unknown failure")
            ver_str = str(targets[0][0]) if targets and isinstance(targets[0], (list, tuple)) else (str(targets[0]) if targets else "unknown")
            lines.append(f"- [Build Failed] {pkg_name} (v{ver_str}) at {stage}: {reason}")
        else:
            lines.append(f"- [Build Failed] {pkg_name}: {fail_info}")

    for mismatch in cert_mismatches:
        pkg_name = mismatch.get("package_name", "unknown")
        ver_name = mismatch.get("version_name", "unknown")
        old_c = str(mismatch.get("old_cert", ""))[:12]
        new_c = str(mismatch.get("new_cert", ""))[:12]
        lines.append(
            f"- [Cert Mismatch] {pkg_name} v{ver_name}: upload blocked ({old_c}... != {new_c}...)"
        )

    total = len(failures) + len(cert_mismatches)
    title = f"AutoMorph: {total} failure/alert(s) in {repo}"
    _dispatch_apprise(title=title, body="\n".join(lines))


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

        targets: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()

        for package_name, details in (patched or {}).items():
            ver = details.get("version_name") if isinstance(details, dict) else None
            if not ver and package_name in patched_results:
                ver = _select_latest_version(patched_results[package_name])
            if ver and (package_name, ver) not in seen:
                targets.append((package_name, ver))
                seen.add((package_name, ver))

        # Optionally catch up any un-published latest version in patched.json
        if patched or sync_all:
            for package_name, versions in patched_results.items():
                if not isinstance(versions, dict) or not versions:
                    continue
                latest_ver = _select_latest_version(versions)
                if latest_ver and (package_name, latest_ver) not in seen:
                    existing = release_state.get(package_name, {}).get(latest_ver)
                    sha = versions[latest_ver].get("file", {}).get("sha256")
                    if force or not (isinstance(existing, dict) and sha and existing.get("sha256") == sha):
                        targets.append((package_name, latest_ver))
                        seen.add((package_name, latest_ver))

        touched_packages: set[str] = set()
        published_items: list[dict[str, Any]] = []
        for package_name, version_name in targets:
            version_entry = patched_results.get(package_name, {}).get(version_name)
            if not isinstance(version_entry, dict):
                logger.warning(f"[!] No metadata in patched.json for {package_name} v{version_name}.")
                continue
            try:
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
                )
                if pub_result:
                    touched_packages.add(package_name)
                    if isinstance(pub_result, dict):
                        published_items.append(pub_result)
                    else:
                        pkg_info = version_entry.get("package", {})
                        published_items.append({
                            "package_name": package_name,
                            "clean_name": pkg_info.get("clean_name", package_name),
                            "version_name": version_name,
                            "arch": pkg_info.get("arch", "arm64-v8a"),
                            "tag": f"{package_name}-v{version_name}",
                        })
            except Exception as e:
                logger.error(f"[✗] Failed to publish GitHub Release for {package_name} v{version_name}: {e}")

        if keep > 0:
            for package_name in touched_packages:
                try:
                    prune_old_releases(package_name, repo, token, keep, release_state=release_state)
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

        _write_json(release_state, state_file)
        send_apprise_notification(published_items, repo)
        send_apprise_failure_notification(patch_failures, cert_mismatches, repo)
        return release_state

    except Exception as e:
        logger.error(f"[✗] GitHub Releases publisher error: {e}")
        return {}

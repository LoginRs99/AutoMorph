"""Unit tests for scripts/github_release.py and fork configuration files."""

from __future__ import annotations

import ast
import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import py_compile
import struct
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zipfile

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import github_release  # noqa: E402


def _len_prefixed(data: bytes) -> bytes:
    return struct.pack("<I", len(data)) + data


def _build_signed_apk(apk_path: Path, cert_der: bytes) -> None:
    """
    Constructs a minimal valid ZIP file with an APK Signature Scheme v2
    Signing Block (magic `APK Sig Block 42`, ID `0x7109871a`) immediately
    before the Central Directory.
    """
    base_zip = apk_path.with_suffix(".base.zip")
    with zipfile.ZipFile(base_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")

    raw = base_zip.read_bytes()
    base_zip.unlink()

    eocd_pos = raw.rfind(b"PK\x05\x06")
    assert eocd_pos != -1
    cd_offset = struct.unpack_from("<I", raw, eocd_pos + 16)[0]

    digests = _len_prefixed(_len_prefixed(b"\x00" * 8))
    certs = _len_prefixed(_len_prefixed(cert_der))
    signed_data = digests + certs + _len_prefixed(b"")
    signer = _len_prefixed(signed_data) + _len_prefixed(b"") + _len_prefixed(b"")
    signers = _len_prefixed(_len_prefixed(signer))

    pair_id = 0x7109871A
    pair_body = struct.pack("<I", pair_id) + signers
    pair = struct.pack("<Q", len(pair_body)) + pair_body

    block_size = len(pair) + 24
    sig_block = (
        struct.pack("<Q", block_size)
        + pair
        + struct.pack("<Q", block_size)
        + b"APK Sig Block 42"
    )

    new_cd_offset = cd_offset + len(sig_block)
    new_eocd = (
        raw[eocd_pos : eocd_pos + 16]
        + struct.pack("<I", new_cd_offset)
        + raw[eocd_pos + 20 :]
    )
    new_raw = raw[:cd_offset] + sig_block + raw[cd_offset:eocd_pos] + new_eocd
    apk_path.write_bytes(new_raw)


def _make_patched_entry(
    pkg: str,
    ver: str,
    vc: int,
    apk_path: Path,
    patches: list[str],
    sha256: str = "a" * 64,
    clean_name: str = "Test App",
) -> dict:
    return {
        "metadata": {"time": "2026-11-26 12:00:00", "time_ms": 1795690800000},
        "package": {
            "clean_name": clean_name,
            "source_package_name": pkg,
            "patched_package_name": pkg,
            "patched_version_name": ver,
            "source_version_code": vc,
            "patched_version_code": vc,
            "arch": "arm64-v8a",
            "min_sdk": 26,
            "target_sdk": 35,
        },
        "file": {
            "file_name": apk_path.name,
            "location": str(apk_path),
            "size_bytes": 10485760,
            "file_size": "10.00 MB",
            "sha256": sha256,
        },
        "patch": {
            "applied_patches": {p: {"repo": "MorpheApp"} for p in patches},
            "repos": ["https://github.com/MorpheApp/morphe-patches"],
            "morphe_desktop_version": "2.3.0",
        },
    }


class TestGitHubRelease(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.state_dir = self.tmp / "tools" / "automorph-data" / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = self.tmp / "tools" / "automorph-data" / "config.yaml"
        self.patched_json = self.state_dir / "patched.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_1_extract_apk_cert_sha256(self) -> None:
        apk_path = self.tmp / "signed.apk"
        fake_cert = b"FAKE-X509-DER-CERTIFICATE-BYTES-123456"
        _build_signed_apk(apk_path, fake_cert)

        expected = hashlib.sha256(fake_cert).hexdigest().lower()
        actual = github_release._extract_apk_cert_sha256(apk_path)
        self.assertEqual(actual, expected)

    def test_2_signing_cert_mismatch_guard(self) -> None:
        apk_v1 = self.tmp / "app_v1.apk"
        apk_v2 = self.tmp / "app_v2.apk"
        cert_a = b"CERT-A-DER-BYTES"
        cert_b = b"CERT-B-DER-BYTES"
        _build_signed_apk(apk_v1, cert_a)
        _build_signed_apk(apk_v2, cert_b)

        release_state = {
            "com.example.app": {
                "1.0.0": {
                    "sha256": "1" * 64,
                    "cert_sha256": hashlib.sha256(cert_a).hexdigest().lower(),
                    "version_name": "1.0.0",
                    "applied_patches": ["Patch A"],
                    "tag": "test-app-v1.0.0",
                    "published_at": "2026-11-25T10:00:00+00:00",
                }
            }
        }
        entry_v2 = _make_patched_entry("com.example.app", "2.0.0", 200, apk_v2, ["Patch A"], sha256="2" * 64)

        mismatches: list[dict] = []
        with patch.object(github_release, "_upsert_release_and_upload") as mock_upload:
            res = github_release.publish_package(
                package_name="com.example.app",
                version_name="2.0.0",
                version_entry=entry_v2,
                repo="user/builds",
                token="tok",
                release_state=release_state,
                allow_cert_change=False,
                cert_mismatches=mismatches,
            )
            self.assertFalse(res)
            self.assertEqual(len(mismatches), 1)
            mock_upload.assert_not_called()

            mock_upload.return_value = (99, "https://github.com/user/builds/releases/tag/test-app-v2.0.0")
            res_allowed = github_release.publish_package(
                package_name="com.example.app",
                version_name="2.0.0",
                version_entry=entry_v2,
                repo="user/builds",
                token="tok",
                release_state=release_state,
                allow_cert_change=True,
                cert_mismatches=mismatches,
            )
            self.assertIsInstance(res_allowed, dict)
            mock_upload.assert_called_once()

    def test_3_slug_resolution_collision_and_obtainium_regex(self) -> None:
        dummy_apk = self.tmp / "dummy.apk"
        patched = {
            "com.zhiliaoapp.musically": {
                "44.6.3": _make_patched_entry("com.zhiliaoapp.musically", "44.6.3", 440, dummy_apk, ["P1"], clean_name="TikTok"),
            },
            "com.dup.one": {
                "1.0.0": _make_patched_entry("com.dup.one", "1.0.0", 100, dummy_apk, ["P1"], clean_name="Dup App!"),
            },
            "com.dup.two": {
                "2.0.0": _make_patched_entry("com.dup.two", "2.0.0", 200, dummy_apk, ["P1"], clean_name="Dup App!"),
            },
        }
        slugs = github_release._resolve_app_slugs(patched)
        self.assertEqual(slugs["com.zhiliaoapp.musically"], "tiktok")
        self.assertEqual(slugs["com.dup.one"], "com-dup-one")
        self.assertEqual(slugs["com.dup.two"], "com-dup-two")

        self.config_path.write_text(
            "packages:\n"
            "  - package_name: com.zhiliaoapp.musically\n"
            "  - package_name: com.dup.one\n"
            "  # - package_name: com.dup.two\n",
            encoding="utf-8",
        )
        self.patched_json.write_text(json.dumps(patched), encoding="utf-8")

        with patch.dict(os.environ, {"GITHUB_RELEASE_EXCLUDE": "com.dup.one"}):
            out = github_release.build_obtainium_github_export(
                self.state_dir, self.patched_json, "user/builds", project_root=self.tmp
            )
        self.assertIsNotNone(out)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(len(data["apps"]), 1)
        app_entry = data["apps"][0]
        self.assertEqual(app_entry["author"], "user")
        settings = json.loads(app_entry["additionalSettings"])
        self.assertFalse(settings["verifyLatestTag"])
        self.assertFalse(settings["releaseTitleAsVersion"])
        self.assertTrue(settings["versionDetection"])
        self.assertTrue(settings["autoApkFilterByArch"])
        self.assertEqual(settings["filterReleasesByRegEx"], "^tiktok-v")
        self.assertEqual(settings["apkFilterRegEx"], r"^tiktok-.*\.apk$")
        deeplink = github_release._build_obtainium_deeplink(app_entry)
        self.assertTrue(deeplink.startswith("https://apps.obtainium.imranr.dev/redirect.html?r=obtainium%3A%2F%2Fadd%2F") or deeplink.startswith("https://apps.obtainium.imranr.dev/redirect.html?r=obtainium://add/"))

    def test_4_prune_matches_slug_and_legacy_package_tags(self) -> None:
        mock_releases = [
            {"id": 1, "tag_name": "tiktok-v44.6.3", "created_at": "2026-11-26T12:00:00Z"},
            {"id": 2, "tag_name": "tiktok-v44.5.0", "created_at": "2026-11-25T12:00:00Z"},
            {"id": 3, "tag_name": "com.zhiliaoapp.musically-v44.4.0", "created_at": "2026-11-24T12:00:00Z"},
            {"id": 4, "tag_name": "automorph-config", "created_at": "2026-11-23T12:00:00Z"},
        ]
        get_resp = MagicMock(status_code=200)
        get_resp.json.return_value = mock_releases
        del_resp = MagicMock(status_code=204)

        release_state = {
            "com.zhiliaoapp.musically": {
                "44.6.3": {"tag": "tiktok-v44.6.3"},
                "44.5.0": {"tag": "tiktok-v44.5.0"},
                "44.4.0": {"tag": "com.zhiliaoapp.musically-v44.4.0"},
            }
        }
        with patch("github_release.requests.get", return_value=get_resp), \
             patch("github_release.requests.delete", return_value=del_resp):
            deleted = github_release.prune_old_releases(
                "com.zhiliaoapp.musically",
                "user/builds",
                "tok",
                keep=2,
                release_state=release_state,
                slug="tiktok",
            )
        self.assertEqual(deleted, ["com.zhiliaoapp.musically-v44.4.0"])
        self.assertNotIn("44.4.0", release_state["com.zhiliaoapp.musically"])
        self.assertIn("44.6.3", release_state["com.zhiliaoapp.musically"])

    def test_5_rich_readme_dashboard_and_skip(self) -> None:
        self.config_path.write_text("packages:\n  - package_name: com.zhiliaoapp.musically\n", encoding="utf-8")
        dummy_apk = self.tmp / "dummy.apk"
        self.patched_json.write_text(
            json.dumps({
                "com.zhiliaoapp.musically": {
                    "44.6.3": _make_patched_entry(
                        "com.zhiliaoapp.musically",
                        "44.6.3",
                        440603,
                        dummy_apk,
                        ["Remove ads", "Spoof client"],
                        clean_name="TikTok",
                    )
                }
            }),
            encoding="utf-8",
        )
        release_state = {
            "com.zhiliaoapp.musically": {
                "44.6.3": {
                    "slug": "tiktok",
                    "version_name": "44.6.3",
                    "sha256": "a" * 64,
                    "cert_sha256": "b" * 64,
                    "applied_patches": ["Remove ads", "Spoof client"],
                    "tag": "tiktok-v44.6.3",
                    "asset_name": "tiktok-44.6.3-arm64-v8a-morphe.apk",
                    "published_at": "2026-11-26T12:00:00+00:00",
                }
            }
        }
        get_resp = MagicMock(status_code=200)
        get_resp.json.return_value = {"sha": "oldreadme", "content": ""}
        put_resp = MagicMock(status_code=200)

        with patch.dict(os.environ, {"GITHUB_RELEASE_UPDATE_README": "true"}), \
             patch("github_release.requests.get", return_value=get_resp), \
             patch("github_release.requests.put", return_value=put_resp) as mock_put:
            updated = github_release.publish_repo_readme(
                self.state_dir, self.patched_json, release_state, "user/builds", "tok", project_root=self.tmp
            )
            self.assertTrue(updated)
            put_json = mock_put.call_args.kwargs["json"]
            decoded = base64.b64decode(put_json["content"]).decode("utf-8")
            self.assertIn("| App | Version | Size | Android SDK | Patches | Updated (UTC) | Download |", decoded)
            self.assertIn("img.shields.io/badge/Active_Apps-1", decoded)
            self.assertIn("> [!TIP]", decoded)
            self.assertIn("API 26–35", decoded)
            self.assertIn("| **TikTok** (`tiktok`) | `v44.6.3` | 10.00 MB | API 26–35 | 2 | 2026-11-26 |", decoded)
            self.assertIn("https://apps.obtainium.imranr.dev/redirect.html?r=obtainium://add/", decoded)
            self.assertIn("<details><summary><strong>TikTok</strong>", decoded)
            self.assertIn("| **Source Package** | `com.zhiliaoapp.musically` |", decoded)
            self.assertIn("- Remove ads", decoded)

            updated_again = github_release.publish_repo_readme(
                self.state_dir, self.patched_json, release_state, "user/builds", "tok", project_root=self.tmp
            )
            self.assertFalse(updated_again)
            self.assertEqual(mock_put.call_count, 1)

    def test_6_changelog_cap_and_catalog_sha_skip(self) -> None:
        old_sections = "\n\n".join(f"## 2026-10-{i:02d} 00:00 UTC\n\n- Old {i}" for i in range(1, 56))
        existing_changelog = "# Changelog\n\nAutomated release history for patched APKs.\n\n" + old_sections + "\n"
        get_cl_resp = MagicMock(status_code=200)
        get_cl_resp.json.return_value = {
            "sha": "clsha",
            "content": base64.b64encode(existing_changelog.encode("utf-8")).decode("ascii"),
        }
        put_cl_resp = MagicMock(status_code=200)

        published_items = [{
            "package_name": "com.zhiliaoapp.musically",
            "clean_name": "TikTok",
            "tag": "tiktok-v44.6.3",
            "asset_name": "tiktok-44.6.3-arm64-v8a-morphe.apk",
            "diff_summary": "44.5.0 -> 44.6.3; no patch changes",
        }]
        with patch.dict(os.environ, {"GITHUB_RELEASE_UPDATE_CHANGELOG": "true"}), \
             patch("github_release.requests.get", return_value=get_cl_resp), \
             patch("github_release.requests.put", return_value=put_cl_resp) as mock_put_cl:
            changed = github_release.publish_repo_changelog(published_items, "user/builds", "tok")
            self.assertTrue(changed)
            cl_content = base64.b64decode(mock_put_cl.call_args.kwargs["json"]["content"]).decode("utf-8")
            section_count = sum(1 for line in cl_content.splitlines() if line.startswith("## "))
            self.assertEqual(section_count, 50)
            self.assertIn("**TikTok** (`tiktok-v44.6.3`)", cl_content)

        # catalog.json generation + SHA skip
        self.config_path.write_text("packages:\n  - package_name: com.zhiliaoapp.musically\n", encoding="utf-8")
        dummy_apk = self.tmp / "dummy.apk"
        self.patched_json.write_text(
            json.dumps({
                "com.zhiliaoapp.musically": {
                    "44.6.3": _make_patched_entry("com.zhiliaoapp.musically", "44.6.3", 440603, dummy_apk, ["P1"], clean_name="TikTok")
                }
            }),
            encoding="utf-8",
        )
        release_state = {
            "com.zhiliaoapp.musically": {
                "44.6.3": {
                    "slug": "tiktok",
                    "version_name": "44.6.3",
                    "sha256": "a" * 64,
                    "cert_sha256": "b" * 64,
                    "applied_patches": ["P1"],
                    "tag": "tiktok-v44.6.3",
                    "asset_name": "tiktok-44.6.3-arm64-v8a-morphe.apk",
                    "published_at": "2026-11-26T12:00:00+00:00",
                }
            }
        }
        get_cat_resp = MagicMock(status_code=404)
        put_cat_resp = MagicMock(status_code=201)
        with patch.dict(os.environ, {"GITHUB_RELEASE_UPDATE_CATALOG": "true"}), \
             patch("github_release.requests.get", return_value=get_cat_resp), \
             patch("github_release.requests.put", return_value=put_cat_resp) as mock_put_cat:
            cat_updated = github_release.publish_repo_catalog(
                self.state_dir, self.patched_json, release_state, "user/builds", "tok", project_root=self.tmp
            )
            self.assertTrue(cat_updated)
            cat_json = json.loads(base64.b64decode(mock_put_cat.call_args.kwargs["json"]["content"]).decode("utf-8"))
            self.assertEqual(cat_json["apps"][0]["slug"], "tiktok")
            self.assertEqual(cat_json["apps"][0]["patch_count"], 1)
            self.assertTrue(cat_json["apps"][0]["obtainium_add_url"].startswith("https://apps.obtainium.imranr.dev/redirect.html?r=obtainium://add/"))

            cat_again = github_release.publish_repo_catalog(
                self.state_dir, self.patched_json, release_state, "user/builds", "tok", project_root=self.tmp
            )
            self.assertFalse(cat_again)
            self.assertEqual(mock_put_cat.call_count, 1)

    def test_7_apprise_single_vs_multi_compact_formatting(self) -> None:
        mock_apprise_mod = MagicMock()
        mock_apobj = MagicMock()
        mock_apprise_mod.Apprise.return_value = mock_apobj

        item1 = {
            "package_name": "com.a",
            "clean_name": "TikTok",
            "version_name": "44.6.3",
            "tag": "tiktok-v44.6.3",
            "version_transition": "44.5.0 -> 44.6.3",
            "patch_diff_short": "+1 / -0 patches",
            "diff_summary": "44.5.0 -> 44.6.3; +1 patch(es)",
        }
        item2 = {
            "package_name": "com.b",
            "clean_name": "YouTube",
            "version_name": "21.30.216",
            "tag": "youtube-v21.30.216",
            "version_transition": "Initial release (v21.30.216)",
            "patch_diff_short": "10 patches",
            "diff_summary": "Initial release (v21.30.216)",
        }

        with patch.object(github_release, "apprise", mock_apprise_mod), \
             patch.dict(os.environ, {"APPRISE_URL": "ntfy://topic1", "APPRISE_NOTIFY_ON_FAILURE": "true"}):
            github_release.send_apprise_notification([item1], "user/builds")
            github_release.send_apprise_notification([item1, item2], "user/builds")
            github_release.send_apprise_failure_notification(
                {"com.fail": {"target_versions": [("1.0", False)], "attempts": [{"stage": "DL", "reason": "404"}]}},
                [],
                "user/builds",
            )
            github_release.send_apprise_failure_notification(
                {"com.fail": {"target_versions": [("1.0", False)], "attempts": [{"stage": "DL", "reason": "404"}]}},
                [{"package_name": "com.cert", "clean_name": "CertApp", "version_name": "2.0", "old_cert": "aaa", "new_cert": "bbb"}],
                "user/builds",
            )

        calls = mock_apobj.notify.call_args_list
        self.assertEqual(calls[0].kwargs["title"], "AutoMorph: TikTok v44.6.3 released")
        self.assertIn("Version: 44.5.0 -> 44.6.3", calls[0].kwargs["body"])
        self.assertEqual(calls[1].kwargs["title"], "AutoMorph: 2 apps released")
        self.assertIn("• TikTok v44.6.3", calls[1].kwargs["body"])
        self.assertIn("• YouTube v21.30.216", calls[1].kwargs["body"])
        self.assertEqual(calls[2].kwargs["title"], "AutoMorph: com.fail failed")
        self.assertEqual(calls[3].kwargs["title"], "AutoMorph: 2 failures/alerts")
        self.assertIn("• CertApp", calls[3].kwargs["body"])

    def test_8_hook_signature_compile_and_yaml_validation(self) -> None:
        sig = inspect.signature(github_release.main)
        self.assertIn("patch_failures", sig.parameters)

        main_src = (SCRIPTS_DIR / "main.py").read_text(encoding="utf-8")
        tree = ast.parse(main_src)
        hook_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "github_release"
            and node.func.attr == "main"
        ]
        self.assertEqual(len(hook_calls), 1)
        self.assertIn("patch_failures", {kw.arg for kw in hook_calls[0].keywords})

        pycache_dir = self.tmp / "pycache"
        for py_file in (SCRIPTS_DIR / "github_release.py", SCRIPTS_DIR / "main.py", Path(__file__)):
            cfile = pycache_dir / f"{py_file.stem}.pyc"
            cfile.parent.mkdir(parents=True, exist_ok=True)
            py_compile.compile(str(py_file), cfile=str(cfile), doraise=True)

        for yml_rel in ("portainer-compose.yaml", "default_compose.yaml", ".github/workflows/upstream-sync.yaml"):
            parsed = yaml.safe_load((REPO_ROOT / yml_rel).read_text(encoding="utf-8"))
            self.assertIsInstance(parsed, dict)

    def test_9_same_version_rebuild_patches_release_body(self) -> None:
        apk_path = self.tmp / "tiktok.apk"
        apk_path.write_bytes(b"APKDATA")

        get_resp = MagicMock(status_code=200)
        get_resp.json.return_value = {
            "id": 777,
            "html_url": "https://github.com/user/builds/releases/tag/tiktok-v44.6.3",
            "assets": [{"id": 555, "name": "tiktok-44.6.3-arm64-v8a-morphe.apk"}],
        }
        del_resp = MagicMock(status_code=204)
        patch_resp = MagicMock(status_code=200)
        post_resp = MagicMock(status_code=201)

        with patch("github_release.requests.get", return_value=get_resp), \
             patch("github_release.requests.delete", return_value=del_resp) as mock_del, \
             patch("github_release.requests.patch", return_value=patch_resp) as mock_patch, \
             patch("github_release.requests.post", return_value=post_resp) as mock_post:
            rel_id, rel_url = github_release._upsert_release_and_upload(
                repo="user/builds",
                token="tok",
                tag="tiktok-v44.6.3",
                title="TikTok v44.6.3 (arm64-v8a)",
                body="#### What Changed\n- **Version:** Rebuild of v44.6.3\n  - `+ New patch`",
                asset_path=apk_path,
                asset_name="tiktok-44.6.3-arm64-v8a-morphe.apk",
                content_type="application/vnd.android.package-archive",
            )

        self.assertEqual(rel_id, 777)
        self.assertIn("tiktok-v44.6.3", rel_url)
        mock_del.assert_called_once()
        mock_patch.assert_called_once()
        patch_json = mock_patch.call_args.kwargs["json"]
        self.assertIn("Rebuild of v44.6.3", patch_json["body"])
        self.assertIn("+ New patch", patch_json["body"])
        mock_post.assert_called_once()

    def test_10_manager_suffixed_version_lookup(self) -> None:
        fake_axml_mod = MagicMock()
        fake_pyaxml = MagicMock()
        fake_pyaxml.axmlprinter = fake_axml_mod
        with patch.dict(sys.modules, {"pyaxmlparser": fake_pyaxml, "pyaxmlparser.axmlprinter": fake_axml_mod}):
            import importlib
            import manager
            importlib.reload(manager)

            pkg_versions = {"12.19.1": {"version_code": 312190100}}
            self.assertEqual(manager._resolve_version_entry(pkg_versions, "12.19.1-release.0")["version_code"], 312190100)
            self.assertEqual(manager._resolve_version_entry(pkg_versions, "12.19.1")["version_code"], 312190100)
            self.assertEqual(manager._resolve_version_entry({}, "12.19.1-release.0"), {})

            apk_path = self.tmp / "com.twitter.android_12.19.1-release.0_patched.apk"
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("AndroidManifest.xml", b"<manifest/>")
            opts_path = self.tmp / "opts.json"
            opts_path.write_text("[]", encoding="utf-8")
            res_path = self.tmp / "result.json"
            res_path.write_text("{}", encoding="utf-8")

            root_elem = MagicMock()
            root_elem.attrib = {
                "package": "com.twitter.android",
                "{http://schemas.android.com/apk/res/android}versionCode": "312190100",
                "{http://schemas.android.com/apk/res/android}versionName": "12.19.1",
            }
            root_elem.find.return_value = None
            fake_axml_mod.AXMLPrinter.return_value.get_xml_obj.return_value = root_elem

            p = manager.Patched(
                repo_details={},
                detailed_patch_list={"com.twitter.android": {"patch_aliases": {}}},
                base_url="http://localhost:8080",
                morphe_location=self.tmp / "morphe-2.3.0.jar",
                patched_data={},
                arch="arm64-v8a",
                enabled_patches_per_app={},
            )
            p.make_patched_data("com.twitter.android", {
                "version_name": "12.19.1-release.0",
                "repos": set(),
                "strat": 1,
                "attempt": 1,
                "options": opts_path,
                "output_dest": apk_path,
                "results_dest": res_path,
                "package": {"com.twitter.android": pkg_versions},
                "time": {"time": "2026-11-26 15:00:00", "time_ms": 1795701600000},
            })
            self.assertEqual(
                p.patched_data["com.twitter.android"]["12.19.1"]["package"]["source_version_code"],
                312190100,
            )

    def test_11_friendly_display_names_and_custom_labels(self) -> None:
        dummy_apk = self.tmp / "dummy.apk"
        patched = {
            "com.zhiliaoapp.musically": {
                "44.6.3": _make_patched_entry("com.zhiliaoapp.musically", "44.6.3", 440, dummy_apk, ["P1"], clean_name="com.zhiliaoapp.musically"),
            },
            "com.reddit.frontpage": {
                "2026.40.0": _make_patched_entry("com.reddit.frontpage", "2026.40.0", 2026, dummy_apk, ["P1"], clean_name=""),
            },
            "com.google.android.youtube": {
                "21.30.216": _make_patched_entry("com.google.android.youtube", "21.30.216", 2130, dummy_apk, ["P1"], clean_name="YouTube LG"),
            },
        }
        slugs = github_release._resolve_app_slugs(patched)
        self.assertEqual(slugs["com.zhiliaoapp.musically"], "tiktok")
        self.assertEqual(slugs["com.reddit.frontpage"], "reddit")
        self.assertEqual(slugs["com.google.android.youtube"], "youtube-lg")
        self.assertEqual(github_release._resolve_display_name("com.zhiliaoapp.musically", "com.zhiliaoapp.musically"), "TikTok")
        self.assertEqual(github_release._resolve_display_name("com.reddit.frontpage", ""), "Reddit")
        self.assertEqual(github_release._resolve_display_name("com.google.android.youtube", "YouTube LG"), "YouTube LG")

    def test_12_rollback_selects_on_disk_and_prunes_higher_release(self) -> None:
        missing_apk = self.tmp / "apps" / "patched" / "com.twitter.android" / "12.38.1-prod.01" / "com.twitter.android_12.38.1-prod.01_patched.apk"
        present_apk = self.tmp / "apps" / "patched" / "com.twitter.android" / "12.19.1-release.0" / "com.twitter.android_12.19.1-release.0_patched.apk"
        present_apk.parent.mkdir(parents=True, exist_ok=True)
        present_apk.write_bytes(b"APK")

        versions = {
            "12.38.1-prod.01": _make_patched_entry("com.twitter.android", "12.38.1-prod.01", 312380100, missing_apk, ["P1"], clean_name="X LG"),
            "12.19.1-release.0": _make_patched_entry("com.twitter.android", "12.19.1-release.0", 312190100, present_apk, ["P1"], clean_name="X LG"),
        }
        selected = github_release._select_active_version_entry(versions, package_name="com.twitter.android", project_root=self.tmp)
        self.assertEqual(selected, "12.19.1-release.0")

        mock_releases = [
            {"id": 10, "tag_name": "x-lg-v12.38.1-prod.01", "created_at": "2026-11-26T12:00:00Z"},
            {"id": 11, "tag_name": "x-lg-v12.19.1-release.0", "created_at": "2026-11-25T12:00:00Z"},
        ]
        get_resp = MagicMock(status_code=200)
        get_resp.json.return_value = mock_releases
        del_resp = MagicMock(status_code=204)

        release_state = {
            "com.twitter.android": {
                "12.38.1-prod.01": {"tag": "x-lg-v12.38.1-prod.01"},
                "12.19.1-release.0": {"tag": "x-lg-v12.19.1-release.0"},
            }
        }
        with patch("github_release.requests.get", return_value=get_resp), \
             patch("github_release.requests.delete", return_value=del_resp):
            deleted = github_release.prune_old_releases(
                "com.twitter.android",
                "user/builds",
                "tok",
                keep=2,
                release_state=release_state,
                slug="x-lg",
                active_version="12.19.1-release.0",
            )
        self.assertEqual(deleted, ["x-lg-v12.38.1-prod.01"])
        self.assertNotIn("12.38.1-prod.01", release_state["com.twitter.android"])
        self.assertIn("12.19.1-release.0", release_state["com.twitter.android"])


if __name__ == "__main__":
    unittest.main()

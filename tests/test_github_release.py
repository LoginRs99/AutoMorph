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

    # block_size = len(pairs) + 8 (footer size field) + 16 (magic)
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
) -> dict:
    return {
        "metadata": {"time": "2026-11-26 12:00:00", "time_ms": 1795690800000},
        "package": {
            "clean_name": "Test App",
            "source_package_name": pkg,
            "patched_package_name": pkg,
            "patched_version_name": ver,
            "source_version_code": vc,
            "patched_version_code": vc,
            "arch": "arm64-v8a",
        },
        "file": {
            "file_name": apk_path.name,
            "location": str(apk_path),
            "sha256": sha256,
        },
        "patch": {
            "applied_patches": {p: {"repo": "MorpheApp"} for p in patches},
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
                    "tag": "com.example.app-v1.0.0",
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

            mock_upload.return_value = (99, "https://github.com/user/builds/releases/tag/com.example.app-v2.0.0")
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

    def test_3_what_changed_diff_generation(self) -> None:
        init_diff = github_release._compute_release_diff("com.a", "1.0.0", ["P1", "P2"], None)
        self.assertEqual(init_diff["version_transition"], "Initial release (v1.0.0)")
        self.assertTrue(init_diff["is_initial"])

        prev = {"version_name": "1.0.0", "applied_patches": ["P1", "P2"]}
        up_diff = github_release._compute_release_diff("com.a", "1.1.0", ["P2", "P3"], prev)
        self.assertEqual(up_diff["version_transition"], "1.0.0 -> 1.1.0")
        self.assertEqual(up_diff["added_patches"], ["P3"])
        self.assertEqual(up_diff["removed_patches"], ["P1"])

        entry = _make_patched_entry("com.a", "1.1.0", 110, self.tmp / "x.apk", ["P2", "P3"])
        body = github_release._build_release_body("com.a", "1.1.0", entry, diff_info=up_diff)
        self.assertIn("#### What Changed", body)
        self.assertIn("1.0.0 -> 1.1.0", body)
        self.assertIn("+ P3", body)
        self.assertIn("- P1", body)

    def test_4_obtainium_export_active_and_exclude_filtering(self) -> None:
        self.config_path.write_text(
            "packages:\n"
            "  - package_name: com.active.app\n"
            "  - package_name: com.private.app\n"
            "  # - package_name: com.disabled.app\n",
            encoding="utf-8",
        )
        dummy_apk = self.tmp / "dummy.apk"
        self.patched_json.write_text(
            json.dumps({
                "com.active.app": {"1.0.0": _make_patched_entry("com.active.app", "1.0.0", 100, dummy_apk, ["P1"])},
                "com.private.app": {"1.0.0": _make_patched_entry("com.private.app", "1.0.0", 100, dummy_apk, ["P1"])},
                "com.disabled.app": {"1.0.0": _make_patched_entry("com.disabled.app", "1.0.0", 100, dummy_apk, ["P1"])},
            }),
            encoding="utf-8",
        )
        with patch.dict(os.environ, {"GITHUB_RELEASE_EXCLUDE": "com.private.app"}):
            out = github_release.build_obtainium_github_export(
                self.state_dir, self.patched_json, "user/builds", project_root=self.tmp
            )
        self.assertIsNotNone(out)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual([a["id"] for a in data["apps"]], ["com.active.app"])

    def test_5_publish_repo_readme_upsert_and_skip(self) -> None:
        self.config_path.write_text("packages:\n  - package_name: com.active.app\n", encoding="utf-8")
        dummy_apk = self.tmp / "dummy.apk"
        self.patched_json.write_text(
            json.dumps({"com.active.app": {"1.2.3": _make_patched_entry("com.active.app", "1.2.3", 123, dummy_apk, ["P1"])}}),
            encoding="utf-8",
        )
        release_state = {
            "com.active.app": {
                "1.2.3": {
                    "version_name": "1.2.3",
                    "tag": "com.active.app-v1.2.3",
                    "asset_name": "com.active.app-1.2.3-arm64-v8a-morphe.apk",
                    "published_at": "2026-11-26T12:00:00+00:00",
                }
            }
        }
        get_resp = MagicMock(status_code=200)
        get_resp.json.return_value = {"sha": "oldblobsha"}
        put_resp = MagicMock(status_code=200)

        with patch.dict(os.environ, {"GITHUB_RELEASE_UPDATE_README": "true"}), \
             patch("github_release.requests.get", return_value=get_resp) as mock_get, \
             patch("github_release.requests.put", return_value=put_resp) as mock_put:
            updated = github_release.publish_repo_readme(
                self.state_dir, self.patched_json, release_state, "user/builds", "tok", project_root=self.tmp
            )
            self.assertTrue(updated)
            mock_get.assert_called_once()
            mock_put.assert_called_once()
            put_json = mock_put.call_args.kwargs["json"]
            self.assertEqual(put_json["sha"], "oldblobsha")
            decoded = base64.b64decode(put_json["content"]).decode("utf-8")
            self.assertIn("com.active.app", decoded)
            self.assertIn("obtainium-github-export.json", decoded)

            # Second run with unchanged state should skip
            updated_again = github_release.publish_repo_readme(
                self.state_dir, self.patched_json, release_state, "user/builds", "tok", project_root=self.tmp
            )
            self.assertFalse(updated_again)
            self.assertEqual(mock_put.call_count, 1)

    def test_6_apprise_success_and_failure_notifications(self) -> None:
        mock_apprise_mod = MagicMock()
        mock_apobj = MagicMock()
        mock_apprise_mod.Apprise.return_value = mock_apobj

        items = [{
            "package_name": "com.a",
            "clean_name": "App A",
            "version_name": "1.0.0",
            "arch": "arm64-v8a",
            "tag": "com.a-v1.0.0",
            "diff_summary": "0.9.0 -> 1.0.0; +1 patch(es)",
        }]
        failures = {
            "com.fail": {
                "target_versions": [("2.0.0", False)],
                "attempts": [{"stage": "Download", "reason": "HTTP 404"}],
            }
        }
        mismatches = [{"package_name": "com.cert", "version_name": "3.0.0", "old_cert": "aaa", "new_cert": "bbb"}]

        with patch.object(github_release, "apprise", mock_apprise_mod), \
             patch.dict(os.environ, {"APPRISE_URL": "ntfy://topic1 discord://id/tok", "APPRISE_NOTIFY_ON_FAILURE": "true"}):
            github_release.send_apprise_notification(items, "user/builds")
            github_release.send_apprise_failure_notification(failures, mismatches, "user/builds")

        self.assertEqual(mock_apobj.add.call_count, 4)  # 2 URLs * 2 notifications
        self.assertEqual(mock_apobj.notify.call_count, 2)
        succ_body = mock_apobj.notify.call_args_list[0].kwargs["body"]
        fail_body = mock_apobj.notify.call_args_list[1].kwargs["body"]
        self.assertIn("0.9.0 -> 1.0.0", succ_body)
        self.assertIn("com.fail", fail_body)
        self.assertIn("com.cert", fail_body)

    def test_7_hook_signature_compile_and_yaml_validation(self) -> None:
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
        kw_names = {kw.arg for kw in hook_calls[0].keywords}
        self.assertIn("patch_failures", kw_names)

        pycache_dir = self.tmp / "pycache"
        for py_file in (SCRIPTS_DIR / "github_release.py", SCRIPTS_DIR / "main.py", Path(__file__)):
            cfile = pycache_dir / f"{py_file.stem}.pyc"
            cfile.parent.mkdir(parents=True, exist_ok=True)
            py_compile.compile(str(py_file), cfile=str(cfile), doraise=True)

        for yml_rel in ("portainer-compose.yaml", "default_compose.yaml", ".github/workflows/upstream-sync.yaml"):
            parsed = yaml.safe_load((REPO_ROOT / yml_rel).read_text(encoding="utf-8"))
            self.assertIsInstance(parsed, dict)


if __name__ == "__main__":
    unittest.main()

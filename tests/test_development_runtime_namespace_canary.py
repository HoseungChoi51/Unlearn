from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.development_runtime_namespace_canary as namespace_canary
from cbds.development_runtime_bundle import (
    DevelopmentRuntimeExecutable,
    build_development_runtime_bundle_manifest,
)
from cbds.development_runtime_fd_snapshot import (
    snapshot_development_runtime_for_launch,
)
from cbds.development_runtime_materializer import (
    materialize_development_runtime_bundle,
)
from cbds.development_runtime_namespace_canary import (
    DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_PROBE_PATH,
    DevelopmentRuntimeNamespaceCanaryError,
    DevelopmentRuntimeNamespaceCanaryLimits,
    DevelopmentRuntimeNamespaceCanaryResult,
    build_development_runtime_namespace_canary_argv,
    run_development_runtime_namespace_canary,
    verify_development_runtime_namespace_canary_evidence,
)


def _hash_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


class _RuntimeCase:
    def __init__(self, root: Path) -> None:
        busybox = Path(DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_PROBE_PATH)
        if not busybox.is_file():
            raise unittest.SkipTest("the fixed /usr/bin/busybox canary is unavailable")
        self.busybox_sha256 = _hash_file(busybox)
        self.manifest = build_development_runtime_bundle_manifest(
            (
                DevelopmentRuntimeExecutable(
                    name="busybox",
                    source_path=str(busybox),
                    expected_sha256=self.busybox_sha256,
                ),
            ),
            allowed_source_roots=("/usr",),
            library_search_directories=(),
        )
        self.evidence = materialize_development_runtime_bundle(
            self.manifest,
            root / "runtime-root",
            expected_manifest_sha256=self.manifest["manifest_sha256"],
        )
        self.executables: dict[str, str] = {}
        for name in ("systemd-run", "bwrap", "systemctl"):
            path = root / (name + "-fixed")
            path.write_bytes(("fixed test executable: " + name + "\n").encode())
            path.chmod(0o555)
            self.executables[name] = str(path)

    def snapshot(self):
        return snapshot_development_runtime_for_launch(
            self.manifest,
            self.evidence,
            expected_manifest_sha256=self.manifest["manifest_sha256"],
        )

    def install_fake_systemd_script(self, body: str) -> None:
        path = Path(self.executables["systemd-run"])
        path.chmod(0o755)
        path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        path.chmod(0o555)


def _observation(snapshot, *, overrides: dict[str, object] | None = None) -> bytes:
    entry = snapshot.regular_entry(DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_PROBE_PATH)
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "probe_sha256": entry.content_sha256,
        "probe_size": entry.size,
        "probe_mode": f"{entry.mode:o}",
        "probe_uid": 65534,
        "probe_gid": 65534,
        "probe_nlink": 0,
        "probe_chmod_blocked": 1,
        "write_blocked": 1,
        "source_fd_leak_count": 0,
        "root_chmod_blocked": 1,
        "root_chmod_then_write_blocked": 1,
        "root_writable": 0,
        "workspace_writable": 1,
        "non_loopback_interfaces": 0,
        "host_home_visible": 0,
        "host_sys_visible": 0,
    }
    if overrides:
        value.update(overrides)
    return (
        json.dumps(value, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )


def _runner_for(snapshot, *, output: bytes | None = None, capture: dict | None = None):
    expected = _observation(snapshot) if output is None else output

    def runner(argv, **kwargs):
        if capture is not None:
            capture["argv"] = argv
            capture["kwargs"] = kwargs
            openfile_fds: list[int] = []
            for index, item in enumerate(argv):
                if item == "--property" and argv[index + 1].startswith("OpenFile="):
                    match = re.search(r"/fd/([0-9]+):", argv[index + 1])
                    if match is None:
                        raise RuntimeError("missing OpenFile descriptor")
                    descriptor = int(match.group(1))
                    os.fstat(descriptor)
                    openfile_fds.append(descriptor)
            capture["controller_fds"] = tuple(openfile_fds)
        return DevelopmentRuntimeNamespaceCanaryResult(
            returncode=0,
            stdout=expected,
        )

    return runner


class DevelopmentRuntimeNamespaceCanaryTests(unittest.TestCase):
    def test_builder_uses_ordered_openfile_and_ro_bind_data_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot:
                argv = build_development_runtime_namespace_canary_argv(
                    snapshot,
                    controller_pid=12345,
                    controller_regular_fds=(71,),
                    bwrap_controller_fd=72,
                    systemd_run="/usr/bin/systemd-run",
                    unit_name=(
                        "cbds-runtime-ns-canary-v1-"
                        + "1" * 32
                        + ".service"
                    ),
                )

        openfile = argv[argv.index("--property", argv.index("--property") + 1) + 1 :]
        self.assertIn(
            "OpenFile=/proc/12345/fd/71:"
            + snapshot.regular_slots[0].slot_id
            + ":read-only",
            argv,
        )
        del openfile
        bind_index = argv.index("--ro-bind-data")
        self.assertEqual(argv[bind_index + 1], "3")
        self.assertEqual(
            argv[bind_index + 2],
            DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_PROBE_PATH,
        )
        self.assertEqual(argv[bind_index - 2 : bind_index], ("--perms", "0555"))
        self.assertNotIn("--ro-bind-fd", argv)
        self.assertNotIn("--ro-bind", argv)
        self.assertNotIn("--bind", argv)
        self.assertNotIn("/etc/ld.so.cache", argv)
        root_chmod = max(index for index, value in enumerate(argv) if value == "--chmod")
        remount = argv.index("--remount-ro")
        self.assertEqual(argv[root_chmod + 1 : root_chmod + 3], ("0555", "/"))
        self.assertEqual(argv[remount + 1], "/")
        self.assertGreater(remount, root_chmod)
        self.assertEqual(
            argv[-3:],
            (DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_PROBE_PATH, "sh", "-s"),
        )

    def test_high_controller_fds_normalize_to_the_exact_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot:
                limits = DevelopmentRuntimeNamespaceCanaryLimits()
                argv = build_development_runtime_namespace_canary_argv(
                    snapshot,
                    controller_pid=12345,
                    controller_regular_fds=(10,),
                    bwrap_controller_fd=100,
                    systemd_run="/usr/bin/systemd-run",
                    unit_name=(
                        "cbds-runtime-ns-canary-v1-"
                        + "a" * 32
                        + ".service"
                    ),
                    limits=limits,
                )
                bindings = namespace_canary._validate_snapshot_for_canary(
                    snapshot,
                    limits,
                )
                contract = namespace_canary._normalized_launch_contract(
                    argv,
                    bindings,
                )

        self.assertEqual(contract.count("@controller-bwrap-fd"), 1)
        self.assertIn(
            "OpenFile=@controller-runtime-fd:"
            + bindings[0].slot_id
            + ":read-only",
            contract,
        )
        self.assertFalse(any("/proc/12345/fd/" in item for item in contract))

    def test_nonexact_snapshot_inventory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            busybox = Path(DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_PROBE_PATH)
            if not busybox.is_file():
                self.skipTest("the fixed /usr/bin/busybox canary is unavailable")
            copied = root / "not-the-fixed-probe"
            shutil.copyfile(busybox, copied)
            copied.chmod(0o555)
            digest = _hash_file(copied)
            manifest = build_development_runtime_bundle_manifest(
                (
                    DevelopmentRuntimeExecutable(
                        name="wrong-path",
                        source_path=str(copied),
                        expected_sha256=digest,
                    ),
                ),
                allowed_source_roots=(str(root),),
                library_search_directories=(),
            )
            materialization = materialize_development_runtime_bundle(
                manifest,
                root / "wrong-runtime-root",
                expected_manifest_sha256=manifest["manifest_sha256"],
            )
            with snapshot_development_runtime_for_launch(
                manifest,
                materialization,
                expected_manifest_sha256=manifest["manifest_sha256"],
            ) as snapshot:
                with self.assertRaisesRegex(
                    DevelopmentRuntimeNamespaceCanaryError,
                    "inventory is not exact",
                ):
                    build_development_runtime_namespace_canary_argv(
                        snapshot,
                        controller_pid=12345,
                        controller_regular_fds=(10,),
                        bwrap_controller_fd=100,
                        unit_name=(
                            "cbds-runtime-ns-canary-v1-"
                            + "b" * 32
                            + ".service"
                        ),
                    )

    def test_injected_runner_validates_observation_but_cannot_mint_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            captured: dict[str, object] = {}
            with case.snapshot() as snapshot:
                evidence = run_development_runtime_namespace_canary(
                    snapshot,
                    systemd_run=case.executables["systemd-run"],
                    bwrap=case.executables["bwrap"],
                    systemctl=case.executables["systemctl"],
                    runner=_runner_for(snapshot, capture=captured),
                )
                self.assertEqual(
                    evidence.source_snapshot_sha256,
                    snapshot.snapshot_sha256,
                )
                self.assertEqual(evidence.expected_probe_sha256, case.busybox_sha256)
                self.assertTrue(evidence.bounded_probe_observation_validated)
                self.assertFalse(evidence.probe_chmod_blocked_verified)
                self.assertFalse(evidence.payload_write_blocked_verified)
                self.assertFalse(evidence.root_chmod_blocked_verified)
                self.assertFalse(evidence.root_read_only_verified)
                self.assertFalse(evidence.workspace_writable_verified)
                self.assertTrue(evidence.runner_injected)
                self.assertFalse(evidence.systemd_openfile_handoff_verified)
                self.assertFalse(evidence.bubblewrap_ro_bind_data_handoff_verified)
                self.assertFalse(evidence.projected_probe_payload_verified)
                self.assertFalse(evidence.projected_probe_mode_verified)
                self.assertFalse(evidence.fixed_probe_executed)
                self.assertFalse(evidence.externally_trusted_launcher)
                self.assertFalse(evidence.externally_trusted_probe_executable)
                self.assertFalse(evidence.harmless_probe_executed)
                self.assertFalse(evidence.namespace_runtime_closure_verified)
                self.assertTrue(
                    evidence.synthesized_candidate_input_api_absent
                )
                self.assertFalse(evidence.candidate_execution_authorized)
                self.assertFalse(evidence.candidate_executed)
                self.assertFalse(evidence.scored_evaluation_eligible)
                self.assertFalse(evidence.claim_pipeline_eligible)
                self.assertTrue(
                    verify_development_runtime_namespace_canary_evidence(evidence)
                )
                self.assertEqual(
                    evidence.to_record()["evidence_sha256"],
                    evidence.evidence_sha256,
                )
                controller_fds = captured["controller_fds"]
                self.assertIsInstance(controller_fds, tuple)
            for descriptor in controller_fds:  # type: ignore[union-attr]
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_every_security_observation_mismatch_fails_closed(self) -> None:
        mutations: dict[str, object] = {
            "probe_sha256": "0" * 64,
            "probe_size": 0,
            "probe_mode": "755",
            "probe_uid": 0,
            "probe_gid": 0,
            "probe_nlink": 1,
            "probe_chmod_blocked": 0,
            "write_blocked": 0,
            "source_fd_leak_count": 1,
            "root_chmod_blocked": 0,
            "root_chmod_then_write_blocked": 0,
            "root_writable": 1,
            "workspace_writable": 0,
            "non_loopback_interfaces": 1,
            "host_home_visible": 1,
            "host_sys_visible": 1,
        }
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot:
                for name, value in mutations.items():
                    with self.subTest(name=name):
                        runner = _runner_for(
                            snapshot,
                            output=_observation(snapshot, overrides={name: value}),
                        )
                        with self.assertRaisesRegex(
                            DevelopmentRuntimeNamespaceCanaryError,
                            "differs from its contract",
                        ):
                            run_development_runtime_namespace_canary(
                                snapshot,
                                systemd_run=case.executables["systemd-run"],
                                bwrap=case.executables["bwrap"],
                                systemctl=case.executables["systemctl"],
                                runner=runner,
                            )

    def test_malformed_frames_and_failed_results_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot:
                malformed = (
                    b'{"schema_version":"1.0.0","schema_version":"1.0.0"}\n',
                    b'{"probe_size":1.5}\n',
                    _observation(snapshot) + b"{}\n",
                )
                for payload in malformed:
                    with self.subTest(payload=payload[:32]):
                        with self.assertRaises(DevelopmentRuntimeNamespaceCanaryError):
                            run_development_runtime_namespace_canary(
                                snapshot,
                                systemd_run=case.executables["systemd-run"],
                                bwrap=case.executables["bwrap"],
                                systemctl=case.executables["systemctl"],
                                runner=_runner_for(snapshot, output=payload),
                            )

                variants = (
                    DevelopmentRuntimeNamespaceCanaryResult(
                        returncode=None, launch_error=True
                    ),
                    DevelopmentRuntimeNamespaceCanaryResult(
                        returncode=None, timed_out=True
                    ),
                    DevelopmentRuntimeNamespaceCanaryResult(
                        returncode=None, output_truncated=True
                    ),
                    DevelopmentRuntimeNamespaceCanaryResult(returncode=1),
                    DevelopmentRuntimeNamespaceCanaryResult(
                        returncode=0,
                        stdout=_observation(snapshot),
                        stderr=b"diagnostic",
                    ),
                )
                for result in variants:
                    with self.subTest(result=result):
                        with self.assertRaises(DevelopmentRuntimeNamespaceCanaryError):
                            run_development_runtime_namespace_canary(
                                snapshot,
                                systemd_run=case.executables["systemd-run"],
                                bwrap=case.executables["bwrap"],
                                systemctl=case.executables["systemctl"],
                                runner=lambda *_args, _result=result, **_kwargs: _result,
                            )

    def test_authority_forgery_and_active_types_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot:
                evidence = run_development_runtime_namespace_canary(
                    snapshot,
                    systemd_run=case.executables["systemd-run"],
                    bwrap=case.executables["bwrap"],
                    systemctl=case.executables["systemctl"],
                    runner=_runner_for(snapshot),
                )
                for kwargs in (
                    {"systemd_openfile_handoff_verified": True},
                    {"launch_eligible": True},
                    {"candidate_execution_authorized": True},
                    {"claim_pipeline_eligible": True},
                    {"evidence_sha256": "0" * 64},
                ):
                    with self.subTest(kwargs=kwargs):
                        with self.assertRaises(DevelopmentRuntimeNamespaceCanaryError):
                            replace(evidence, **kwargs)
                with self.assertRaises(FrozenInstanceError):
                    evidence.launch_eligible = True  # type: ignore[misc]
                self.assertFalse(
                    verify_development_runtime_namespace_canary_evidence(object())
                )

    def test_rehashed_launch_contract_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot:
                evidence = run_development_runtime_namespace_canary(
                    snapshot,
                    systemd_run=case.executables["systemd-run"],
                    bwrap=case.executables["bwrap"],
                    systemctl=case.executables["systemctl"],
                    runner=_runner_for(snapshot),
                )

        forged = object.__new__(type(evidence))
        for name in evidence.__dataclass_fields__:
            object.__setattr__(forged, name, getattr(evidence, name))
        contract = list(evidence.launch_contract_argv)
        clearenv = contract.index("--clearenv")
        contract[clearenv] = "--share-net"
        mutated = tuple(contract)
        object.__setattr__(forged, "launch_contract_argv", mutated)
        object.__setattr__(
            forged,
            "launch_contract_sha256",
            sha256(
                namespace_canary.canonical_development_runtime_json_bytes(
                    list(mutated)
                )
            ).hexdigest(),
        )
        object.__setattr__(forged, "evidence_sha256", "0" * 64)
        object.__setattr__(
            forged,
            "evidence_sha256",
            namespace_canary._compute_evidence_sha256(forged),
        )

        with self.assertRaisesRegex(
            DevelopmentRuntimeNamespaceCanaryError,
            "exact fixed template",
        ):
            namespace_canary._validate_evidence(forged)
        self.assertFalse(
            verify_development_runtime_namespace_canary_evidence(forged)
        )

    def test_rehashed_extra_binding_cannot_mint_fixed_inventory_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot:
                evidence = run_development_runtime_namespace_canary(
                    snapshot,
                    systemd_run=case.executables["systemd-run"],
                    bwrap=case.executables["bwrap"],
                    systemctl=case.executables["systemctl"],
                    runner=_runner_for(snapshot),
                )

        extra = namespace_canary.DevelopmentRuntimeNamespaceBinding(
            ordinal=1,
            service_fd=4,
            slot_id="slot-" + "f" * 24,
            destination_path="/usr/bin/extra",
            mode=0o555,
            size=1,
            content_sha256="f" * 64,
        )
        bindings = evidence.bindings + (extra,)
        contract = namespace_canary._build_launch_argv_from_bindings(
            bindings,
            systemd_run=evidence.systemd_run_path,
            unit_name=evidence.unit_name,
            limits=evidence.limits,
            openfile_sources=(
                "@controller-runtime-fd",
                "@controller-runtime-fd",
            ),
            bwrap_executable="@controller-bwrap-fd",
        )
        forged = object.__new__(type(evidence))
        for name in evidence.__dataclass_fields__:
            object.__setattr__(forged, name, getattr(evidence, name))
        object.__setattr__(forged, "bindings", bindings)
        object.__setattr__(
            forged,
            "binding_index_sha256",
            namespace_canary._binding_index_sha256(bindings),
        )
        object.__setattr__(forged, "launch_contract_argv", contract)
        object.__setattr__(
            forged,
            "launch_contract_sha256",
            sha256(
                namespace_canary.canonical_development_runtime_json_bytes(
                    list(contract)
                )
            ).hexdigest(),
        )
        object.__setattr__(forged, "evidence_sha256", "0" * 64)
        object.__setattr__(
            forged,
            "evidence_sha256",
            namespace_canary._compute_evidence_sha256(forged),
        )

        with self.assertRaisesRegex(
            DevelopmentRuntimeNamespaceCanaryError,
            "evidence bindings are invalid",
        ):
            namespace_canary._validate_evidence(forged)
        self.assertFalse(
            verify_development_runtime_namespace_canary_evidence(forged)
        )

    def test_fixed_api_has_no_candidate_or_command_input(self) -> None:
        run_parameters = inspect.signature(
            run_development_runtime_namespace_canary
        ).parameters
        self.assertEqual(
            tuple(run_parameters),
            ("snapshot", "limits", "systemd_run", "bwrap", "systemctl", "runner"),
        )
        build_parameters = inspect.signature(
            build_development_runtime_namespace_canary_argv
        ).parameters
        forbidden = {"candidate", "program", "command", "argv", "stdin", "fixture"}
        self.assertFalse(forbidden & set(run_parameters))
        self.assertFalse(forbidden & set(build_parameters))

    def test_closed_snapshot_and_probe_source_mutation_fail_before_runner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            snapshot = case.snapshot()
            snapshot.close()
            with self.assertRaisesRegex(
                DevelopmentRuntimeNamespaceCanaryError,
                "already closed",
            ):
                run_development_runtime_namespace_canary(
                    snapshot,
                    systemd_run=case.executables["systemd-run"],
                    bwrap=case.executables["bwrap"],
                    systemctl=case.executables["systemctl"],
                    runner=lambda *_args, **_kwargs: self.fail("runner called"),
                )

            with case.snapshot() as live, mock.patch.object(
                namespace_canary,
                "_FIXED_PROBE_SOURCE",
                namespace_canary._FIXED_PROBE_SOURCE + "\n# changed\n",
            ), mock.patch.object(
                namespace_canary,
                "_open_pinned_executable",
                side_effect=AssertionError("executable opened"),
            ):
                with self.assertRaisesRegex(
                    DevelopmentRuntimeNamespaceCanaryError,
                    "differs from its import-time digest",
                ):
                    run_development_runtime_namespace_canary(live)

    def test_limits_and_descriptor_table_fail_closed(self) -> None:
        for kwargs in (
            {"timeout_seconds": True},
            {"kill_grace_seconds": 11.0},
            {"open_files": 31},
            {"uid": 0},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    DevelopmentRuntimeNamespaceCanaryLimits(**kwargs)
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot:
                for descriptors in ((), (2,), (4, 4), ("4",)):
                    with self.subTest(descriptors=descriptors):
                        with self.assertRaises(DevelopmentRuntimeNamespaceCanaryError):
                            build_development_runtime_namespace_canary_argv(
                                snapshot,
                                controller_pid=12345,
                                controller_regular_fds=descriptors,  # type: ignore[arg-type]
                                bwrap_controller_fd=72,
                                unit_name=(
                                    "cbds-runtime-ns-canary-v1-"
                                    + "2" * 32
                                    + ".service"
                                ),
                            )
                with self.assertRaisesRegex(
                    DevelopmentRuntimeNamespaceCanaryError,
                    "Bubblewrap controller descriptor",
                ):
                    build_development_runtime_namespace_canary_argv(
                        snapshot,
                        controller_pid=12345,
                        controller_regular_fds=(71,),
                        bwrap_controller_fd=2,
                        unit_name=(
                            "cbds-runtime-ns-canary-v1-"
                            + "2" * 32
                            + ".service"
                        ),
                    )

    def test_noninjected_fake_launcher_cannot_mint_verified_facts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot:
                output = _observation(snapshot).decode("utf-8")
                case.install_fake_systemd_script(
                    "/usr/bin/cat >/dev/null\n"
                    + "/usr/bin/printf %s "
                    + shlex.quote(output)
                    + "\n"
                )
                evidence = run_development_runtime_namespace_canary(
                    snapshot,
                    systemd_run=case.executables["systemd-run"],
                    bwrap=case.executables["bwrap"],
                    systemctl=case.executables["systemctl"],
                )

        self.assertFalse(evidence.runner_injected)
        self.assertTrue(evidence.default_runner_invoked)
        self.assertTrue(evidence.bounded_probe_observation_validated)
        self.assertTrue(evidence.synthesized_candidate_input_api_absent)
        self.assertTrue(evidence.only_fixed_probe_payload_present)
        for name in (
            "payload_write_blocked_verified",
            "probe_chmod_blocked_verified",
            "activation_fds_closed_verified",
            "root_chmod_blocked_verified",
            "root_read_only_verified",
            "workspace_writable_verified",
            "no_non_loopback_interfaces_verified",
            "host_home_absent_verified",
            "host_sys_absent_verified",
            "systemd_openfile_handoff_verified",
            "bubblewrap_ro_bind_data_handoff_verified",
            "projected_probe_payload_verified",
            "projected_probe_mode_verified",
            "fixed_probe_executed",
            "externally_trusted_launcher",
            "externally_trusted_probe_executable",
            "harmless_probe_executed",
        ):
            with self.subTest(name=name):
                self.assertFalse(getattr(evidence, name))
        self.assertTrue(
            verify_development_runtime_namespace_canary_evidence(evidence)
        )

    def test_internal_runner_timeout_and_overflow_are_classified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot:
                case.install_fake_systemd_script(
                    "/usr/bin/cat >/dev/null\n/usr/bin/sleep 5\n"
                )
                with self.assertRaisesRegex(
                    DevelopmentRuntimeNamespaceCanaryError,
                    "timed out",
                ):
                    run_development_runtime_namespace_canary(
                        snapshot,
                        limits=DevelopmentRuntimeNamespaceCanaryLimits(
                            timeout_seconds=0.05,
                            kill_grace_seconds=0.05,
                        ),
                        systemd_run=case.executables["systemd-run"],
                        bwrap=case.executables["bwrap"],
                        systemctl=case.executables["systemctl"],
                    )

                case.install_fake_systemd_script(
                    "/usr/bin/cat >/dev/null\n"
                    "/usr/bin/head -c 4096 /dev/zero\n"
                )
                with self.assertRaisesRegex(
                    DevelopmentRuntimeNamespaceCanaryError,
                    "output bound",
                ):
                    run_development_runtime_namespace_canary(
                        snapshot,
                        limits=DevelopmentRuntimeNamespaceCanaryLimits(
                            max_output_bytes=64,
                        ),
                        systemd_run=case.executables["systemd-run"],
                        bwrap=case.executables["bwrap"],
                        systemctl=case.executables["systemctl"],
                    )

    def test_selector_setup_exception_terminates_and_reaps_process(self) -> None:
        launched = []
        original_popen = namespace_canary.subprocess.Popen

        def recording_popen(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            launched.append(process)
            return process

        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            case.install_fake_systemd_script(
                "/usr/bin/cat >/dev/null\n/usr/bin/sleep 5\n"
            )
            with case.snapshot() as snapshot, mock.patch.object(
                namespace_canary.subprocess,
                "Popen",
                side_effect=recording_popen,
            ), mock.patch.object(
                namespace_canary.selectors,
                "DefaultSelector",
                side_effect=RuntimeError("selector setup failed"),
            ):
                with self.assertRaisesRegex(
                    DevelopmentRuntimeNamespaceCanaryError,
                    "runner failed closed",
                ):
                    run_development_runtime_namespace_canary(
                        snapshot,
                        limits=DevelopmentRuntimeNamespaceCanaryLimits(
                            timeout_seconds=0.2,
                            kill_grace_seconds=0.05,
                        ),
                        systemd_run=case.executables["systemd-run"],
                        bwrap=case.executables["bwrap"],
                        systemctl=case.executables["systemctl"],
                    )
        self.assertGreaterEqual(len(launched), 1)
        self.assertIsNotNone(launched[0].poll())

    def test_selector_read_exception_terminates_and_reaps_process(self) -> None:
        launched = []
        original_popen = namespace_canary.subprocess.Popen
        original_selector = namespace_canary.selectors.DefaultSelector

        def recording_popen(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            launched.append(process)
            return process

        class FailingSelect:
            def __init__(self) -> None:
                self._inner = original_selector()

            def register(self, *args, **kwargs):
                return self._inner.register(*args, **kwargs)

            def select(self, _timeout=None):
                raise RuntimeError("selector read failed")

            def get_map(self):
                return self._inner.get_map()

            def unregister(self, *args, **kwargs):
                return self._inner.unregister(*args, **kwargs)

            def close(self) -> None:
                self._inner.close()

        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            case.install_fake_systemd_script(
                "/usr/bin/cat >/dev/null\n/usr/bin/sleep 5\n"
            )
            with case.snapshot() as snapshot, mock.patch.object(
                namespace_canary.subprocess,
                "Popen",
                side_effect=recording_popen,
            ), mock.patch.object(
                namespace_canary.selectors,
                "DefaultSelector",
                FailingSelect,
            ):
                with self.assertRaisesRegex(
                    DevelopmentRuntimeNamespaceCanaryError,
                    "runner failed closed",
                ):
                    run_development_runtime_namespace_canary(
                        snapshot,
                        limits=DevelopmentRuntimeNamespaceCanaryLimits(
                            timeout_seconds=0.2,
                            kill_grace_seconds=0.05,
                        ),
                        systemd_run=case.executables["systemd-run"],
                        bwrap=case.executables["bwrap"],
                        systemctl=case.executables["systemctl"],
                    )
        self.assertGreaterEqual(len(launched), 1)
        self.assertIsNotNone(launched[0].poll())

    def test_module_has_no_assert_dependent_safety_checks(self) -> None:
        source = Path(namespace_canary.__file__).read_text(encoding="utf-8")
        self.assertNotIn("assert ", source)


if __name__ == "__main__":
    unittest.main()

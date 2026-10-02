#!/usr/bin/env python3
# ============================================================================
#  scanners.py — Phase 3 scanner adapter layer + profile registry.
#  ---------------------------------------------------------------------------
#  Static allowlist of profiles actually supported by the current codebase.
#  A user-supplied profile name that is not in the registry is rejected —
#  there is NO dynamic module loading, NO arbitrary code execution.
#
#  Adapters orchestrate the EXISTING scanners:
#    - argv is ALWAYS an argument array, shell=False (no shell interpolation)
#    - targets come from validated job payloads (jobs.validate_payload)
#    - bounded stdout/stderr capture (truncation flagged, never silent)
#    - bounded timeout with controlled terminate → escalate
#    - output JSON is bounded before parsing; redaction happens downstream in
#      platform evidence/normalization (single source of truth)
# ============================================================================

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time

import errors
import store

PY = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(PY)
RUST_DIR = os.path.join(ROOT, "rust")

MAX_STDOUT = 1_000_000        # ~1 MiB of captured output per stage
MAX_STDERR = 200_000          # ~200 KiB
MAX_JSON = 4_000_000          # ~4 MiB result JSON parsed per stage
TERMINATE_GRACE = 5.0         # seconds between SIGTERM and SIGKILL


class Profile:
    """One static scanner profile."""

    def __init__(self, name: str, description: str, stages: list,
                 active_required: bool = False, timeout: int = 300,
                 permissions_required: tuple = ("scan.create",),
                 in_process: bool = False):
        self.name = name
        self.description = description
        self.stages = tuple(stages)
        self.active_required = active_required
        self.timeout = int(timeout)
        self.permissions_required = tuple(permissions_required)
        # Phase 9: in-process profiles run inside the worker (no subprocess,
        # no shell). They may never be invoked as external argv.
        self.in_process = bool(in_process)

    def to_dict(self) -> dict:
        return {"name": self.name, "description": self.description,
                "stages": list(self.stages),
                "active_required": self.active_required,
                "timeout": self.timeout,
                "permissions_required": list(self.permissions_required),
                "in_process": self.in_process}


class ScannerRegistry:
    """Static profile allowlist — the ONLY profile source in the platform."""

    def __init__(self):
        self.PROFILES: dict[str, Profile] = {}
        self._register()

    def _add(self, profile: Profile):
        self.PROFILES[profile.name] = profile

    def _register(self):
        self._add(Profile(
            "web-audit", "Full web security audit (SecuAudit)", ["web_audit"],
            timeout=240))
        self._add(Profile(
            "api-audit", "OWASP API Top 10 audit (SecuAudit API)",
            ["api_audit"], timeout=180))
        self._add(Profile(
            "template-scan", "Nucleus YAML template engine scan",
            ["template"], timeout=300))
        self._add(Profile(
            "crawler", "Endpoint discovery (SecuSpider)", ["crawl"],
            timeout=240))
        self._add(Profile(
            "waf-detect", "WAF fingerprinting (WallFinder)", ["waf"],
            timeout=120))
        self._add(Profile(
            "recon", "Passive subdomain enumeration (SubKraken)", ["recon"],
            timeout=300))
        self._add(Profile(
            "cloud-check", "Cloud/DB exposure checks (CloudScope)",
            ["cloud"], timeout=180))
        self._add(Profile(
            "active-fuzz", "ACTIVE payload fuzzing (Injector) — authorized "
            "targets only", ["active"], active_required=True, timeout=300))
        self._add(Profile(
            "port-scan", "Fast TCP port scan (Rust back-end)", ["port"],
            timeout=120))
        self._add(Profile(
            "dir-fuzz", "Directory fuzzing (Rust back-end, passive wordlist)",
            ["fuzz"], timeout=180))
        self._add(Profile(
            "full-assessment", "One-command assessment chain (workflow.py: "
            "recon→probe→waf→crawl→template→[active]) — checkpointed as a "
            "single stage; add --active for the active stage", ["workflow"],
            timeout=1800))
        # ------------------------------------------------------ Phase 9
        # In-process profiles: no subprocess/shell. Worker (worker.py)
        # dispatches these to the Phase-9 services; results persist through
        # the EXISTING asset/finding/evidence pipeline.
        self._add(Profile(
            "cloud-scan", "Cloud account inventory + CLOUD rule assessment "
            "(in-process; fixture/aws/azure/gcp providers)", ["cloud_assess"],
            timeout=300, in_process=True))
        self._add(Profile(
            "cloud-inventory", "Cloud account inventory refresh "
            "(in-process; no assessment)", ["cloud_inventory"],
            timeout=300, in_process=True))
        self._add(Profile(
            "container-scan", "Container image assessment (digest identity; "
            "supplied package/CVE inventory, in-process)",
            ["container_assess"], timeout=300, in_process=True))
        self._add(Profile(
            "kubernetes-scan", "Kubernetes declarative manifest assessment "
            "(in-process; bounded YAML, secret metadata only)",
            ["k8s_assess"], timeout=300, in_process=True))
        self._add(Profile(
            "iac-scan", "Infrastructure-as-Code assessment (Terraform/CFN; "
            "in-process; secrets always redacted)", ["iac_assess"],
            timeout=300, in_process=True))
        self._add(Profile(
            "posture-snapshot", "Project security posture snapshot from "
            "existing findings + risk engine (in-process; no new stores)",
            ["posture_snapshot"], timeout=120, in_process=True))
        # ------------------------------------------------------ Phase 12
        # Federation bulk operations: bounded, checkpointed orchestration
        # of bulk export/import/classify/retention-preview through the
        # EXISTING Phase-3 job engine (in-process; no subprocess/shell;
        # bulk material is staged on the scan record, never the payload).
        self._add(Profile(
            "federation-bulk", "Federation bulk operation (in-process; "
            "chunked export/import/classify/retention-preview with "
            "checkpoints, pause/resume/cancel and bounded concurrency)",
            ["federation_bulk"], timeout=1800, in_process=True,
            permissions_required=("federation.bulk",)))
        # Phase 13 integration deliveries: bounded outbound provider
        # deliveries through the SAME job engine (in-process; no
        # subprocess/shell; the delivery envelope is staged on the scan
        # record, never in the scalar-only payload; retry taxonomy,
        # backoff, leases, cancel and dead-letter belong to the engine).
        self._add(Profile(
            "integration-delivery", "Integration delivery (in-process; "
            "one bounded outbound provider delivery attempt per job with "
            "the existing retry taxonomy, backoff, heartbeat, cancel and "
            "dead-letter semantics)",
            ["integration_delivery"], timeout=300, in_process=True,
            permissions_required=("integration.send",)))

    @property
    def ACTIVE_PROFILES(self) -> frozenset:
        return frozenset(p.name for p in self.PROFILES.values()
                         if p.active_required)

    @property
    def IN_PROCESS_PROFILES(self) -> frozenset:
        return frozenset(p.name for p in self.PROFILES.values()
                         if p.in_process)

    def validate_profile(self, name: str) -> str:
        n = str(name or "").strip()
        if n not in self.PROFILES:
            raise errors.ValidationError(
                f"profile_unknown: unknown scanner profile {n!r}")
        return n

    def get(self, name: str) -> Profile:
        return self.PROFILES[self.validate_profile(name)]

    def list_profiles(self):
        return [p.to_dict() for p in sorted(self.PROFILES.values(),
                                            key=lambda p: p.name)]

    def build_argv(self, profile: str, target: str, payload: dict,
                   workdir: str, timeout: float) -> list[str]:
        """Strict argv construction (argument array, shell never involved).
        In-process (Phase 9) profiles have no external adapter — attempting
        argv construction for one is an explicit error, never silent."""
        p = self.get(profile)
        if p.in_process:
            raise errors.ValidationError(
                f"profile_in_process: {profile!r} runs inside the worker "
                f"(no external adapter)")
        result_path = os.path.join(workdir, "result.json")
        if profile == "cloud-check":
            return [sys.executable, os.path.join(PY, "cloud_check.py")] + \
                self._cloud_argv(target, payload, result_path, timeout)
        py = {
            "web-audit": ["--url", target, "--out",
                          os.path.join(workdir, "report.html"),
                          "--json", result_path, "--timeout", str(timeout)],
            "api-audit": ["--url", target, "--json", result_path,
                          "--timeout", str(timeout)],
            "template-scan": ["--target", target, "--out", result_path,
                              "--timeout", str(timeout)],
            "crawler": ["--url", target, "--depth",
                        str(int(payload.get("depth", 1))),
                        "--limit", str(int(payload.get("limit", 40))),
                        "--out", result_path, "--timeout", str(timeout)],
            "waf-detect": ["--url", target, "--json", result_path,
                           "--timeout", str(timeout)],
            "recon": ["--domain", target, "--out", result_path,
                      "--threads", str(int(payload.get("threads", 50))),
                      "--timeout", str(min(float(timeout), 30))],
            "active-fuzz": ["--url", target, "--max",
                            str(int(payload.get("max", 10))),
                            "--delay", "1.0", "--timeout", str(timeout),
                            "--out", result_path],
        }
        if profile in py:
            return [sys.executable,
                    os.path.join(PY, self._script(profile))] + py[profile]
        if profile == "port-scan":
            ports = str(payload.get("ports", ""))
            argv = [os.path.join(RUST_DIR, "port_scanner"), target,
                    "--top", "100", "--threads", "400",
                    "--timeout", str(int(min(timeout, 120) * 1000))]
            if ports and _safe_ports(ports):
                argv = [os.path.join(RUST_DIR, "port_scanner"), target,
                        ports, "--threads", "400",
                        "--timeout", str(int(min(timeout, 120) * 1000))]
            return argv
        if profile == "dir-fuzz":
            return [os.path.join(RUST_DIR, "dir_fuzzer"), target]
        if profile == "workflow":
            import hashlib as _h
            client = "job_" + _h.sha1(target.encode("utf-8")).hexdigest()[:8]
            return [os.path.join(PY, "workflow.py"), "--domain", target,
                    "--client", client, "--threads",
                    str(int(payload.get("threads", 30))),
                    "--timeout", str(min(float(timeout), 30)),
                    "--max-hosts", "20", "--depth", "1"]
        raise errors.ValidationError(
            f"profile_unknown: no adapter for {profile!r}")

    @staticmethod
    def _script(name: str) -> str:
        return {
            "web-audit": "web_security_audit.py",
            "api-audit": "api_security_audit.py",
            "template-scan": "template_engine.py",
            "crawler": "spider.py",
            "waf-detect": "waf_detect.py",
            "recon": "subdomain_enum.py",
            "cloud-check": "cloud_check.py",
            "active-fuzz": "active_fuzzer.py",
            "workflow": "workflow.py",
        }[name]

    @staticmethod
    def _cloud_argv(target, payload, result_path, timeout):
        if payload.get("bucket"):
            return ["--bucket", target, "--out", result_path,
                    "--timeout", str(min(float(timeout), 30))]
        if payload.get("service"):
            return ["--service", target, "--out", result_path,
                    "--timeout", str(min(float(timeout), 30))]
        raise errors.ValidationError(
            "payload_rejected: cloud-check requires bucket or service")

    def capture_output(self, argv: list[str], timeout: float, poll=None):
        """Run one stage command:
        - argv array + shell=False (no shell interpretation, ever)
        - timeout → controlled terminate → grace → escalate to kill
        - `poll` (optional callable) is checked at safe checkpoints: when it
          returns 'cancelling' the subprocess is terminated in a controlled
          way and WorkerStopped propagates — no blind kill, no zombies
        - stdout/stderr bounded; truncation flagged, never silent
        - returns (returncode, stdout_text, stderr_text, truncated)
        """
        try:
            proc = subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=False, start_new_session=False)
        except FileNotFoundError as e:
            raise errors.ScannerError(
                f"config_invalid: cannot execute {argv[0]}: {e}") from e
        state = {"out": b"", "err": b"", "out_trunc": False,
                 "err_trunc": False}
        t1 = threading.Thread(target=self._pump,
                              args=(proc.stdout, MAX_STDOUT, state,
                                    "out_trunc"), daemon=True)
        t2 = threading.Thread(target=self._pump,
                              args=(proc.stderr, MAX_STDERR, state,
                                    "err_trunc"), daemon=True)
        t1.start()
        t2.start()
        deadline = time.monotonic() + float(timeout)
        rc = None
        while True:
            rc = proc.poll()
            if rc is not None:
                break
            if poll is not None and poll() == "cancelling":
                self._terminate(proc, t1, t2)
                raise WorkerStopped("cancelled at checkpoint")
            if time.monotonic() >= deadline:
                self._terminate(proc, t1, t2)
                raise errors.ScannerError(
                    "timeout: scanner exceeded its time budget")
            time.sleep(0.5)
        t1.join(timeout=5)
        t2.join(timeout=5)
        return (rc, state["out"].decode("utf-8", "replace"),
                state["err"].decode("utf-8", "replace"),
                (state["out_trunc"] or state["err_trunc"]))

    @staticmethod
    def _terminate(proc, t1, t2):
        proc.terminate()                     # controlled: grace period first
        try:
            proc.wait(timeout=TERMINATE_GRACE)
        except subprocess.TimeoutExpired:
            proc.kill()                      # escalation — not blind first
            proc.wait(timeout=5)
        t1.join(timeout=2)
        t2.join(timeout=2)

    @staticmethod
    def _pump(stream, cap, state, flag):
        data = bytearray()
        with stream:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                room = cap - len(data)
                if room > 0:
                    data.extend(chunk[:room])
                if len(chunk) > room:
                    state[flag] = True
        state["out" if flag == "out_trunc" else "err"] = bytes(data)

    def read_json_result(self, workdir: str, path: str = "result.json"):
        """Bounded JSON read. Truncation/size violations are surfaced as
        errors — JSON is never silently corrupted."""
        p = os.path.join(workdir, path)
        if not os.path.isfile(p):
            return None
        size = os.path.getsize(p)
        if size > MAX_JSON:
            raise errors.ScannerError(
                "validation_rejected: result JSON too large "
                f"({size} bytes)")
        with open(p, "rb") as fh:
            raw = fh.read(MAX_JSON + 1)
        if len(raw) > MAX_JSON:
            raise errors.ScannerError(
                "validation_rejected: result JSON exceeds bound")
        try:
            return json.loads(raw.decode("utf-8", "strict"))
        except Exception as e:
            raise errors.ScannerError(
                f"malformed_output: invalid JSON from scanner ({e})"
            ) from e


def _safe_ports(spec: str) -> bool:
    """Port lists must match 1-65535 numbers/commas/ranges — used verbatim
    as a single argv element (no shell), validated defensively."""
    import re as _re
    if len(spec) > 200:
        return False
    return bool(_re.fullmatch(r"[0-9,\-]{1,200}", spec))


REGISTRY = ScannerRegistry()

#!/usr/bin/env python3
# ============================================================================
#  Phase-12 suite — enterprise data federation / evidence exchange / bulk
#  operations / external integration governance: peer trust lifecycle
#  (pending -> active, separation of duties on approval, terminal
#  revocation, expiry fail-closed), exchange policies (classification +
#  field gates, secret/authentication_material never exportable without an
#  explicit decision), deterministic provider-neutral packages (canonical
#  sha256 integrity, tamper rejection), the 12-gate inbound validation
#  chain, provenance-preserving imports through the EXISTING finding/asset/
#  evidence/case/IOC pipelines (dedup, collision strategies, idempotent
#  re-import), bulk operations through the EXISTING Phase-3 job engine
#  (checkpoints, cancel, non-retryable refusals), the controlled external
#  integration boundary (redacted, bounded, audited events), RBAC (viewers
#  and analysts get NOTHING), tenant isolation, audit-chain integrity,
#  dashboard/API panels, CLI smoke, failure injection, concurrency and
#  bounded scale. Fully offline, deterministic, temp SQLite per test class.
# ============================================================================
from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import shutil
import runpy
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = os.path.join(ROOT, "python")
sys.path.insert(0, PY)
sys.path.insert(0, HERE)

import errors
import models
import notify
import platform_service as pf
import rbac
import store

import federation as fed
import dashboard as dbmod
import jobs as jobs_mod
import scanners as scanners_mod
import worker as worker_mod


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
class FedBase(unittest.TestCase):
    """Two tenants (A exports, B imports) with an approved bidirectional
    peer pair and active policies on both sides."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="p12t_")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.db_path = os.path.join(self.dir, "t.db")
        self.svc = pf.PlatformService(self.db_path)
        self.provider_a = notify.RecordingProvider()
        self.provider_b = notify.RecordingProvider()
        self.A = fed.FederationService(self.svc, provider=self.provider_a)
        self.B = fed.FederationService(self.svc, provider=self.provider_b)
        self.orgA = self.svc.org_create("OrgA")
        self.orgB = self.svc.org_create("OrgB")
        self.pA = self.svc.project_create(self.orgA.id, "CoreA")
        self.pB = self.svc.project_create(self.orgB.id, "CoreB")
        self.peerA = self.A.peers.create(
            self.orgA.id, peer_org_id=self.orgB.id, name="peer-to-b",
            purpose="evidence exchange", direction="bidirectional",
            actor="alice")
        self.peerA = self.A.peers.approve(
            self.orgA.id, self.peerA["id"], approved_by="bob", actor="bob")
        self.peerB = self.B.peers.create(
            self.orgB.id, peer_org_id=self.orgA.id, name="peer-from-a",
            direction="bidirectional", actor="carol")
        self.peerB = self.B.peers.approve(
            self.orgB.id, self.peerB["id"], approved_by="dave",
            actor="dave")
        self.polA = self.A.policies.create(
            self.orgA.id, peer_id=self.peerA["id"], name="policy-export-a",
            project_id=self.pA.id,
            object_types=["asset", "finding", "evidence"],
            classifications=["public", "internal", "confidential"],
            max_objects=500, actor="alice")
        self.polB = self.B.policies.create(
            self.orgB.id, peer_id=self.peerB["id"], name="policy-import-b",
            project_id=self.pB.id,
            object_types=["asset", "finding", "evidence"],
            classifications=["public", "internal", "confidential"],
            max_objects=500, actor="carol")

    # ------------------------------------------------------------ seeding
    def seed_a(self, n_findings=1, with_evidence=True):
        scan = self.svc.scan_create(self.pA.id, "web-audit")
        asset = self.svc.asset_add(self.pA.id, "hostname",
                                   "shop.example.com")
        finding_ids = []
        for i in range(n_findings):
            f = models.Finding(
                scan_id=scan.id, project_id=self.pA.id, asset_id=asset.id,
                title=f"SQL injection variant {i} in /item",
                description=f"d{i}", severity="High", category="sqli",
                source="SecuAudit", rule_id=f"sqli-{i}",
                raw={"parameter": "id", "endpoint": "/item"})
            self.svc.finding_ingest(f)
            if with_evidence:
                self.svc.evidence_add(
                    f.id, evidence_type="log", url="http://x/item?id=1",
                    response_snippet="SQL syntax error",
                    detection_reason="error-based")
            finding_ids.append(f.id)
        return scan, asset, finding_ids

    def build(self, **kw):
        kw.setdefault("actor", "alice")
        return self.A.packages.build(
            self.orgA.id, peer_id=self.peerA["id"],
            policy_id=self.polA["id"], project_id=self.pA.id, **kw)

    def unique_env(self, tag, **kw):
        """A structurally valid envelope whose hash differs from every
        other (distinct provenance.created_by) — for re-import tests."""
        env = self.build(**kw)["envelope"]
        env["provenance"]["created_by"] = str(tag)
        env["integrity"]["hash"] = fed.package_hash(env)
        return env

    def assertRejected(self, env, code, *, org=None, project=None, **kw):
        kw.setdefault("actor", "carol")
        with self.assertRaises(errors.ValidationError) as cm:
            self.B.imports.import_envelope(
                org or self.orgB.id, envelope=env,
                target_project_id=project or self.pB.id, **kw)
        self.assertIn("import_rejected: " + code, str(cm.exception))
        return str(cm.exception)

    def run_jobs(self, n=1, worker_id="w-fed"):
        js = jobs_mod.JobService(self.svc, scanners_mod.ScannerRegistry())
        rt = worker_mod.WorkerRuntime(self.svc, None, js,
                                      scanners_mod.ScannerRegistry(),
                                      worker_id=worker_id,
                                      heartbeat_interval=0.5)
        rt.run_forever(max_jobs=n)
        return js

    def db_count(self, sql, args=()):
        return int(self.svc.db.query_one(sql, args)["n"])


# ---------------------------------------------------------------------------
# 1. Vocabulary / schema / registry wiring (extension, never duplication)
# ---------------------------------------------------------------------------
class VocabularySchemaTests(FedBase):
    def test_peer_status_vocabulary_exact(self):
        self.assertEqual(
            tuple(models.FEDERATION_PEER_STATUSES),
            ("pending", "active", "suspended", "expired", "revoked"))

    def test_peer_transition_table_is_closed(self):
        t = models.FEDERATION_PEER_TRANSITIONS
        self.assertEqual(t["pending"], {"active", "revoked"})
        self.assertEqual(t["expired"], {"pending"})   # re-request only
        self.assertEqual(t["revoked"], set())         # terminal

    def test_schema_version_and_vocabulary(self):
        self.assertEqual(models.FEDERATION_SCHEMA_VERSION, "fed-package-v1")
        self.assertEqual(
            set(models.FEDERATION_IMPORTABLE_TYPES),
            {"asset", "finding", "evidence", "case", "threat_intel_match"})
        self.assertEqual(
            set(models.FEDERATION_SENSITIVE_BY_DEFAULT),
            {"secret", "authentication_material"})
        self.assertEqual(
            set(models.FEDERATION_COLLISION_STRATEGIES),
            {"skip", "link", "merge_metadata", "reject"})
        self.assertEqual(
            set(models.FEDERATION_TRUST_MODES),
            {"unsigned", "integrity_verified", "externally_signed"})
        self.assertIn("in_progress", models.FEDERATION_IMPORT_STATUSES)
        self.assertEqual(
            set(models.BULK_OPERATIONS),
            {"bulk_export", "bulk_import", "bulk_classify",
             "bulk_retention_preview"})
        self.assertEqual(
            set(models.INTEGRATION_KINDS),
            {"siem_export", "ticketing_export", "data_lake_export",
             "grc_ingestion", "webhook"})

    def test_schema_v15_preserves_v14_tables_with_unique_claims(self):
        # Phase 13 advanced the schema to v15 (integration pipeline tables);
        # the v14 tables and constraints asserted here are unchanged.
        v = self.svc.db.query_one(
            "SELECT MAX(version) v FROM schema_version")
        self.assertEqual(int(v["v"]), 15)
        for table in ("federation_peers", "federation_policies",
                      "federation_packages", "federation_imports",
                      "external_integrations", "integration_events"):
            rows = self.svc.db.query(
                "SELECT sql FROM sqlite_master WHERE type='table' "
                "AND name=?", (table,))
            self.assertTrue(rows, f"missing table {table}")
        # import idempotency claim: UNIQUE(org_id, package_hash)
        sql = self.svc.db.query(
            "SELECT sql FROM sqlite_master WHERE type='table' AND "
            "name='federation_imports'")[0]["sql"]
        self.assertIn("UNIQUE(org_id, package_hash)", sql)

    def test_event_and_audit_vocabularies_extended(self):
        for ev in ("federation.peer_created", "federation.peer_revoked",
                   "federation.package_created",
                   "federation.package_imported",
                   "federation.integrity_failure", "bulk.started",
                   "bulk.completed", "bulk.failed", "integration.created",
                   "integration.delivered", "integration.failed"):
            self.assertIn(ev, models.EVENT_TYPES, ev)
        for act in ("federation.peer.created", "federation.peer.approved",
                    "federation.peer.revoked", "federation.policy.created",
                    "federation.package.created",
                    "federation.package.imported",
                    "federation.package.rejected",
                    "federation.integrity_failure",
                    "federation.bulk.started", "integration.created",
                    "integration.emitted"):
            self.assertIn(act, models.AuditEvent.ACTIONS, act)

    def test_metrics_registry_extended(self):
        import metrics
        for name in ("federation_peers_created",
                     "federation_packages_created",
                     "federation_packages_imported",
                     "federation_imports_rejected",
                     "federation_integrity_failures",
                     "federation_bulk_jobs",
                     "federation_integrations_created",
                     "federation_integration_events",
                     "federation_audit_failures"):
            metrics.inc(name, 0)     # raises KeyError when unregistered

    def test_bulk_profile_registered_in_process(self):
        reg = scanners_mod.ScannerRegistry()
        prof = reg.get("federation-bulk")
        self.assertTrue(prof.in_process)
        self.assertIn("federation-bulk", reg.IN_PROCESS_PROFILES)
        self.assertEqual(prof.stages, ("federation_bulk",))
        self.assertIn("federation.bulk", prof.permissions_required)
        with self.assertRaises(errors.ValidationError):
            reg.build_argv("federation-bulk", "target", {}, self.dir, 60)

    def test_job_payload_vocabulary_extended(self):
        jobs_mod.validate_payload({
            "op": "bulk_export", "target": "bulk:bulk_export",
            "peer_id": "p1", "policy_id": "q1", "package_id": "k1",
            "strategy": "skip", "object_types": "asset,finding"})
        with self.assertRaises(errors.ValidationError):
            jobs_mod.validate_payload({"op": "bulk_export", "evil": "x"})

    def test_retention_spec_reuses_phase11_engine(self):
        import data_governance as dg
        for kind in ("federation_packages", "federation_imports",
                     "integration_events"):
            self.assertIn(kind, models.RETENTION_KINDS)
            self.assertIn(kind, dg.RETENTION_SPEC)
        self.assertEqual(
            models.RETENTION_DEFAULTS["federation_packages"], 365)
        self.assertEqual(
            models.RETENTION_DEFAULTS["federation_imports"], 1095)
        # tombstone (payload purge) — the row/audit trail survives
        self.assertEqual(dg.RETENTION_SPEC["federation_packages"]["apply"],
                         "tombstone")
        self.assertEqual(dg.RETENTION_SPEC["integration_events"]["apply"],
                         "delete")


def _isolated_models_registry(*, synthetic_kind=None, synthetic_default=47,
                              default_overrides=None):
    """Execute models.py in an isolated module with test-only registry edits."""
    source_path = os.path.abspath(models.__file__)
    with open(source_path, encoding="utf-8") as source_file:
        tree = ast.parse(source_file.read(), filename=source_path)

    assignments = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = node
    kinds = assignments["RETENTION_KINDS"].value
    defaults = assignments["RETENTION_DEFAULTS"].value
    if synthetic_kind is not None:
        if not isinstance(kinds, ast.Tuple) or not isinstance(defaults, ast.Dict):
            raise AssertionError("canonical retention registry shape changed")
        kinds.elts.append(ast.Constant(value=synthetic_kind))
        defaults.keys.append(ast.Constant(value=synthetic_kind))
        defaults.values.append(ast.Constant(value=synthetic_default))

    for kind, value in (default_overrides or {}).items():
        for index, key in enumerate(defaults.keys):
            if isinstance(key, ast.Constant) and key.value == kind:
                defaults.values[index] = ast.Constant(value=value)
                break
        else:
            raise AssertionError(f"canonical default not found: {kind}")

    module_name = f"_retention_registry_probe_{id(tree):x}"
    with tempfile.TemporaryDirectory(
            prefix="retention_models_probe_") as directory:
        probe_path = os.path.join(directory, "models_probe.py")
        with open(probe_path, "w", encoding="utf-8") as probe_file:
            probe_file.write(ast.unparse(tree))
        return runpy.run_path(probe_path, run_name=module_name)


class RetentionRegistryMigrationTests(unittest.TestCase):
    def test_compatibility_kind_tuple_is_derived_and_ordered(self):
        expected = tuple(
            kind for kind in models.RETENTION_KINDS
            if kind.startswith("integration_") and kind != "integration_events"
        )
        self.assertIs(type(models.INTEGRATION_RETENTION_KINDS), tuple)
        self.assertEqual(models.INTEGRATION_RETENTION_KINDS, expected)
        self.assertEqual(
            models.INTEGRATION_RETENTION_KINDS,
            models._derive_integration_retention_kinds(models.RETENTION_KINDS))
        self.assertEqual(
            models.INTEGRATION_RETENTION_KINDS,
            models._derive_integration_retention_kinds(models.RETENTION_KINDS))
        self.assertIn("integration_events", models.RETENTION_KINDS)
        self.assertNotIn("integration_events", models.INTEGRATION_RETENTION_KINDS)

    def test_synthetic_canonical_kind_flows_into_isolated_compatibility_view(self):
        original_kinds = models.RETENTION_KINDS
        original_compatibility = models.INTEGRATION_RETENTION_KINDS
        original_defaults = dict(models.RETENTION_DEFAULTS)
        synthetic = "integration_registry_probe"

        probe = _isolated_models_registry(synthetic_kind=synthetic)

        self.assertIn(synthetic, probe["RETENTION_KINDS"])
        self.assertIn(synthetic, probe["INTEGRATION_RETENTION_KINDS"])
        self.assertEqual(type(probe["INTEGRATION_RETENTION_KINDS"]), tuple)
        self.assertNotIn("integration_events",
                         probe["INTEGRATION_RETENTION_KINDS"])
        self.assertEqual(probe["INTEGRATION_RETENTION_DEFAULTS"][synthetic], 47)
        self.assertIs(models.RETENTION_KINDS, original_kinds)
        self.assertIs(models.INTEGRATION_RETENTION_KINDS, original_compatibility)
        self.assertEqual(dict(models.RETENTION_DEFAULTS), original_defaults)

    def test_compatibility_defaults_follow_isolated_canonical_default_change(self):
        original_defaults = dict(models.RETENTION_DEFAULTS)
        original_compatibility = dict(models.INTEGRATION_RETENTION_DEFAULTS)
        changed_days = 241

        probe = _isolated_models_registry(
            default_overrides={"integration_deliveries": changed_days})

        self.assertEqual(
            probe["RETENTION_DEFAULTS"]["integration_deliveries"],
            changed_days)
        self.assertEqual(
            probe["INTEGRATION_RETENTION_DEFAULTS"]["integration_deliveries"],
            changed_days)
        self.assertEqual(dict(models.RETENTION_DEFAULTS), original_defaults)
        self.assertEqual(
            dict(models.INTEGRATION_RETENTION_DEFAULTS), original_compatibility)

    def test_compatibility_defaults_are_json_serializable_without_leakage(self):
        serialized = json.dumps(models.INTEGRATION_RETENTION_DEFAULTS,
                                 sort_keys=True)
        decoded = json.loads(serialized)
        expected = {
            kind: models.RETENTION_DEFAULTS[kind]
            for kind in models.INTEGRATION_RETENTION_KINDS
        }
        self.assertEqual(decoded, expected)
        self.assertEqual(set(decoded), set(models.INTEGRATION_RETENTION_KINDS))
        self.assertNotIn("integration_events", decoded)
        self.assertNotIn("audit_events", decoded)
        self.assertNotIn("evidence", decoded)

    def test_integration_kinds_match_canonical_specs_and_defaults(self):
        import data_governance as dg

        self.assertTrue(dg.validate_retention_catalog())
        for kind in models.INTEGRATION_RETENTION_KINDS:
            with self.subTest(kind=kind):
                self.assertIn(kind, models.RETENTION_KINDS)
                self.assertIn(kind, dg.RETENTION_SPEC)
                self.assertIn(kind, models.RETENTION_DEFAULTS)
                self.assertIn(kind, models.INTEGRATION_RETENTION_DEFAULTS)
                self.assertEqual(
                    models.INTEGRATION_RETENTION_DEFAULTS[kind],
                    models.RETENTION_DEFAULTS[kind])
        self.assertNotIn("integration_events", models.INTEGRATION_RETENTION_KINDS)
        self.assertIn("integration_events", dg.RETENTION_SPEC)

    def test_read_only_defaults_reject_all_standard_mutators_atomically(self):
        mapping = models.INTEGRATION_RETENTION_DEFAULTS
        key = models.INTEGRATION_RETENTION_KINDS[0]
        canonical_before = dict(models.RETENTION_DEFAULTS)
        compatibility_before = dict(mapping)

        def set_new():
            mapping["integration_registry_probe"] = 1

        def set_existing():
            mapping[key] = -1

        def delete_existing():
            del mapping[key]

        mutations = (
            set_new,
            set_existing,
            delete_existing,
            lambda: mapping.update({"integration_registry_probe": 1}),
            lambda: mapping.pop(key),
            lambda: mapping.clear(),
            lambda: mapping.setdefault("integration_registry_probe", 1),
            lambda: mapping.popitem(),
            lambda: mapping.__ior__({"integration_registry_probe": 1}),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(TypeError):
                    mutation()
                self.assertEqual(dict(mapping), compatibility_before)
                self.assertEqual(dict(models.RETENTION_DEFAULTS),
                                 canonical_before)

    def test_tuple_and_mapping_stay_immutable_catalog_valid_and_stable(self):
        import data_governance as dg

        kinds_before = models.RETENTION_KINDS
        compatibility_kinds_before = models.INTEGRATION_RETENTION_KINDS
        defaults_before = dict(models.RETENTION_DEFAULTS)
        compatibility_before = dict(models.INTEGRATION_RETENTION_DEFAULTS)
        serialized_before = json.dumps(
            models.INTEGRATION_RETENTION_DEFAULTS, sort_keys=True)
        self.assertTrue(dg.validate_retention_catalog())

        with self.assertRaises(TypeError):
            models.INTEGRATION_RETENTION_KINDS[0] = "altered_kind"
        with self.assertRaises(TypeError):
            models.INTEGRATION_RETENTION_DEFAULTS[
                models.INTEGRATION_RETENTION_KINDS[0]] = -1

        self.assertIs(models.RETENTION_KINDS, kinds_before)
        self.assertIs(models.INTEGRATION_RETENTION_KINDS,
                      compatibility_kinds_before)
        self.assertEqual(dict(models.RETENTION_DEFAULTS), defaults_before)
        self.assertEqual(dict(models.INTEGRATION_RETENTION_DEFAULTS),
                         compatibility_before)
        self.assertEqual(json.dumps(models.INTEGRATION_RETENTION_DEFAULTS,
                                    sort_keys=True), serialized_before)
        self.assertTrue(dg.validate_retention_catalog())

    def test_catalog_validation_rejects_malformed_and_unsafe_entries(self):
        import data_governance as dg

        kind = models.INTEGRATION_RETENTION_KINDS[0]

        with self.subTest(case="malformed canonical kind"):
            with mock.patch.object(
                    models, "RETENTION_KINDS",
                    models.RETENTION_KINDS + ("",)):
                with self.assertRaises(errors.ConfigurationError):
                    dg.validate_retention_catalog()

        with self.subTest(case="missing default"):
            with mock.patch.dict(models.RETENTION_DEFAULTS):
                del models.RETENTION_DEFAULTS[kind]
                with self.assertRaises(errors.ConfigurationError):
                    dg.validate_retention_catalog()

        with self.subTest(case="malformed spec entry"):
            with mock.patch.dict(dg.RETENTION_SPEC[kind]):
                del dg.RETENTION_SPEC[kind]["apply"]
                with self.assertRaises(errors.ConfigurationError):
                    dg.validate_retention_catalog()

        for invalid_days in (0, True, "30", 3651):
            with self.subTest(case="invalid retention value",
                              value=invalid_days):
                with mock.patch.dict(
                        models.RETENTION_DEFAULTS, {kind: invalid_days}):
                    with self.assertRaises(errors.ConfigurationError):
                        dg.validate_retention_catalog()

        with self.subTest(case="inconsistent canonical specification"):
            with mock.patch.dict(dg.RETENTION_SPEC):
                del dg.RETENTION_SPEC[kind]
                with self.assertRaises(errors.ConfigurationError):
                    dg.validate_retention_catalog()

        for forbidden_table in ("external_integrations", "secrets_registry"):
            with self.subTest(case="credential-bearing retention table",
                              table=forbidden_table):
                with mock.patch.dict(
                        dg.RETENTION_SPEC[kind], {"table": forbidden_table}):
                    with self.assertRaises(errors.ConfigurationError):
                        dg.validate_retention_catalog()

        self.assertTrue(dg.validate_retention_catalog())

    def test_existing_import_paths_expose_canonical_and_legacy_names(self):
        from data_governance import RETENTION_SPEC, validate_retention_catalog
        from models import (INTEGRATION_RETENTION_DEFAULTS,
                            INTEGRATION_RETENTION_KINDS,
                            RETENTION_DEFAULTS, RETENTION_KINDS)

        import data_governance as dg

        self.assertIs(RETENTION_KINDS, models.RETENTION_KINDS)
        self.assertIs(RETENTION_DEFAULTS, models.RETENTION_DEFAULTS)
        self.assertIs(INTEGRATION_RETENTION_KINDS,
                      models.INTEGRATION_RETENTION_KINDS)
        self.assertIs(INTEGRATION_RETENTION_DEFAULTS,
                      models.INTEGRATION_RETENTION_DEFAULTS)
        self.assertIs(RETENTION_SPEC, dg.RETENTION_SPEC)
        self.assertTrue(validate_retention_catalog())

    def test_source_ast_has_one_canonical_and_derived_registry(self):
        source_root = PY
        definition_files = {
            "RETENTION_KINDS": set(),
            "RETENTION_DEFAULTS": set(),
            "RETENTION_SPEC": set(),
            "INTEGRATION_RETENTION_KINDS": set(),
            "INTEGRATION_RETENTION_DEFAULTS": set(),
        }

        def names_in_target(target):
            if isinstance(target, ast.Name):
                return {target.id}
            if isinstance(target, (ast.Tuple, ast.List)):
                names = set()
                for item in target.elts:
                    names.update(names_in_target(item))
                return names
            return set()

        for directory, subdirectories, filenames in os.walk(source_root):
            subdirectories[:] = [name for name in subdirectories
                                 if name != "__pycache__"]
            for filename in filenames:
                if not filename.endswith(".py"):
                    continue
                path = os.path.join(directory, filename)
                with open(path, encoding="utf-8") as source_file:
                    tree = ast.parse(source_file.read(), filename=path)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Assign):
                        targets = node.targets
                    elif isinstance(node, ast.AnnAssign):
                        targets = (node.target,)
                    else:
                        continue
                    for target in targets:
                        for name in names_in_target(target):
                            if name in definition_files:
                                definition_files[name].add(
                                    os.path.relpath(path, ROOT))

        self.assertEqual(definition_files, {
            "RETENTION_KINDS": {"python/models.py"},
            "RETENTION_DEFAULTS": {"python/models.py"},
            "RETENTION_SPEC": {"python/data_governance.py"},
            "INTEGRATION_RETENTION_KINDS": {"python/models.py"},
            "INTEGRATION_RETENTION_DEFAULTS": {"python/models.py"},
        })

        with open(models.__file__, encoding="utf-8") as source_file:
            models_tree = ast.parse(source_file.read(), filename=models.__file__)
        module_assignments = {}
        for node in models_tree.body:
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    module_assignments[target.id] = node.value
        kinds_view = module_assignments["INTEGRATION_RETENTION_KINDS"]
        self.assertIsInstance(kinds_view, ast.Call)
        self.assertEqual(ast.unparse(kinds_view.func),
                         "_derive_integration_retention_kinds")
        self.assertEqual(ast.unparse(kinds_view.args[0]), "RETENTION_KINDS")

        defaults_view = module_assignments["INTEGRATION_RETENTION_DEFAULTS"]
        self.assertIsInstance(defaults_view, ast.Call)
        self.assertEqual(ast.unparse(defaults_view.func),
                         "_ReadOnlyRetentionDefaults")
        comprehension = defaults_view.args[0]
        self.assertIsInstance(comprehension, ast.DictComp)
        self.assertEqual(ast.unparse(comprehension.generators[0].iter),
                         "INTEGRATION_RETENTION_KINDS")
        self.assertEqual(ast.unparse(comprehension.value),
                         "RETENTION_DEFAULTS[kind]")

    def test_integration_lookup_and_retention_enforcement_use_canonical_kind(self):
        import data_governance as dg

        with tempfile.TemporaryDirectory(
                prefix="retention_registry_") as directory:
            service = pf.PlatformService(
                os.path.join(directory, "registry.sqlite3"))
            org = service.org_create("RegistryTenant")
            governance = dg.SecurityGovernance(service)
            kind = models.INTEGRATION_RETENTION_KINDS[0]

            self.assertEqual(
                dg._retention_spec(kind), dg.RETENTION_SPEC[kind])
            self.assertEqual(
                governance.retention.effective_days(org.id, kind),
                models.INTEGRATION_RETENTION_DEFAULTS[kind])
            preview = governance.retention.preview(
                org.id, kind=kind, now="2030-01-01T00:00:00Z")
            self.assertEqual(preview["kind"], kind)
            self.assertEqual(preview["days"], models.RETENTION_DEFAULTS[kind])
            self.assertEqual(preview["mode"], "preview")

            governance.retention.policy_set(org.id, kind=kind, days=90)
            self.assertEqual(
                governance.retention.effective_days(org.id, kind), 90)
            self.assertEqual(
                governance.retention.preview(
                    org.id, kind=kind, now="2030-01-01T00:00:00Z")["days"],
                90)
            with self.assertRaises(errors.ValidationError):
                governance.retention.effective_days(
                    org.id, "integration_not_canonical")


# ---------------------------------------------------------------------------
# 2. Peer trust lifecycle
# ---------------------------------------------------------------------------
class PeerLifecycleTests(FedBase):
    def test_create_is_always_pending_no_implicit_trust(self):
        org_c = self.svc.org_create("OrgC")
        p = self.A.peers.create(self.orgA.id, peer_org_id=org_c.id,
                                name="peer-c", direction="outbound",
                                actor="alice")
        self.assertEqual(p["status"], "pending")
        self.assertEqual(p["approved_by"], "")
        # a pending peer can never export
        with self.assertRaises(errors.ValidationError):
            self.A.packages.build(self.orgA.id, peer_id=p["id"],
                                  policy_id="", project_id=self.pA.id,
                                  actor="alice")

    def test_trust_record_carries_required_fields(self):
        row = self.A.peers.get(self.orgA.id, self.peerA["id"])
        for field in ("peer_org_id", "purpose", "created_by", "approved_by",
                      "created_at", "direction", "status"):
            self.assertIn(field, row)
        self.assertEqual(row["created_by"], "alice")
        self.assertEqual(row["approved_by"], "bob")
        self.assertNotEqual(row["created_by"], row["approved_by"])

    def test_approval_requires_separation_of_duties(self):
        org_c = self.svc.org_create("OrgC2")
        p = self.A.peers.create(self.orgA.id, peer_org_id=org_c.id,
                                name="peer-sod", actor="alice")
        with self.assertRaises(errors.AuthorizationError) as cm:
            self.A.peers.approve(self.orgA.id, p["id"], approved_by="alice",
                                 actor="alice")
        self.assertIn("Forbidden", str(cm.exception))
        # an empty approved_by falls back to the authenticated actor — the
        # approving identity is always recorded and always != the creator
        ok = self.A.peers.approve(self.orgA.id, p["id"], approved_by="",
                                  actor="bob")
        self.assertEqual(ok["status"], "active")
        self.assertEqual(ok["approved_by"], "bob")

    def test_suspend_resume_revoke_terminal(self):
        s = self.A.peers.suspend(self.orgA.id, self.peerA["id"],
                                 reason="incident", actor="bob")
        self.assertEqual(s["status"], "suspended")
        # suspended peer: exports fail closed
        with self.assertRaises(errors.ValidationError):
            self.build()
        r = self.A.peers.resume(self.orgA.id, self.peerA["id"], actor="bob")
        self.assertEqual(r["status"], "active")
        with self.assertRaises(errors.ValidationError):
            self.A.peers.revoke(self.orgA.id, self.peerA["id"], reason="",
                                actor="bob")     # reason required
        rev = self.A.peers.revoke(self.orgA.id, self.peerA["id"],
                                  reason="contract ended", actor="bob")
        self.assertEqual(rev["status"], "revoked")
        self.assertTrue(rev["revoked_at"])
        with self.assertRaises(errors.LifecycleError):
            self.A.peers.resume(self.orgA.id, self.peerA["id"], actor="bob")

    def test_revocation_blocks_new_ops_but_never_erases_local_data(self):
        self.seed_a()
        env = self.build()["envelope"]
        self.B.imports.import_envelope(self.orgB.id, envelope=env,
                                       target_project_id=self.pB.id,
                                       actor="carol")
        before = self.db_count(
            "SELECT COUNT(*) n FROM findings WHERE project_id=?",
            (self.pB.id,))
        self.B.peers.revoke(self.orgB.id, self.peerB["id"],
                            reason="trust withdrawn", actor="dave")
        # new import blocked (fresh envelope, same peer)
        self.assertRejected(self.unique_env("after-revoke"), "peer_revoked")
        after = self.db_count(
            "SELECT COUNT(*) n FROM findings WHERE project_id=?",
            (self.pB.id,))
        self.assertEqual(before, after)          # local data untouched
        self.assertGreater(before, 0)

    def test_expiry_sweep_and_fail_closed_usage(self):
        org_c = self.svc.org_create("OrgExp")
        p = self.A.peers.create(self.orgA.id, peer_org_id=org_c.id,
                                name="peer-exp", direction="outbound",
                                expires_at="2020-01-01T00:00:00Z",
                                actor="alice")
        # approval of an already-expired window is refused
        with self.assertRaises(errors.LifecycleError):
            self.A.peers.approve(self.orgA.id, p["id"], approved_by="bob",
                                 actor="bob")
        p2 = self.A.peers.create(self.orgA.id, peer_org_id=org_c.id,
                                 name="peer-exp2", direction="outbound",
                                 actor="alice")
        p2 = self.A.peers.approve(self.orgA.id, p2["id"], approved_by="bob",
                                  actor="bob")
        self.svc.db.execute(
            "UPDATE federation_peers SET expires_at=? WHERE id=?",
            ("2020-01-01T00:00:00Z", p2["id"]))
        # usage fails closed BEFORE any sweep runs
        pol = self.A.policies.create(
            self.orgA.id, peer_id=p2["id"], name="policy-exp",
            project_id=self.pA.id, object_types=["asset"],
            classifications=["internal"], actor="alice")
        with self.assertRaises(errors.AuthorizationError):
            self.A.packages.build(self.orgA.id, peer_id=p2["id"],
                                  policy_id=pol["id"],
                                  project_id=self.pA.id, actor="alice")
        r = self.A.peers.sweep_expiry(self.orgA.id, actor="system")
        self.assertEqual(r["expired"], 1)
        self.assertEqual(
            self.A.peers.get(self.orgA.id, p2["id"])["status"], "expired")

    def test_re_request_is_the_only_renewal_path(self):
        self.svc.db.execute(
            "UPDATE federation_peers SET expires_at=? WHERE id=?",
            ("2020-01-01T00:00:00Z", self.peerA["id"]))
        self.A.peers.sweep_expiry(self.orgA.id, actor="system")
        with self.assertRaises(errors.LifecycleError):
            self.A.peers.resume(self.orgA.id, self.peerA["id"], actor="bob")
        rr = self.A.peers.re_request(self.orgA.id, self.peerA["id"],
                                     actor="alice")
        self.assertEqual(rr["status"], "pending")
        self.assertEqual(rr["approved_by"], "")   # fresh approval required
        again = self.A.peers.approve(self.orgA.id, self.peerA["id"],
                                     approved_by="bob", actor="bob")
        self.assertEqual(again["status"], "active")

    def test_duplicate_peer_rejected(self):
        with self.assertRaises(errors.DuplicateError):
            self.A.peers.create(self.orgA.id, peer_org_id=self.orgB.id,
                                name="peer-to-b", actor="alice")


# ---------------------------------------------------------------------------
# 3. Exchange policy ruleset
# ---------------------------------------------------------------------------
class PolicyTests(FedBase):
    def test_secret_classes_never_exportable_by_default(self):
        for cls in ("secret", "authentication_material"):
            with self.assertRaises(errors.ValidationError) as cm:
                self.A.policies.create(
                    self.orgA.id, peer_id=self.peerA["id"],
                    name=f"policy-bad-{cls}", project_id=self.pA.id,
                    object_types=["finding"],
                    classifications=["internal", cls], actor="alice")
            self.assertIn(cls, str(cm.exception))
        # explicit decision unlocks the CLASS, never raw secret values
        ok = self.A.policies.create(
            self.orgA.id, peer_id=self.peerA["id"], name="policy-explicit",
            project_id=self.pA.id, object_types=["finding"],
            classifications=["internal", "secret"],
            explicit_sensitive=True, actor="alice")
        self.assertIn("secret", ok["allowed_classifications"])

    def test_unknown_types_and_classes_rejected(self):
        with self.assertRaises(errors.ValidationError):
            self.A.policies.create(
                self.orgA.id, peer_id=self.peerA["id"], name="policy-x1",
                object_types=["everything"], classifications=["internal"],
                actor="alice")
        with self.assertRaises(errors.ValidationError):
            self.A.policies.create(
                self.orgA.id, peer_id=self.peerA["id"], name="policy-x2",
                object_types=["finding"], classifications=["top-secret"],
                actor="alice")

    def test_field_narrowing_only_never_widens(self):
        pol = self.A.policies.create(
            self.orgA.id, peer_id=self.peerA["id"], name="policy-fields",
            project_id=self.pA.id, object_types=["finding"],
            classifications=["internal"],
            fields={"finding": ["id", "title", "severity",
                                "not_a_real_field"]},
            actor="alice")
        allowed = pol["allowed_fields"]["finding"]
        self.assertNotIn("not_a_real_field", allowed)
        self.assertEqual(set(allowed), {"id", "title", "severity"})
        # narrowing changes the actual export: only allowed fields leave
        self.seed_a()
        r = self.A.packages.build(self.orgA.id, peer_id=self.peerA["id"],
                                  policy_id=pol["id"],
                                  project_id=self.pA.id, actor="alice")
        fobj = r["envelope"]["objects"]["finding"][0]
        self.assertEqual(set(fobj) - {"_classification", "_provenance"},
                         {"id", "title", "severity"})

    def test_update_revalidates_full_ruleset(self):
        with self.assertRaises(errors.ValidationError):
            self.A.policies.update(self.orgA.id, self.polA["id"],
                                   classifications=["internal", "secret"],
                                   actor="alice")   # no explicit_sensitive
        upd = self.A.policies.update(self.orgA.id, self.polA["id"],
                                     max_objects=42, actor="alice")
        self.assertEqual(upd["max_objects"], 42)
        upd2 = self.A.policies.update(
            self.orgA.id, self.polA["id"],
            fields={"finding": ["id", "title"]}, actor="alice")
        self.assertEqual(set(upd2["allowed_fields"]["finding"]),
                         {"id", "title"})

    def test_disable_and_expired_immutable(self):
        d = self.A.policies.disable(self.orgA.id, self.polA["id"],
                                    actor="alice")
        self.assertEqual(d["status"], "disabled")
        with self.assertRaises(errors.ValidationError):
            self.build()      # disabled policy: export fails closed
        pol = self.A.policies.create(
            self.orgA.id, peer_id=self.peerA["id"], name="policy-old",
            project_id=self.pA.id, object_types=["asset"],
            classifications=["internal"],
            expires_at="2020-01-01T00:00:00Z", actor="alice")
        swept = self.A.policies.sweep_expiry(self.orgA.id, actor="system")
        self.assertEqual(swept["expired"], 1)
        with self.assertRaises(errors.LifecycleError):
            self.A.policies.update(self.orgA.id, pol["id"], max_objects=5,
                                   actor="alice")


# ---------------------------------------------------------------------------
# 4. Package build: determinism, gates, minimization
# ---------------------------------------------------------------------------
class PackageBuildTests(FedBase):
    def test_build_is_deterministic_and_hashed(self):
        self.seed_a()
        r1 = self.build()
        r2 = self.build()
        self.assertEqual(r1["package_id"], r2["package_id"])
        self.assertEqual(r1["integrity"], r2["integrity"])
        self.assertEqual(
            r1["integrity"],
            hashlib.sha256(
                fed.canonical_payload(r1["envelope"]).encode("utf-8")
            ).hexdigest())
        v = fed.verify_envelope(r1["envelope"])
        self.assertTrue(v["valid"], v["error"])

    def test_envelope_shape_is_provider_neutral(self):
        self.seed_a()
        env = self.build()["envelope"]
        for key in ("package_id", "schema_version", "source_organization",
                    "destination", "created_at", "classification", "objects",
                    "provenance", "integrity", "policy_reference"):
            self.assertIn(key, env)
        self.assertEqual(env["schema_version"],
                         models.FEDERATION_SCHEMA_VERSION)
        self.assertEqual(env["integrity"]["algorithm"], "sha256")
        self.assertEqual(env["source_organization"]["id"], self.orgA.id)
        self.assertEqual(env["destination"]["org_id"], self.orgB.id)

    def test_provenance_on_every_object(self):
        self.seed_a()
        env = self.build()["envelope"]
        for otype, objs in env["objects"].items():
            for o in objs:
                prov = o["_provenance"]
                self.assertEqual(prov["source_org_id"], self.orgA.id)
                self.assertEqual(prov["source_project_id"], self.pA.id)
                self.assertTrue(prov["source_object_id"])
                self.assertEqual(prov["object_type"], otype)
                self.assertIn("_classification", o)
        # evidence rows additionally carry their source finding mapping
        ev = env["objects"]["evidence"][0]
        self.assertTrue(ev["_provenance"]["source_finding_id"])

    def test_classification_gate_denies_objects(self):
        self.seed_a()
        a2 = self.svc.asset_add(self.pA.id, "hostname", "vault.example.com")
        self.A.gov.classification.classify(
            self.orgA.id, "asset", object_id=a2.id,
            classification="restricted", actor="alice")
        pol = self.A.policies.create(
            self.orgA.id, peer_id=self.peerA["id"], name="policy-narrow2",
            project_id=self.pA.id,
            object_types=["asset", "finding", "evidence"],
            classifications=["public", "internal"], actor="alice")
        r = self.A.packages.build(self.orgA.id, peer_id=self.peerA["id"],
                                  policy_id=pol["id"],
                                  project_id=self.pA.id, actor="alice")
        self.assertEqual(r["denied"]["classification"], 1)
        values = [o["value"] for o in r["envelope"]["objects"]["asset"]]
        self.assertNotIn("vault.example.com", values)
        self.assertIn("shop.example.com", values)

    def test_privacy_restriction_wins_over_export(self):
        _, _, fids = self.seed_a()
        self.svc.db.execute(
            "UPDATE findings SET title=? WHERE id=?",
            ("[REDACTED-SUBJECT: erasure] leak", fids[0]))
        r = self.build()
        self.assertEqual(r["denied"]["privacy"], 1)
        self.assertEqual(r["counts"].get("finding", 0), 0)

    def test_secret_shapes_never_leave_raw(self):
        scan, asset, _ = self.seed_a(with_evidence=False)
        f = models.Finding(
            scan_id=scan.id, project_id=self.pA.id, asset_id=asset.id,
            title="Leaked key AKIAABCDEFGHIJKLMNOP in config",
            description="token ghp_" + "q" * 36, severity="High",
            category="secrets", source="SecuAudit", rule_id="leak-1",
            raw={})
        self.svc.finding_ingest(f)
        r = self.build()
        blob = json.dumps(r["envelope"])
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", blob)
        self.assertNotIn("ghp_" + "q" * 36, blob)

    def test_internal_finding_fields_never_exported(self):
        self.seed_a()
        env = self.build()["envelope"]
        fobj = env["objects"]["finding"][0]
        for internal in ("risk_score", "priority_score", "canonical_key",
                         "occurrence_count", "business_impact",
                         "exploitability", "suppression_state", "raw",
                         "scan_id", "fingerprint"):
            self.assertNotIn(internal, fobj)
        # parameter/endpoint come from raw but as bounded scalars
        self.assertEqual(fobj.get("parameter"), "id")
        self.assertEqual(fobj.get("endpoint"), "/item")

    def test_max_objects_cap_and_truncation_flag(self):
        self.seed_a(n_findings=6, with_evidence=False)
        pol = self.A.policies.create(
            self.orgA.id, peer_id=self.peerA["id"], name="policy-tiny",
            project_id=self.pA.id,
            object_types=["asset", "finding", "evidence"],
            classifications=["public", "internal", "confidential"],
            max_objects=3, actor="alice")
        r = self.A.packages.build(self.orgA.id, peer_id=self.peerA["id"],
                                  policy_id=pol["id"],
                                  project_id=self.pA.id, actor="alice")
        self.assertLessEqual(r["object_count"], 3)
        self.assertTrue(r["truncated"])
        with self.assertRaises(errors.ValidationError):
            self.A.packages.build(self.orgA.id, peer_id=self.peerA["id"],
                                  policy_id=pol["id"],
                                  project_id=self.pA.id, limit=99,
                                  actor="alice")   # above policy cap

    def test_unsigned_build_rejected_external_signing_is_reference_only(self):
        self.seed_a()
        with self.assertRaises(errors.ValidationError):
            self.build(trust_mode="unsigned")
        r = self.build(trust_mode="externally_signed",
                       external_signature_ref="ext:sig-store:abc123")
        self.assertEqual(r["trust_mode"], "externally_signed")
        v = fed.verify_envelope(r["envelope"])
        self.assertTrue(v["valid"])
        # local code NEVER claims the external signature was verified
        ext = r["envelope"].get("external_signature") or {}
        self.assertEqual(ext.get("mode"), "externally_signed")
        self.assertFalse(ext.get("verified", False))

    def test_get_and_list_never_return_payload(self):
        self.seed_a()
        r = self.build()
        row = self.A.packages.get(self.orgA.id, r["package_id"])
        self.assertNotIn("payload", row)
        lst = self.A.packages.list(self.orgA.id)
        self.assertEqual(lst["total"], 1)
        for item in lst["items"]:
            self.assertNotIn("payload", item)
        # serialize IS the export action and returns the envelope
        env = self.A.packages.serialize(self.orgA.id, r["package_id"],
                                        actor="alice")
        self.assertTrue(fed.verify_envelope(env)["valid"])

    def test_export_requires_active_peer_direction_and_policy_scope(self):
        self.seed_a()
        # an inbound-only peer can receive but never send
        org_c = self.svc.org_create("OrgDir")
        p = self.A.peers.create(self.orgA.id, peer_org_id=org_c.id,
                                name="peer-in-only", direction="inbound",
                                actor="alice")
        p = self.A.peers.approve(self.orgA.id, p["id"], approved_by="bob",
                                 actor="bob")
        pol = self.A.policies.create(
            self.orgA.id, peer_id=p["id"], name="policy-dir",
            project_id=self.pA.id, object_types=["asset"],
            classifications=["internal"], actor="alice")
        with self.assertRaises(errors.AuthorizationError):
            self.A.packages.build(self.orgA.id, peer_id=p["id"],
                                  policy_id=pol["id"],
                                  project_id=self.pA.id, actor="alice")

    def test_object_type_outside_policy_rejected(self):
        self.seed_a()
        with self.assertRaises(errors.ValidationError):
            self.build(object_types=["case"])


# ---------------------------------------------------------------------------
# 5. Integrity / canonicalization (pure functions)
# ---------------------------------------------------------------------------
class IntegrityTests(unittest.TestCase):
    def _env(self):
        env = {
            "schema_version": models.FEDERATION_SCHEMA_VERSION,
            "source_organization": {"id": "o1", "name": "A"},
            "destination": {"org_id": "o2", "peer_id": "p2"},
            "policy_reference": {"policy_id": "pol", "peer_id": "p2",
                                 "name": "policy"},
            "classification": "internal",
            "provenance": {"platform": "SecuToolkit",
                           "canonicalization": fed.CANONICALIZATION,
                           "created_by": "alice"},
            "objects": {"asset": [{"id": "a1", "value": "x.example",
                                   "_classification": "internal",
                                   "_provenance": {
                                       "source_org_id": "o1",
                                       "source_project_id": "pj",
                                       "source_object_id": "a1",
                                       "object_type": "asset"}}]},
            "counts": {"asset": 1}, "denied": {}, "truncated": False,
        }
        env["package_id"] = "pkg-1"
        env["created_at"] = "2026-01-01T00:00:00Z"
        env["trust_mode"] = "integrity_verified"
        env["integrity"] = {"algorithm": "sha256",
                            "hash": fed.package_hash(env),
                            "canonicalization": fed.CANONICALIZATION}
        return env

    def test_canonicalization_is_key_order_stable(self):
        env = self._env()
        alt = {}
        for k in reversed(list(env.keys())):
            alt[k] = copy.deepcopy(env[k])
        self.assertEqual(fed.package_hash(env), fed.package_hash(alt))

    def test_volatile_keys_do_not_change_the_hash(self):
        env = self._env()
        env2 = copy.deepcopy(env)
        env2["created_at"] = "2030-01-01T00:00:00Z"
        env2["package_id"] = "different"
        self.assertEqual(fed.package_hash(env), fed.package_hash(env2))

    def test_verify_rejects_tampering_and_malformed_input(self):
        env = self._env()
        self.assertTrue(fed.verify_envelope(env)["valid"])
        bad = copy.deepcopy(env)
        bad["objects"]["asset"][0]["value"] = "tampered.example"
        v = fed.verify_envelope(bad)
        self.assertFalse(v["valid"])
        self.assertEqual(v["error"], "integrity_mismatch")
        self.assertFalse(fed.verify_envelope("not json {")["valid"])
        self.assertEqual(fed.verify_envelope("not json {")["error"],
                         "package_unparsable")
        self.assertEqual(fed.verify_envelope({})["error"],
                         "integrity_missing")
        wrong_algo = copy.deepcopy(env)
        wrong_algo["integrity"]["algorithm"] = "md5"
        self.assertEqual(fed.verify_envelope(wrong_algo)["error"],
                         "integrity_algorithm_unsupported")
        malformed = copy.deepcopy(env)
        malformed["integrity"]["hash"] = "ZZ"
        self.assertEqual(fed.verify_envelope(malformed)["error"],
                         "integrity_hash_malformed")

    def test_verify_accepts_string_bytes_and_rejects_oversized(self):
        env = self._env()
        text = json.dumps(env)
        self.assertTrue(fed.verify_envelope(text)["valid"])
        self.assertTrue(fed.verify_envelope(text.encode("utf-8"))["valid"])
        huge = "x" * (fed.MAX_IMPORT_BYTES + 10)
        self.assertEqual(fed.verify_envelope(huge)["error"],
                         "package_too_large")

    def test_structure_guard_blocks_deep_nesting(self):
        env = self._env()
        deep = {}
        cur = deep
        for _ in range(fed.MAX_OBJECT_DEPTH + 4):
            cur["n"] = {}
            cur = cur["n"]
        env["objects"]["asset"][0]["deep"] = deep
        env["integrity"]["hash"] = fed.package_hash(env)
        v = fed.verify_envelope(env)
        self.assertFalse(v["valid"])
        self.assertIn("structure_invalid", v["error"])
        self.assertIn("package_structure_exceeded", v["error"])


# ---------------------------------------------------------------------------
# 6. Import: the 12 validation gates (fail closed)
# ---------------------------------------------------------------------------
class ImportGateTests(FedBase):
    def test_gate_syntax_and_schema_version(self):
        self.seed_a()
        env = self.build()["envelope"]
        bad = copy.deepcopy(env)
        bad["schema_version"] = "fed-package-v0"
        bad["integrity"]["hash"] = fed.package_hash(bad)
        self.assertRejected(bad, "schema_mismatch")
        with self.assertRaises(errors.ValidationError) as cm:
            self.B.imports.import_envelope(
                self.orgB.id, envelope={"nonsense": True},
                target_project_id=self.pB.id, actor="carol")
        self.assertIn("package_keys_missing", str(cm.exception))

    def test_gate_integrity_tamper_fails_closed_with_finding(self):
        self.seed_a()
        env = self.build()["envelope"]
        bad = copy.deepcopy(env)
        bad["objects"]["finding"][0]["title"] = "TAMPERED"
        self.assertRejected(bad, "integrity_")
        # a real platform finding was raised (Phase-10 secops reuse)
        n = self.db_count(
            "SELECT COUNT(*) n FROM findings WHERE rule_id=?",
            ("fed-integrity-mismatch",))
        self.assertGreaterEqual(n, 1)
        # the import row is recorded as rejected — replay re-reports it
        self.assertRejected(bad, "integrity_")
        rows = self.svc.db.query(
            "SELECT status FROM federation_imports WHERE org_id=? AND "
            "status='rejected'", (self.orgB.id,))
        self.assertTrue(rows)

    def test_gate_grant_missing_for_unknown_sender(self):
        self.seed_a()
        org_c = self.svc.org_create("OrgNoGrant")
        p_c = self.svc.project_create(org_c.id, "CoreC")
        # retarget the envelope at org C (valid hash) — C has no peer/policy
        env = self.build()["envelope"]
        env["destination"]["org_id"] = org_c.id
        env["integrity"]["hash"] = fed.package_hash(env)
        self.assertRejected(env, "grant_missing", org=org_c.id,
                            project=p_c.id)

    def test_gate_destination_mismatch(self):
        self.seed_a()
        env = self.build()["envelope"]
        org_c = self.svc.org_create("OrgWrongDest")
        p_c = self.svc.project_create(org_c.id, "CoreC")
        # the envelope names org B as destination; importing under C fails
        self.assertRejected(env, "destination_mismatch", org=org_c.id,
                            project=p_c.id)

    def test_gate_sender_revoked_and_expired(self):
        self.seed_a()
        env = self.build()["envelope"]
        self.B.peers.revoke(self.orgB.id, self.peerB["id"],
                            reason="test", actor="dave")
        self.assertRejected(self.unique_env("rev"), "peer_revoked")
        # expired: a NEWER peer pair with a lapsed window wins resolution
        peer2 = self.B.peers.create(self.orgB.id, peer_org_id=self.orgA.id,
                                    name="peer-exp-in",
                                    direction="bidirectional",
                                    actor="carol")
        peer2 = self.B.peers.approve(self.orgB.id, peer2["id"],
                                     approved_by="dave", actor="dave")
        self.svc.db.execute(
            "UPDATE federation_peers SET expires_at=? WHERE id=?",
            ("2020-01-01T00:00:00Z", peer2["id"]))
        self.B.policies.create(
            self.orgB.id, peer_id=peer2["id"], name="policy-exp-in",
            project_id=self.pB.id,
            object_types=["asset", "finding", "evidence"],
            classifications=["public", "internal", "confidential"],
            actor="carol")
        self.assertRejected(self.unique_env("exp"), "grant_expired")

    def test_gate_direction_denied(self):
        self.seed_a()
        env = self.build()["envelope"]
        # B's peer becomes OUTBOUND-only: it can send but never receive
        self.svc.db.execute(
            "UPDATE federation_peers SET direction='outbound' WHERE id=?",
            (self.peerB["id"],))
        self.assertRejected(env, "direction_denied")

    def test_gate_classification_policy(self):
        self.seed_a()
        env = self.build()["envelope"]
        self.B.policies.update(self.orgB.id, self.polB["id"],
                               classifications=["public"], actor="carol")
        self.assertRejected(env, "policy_denied:classification")

    def test_gate_object_limits(self):
        self.seed_a(n_findings=3, with_evidence=False)
        env = self.build()["envelope"]
        self.B.policies.update(self.orgB.id, self.polB["id"],
                               max_objects=2, actor="carol")
        self.assertRejected(env, "limit_exceeded")

    def test_gate_object_type_not_allowed(self):
        self.seed_a()
        env = self.build()["envelope"]
        self.B.policies.update(self.orgB.id, self.polB["id"],
                               object_types=["asset"], actor="carol")
        self.assertRejected(env, "policy_denied:type")

    def test_gate_field_policy_violation(self):
        self.seed_a()
        env = self.build()["envelope"]
        # a field outside the closed universe is a violation even when the
        # recomputed hash matches (defense in depth against tampering)
        env["objects"]["finding"][0]["totally_unknown_field"] = "smuggled"
        env["integrity"]["hash"] = fed.package_hash(env)
        self.assertRejected(env, "policy_field_violation")
        n = self.db_count(
            "SELECT COUNT(*) n FROM findings WHERE rule_id=?",
            ("fed-field-policy-violation",))
        self.assertGreaterEqual(n, 1)

    def test_gate_tenant_mapping_target_must_be_own_project(self):
        self.seed_a()
        env = self.build()["envelope"]
        with self.assertRaises(errors.NotFoundError):
            self.B.imports.import_envelope(
                self.orgB.id, envelope=env,
                target_project_id=self.pA.id,   # project of org A
                actor="carol")

    def test_gate_provenance_required_on_objects(self):
        self.seed_a()
        env = self.build()["envelope"]
        del env["objects"]["asset"][0]["_provenance"]
        env["integrity"]["hash"] = fed.package_hash(env)
        self.assertRejected(env, "provenance_invalid")

    def test_unsupported_object_type_rejected(self):
        self.seed_a()
        env = self.build()["envelope"]
        # organization is EXPORT-only vocabulary: even when the receiving
        # policy allows the type, there is no import merge path — explicit
        # rejection, never a silent drop
        self.B.policies.update(self.orgB.id, self.polB["id"],
                               object_types=["asset", "finding", "evidence",
                                             "organization"],
                               actor="carol")
        env["objects"]["organization"] = [
            {"id": self.orgA.id, "name": "OrgA",
             "_classification": "internal",
             "_provenance": {"source_org_id": self.orgA.id,
                             "source_project_id": "",
                             "source_object_id": self.orgA.id,
                             "object_type": "organization"}}]
        env["counts"]["organization"] = 1
        env["integrity"]["hash"] = fed.package_hash(env)
        self.assertRejected(env, "import_unsupported:organization")


# ---------------------------------------------------------------------------
# 7. Import application: provenance, dedup, collisions, evidence, cases, IOC
# ---------------------------------------------------------------------------
class ImportApplyTests(FedBase):
    def _pol_wide(self):
        self.A.policies.update(self.orgA.id, self.polA["id"],
                               object_types=["asset", "finding", "evidence",
                                             "case", "threat_intel_match"],
                               actor="alice")
        self.B.policies.update(self.orgB.id, self.polB["id"],
                               object_types=["asset", "finding", "evidence",
                                             "case", "threat_intel_match"],
                               actor="carol")

    def test_import_creates_provenanced_objects(self):
        self.seed_a()
        env = self.build()["envelope"]
        r = self.B.imports.import_envelope(
            self.orgB.id, envelope=env, target_project_id=self.pB.id,
            collision="skip", actor="carol")
        self.assertEqual(r["status"], "completed")
        self.assertEqual(r["imported"], 2)      # asset + finding
        row = self.svc.db.query_one(
            "SELECT raw, source, project_id FROM findings WHERE "
            "project_id=? AND source='federation'", (self.pB.id,))
        raw = store.loads(row["raw"], default={})
        prov = raw["_federation"]
        for key in ("source_org_id", "source_project_id",
                    "source_object_id", "package_id", "package_hash",
                    "import_id", "imported_at", "policy_id", "peer_id"):
            self.assertIn(key, prov)
        self.assertEqual(prov["source_org_id"], self.orgA.id)
        self.assertEqual(prov["package_id"], env["package_id"])
        # evidence reuses the EXISTING store, mapped via source finding
        ev = self.svc.db.query(
            "SELECT scanner, detection_reason FROM evidence e JOIN "
            "findings f ON f.id=e.finding_id WHERE f.project_id=?",
            (self.pB.id,))
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["scanner"], "federation")
        self.assertIn("[federated:", ev[0]["detection_reason"])

    def test_reimport_never_duplicates_findings(self):
        self.seed_a()
        env = self.build()["envelope"]
        self.B.imports.import_envelope(self.orgB.id, envelope=env,
                                       target_project_id=self.pB.id,
                                       actor="carol")
        n1 = self.db_count(
            "SELECT COUNT(*) n FROM findings WHERE project_id=?",
            (self.pB.id,))
        # a NEW envelope with identical content (fresh hash) — objects still
        # dedup through the Phase-4 fingerprint
        r2 = self.B.imports.import_envelope(
            self.orgB.id, envelope=self.unique_env("again"),
            target_project_id=self.pB.id, collision="skip", actor="carol")
        n2 = self.db_count(
            "SELECT COUNT(*) n FROM findings WHERE project_id=?",
            (self.pB.id,))
        self.assertEqual(n1, n2)
        self.assertEqual(r2["imported"], 0)
        self.assertGreaterEqual(r2["skipped"], 1)
        a1 = self.db_count(
            "SELECT COUNT(*) n FROM assets WHERE project_id=?",
            (self.pB.id,))
        self.assertEqual(a1, 1)

    def test_duplicate_envelope_is_idempotent_shortcut(self):
        self.seed_a()
        env = self.build()["envelope"]
        r1 = self.B.imports.import_envelope(
            self.orgB.id, envelope=env, target_project_id=self.pB.id,
            actor="carol")
        r2 = self.B.imports.import_envelope(
            self.orgB.id, envelope=env, target_project_id=self.pB.id,
            collision="link", actor="carol")
        self.assertTrue(r2["duplicate"])
        self.assertEqual(r2["import_id"], r1["import_id"])
        self.assertEqual(r2["imported"], r1["imported"])

    def test_collision_strategies_never_silently_overwrite(self):
        self.seed_a()
        env = self.build()["envelope"]
        self.B.imports.import_envelope(self.orgB.id, envelope=env,
                                       target_project_id=self.pB.id,
                                       collision="skip", actor="carol")
        title0 = self.svc.db.query_one(
            "SELECT title FROM findings WHERE project_id=? AND "
            "source='federation'", (self.pB.id,))["title"]
        res = {}
        for strat in ("skip", "link", "merge_metadata"):
            res[strat] = self.B.imports.import_envelope(
                self.orgB.id, envelope=self.unique_env(strat),
                target_project_id=self.pB.id, collision=strat,
                actor="carol")
        self.assertEqual(res["skip"]["skipped"], 2)
        self.assertEqual(res["link"]["linked"], 2)
        self.assertEqual(res["merge_metadata"]["imported"], 2)
        title1 = self.svc.db.query_one(
            "SELECT title FROM findings WHERE project_id=? AND "
            "source='federation'", (self.pB.id,))["title"]
        self.assertEqual(title0, title1)      # local object not replaced
        # reject: deterministic refusal, recorded as rejected
        with self.assertRaises(errors.ValidationError) as cm:
            self.B.imports.import_envelope(
                self.orgB.id, envelope=self.unique_env("rejectcase"),
                target_project_id=self.pB.id, collision="reject",
                actor="carol")
        self.assertIn("collision_reject", str(cm.exception))
        row = self.svc.db.query_one(
            "SELECT status, error FROM federation_imports WHERE org_id=? "
            "AND collision_strategy='reject'", (self.orgB.id,))
        self.assertEqual(row["status"], "rejected")
        # still exactly one local finding + asset
        self.assertEqual(
            self.db_count("SELECT COUNT(*) n FROM findings WHERE "
                          "project_id=? AND source='federation'",
                          (self.pB.id,)), 1)
        self.assertEqual(
            self.db_count("SELECT COUNT(*) n FROM assets WHERE "
                          "project_id=?", (self.pB.id,)), 1)

    def test_invalid_evidence_structure_never_imported(self):
        self.seed_a()
        env = self.build()["envelope"]
        ev = env["objects"]["evidence"][0]
        ev["evidence_type"] = "totally-unknown"
        ev["response_snippet"] = "x" * 5000
        env["integrity"]["hash"] = fed.package_hash(env)
        r = self.B.imports.import_envelope(
            self.orgB.id, envelope=env, target_project_id=self.pB.id,
            actor="carol")
        self.assertEqual(r["status"], "completed")
        row = self.svc.db.query_one(
            "SELECT evidence_type, response_snippet FROM evidence e JOIN "
            "findings f ON f.id=e.finding_id WHERE f.project_id=?",
            (self.pB.id,))
        self.assertEqual(row["evidence_type"], "other")   # vocabulary guard
        self.assertLessEqual(len(row["response_snippet"]), 4000)

    def test_case_import_marker_and_bola_safe_refs(self):
        self._pol_wide()
        self.seed_a()
        env = self.build()["envelope"]
        foreign_finding = "11111111-2222-3333-4444-555555555555"
        env["objects"]["case"] = [{
            "id": "case-src-1", "title": "Federated intrusion case",
            "description": "cross-org investigation", "status": "open",
            "priority": "high", "owner": "soc",
            "refs": [{"ref_type": "finding", "ref_id": foreign_finding}],
            "_classification": "internal",
            "_provenance": {"source_org_id": self.orgA.id,
                            "source_project_id": self.pA.id,
                            "source_object_id": "case-src-1",
                            "object_type": "case"}}]
        env["counts"]["case"] = 1
        env["integrity"]["hash"] = fed.package_hash(env)
        r = self.B.imports.import_envelope(
            self.orgB.id, envelope=env, target_project_id=self.pB.id,
            actor="carol")
        self.assertEqual(r["status"], "completed")
        case = self.svc.db.query_one(
            "SELECT id, description FROM investigation_cases WHERE org_id=?",
            (self.orgB.id,))
        self.assertIn("[federated:", case["description"])
        # the FOREIGN finding id was never linked (BOLA-safe)
        refs = self.svc.db.query(
            "SELECT ref_id FROM case_refs WHERE case_id=?", (case["id"],))
        self.assertEqual(
            [x["ref_id"] for x in refs if x["ref_id"] == foreign_finding],
            [])
        self.assertGreaterEqual(r["skipped"], 1)   # dangling ref skipped

    def test_threat_intel_match_reuses_ioc_catalog(self):
        self._pol_wide()
        self.seed_a()
        env = self.build()["envelope"]
        env["objects"]["threat_intel_match"] = [{
            "id": "m1", "ioc_type": "ipv4", "indicator": "203.0.113.9",
            "confidence": "high", "matched_on": "203.0.113.9",
            "_classification": "internal",
            "_provenance": {"source_org_id": self.orgA.id,
                            "source_project_id": self.pA.id,
                            "source_object_id": "m1",
                            "object_type": "threat_intel_match"}}]
        env["counts"]["threat_intel_match"] = 1
        env["integrity"]["hash"] = fed.package_hash(env)
        r = self.B.imports.import_envelope(
            self.orgB.id, envelope=env, target_project_id=self.pB.id,
            actor="carol")
        self.assertEqual(r["status"], "completed")
        n = self.db_count(
            "SELECT COUNT(*) n FROM threat_indicators WHERE org_id=? AND "
            "indicator LIKE '%203.0.113.9%'", (self.orgB.id,))
        self.assertEqual(n, 1)
        # replay: the indicator exists -> skipped, never duplicated
        env2 = copy.deepcopy(env)
        env2["provenance"]["created_by"] = "ioc-again"
        env2["integrity"]["hash"] = fed.package_hash(env2)
        r2 = self.B.imports.import_envelope(
            self.orgB.id, envelope=env2, target_project_id=self.pB.id,
            actor="carol")
        n2 = self.db_count(
            "SELECT COUNT(*) n FROM threat_indicators WHERE org_id=? AND "
            "indicator LIKE '%203.0.113.9%'", (self.orgB.id,))
        self.assertEqual(n2, 1)
        self.assertEqual(r2["status"], "completed")
        self.assertEqual(r["imported"], 3)    # asset + finding + IOC
        self.assertEqual(r2["imported"], 0)   # everything already exists
        self.assertGreaterEqual(r2["skipped"], 3)

    def test_repeated_rejections_raise_security_finding(self):
        self.seed_a()
        env = self.build()["envelope"]
        for i in range(3):
            e = copy.deepcopy(env)
            e["objects"]["finding"][0]["title"] = f"tamper-{i}"
            with self.assertRaises(errors.ValidationError):
                self.B.imports.import_envelope(
                    self.orgB.id, envelope=e,
                    target_project_id=self.pB.id, actor="carol")
        n = self.db_count(
            "SELECT COUNT(*) n FROM findings WHERE rule_id IN "
            "('fed-repeated-rejection','fed-integrity-mismatch')")
        self.assertGreaterEqual(n, 1)


# ---------------------------------------------------------------------------
# 8. Idempotency + concurrency on the import claim
# ---------------------------------------------------------------------------
class IdempotencyConcurrencyTests(FedBase):
    def test_in_progress_claim_blocks_second_import(self):
        self.seed_a()
        env = self.build()["envelope"]
        digest = fed.package_hash(env)
        # simulate a crashed/in-flight claim row (full column set)
        now = models.utcnow()
        self.svc.db.execute(
            "INSERT INTO federation_imports (id, org_id, package_id, "
            "package_hash, source_org_id, peer_id, policy_id, "
            "target_project_id, status, collision_strategy, object_count, "
            "imported_count, skipped_count, linked_count, detail_json, "
            "error, created_by, created_at, updated_at) VALUES "
            "(?,?,?,?,?,?,?,?, 'in_progress', ?, 0, 0, 0, 0, '{}', '', "
            "?, ?, ?)",
            ("imp-locked", self.orgB.id, env["package_id"], digest,
             self.orgA.id, self.peerB["id"], self.polB["id"], self.pB.id,
             "skip", "carol", now, now))
        with self.assertRaises(errors.DuplicateError) as cm:
            self.B.imports.import_envelope(
                self.orgB.id, envelope=env, target_project_id=self.pB.id,
                actor="carol")
        self.assertIn("in progress", str(cm.exception))
        # nothing was applied twice
        self.assertEqual(
            self.db_count("SELECT COUNT(*) n FROM findings WHERE "
                          "project_id=?", (self.pB.id,)), 0)

    def test_concurrent_imports_apply_once(self):
        self.seed_a(n_findings=4)
        env = self.build()["envelope"]
        results = []
        barrier = threading.Barrier(2, timeout=60)

        def attempt():
            try:
                barrier.wait()
                r = self.B.imports.import_envelope(
                    self.orgB.id, envelope=env,
                    target_project_id=self.pB.id, actor="carol")
                results.append(("ok", r))
            except errors.DuplicateError as e:
                results.append(("dup", str(e)))
            except errors.SecurityToolkitError as e:
                results.append(("err", str(e)))

        ts = [threading.Thread(target=attempt) for _ in range(2)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(timeout=180)
        self.assertEqual(len(results), 2, results)
        completed = [r for k, r in results
                     if k == "ok" and not r.get("duplicate")]
        self.assertEqual(len(completed), 1, results)
        # findings applied exactly once regardless of the race outcome
        self.assertEqual(
            self.db_count("SELECT COUNT(*) n FROM findings WHERE "
                          "project_id=? AND source='federation'",
                          (self.pB.id,)), 4)
        rows = self.svc.db.query(
            "SELECT status FROM federation_imports WHERE org_id=?",
            (self.orgB.id,))
        self.assertEqual(
            len([r for r in rows if r["status"] == "completed"]), 1)


# ---------------------------------------------------------------------------
# 9. Bulk operations through the EXISTING job engine
# ---------------------------------------------------------------------------
class BulkOperationTests(FedBase):
    def test_enqueue_requires_bounded_explicit_scope(self):
        with self.assertRaises(errors.ValidationError):
            self.A.bulk.enqueue(self.orgA.id, self.pA.id, op="share_all",
                                actor="alice")
        with self.assertRaises(errors.ValidationError):
            self.A.bulk.enqueue(self.orgB.id, self.pB.id, op="bulk_import",
                                actor="carol")     # no staged envelope
        with self.assertRaises(errors.NotFoundError):
            self.A.bulk.enqueue(self.orgA.id, self.pB.id, op="bulk_export",
                                peer_id=self.peerA["id"],
                                actor="alice")     # foreign project
        # an export without a peer enqueues but can never RUN (no
        # unbounded "share everything" exports)
        q = self.A.bulk.enqueue(self.orgA.id, self.pA.id, op="bulk_export",
                                actor="alice")
        self.assertTrue(q["job_id"])
        with self.assertRaises(errors.ValidationError) as cm:
            self.A.bulk_runner.run(org_id=self.orgA.id,
                                   project_id=self.pA.id, op="bulk_export",
                                   actor="alice")
        self.assertIn("explicit peer", str(cm.exception))

    def test_enqueue_creates_job_with_scalar_payload(self):
        q = self.A.bulk.enqueue(self.orgA.id, self.pA.id, op="bulk_export",
                                peer_id=self.peerA["id"],
                                policy_id=self.polA["id"], actor="alice")
        js = jobs_mod.JobService(
            self.svc, scanners_mod.ScannerRegistry()).job_get(q["job_id"])
        job = js
        self.assertEqual(job.job_type, "federation_bulk")
        self.assertEqual(job.profile, "federation-bulk")
        self.assertEqual(job.payload["op"], "bulk_export")
        self.assertEqual(job.payload["target"], "bulk:bulk_export")
        for v in job.payload.values():
            self.assertTrue(isinstance(v, (str, int, float, bool)))
        self.assertLessEqual(len(json.dumps(job.payload)), 4096)
        # re-enqueue creates a DISTINCT job (per-scan sequence)
        q2 = self.A.bulk.enqueue(self.orgA.id, self.pA.id, op="bulk_export",
                                 peer_id=self.peerA["id"],
                                 policy_id=self.polA["id"], actor="alice")
        self.assertNotEqual(q2["job_id"], q["job_id"])

    def test_worker_runs_bulk_export_with_counters(self):
        self.seed_a()
        q = self.A.bulk.enqueue(self.orgA.id, self.pA.id, op="bulk_export",
                                peer_id=self.peerA["id"],
                                policy_id=self.polA["id"], actor="alice")
        js = self.run_jobs(1)
        job = js.job_get(q["job_id"])
        self.assertEqual(job.status, "completed", job.error_message)
        stage = self.svc.db.query_one(
            "SELECT result_reference FROM scan_stages WHERE scan_id=? "
            "ORDER BY rowid DESC", (q["scan_id"],))
        self.assertIn("phase12.packages:1", stage["result_reference"])
        self.assertIn("phase12.objects:3", stage["result_reference"])
        self.assertEqual(
            self.db_count("SELECT COUNT(*) n FROM federation_packages "
                          "WHERE org_id=?", (self.orgA.id,)), 1)

    def test_worker_runs_bulk_import_from_staged_envelope(self):
        self.seed_a()
        env = self.build()["envelope"]
        q = self.B.bulk.enqueue(self.orgB.id, self.pB.id, op="bulk_import",
                                peer_id=self.peerB["id"], envelope=env,
                                strategy="skip", actor="carol")
        js = self.run_jobs(1)
        job = js.job_get(q["job_id"])
        self.assertEqual(job.status, "completed", job.error_message)
        stage = self.svc.db.query_one(
            "SELECT result_reference FROM scan_stages WHERE scan_id=? "
            "ORDER BY rowid DESC", (q["scan_id"],))
        self.assertIn("phase12.imported:2", stage["result_reference"])
        self.assertEqual(
            self.db_count("SELECT COUNT(*) n FROM findings WHERE "
                          "project_id=? AND source='federation'",
                          (self.pB.id,)), 1)
        # the staged envelope survived the storage redactor byte-stable
        scan = self.svc.scan_get(q["scan_id"])
        staged = (scan.raw or {}).get("package")
        self.assertEqual(fed.package_hash(staged),
                         env["integrity"]["hash"])

    def test_oversized_envelope_refused_at_enqueue(self):
        huge = {"schema_version": models.FEDERATION_SCHEMA_VERSION,
                "objects": {"asset": [{"id": f"a{i}", "value": "x" * 200}
                                      for i in range(20)]}}
        blob = json.dumps(huge)
        # shrink the inbound ceiling for the test: the guard reads the
        # module constant at call time
        original = fed.MAX_IMPORT_BYTES
        try:
            fed.MAX_IMPORT_BYTES = len(blob) - 1
            with self.assertRaises(errors.ValidationError) as cm:
                self.B.bulk.enqueue(self.orgB.id, self.pB.id,
                                    op="bulk_import", envelope=huge,
                                    actor="carol")
            self.assertIn("package_too_large", str(cm.exception))
        finally:
            fed.MAX_IMPORT_BYTES = original

    def test_deterministic_refusal_is_non_retryable(self):
        q = self.B.bulk.enqueue(self.orgB.id, self.pB.id,
                                op="bulk_classify",
                                params={"classification": "not-a-class"},
                                actor="carol")
        js = self.run_jobs(1)
        job = js.job_get(q["job_id"])
        self.assertEqual(job.status, "failed")     # never retry_wait
        self.assertEqual(job.error_code, "validation_rejected")
        self.assertEqual(job.attempt, 1)

    def test_cancelled_job_is_never_claimed(self):
        self.seed_a()
        q = self.A.bulk.enqueue(self.orgA.id, self.pA.id, op="bulk_export",
                                peer_id=self.peerA["id"],
                                policy_id=self.polA["id"], actor="alice")
        js = jobs_mod.JobService(self.svc, scanners_mod.ScannerRegistry())
        js.cancel(q["job_id"], actor="alice")
        self.assertIsNone(js.claim_next("w-other"))
        self.assertEqual(js.job_get(q["job_id"]).status, "cancelling")

    def test_cancel_check_stops_runner_mid_flight(self):
        self.seed_a(n_findings=3)
        calls = {"n": 0}

        def cancel_now():
            calls["n"] += 1
            raise errors.WorkerStopped("bulk cancelling at checkpoint")

        with self.assertRaises(errors.WorkerStopped):
            self.A.bulk_runner.run(
                org_id=self.orgA.id, project_id=self.pA.id,
                op="bulk_export", peer_id=self.peerA["id"],
                policy_id=self.polA["id"], actor="alice",
                cancel_check=cancel_now)
        self.assertGreaterEqual(calls["n"], 1)

    def test_sync_runner_all_four_ops(self):
        self.seed_a()
        r1 = self.A.bulk_runner.run(
            org_id=self.orgA.id, project_id=self.pA.id, op="bulk_export",
            peer_id=self.peerA["id"], policy_id=self.polA["id"],
            actor="alice")
        self.assertEqual(r1["op"], "bulk_export")
        self.assertEqual(r1["packages"], 1)
        env = self.build()["envelope"]
        r2 = self.B.bulk_runner.run(
            org_id=self.orgB.id, project_id=self.pB.id, op="bulk_import",
            peer_id=self.peerB["id"], envelope=env, strategy="skip",
            actor="carol")
        self.assertEqual(r2["imported"], 2)
        r3 = self.A.bulk_runner.run(
            org_id=self.orgA.id, project_id=self.pA.id, op="bulk_classify",
            params={"classification": "internal"}, actor="alice")
        self.assertEqual(r3["classification"], "internal")
        r4 = self.B.bulk_runner.run(
            org_id=self.orgB.id, project_id=self.pB.id,
            op="bulk_retention_preview", actor="carol")
        self.assertEqual(r4["kinds"], len(models.RETENTION_KINDS))

    def test_bulk_jobs_list_is_tenant_scoped(self):
        self.A.bulk.enqueue(self.orgA.id, self.pA.id, op="bulk_export",
                            peer_id=self.peerA["id"], actor="alice")
        lst = self.A.bulk.jobs_list(self.orgA.id)
        self.assertEqual(lst["total"], 1)
        self.assertEqual(self.A.bulk.jobs_list(self.orgB.id)["total"], 0)


# ---------------------------------------------------------------------------
# 10. RBAC — viewers and analysts get NOTHING (spec §34)
# ---------------------------------------------------------------------------
class RbacTierTests(unittest.TestCase):
    PHASE12 = {"federation.read", "federation.create", "federation.update",
               "federation.approve", "federation.revoke",
               "federation.export", "federation.import",
               "federation.manage_policy", "federation.bulk",
               "federation.audit", "integration.read", "integration.create",
               "integration.update", "integration.disable",
               "integration.export"}

    def test_permission_vocabulary_registered(self):
        self.assertTrue(self.PHASE12.issubset(set(rbac.PERMISSIONS)))
        # Phase 13 added 8 integration.* permissions (137 -> 145); the
        # Phase-12 subset above is unchanged.
        self.assertEqual(len(rbac.PERMISSIONS), 145)

    def test_viewer_and_analyst_get_nothing(self):
        for role in ("viewer", "analyst"):
            perms = rbac.permissions_for((role,))
            self.assertEqual(perms & self.PHASE12, set(), role)

    def test_security_manager_operates_but_never_approves(self):
        perms = rbac.permissions_for(("security_manager",))
        for p in ("federation.read", "federation.create",
                  "federation.update", "federation.export",
                  "federation.import", "federation.manage_policy",
                  "federation.bulk", "federation.audit", "integration.read",
                  "integration.create", "integration.update",
                  "integration.disable", "integration.export"):
            self.assertIn(p, perms)
        self.assertNotIn("federation.approve", perms)
        self.assertNotIn("federation.revoke", perms)

    def test_admin_and_owner_hold_approve_and_revoke(self):
        for role in ("admin", "owner"):
            perms = rbac.permissions_for((role,))
            self.assertTrue(self.PHASE12.issubset(perms), role)
        self.assertEqual(len(rbac.permissions_for(("viewer",))), 35)
        self.assertEqual(len(rbac.permissions_for(("analyst",))), 63)
        # Phase 13: security_manager +6 operational integration perms
        # (113 -> 119); admin/owner +2 high-impact (137 -> 145).
        self.assertEqual(
            len(rbac.permissions_for(("security_manager",))), 119)
        self.assertEqual(len(rbac.permissions_for(("admin",))), 145)

    def test_tiers_are_monotonic(self):
        v = rbac.permissions_for(("viewer",))
        a = rbac.permissions_for(("analyst",))
        s = rbac.permissions_for(("security_manager",))
        d = rbac.permissions_for(("admin",))
        o = rbac.permissions_for(("owner",))
        self.assertTrue(v <= a <= s <= d)
        self.assertEqual(d, o)


# ---------------------------------------------------------------------------
# 11. Tenant isolation
# ---------------------------------------------------------------------------
class TenantIsolationTests(FedBase):
    def test_cross_tenant_reads_are_not_found(self):
        self.seed_a()
        r = self.build()
        integ = self.A.integrations.create(
            self.orgA.id, name="iso-int", kind="siem_export",
            project_id=self.pA.id, actor="alice")
        with self.assertRaises(errors.NotFoundError):
            self.B.peers.get(self.orgB.id, self.peerA["id"])
        with self.assertRaises(errors.NotFoundError):
            self.B.policies.get(self.orgB.id, self.polA["id"])
        with self.assertRaises(errors.NotFoundError):
            self.B.packages.get(self.orgB.id, r["package_id"])
        with self.assertRaises(errors.NotFoundError):
            self.B.integrations.get(self.orgB.id, integ["id"])
        # lists never leak across tenants
        self.assertEqual(self.B.peers.list(self.orgB.id)["total"], 1)
        self.assertEqual(self.B.packages.list(self.orgB.id)["total"], 0)
        for item in self.B.peers.list(self.orgB.id)["items"]:
            self.assertEqual(item["peer_org_id"], self.orgA.id)

    def test_cross_tenant_mutations_fail_closed(self):
        with self.assertRaises(errors.NotFoundError):
            self.B.peers.revoke(self.orgB.id, self.peerA["id"],
                                reason="hostile", actor="mallory")
        with self.assertRaises(errors.NotFoundError):
            self.B.policies.update(self.orgB.id, self.polA["id"],
                                   max_objects=1, actor="mallory")

    def test_audit_and_jobs_are_tenant_scoped(self):
        self.seed_a()
        self.build()
        self.A.bulk.enqueue(self.orgA.id, self.pA.id, op="bulk_export",
                            peer_id=self.peerA["id"], actor="alice")
        for e in self.svc.audit_list_org(self.orgB.id, limit=200):
            if e.action.startswith("federation."):
                self.assertNotIn("package.created", e.action)
        self.assertEqual(self.A.bulk.jobs_list(self.orgB.id)["total"], 0)


# ---------------------------------------------------------------------------
# 12. External integration boundary
# ---------------------------------------------------------------------------
class FedIntegrationBoundaryTests(FedBase):
    ENDPOINT = "https://siem.example.com/ingest"

    def _integ(self, name="siem-main", **kw):
        kw.setdefault("endpoint_url", self.ENDPOINT)
        return self.A.integrations.create(
            self.orgA.id, name=name, kind=kw.pop("kind", "siem_export"),
            project_id=self.pA.id, actor="alice", **kw)

    def test_create_validates_kind_and_endpoint(self):
        with self.assertRaises(errors.ValidationError):
            self.A.integrations.create(self.orgA.id, name="bad-kind",
                                       kind="soap_bridge", actor="alice")
        with self.assertRaises(errors.ValidationError):
            self._integ(name="plain-http",
                        endpoint_url="http://siem.example.com/x")
        with self.assertRaises(errors.ValidationError):
            self._integ(name="private-ip",
                        endpoint_url="https://10.0.0.5/ingest")
        ok = self._integ()
        self.assertEqual(ok["status"], "enabled")
        with self.assertRaises(errors.DuplicateError):
            self._integ()

    def test_emit_is_allowlisted_redacted_bounded_audited(self):
        integ = self._integ()
        with self.assertRaises(errors.ValidationError):
            self.A.integrations.emit(self.orgA.id, integ["id"],
                                     "everything.happened", {},
                                     actor="alice")
        e = self.A.integrations.emit(
            self.orgA.id, integ["id"], "package.created",
            {"package_id": "p1", "objects": 3, "password": "hunter2",
             "api_key": "AKIAABCDEFGHIJKLMNOP"}, actor="alice")
        self.assertEqual(e["status"], "sent")
        self.assertEqual(e["outcome"], "sent")
        self.assertEqual(len(e["payload_sha256"]), 64)
        self.assertLessEqual(e["byte_size"], fed.MAX_WEBHOOK_PAYLOAD_BYTES)
        sent = json.dumps(self.provider_a.deliveries)
        self.assertNotIn("hunter2", sent)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", sent)
        # event row + audit trail exist
        evs = self.A.integrations.events_list(self.orgA.id)
        self.assertEqual(evs["total"], 1)
        self.assertEqual(evs["items"][0]["event_type"], "package.created")
        actions = [x.action for x in
                   self.svc.audit_list_org(self.orgA.id, limit=200)]
        self.assertIn("integration.emitted", actions)

    def test_oversized_payload_degrades_to_summary(self):
        integ = self._integ()
        e = self.A.integrations.emit(
            self.orgA.id, integ["id"], "bulk.completed",
            {"blob": "x" * (fed.MAX_WEBHOOK_PAYLOAD_BYTES * 3)},
            actor="alice")
        self.assertLessEqual(e["byte_size"], fed.MAX_WEBHOOK_PAYLOAD_BYTES)
        self.assertEqual(e["status"], "sent")

    def test_delivery_failure_is_recorded_not_swallowed(self):
        integ = self._integ()
        A2 = fed.FederationService(
            self.svc, provider=notify.RecordingProvider(fail=True))
        e = A2.integrations.emit(self.orgA.id, integ["id"],
                                 "package.created", {"x": 1}, actor="alice")
        self.assertEqual(e["status"], "failed")
        self.assertTrue(e["error"])
        evs = A2.integrations.events_list(self.orgA.id)
        self.assertEqual(evs["items"][0]["status"], "failed")

    def test_disable_blocks_emission(self):
        integ = self._integ()
        d = self.A.integrations.disable(self.orgA.id, integ["id"],
                                        actor="alice")
        self.assertEqual(d["status"], "disabled")
        e = self.A.integrations.emit(self.orgA.id, integ["id"],
                                     "package.created", {"x": 1},
                                     actor="alice")
        self.assertEqual(e["status"], "skipped")

    def test_webhook_event_vocabulary_exact(self):
        self.assertEqual(
            set(fed.WEBHOOK_EVENTS),
            {"package.created", "package.imported", "package.rejected",
             "peer.revoked", "policy.expired", "bulk.completed",
             "bulk.failed"})
        with self.assertRaises(errors.ValidationError):
            self.A.notify_integrations(self.orgA.id, "not.an.event", {})

    def test_notify_integrations_fanout_is_bounded(self):
        for i in range(3):
            self._integ(name=f"fan-{i}")
        out = self.A.notify_integrations(self.orgA.id, "peer.revoked",
                                         {"peer_id": self.peerA["id"]},
                                         project_id=self.pA.id,
                                         actor="system")
        self.assertEqual(len(out), 3)
        self.assertEqual([o["status"] for o in out], ["sent"] * 3)


# ---------------------------------------------------------------------------
# 13. Audit chain
# ---------------------------------------------------------------------------
class AuditTests(FedBase):
    def test_full_lifecycle_is_audited_and_chain_verifies(self):
        self.seed_a()
        r = self.build()
        self.A.packages.serialize(self.orgA.id, r["package_id"],
                                  actor="alice")
        env = r["envelope"]
        self.B.imports.import_envelope(self.orgB.id, envelope=env,
                                       target_project_id=self.pB.id,
                                       actor="carol")
        bad = copy.deepcopy(env)
        bad["objects"]["finding"][0]["title"] = "T"
        with self.assertRaises(errors.ValidationError):
            self.B.imports.import_envelope(
                self.orgB.id, envelope=bad,
                target_project_id=self.pB.id, actor="carol")
        actions_a = {e.action for e in
                     self.svc.audit_list_org(self.orgA.id, limit=300)}
        actions_b = {e.action for e in
                     self.svc.audit_list_org(self.orgB.id, limit=300)}
        for act in ("federation.peer.created", "federation.peer.approved",
                    "federation.policy.created",
                    "federation.package.created",
                    "federation.package.exported"):
            self.assertIn(act, actions_a, act)
        self.assertIn("federation.package.imported", actions_b)
        self.assertIn("federation.package.rejected", actions_b)
        self.assertIn("federation.integrity_failure", actions_b)
        ver = self.svc.audit_verify()
        self.assertTrue(ver["ok"], ver["issues"])
        self.assertEqual(ver["legacy"], 0)

    def test_audit_metadata_never_contains_payload_or_secrets(self):
        self.seed_a()
        self.build()
        for e in self.svc.audit_list_org(self.orgA.id, limit=300):
            blob = json.dumps(e.metadata, default=str).lower()
            self.assertNotIn("payload", blob)
            self.assertNotIn("sql syntax error", blob)
            self.assertNotIn("hunter2", blob)


# ---------------------------------------------------------------------------
# 14. Dashboard + read-only API
# ---------------------------------------------------------------------------
class FedDashboardTests(FedBase):
    def _state(self):
        self.seed_a()
        r = self.build()
        self.B.imports.import_envelope(self.orgB.id,
                                       envelope=r["envelope"],
                                       target_project_id=self.pB.id,
                                       actor="carol")
        bad = copy.deepcopy(r["envelope"])
        bad["objects"]["finding"][0]["title"] = "T"
        # a distinct declared hash keeps this rejection a SEPARATE claim
        # row (the completed import above already owns the original hash)
        bad["integrity"]["hash"] = "0" * 64
        with self.assertRaises(errors.ValidationError):
            self.B.imports.import_envelope(
                self.orgB.id, envelope=bad,
                target_project_id=self.pB.id, actor="carol")
        self.A.integrations.create(self.orgA.id, name="dash-int",
                                   kind="webhook", project_id=self.pA.id,
                                   actor="alice")
        self.A.bulk.enqueue(self.orgA.id, self.pA.id, op="bulk_export",
                            peer_id=self.peerA["id"], actor="alice")
        return r

    def test_snapshot_is_tenant_scoped(self):
        self._state()
        sa = dbmod.load_phase12_snapshot(self.db_path, self.orgA.id)
        sb = dbmod.load_phase12_snapshot(self.db_path, self.orgB.id)
        self.assertEqual(sa["peers"], {"active": 1})
        self.assertEqual(sa["packages"], 1)
        self.assertEqual(sb["packages"], 0)
        self.assertEqual(sb["imports"].get("completed"), 1)
        self.assertEqual(sb["imports"].get("rejected"), 1)
        self.assertTrue(sb["rejected_recent"])
        self.assertEqual(sa["bulk_jobs"], {"queued": 1})
        self.assertEqual(sb["bulk_jobs"], {})

    def test_page_renders_escaped_and_error_safe(self):
        self._state()
        snap = dbmod.load_phase12_snapshot(self.db_path, self.orgA.id)
        html = dbmod.phase12_page(snap)
        self.assertIn("Phase 12", html)
        self.assertIn("federation", html.lower())
        self.assertIn("/phase12", html)
        err = dbmod.phase12_page({"error": "x"})
        self.assertIn("unavailable", err)
        self.assertIn("Phase 12", err)

    def test_api_payload_is_metadata_only(self):
        self._state()
        api = dbmod.load_phase12_api(self.db_path, self.orgA.id)
        self.assertNotIn("error", api)
        for pkg in api["packages"]:
            self.assertNotIn("payload", pkg)
            self.assertEqual(len(pkg["integrity_hash"]), 64)
        self.assertTrue(api["peers"] and api["policies"])
        apib = dbmod.load_phase12_api(self.db_path, self.orgB.id)
        self.assertEqual(len(apib["packages"]), 0)
        self.assertEqual(len(apib["imports"]), 2)
        blob = json.dumps(api)
        self.assertNotIn("SQL syntax error", blob)

    def test_summary_facade_shape(self):
        self._state()
        s = self.A.summary(self.orgA.id)
        for key in ("generated_at", "peers", "policies", "packages",
                    "imports", "bulk_jobs", "integrations", "recent_audit"):
            self.assertIn(key, s)


# ---------------------------------------------------------------------------
# 15. Reuse of Phases 4-11 (never a parallel system)
# ---------------------------------------------------------------------------
class ReuseIntegrationTests(FedBase):
    def test_reporting_federation_section(self):
        import reporting
        self.seed_a()
        self.build()
        rep = reporting.ReportService(self.svc)
        snap = rep.snapshot(self.pA.id, "federation")
        section = snap["federation"]
        for key in ("peers_by_status", "active_peers", "policies_by_status",
                    "packages", "imports", "integrity_failures",
                    "policy_violations", "bulk_jobs_by_status",
                    "integrations_by_status",
                    "integration_events_by_status"):
            self.assertIn(key, section)
        self.assertEqual(section["packages"]["total"], 1)

    def test_monitoring_rule_templates_registered(self):
        import alerts
        names = {t["name"] for t in alerts.DEFAULT_RULE_TEMPLATES}
        for n in ("federation-integrity-failure",
                  "federation-import-rejected", "federation-peer-revoked",
                  "federation-peer-expired", "federation-policy-expired",
                  "bulk-operation-failed", "integration-delivery-failed"):
            self.assertIn(n, names)

    def test_devsecops_gate_signals(self):
        import devsecops as ds
        for key in ("max_federation_policy_violations",
                    "max_federation_integrity_failures",
                    "max_expired_federation_grants",
                    "max_unapproved_federation_exports",
                    "require_safe_external_integrations"):
            self.assertIn(key, ds.POLICY_SPEC)
        self.seed_a()
        env = self.build()["envelope"]
        bad = copy.deepcopy(env)
        bad["objects"]["finding"][0]["title"] = "T"
        with self.assertRaises(errors.ValidationError):
            self.B.imports.import_envelope(
                self.orgB.id, envelope=bad,
                target_project_id=self.pB.id, actor="carol")
        svc = ds.DevSecOpsService(self.svc)
        sig = svc._federation_signals(self.pB.id)
        self.assertEqual(sig["max_federation_integrity_failures"], 1)
        self.assertEqual(sig["max_federation_policy_violations"], 0)
        self.assertTrue(sig["require_safe_external_integrations"])

    def test_retention_preview_covers_new_kinds(self):
        self.seed_a()
        r = self.build()
        prev = self.A.gov.retention.preview(
            self.orgA.id, kind="federation_packages",
            project_id=self.pA.id, actor="alice",
            now="2099-01-01T00:00:00Z")
        self.assertEqual(prev["eligible"], 1)
        self.assertEqual(prev["held"], 0)
        self.assertEqual(prev["protected"], 1)
        # a hold protects the package (existing engine, no second system;
        # holds are keyed by the retention KIND, the Phase-11 convention)
        h = self.A.gov.retention.hold_create(
            self.orgA.id, object_type="federation_packages",
            object_id=r["package_id"], reason="investigation",
            actor="alice")
        prev2 = self.A.gov.retention.preview(
            self.orgA.id, kind="federation_packages",
            project_id=self.pA.id, actor="alice",
            now="2099-01-01T00:00:00Z")
        self.assertEqual(prev2["eligible"], 1)   # still retention-due ...
        self.assertEqual(prev2["held"], 1)       # ... but under hold ...
        self.assertEqual(prev2["protected"], 0)  # ... so nothing deletable
        self.A.gov.retention.hold_release(self.orgA.id, h["id"],
                                          reason="done", actor="alice")

    def test_imported_findings_flow_through_phase4_pipeline(self):
        self.seed_a()
        env = self.build()["envelope"]
        self.B.imports.import_envelope(self.orgB.id, envelope=env,
                                       target_project_id=self.pB.id,
                                       actor="carol")
        row = self.svc.db.query_one(
            "SELECT fingerprint, severity, lifecycle FROM findings WHERE "
            "project_id=? AND source='federation'", (self.pB.id,))
        self.assertTrue(row["fingerprint"])
        self.assertEqual(row["severity"], "High")
        self.assertEqual(row["lifecycle"], "open")


# ---------------------------------------------------------------------------
# 16. Failure injection / abuse paths
# ---------------------------------------------------------------------------
class FailureInjectionTests(FedBase):
    def test_import_never_leaves_claim_row_in_progress(self):
        self.seed_a()
        env = self.build()["envelope"]
        bad = copy.deepcopy(env)
        bad["objects"]["finding"][0]["title"] = "T"
        with self.assertRaises(errors.ValidationError):
            self.B.imports.import_envelope(
                self.orgB.id, envelope=bad,
                target_project_id=self.pB.id, actor="carol")
        stuck = self.db_count(
            "SELECT COUNT(*) n FROM federation_imports WHERE org_id=? AND "
            "status='in_progress'", (self.orgB.id,))
        self.assertEqual(stuck, 0)

    def test_worker_stopped_marks_import_failed_and_reraises(self):
        self.seed_a(n_findings=3)
        env = self.build()["envelope"]

        def stop():
            raise errors.WorkerStopped("bulk cancelling at checkpoint")

        with self.assertRaises(errors.WorkerStopped):
            self.B.imports.import_envelope(
                self.orgB.id, envelope=env,
                target_project_id=self.pB.id, actor="carol",
                cancel_check=stop)
        row = self.svc.db.query_one(
            "SELECT status, error FROM federation_imports WHERE org_id=?",
            (self.orgB.id,))
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["error"], "cancelled")

    def test_rate_limits_are_enforced(self):
        org_c = self.svc.org_create("OrgRate")
        original = dict(fed.RATE)
        try:
            fed.RATE["peer"] = (1, 60)
            self.A.peers.create(org_c.id, peer_org_id=self.orgB.id,
                                name="rate-1", actor="alice")
            with self.assertRaises(errors.RateLimitedError):
                self.A.peers.create(org_c.id, peer_org_id=self.orgB.id,
                                    name="rate-2", actor="alice")
        finally:
            fed.RATE.clear()
            fed.RATE.update(original)

    def test_stored_payload_tamper_detected_by_verify(self):
        self.seed_a()
        r = self.build()
        row = self.svc.db.query_one(
            "SELECT payload FROM federation_packages WHERE id=?",
            (r["package_id"],))
        core = store.loads(row["payload"], default={})
        core["objects"]["asset"][0]["value"] = "evil.example"
        self.svc.db.execute(
            "UPDATE federation_packages SET payload=? WHERE id=?",
            (store.dumps(core), r["package_id"]))
        v = self.A.packages.verify(self.orgA.id, r["package_id"])
        self.assertFalse(v["valid"])

    def test_envelope_with_huge_object_count_rejected(self):
        self.seed_a()
        env = self.build()["envelope"]
        # synthesize an envelope above the receiving policy cap
        cap = int(self.polB["max_objects"])
        filler = []
        for i in range(cap + 1):
            filler.append({
                "id": f"synthetic-{i}", "value": f"h{i}.example",
                "_classification": "internal",
                "_provenance": {"source_org_id": self.orgA.id,
                                "source_project_id": self.pA.id,
                                "source_object_id": f"synthetic-{i}",
                                "object_type": "asset"}})
        env["objects"]["asset"] = filler
        env["counts"]["asset"] = len(filler)
        env["integrity"]["hash"] = fed.package_hash(env)
        self.assertRejected(env, "limit_exceeded")


# ---------------------------------------------------------------------------
# 17. Bounded scale (proportional to the unit-suite budget; the literal
#     production figures from the spec — 10k findings / 500k package
#     objects / 100 concurrent jobs — are bounded by the SAME caps proven
#     here (MAX_PACKAGE_OBJECTS, keyset paging, bounded concurrency), and
#     the scaled-down figures are documented as an honest limitation of
#     the offline test environment in PHASE12_FINAL_REPORT.md)
# ---------------------------------------------------------------------------
class FedScaleTests(FedBase):
    def test_bulk_pipeline_under_load(self):
        t0 = time.monotonic()
        n = 120
        scan = self.svc.scan_create(self.pA.id, "web-audit")
        asset = self.svc.asset_add(self.pA.id, "hostname",
                                   "scale.example.com")
        for i in range(n):
            f = models.Finding(
                scan_id=scan.id, project_id=self.pA.id, asset_id=asset.id,
                title=f"Scale finding {i}", description="d",
                severity="Medium", category="misc", source="SecuAudit",
                rule_id=f"scale-{i}", raw={})
            self.svc.finding_ingest(f)
            self.svc.evidence_add(f.id, evidence_type="log", url="http://x",
                                  response_snippet="r" * 200,
                                  detection_reason="scale")
        self.A.policies.update(self.orgA.id, self.polA["id"],
                               max_objects=5000, actor="alice")
        self.B.policies.update(self.orgB.id, self.polB["id"],
                               max_objects=5000, actor="carol")
        r = self.build()
        self.assertEqual(r["object_count"], 1 + 2 * n)
        self.assertFalse(r["truncated"])
        imp = self.B.imports.import_envelope(
            self.orgB.id, envelope=r["envelope"],
            target_project_id=self.pB.id, actor="carol")
        self.assertEqual(imp["imported"], 1 + n)
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 150.0, f"scale run too slow: {elapsed:.1f}s")
        # 30 concurrent bulk job enqueues without id collision (the rate
        # bucket is widened for the test — the LIMIT itself is proven in
        # FailureInjectionTests)
        original = dict(fed.RATE)
        try:
            fed.RATE["bulk"] = (1000, 60)
            ids = set()
            for _ in range(30):
                q = self.A.bulk.enqueue(self.orgA.id, self.pA.id,
                                        op="bulk_export",
                                        peer_id=self.peerA["id"],
                                        policy_id=self.polA["id"],
                                        actor="alice")
                ids.add(q["job_id"])
            self.assertEqual(len(ids), 30)
        finally:
            fed.RATE.clear()
            fed.RATE.update(original)


# ---------------------------------------------------------------------------
# 18. CLI smoke (local mode + --as RBAC gates, fail closed)
# ---------------------------------------------------------------------------
class FedCliSmokeTests(FedBase):
    def _run(self, *argv, tok=""):
        full = [sys.executable, os.path.join(ROOT, "main.py"),
                "security", "--db", self.db_path]
        if tok:
            full += ["--as", tok]
        full += ["federation", *argv]
        return subprocess.run(full, capture_output=True, text=True,
                              timeout=180)

    def _token(self, username, roles):
        import identity as idm
        id_svc = idm.IdentityService(self.svc)
        id_svc.user_create(self.orgA.id, username,
                           username + "@x.example.com",
                           "Str0ng!Passw0rd", roles=roles, actor="test",
                           allow_any_role=True)
        tok = id_svc.login(username, "Str0ng!Passw0rd")
        for v in tok.values():
            if isinstance(v, str) and len(v) > 20:
                return v
        raise RuntimeError("no token")

    def test_cli_local_lifecycle(self):
        self.seed_a()
        o = self._run("peer-list", "--org", self.orgA.id)
        self.assertEqual(o.returncode, 0, o.stderr)
        self.assertIn("1 of 1 peers", o.stdout)
        o = self._run("policy-list", "--org", self.orgA.id)
        self.assertIn("1 of 1 policies", o.stdout)
        out = os.path.join(self.dir, "env.json")
        o = self._run("package-create", "--org", self.orgA.id,
                      "--peer-id", self.peerA["id"],
                      "--policy-id", self.polA["id"],
                      "--project", self.pA.id, "--out", out)
        self.assertEqual(o.returncode, 0, o.stdout + o.stderr)
        self.assertIn("integrity=sha256:", o.stdout)
        pkg = o.stdout.split("package ")[1].split(" ")[0]
        o = self._run("package-verify", "--org", self.orgA.id,
                      "--package-id", pkg)
        self.assertEqual(o.returncode, 0, o.stdout + o.stderr)
        self.assertIn("valid=True", o.stdout)
        o = self._run("package-import", "--org", self.orgB.id,
                      "--file", out, "--project", self.pB.id)
        self.assertEqual(o.returncode, 0, o.stdout + o.stderr)
        self.assertIn("status=completed", o.stdout)
        o = self._run("package-import", "--org", self.orgB.id,
                      "--file", out, "--project", self.pB.id)
        self.assertEqual(o.returncode, 0, o.stdout + o.stderr)
        self.assertIn("duplicate", o.stdout)
        o = self._run("bulk-export", "--org", self.orgA.id,
                      "--project", self.pA.id,
                      "--peer-id", self.peerA["id"], "--now")
        self.assertEqual(o.returncode, 0, o.stdout + o.stderr)
        self.assertIn("packages=1", o.stdout)
        o = self._run("bulk-jobs", "--org", self.orgA.id)
        self.assertEqual(o.returncode, 0, o.stdout + o.stderr)
        self.assertIn("bulk jobs", o.stdout)
        o = self._run("audit", "--org", self.orgB.id)
        self.assertEqual(o.returncode, 0, o.stderr)
        self.assertIn("federation/integration audit events", o.stdout)
        o = self._run("peer-revoke", "--org", self.orgA.id,
                      "--peer-id", self.peerA["id"], "--reason", "done")
        self.assertEqual(o.returncode, 0, o.stdout + o.stderr)
        self.assertIn("revoked", o.stdout)

    def test_cli_rbac_gates_fail_closed(self):
        vtok = self._token("fedview", ("viewer",))
        stok = self._token("fedsmgr", ("security_manager",))
        atok = self._token("fedadm", ("admin",))
        o = self._run("peer-list", "--org", self.orgA.id, tok=vtok)
        self.assertNotEqual(o.returncode, 0)
        self.assertIn("Forbidden", o.stdout + o.stderr)
        o = self._run("peer-list", "--org", self.orgA.id, tok=stok)
        self.assertEqual(o.returncode, 0, o.stdout + o.stderr)
        o = self._run("peer-approve", "--org", self.orgA.id,
                      "--peer-id", self.peerA["id"], tok=stok)
        self.assertNotEqual(o.returncode, 0)
        self.assertIn("Forbidden", o.stdout + o.stderr)
        o = self._run("peer-revoke", "--org", self.orgA.id,
                      "--peer-id", self.peerA["id"], "--reason", "x",
                      tok=atok)
        self.assertEqual(o.returncode, 0, o.stdout + o.stderr)
        # cross-tenant: an admin of A cannot list B's peers
        o = self._run("peer-list", "--org", self.orgB.id, tok=atok)
        self.assertNotEqual(o.returncode, 0)
        self.assertIn("Forbidden", o.stdout + o.stderr)

    def test_cli_bad_package_files_fail_closed(self):
        o = self._run("package-import", "--org", self.orgB.id,
                      "--file", os.path.join(self.dir, "missing.json"),
                      "--project", self.pB.id)
        self.assertNotEqual(o.returncode, 0)
        self.assertIn("cannot read package file", o.stdout + o.stderr)
        bad = os.path.join(self.dir, "bad.json")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        o = self._run("package-import", "--org", self.orgB.id,
                      "--file", bad, "--project", self.pB.id)
        self.assertNotEqual(o.returncode, 0)
        self.assertIn("not valid JSON", o.stdout + o.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)

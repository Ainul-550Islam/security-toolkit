#!/usr/bin/env python3
# ============================================================================
#  test_cloud_security.py — Phase-9 enterprise security test suite (spec §49).
#  Covers: provider registry + fixture determinism, exposure classifier
#  invariant, cloud account CRUD + credential encryption-at-rest, CLOUD rule
#  assessment + persistence, explicit failure taxonomy, container digest
#  identity + misconfig/CVE rules, Kubernetes declarative assessment (Secret
#  metadata only), IaC bounded parsing + secret redaction, tenant isolation
#  (BOLA), RBAC matrix, in-process job profiles, DevSecOps gate + SARIF
#  interop, dashboard snapshot isolation, and §50 deterministic scale.
#  Pure local: no internet, no live scanners.
#  Loaded by tests/run_tests.py so the WHOLE suite runs together.
# ============================================================================

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PY = os.path.join(os.path.dirname(HERE), "python")
sys.path.insert(0, PY)

import errors  # noqa: E402
import platform_service as pf  # noqa: E402
import cloud_security as cs  # noqa: E402
import container_security as csec  # noqa: E402
import kubernetes_security as ksec  # noqa: E402
import iac_security as isec  # noqa: E402
import rbac as rbac_mod  # noqa: E402
import jobs as jobs_mod  # noqa: E402
import worker as worker_mod  # noqa: E402
import devsecops as dso_mod  # noqa: E402
import sarif_export  # noqa: E402
from scanners import ScannerRegistry  # noqa: E402
import dashboard as dash_mod  # noqa: E402

CLOUD_RULES = cs.checks_list()
CONT_RULES = csec.container_checks_meta()
K8S_RULES = ksec.k8s_rules_meta()
IAC_RULES = isec.iac_rules_meta()


def make_service(tmp):
    return pf.PlatformService(os.path.join(tmp, "p9.db"))


class Phase9Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="p9t_")
        self.svc = make_service(self.tmp)
        self.org = self.svc.org_create("acme")
        self.org2 = self.svc.org_create("globex")
        self.proj = self.svc.project_create(self.org.id, "core")
        self.reg = ScannerRegistry()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def conn(self):
        return sqlite3.connect(self.svc.db_path)


# ============================================================================
# Provider registry + fixture determinism (§7, §8)
# ============================================================================
class TestProviderRegistry(Phase9Base):
    def test_provider_allowlist(self):
        self.assertIn("fixture", cs.registered_providers())
        self.assertIn("aws", cs.registered_providers())
        self.assertIn("azure", cs.registered_providers())
        self.assertIn("gcp", cs.registered_providers())

    def test_unknown_provider_rejected(self):
        svc = cs.CloudSecurityService(self.svc)
        with self.assertRaises(errors.ValidationError):
            svc.account_create(self.org.id, provider="openstack",
                               account_identifier="x",
                               credential_ref="env:T")

    def test_fixture_inventory_deterministic(self):
        svc = cs.CloudSecurityService(self.svc)
        acct = svc.account_create(self.org.id, provider="fixture",
                                  account_identifier="111122223333",
                                  credential_ref="env:T")
        inv1 = svc.inventory(self.org.id, acct.id)
        inv2 = svc.inventory(self.org.id, acct.id)
        self.assertEqual(len(inv1), 10)
        self.assertEqual(len(inv2), 10)
        ids1 = [cs.canonical_resource_id(r["provider"], r["account"],
                                         r["region"], r["resource_type"],
                                         r["resource_id"]) for r in inv1]
        ids2 = [cs.canonical_resource_id(r["provider"], r["account"],
                                         r["region"], r["resource_type"],
                                         r["resource_id"]) for r in inv2]
        self.assertEqual(ids1, ids2)          # byte-identical ordering
        self.assertIn("fixture|111122223333|global|storage_bucket|bkt-app",
                      ids1)


class TestExposureClassifier(Phase9Base):
    def test_exposure_invariant_internal_only(self):
        resource = {"provider": "fixture", "account": "a", "region": "r",
                    "resource_type": "compute_instance",
                    "resource_id": "i-1",
                    "attributes": {"internal_only": True,
                                   "public_ip": "203.0.113.9",
                                   "public_acl": True,
                                   "scheme": "internet-facing"}}
        self.assertEqual(cs.classify_exposure(resource), "internal")

    def test_exposure_public(self):
        resource = {"provider": "fixture", "account": "a", "region": "r",
                    "resource_type": "storage_bucket",
                    "resource_id": "b-1",
                    "attributes": {"public_acl": True}}
        self.assertEqual(cs.classify_exposure(resource), "internet_facing")
        resource["attributes"]["internal_only"] = True
        self.assertEqual(cs.classify_exposure(resource), "internal")

    def test_exposure_values(self):
        for ok in ("internal", "internet_facing"):
            self.assertIn(ok, ("internal", "internet_facing"))
        res = {"attributes": {}}
        got = cs.classify_exposure(res)
        self.assertIn(got, ("internal", "internet_facing"))


# ============================================================================
# Cloud account lifecycle + credentials (§11, §13, §32)
# ============================================================================
class TestCloudAccountLifecycle(Phase9Base):
    def test_account_create_and_stable_identity(self):
        svc = cs.CloudSecurityService(self.svc)
        a = svc.account_create(self.org.id, provider="fixture",
                               account_identifier="111122223333",
                               credential_ref="env:T")
        self.assertEqual(a.provider, "fixture")
        self.assertEqual(a.account_identifier, "111122223333")
        self.assertTrue(a.id)

    def test_duplicate_rejected(self):
        svc = cs.CloudSecurityService(self.svc)
        svc.account_create(self.org.id, provider="fixture",
                           account_identifier="111122223333",
                           credential_ref="env:T")
        with self.assertRaises(errors.DuplicateError):
            svc.account_create(self.org.id, provider="fixture",
                               account_identifier="111122223333",
                               credential_ref="env:T")

    def test_credential_encryption_at_rest(self):
        svc = cs.CloudSecurityService(self.svc)
        secret = "S3CR3T-KEY-ABCDEF-1234567890"
        a = svc.account_create(self.org.id, provider="fixture",
                               account_identifier="111122223333",
                               credential_ref="env:T",
                               credential_secret=secret)
        row = self.svc.db.query(
            "SELECT credential_enc, credential_hint FROM cloud_accounts "
            "WHERE id=?", (a.id,))[0]
        self.assertTrue(row["credential_enc"])
        self.assertNotIn(secret, row["credential_enc"])
        self.assertTrue(row["credential_hint"].startswith("enc:"))
        # non-reversible: hint never contains secret characters
        self.assertNotIn(secret[:8], row["credential_hint"])
        self.assertNotIn(secret, json.dumps(a.to_dict()))
        # view redaction (defense in depth)
        import redact
        view = redact.redact(a.to_dict())
        self.assertNotIn("S3CR3T", json.dumps(view))

    def test_cross_tenant_account_blocked(self):
        svc = cs.CloudSecurityService(self.svc)
        a = svc.account_create(self.org.id, provider="fixture",
                               account_identifier="111122223333",
                               credential_ref="env:T")
        with self.assertRaises(errors.NotFoundError):
            svc.account_get(self.org2.id, a.id)


# ============================================================================
# Cloud assessment + persistence (§13, §32)
# ============================================================================
class TestCloudAssessment(Phase9Base):
    def setUp(self):
        super().setUp()
        self.s = cs.CloudSecurityService(self.svc)
        self.acct = self.s.account_create(
            self.org.id, provider="fixture",
            account_identifier="111122223333", credential_ref="env:T")

    def test_scan_counts_and_persistence(self):
        out = self.s.scan(self.org.id, self.proj.id, self.acct.id)
        self.assertEqual(out["resource_count"], 10)
        self.assertEqual(out["assets"], 10)
        self.assertEqual(out["findings"], 11)
        rows = self.svc.db.query("SELECT COUNT(*) n FROM findings", ())
        self.assertEqual(rows[0]["n"], 11)
        self.assertEqual(self.svc.db.query(
            "SELECT COUNT(*) n FROM assets", ())[0]["n"], 10)
        self.assertEqual(self.svc.db.query(
            "SELECT COUNT(*) n FROM evidence", ())[0]["n"], 11)
        # every finding carries risk + observation (gate interop)
        self.assertEqual(self.svc.db.query(
            "SELECT COUNT(*) n FROM finding_observations", ())[0]["n"], 11)
        bad = self.svc.db.query(
            "SELECT COUNT(*) n FROM findings WHERE calc_version='' OR "
            "risk_score IS NULL", ())
        self.assertEqual(bad[0]["n"], 0)

    def test_findings_by_account_identifier(self):
        self.s.scan(self.org.id, self.proj.id, self.acct.id)
        fl = self.s.findings(self.org.id,
                             account_identifier="111122223333")
        self.assertEqual(len(fl), 11)
        # cross-tenant isolation
        self.assertEqual(len(self.s.findings(
            self.org2.id, account_identifier="111122223333")), 0)

    def test_rescan_idempotent(self):
        self.s.scan(self.org.id, self.proj.id, self.acct.id)
        out2 = self.s.scan(self.org.id, self.proj.id, self.acct.id)
        self.assertEqual(self.svc.db.query(
            "SELECT COUNT(*) n FROM findings", ())[0]["n"], 11)
        self.assertEqual(self.svc.db.query(
            "SELECT COUNT(*) n FROM assets", ())[0]["n"], 10)

    def test_rule_inventory(self):
        self.assertEqual(len(CLOUD_RULES), 10)
        for r in CLOUD_RULES:
            self.assertEqual(r["version"], "v1")
            self.assertRegex(r["rule_id"], r"^CLOUD-[A-Z0-9-]+\.*\d{3}$")
        ids = {r["rule_id"] for r in CLOUD_RULES}
        self.assertIn("CLOUD-STORAGE-PUBLIC-001", ids)
        self.assertIn("CLOUD-LB-PUBLIC-010", ids)

    def test_failure_taxonomy_invalid_credentials(self):
        a = self.s.account_create(self.org.id, provider="aws",
                                  account_identifier="123456789012",
                                  credential_ref="env:AWS_NOPE")
        with self.assertRaises(cs.AssessmentError) as cm:
            self.s.inventory(self.org.id, a.id)
        self.assertEqual(cm.exception.code, "invalid_cloud_credentials")

    def test_failure_taxonomy_provider_unavailable(self):
        import os as _os
        _os.environ["AWS_ACCESS_KEY_ID"] = "P9-TEST"
        try:
            a = self.s.account_create(self.org.id, provider="aws",
                                      account_identifier="123456789012",
                                      credential_ref="env:AWS_ACCESS_KEY_ID")
            with self.assertRaises(cs.AssessmentError) as cm:
                self.s.inventory(self.org.id, a.id)
            self.assertEqual(cm.exception.code,
                             "cloud_provider_unavailable")
        finally:
            _os.environ.pop("AWS_ACCESS_KEY_ID", None)


# ============================================================================
# Container security (§17–§20)
# ============================================================================
class TestContainerSecurity(Phase9Base):
    def setUp(self):
        super().setUp()
        self.s = csec.ContainerSecurityService(self.svc)
        self.img = self.s.image_register(
            self.org.id, repository="ghcr.io/acme/web",
            digest="sha256:" + "a" * 64)

    def test_digest_identity_ignores_tags(self):
        r1 = csec.parse_image_ref("ghcr.io/acme/web@sha256:" + "a" * 64)
        r2 = csec.parse_image_ref("ghcr.io/acme/web:v9@sha256:" + "a" * 64)
        self.assertEqual(r1["canonical"], r2["canonical"])
        self.assertTrue(r1["digest"].startswith("sha256:"))

    def test_bad_digest_rejected(self):
        for bad in ("sha256:zz", "sha256:" + "g" * 64, "v1", "latest"):
            with self.assertRaises(errors.ValidationError):
                csec.parse_image_ref(f"ghcr.io/acme/web@{bad}")
        # plain tag-only refs are valid (identity then includes the tag)
        self.assertTrue(csec.parse_image_ref("ghcr.io/acme/web:latest")
                        ["canonical"].endswith(":latest"))

    def test_duplicate_register_idempotent(self):
        img2 = self.s.image_register(self.org.id,
                                     repository="ghcr.io/acme/web",
                                     digest="sha256:" + "a" * 64)
        self.assertEqual(img2.id, self.img.id)

    def test_scan_misconfig_and_cve(self):
        out = self.s.scan(
            self.org.id, self.proj.id, self.img.id,
            packages=[{"name": "openssl", "version": "1.1.1k"},
                      {"name": "libssl", "version": "1.1.1k"}],
            vulnerabilities=[
                {"cve": "CVE-2022-0778", "package": "openssl",
                 "installed_version": "1.1.1k",
                 "fixed_version": "1.1.1l", "severity": "High",
                 "source": "debian"},
                {"cve": "CVE-2021-3618", "package": "libssl",
                 "installed_version": "1.1.1k", "severity": "Critical"}],
            image_metadata={"privileged": True, "host_network": True,
                            "run_as_uid": 0,
                            "capabilities": ["CAP_SYS_ADMIN"],
                            "limits": {"cpu": "1"},
                            "sensitive_env_keys": ["DB_PASSWORD"]})
        self.assertEqual(out["packages"], 2)
        self.assertEqual(out["findings"], 8)
        fl = self.s.findings(self.org.id, digest="sha256:" + "a" * 64)
        self.assertEqual(len(fl), 8)
        rules = {r["rule_id"] for r in fl}
        self.assertIn("CONT-CVE-CVE-2022-0778", rules)
        self.assertIn("CONT-PRIVILEGED-001", rules)

    def test_rescan_idempotent(self):
        self.s.scan(self.org.id, self.proj.id, self.img.id,
                    packages=[{"name": "openssl", "version": "1"}])
        self.s.scan(self.org.id, self.proj.id, self.img.id,
                    packages=[{"name": "openssl", "version": "1"}])
        # metadata-only finding set: root user + no resource limits
        self.assertEqual(self.svc.db.query(
            "SELECT COUNT(*) n FROM findings", ())[0]["n"], 2)

    def test_ceiling_explicit(self):
        with self.assertRaises(csec.ContainerAssessmentError) as cm:
            self.s.scan(self.org.id, self.proj.id, self.img.id,
                        packages=[{"name": "p", "version": "1"}] * 60000)
        self.assertEqual(cm.exception.code, "parser_failure")

    def test_cross_tenant_blocked(self):
        with self.assertRaises(errors.NotFoundError):
            self.s.image_get(self.org2.id, self.img.id)
        self.assertEqual(len(self.s.findings(self.org2.id)), 0)


# ============================================================================
# Kubernetes security (§21–§25)
# ============================================================================
K8S_DOC = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: app
          image: nginx:1.25
          securityContext:
            privileged: true
            capabilities:
              add: ["SYS_ADMIN"]
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: db-creds
                  key: password
---
kind: Service
metadata:
  name: web-svc
  namespace: prod
spec:
  type: LoadBalancer
  ports: [{port: 80}]
---
kind: Secret
metadata:
  name: db-creds
  namespace: prod
type: Opaque
data:
  password: c3VwZXItc2VjcmV0LXZhbHVl
stringData:
  token: never-store-this-value
"""


class TestKubernetesSecurity(Phase9Base):
    def setUp(self):
        super().setUp()
        self.s = ksec.KubernetesSecurityService(self.svc)
        self.cl = self.s.cluster_register(self.org.id, name="prod-cluster",
                                          endpoint="k8s.example:6443",
                                          credential_ref="env:KUBECONFIG",
                                          credential_secret="kb-secret-xyz")

    def test_cluster_register_and_dup(self):
        cl2 = self.s.cluster_register(self.org.id, name="prod-cluster")
        self.assertEqual(cl2.id, self.cl.id)
        self.assertTrue(self.cl.context.get("credential_enc"))
        hint = self.cl.context.get("credential_hint", "")
        self.assertTrue(hint.startswith("enc:"))

    def test_probe_unreachable_is_explicit(self):
        with self.assertRaises(ksec.KubernetesAssessmentError) as cm:
            self.s.probe(self.org.id, self.cl.id, timeout_s=0.5)
        self.assertEqual(cm.exception.code, "k8s_api_unavailable")

    def test_manifest_bounds(self):
        with self.assertRaises(ksec.KubernetesAssessmentError) as cm:
            ksec.parse_manifest("kind: Nope\nmetadata: {name: x}")
        self.assertEqual(cm.exception.code, "k8s_manifest_invalid")
        with self.assertRaises(ksec.KubernetesAssessmentError):
            ksec.parse_manifest("kind: Deployment\n  bad: [unclosed")
        self.assertEqual(
            ksec.parse_manifest("kind: Pod\nmetadata: {name: ok}\n"
                                "spec: {containers: []}")[0]["kind"], "Pod")

    def test_scan_rules_and_secret_metadata_only(self):
        out = self.s.scan(self.org.id, self.proj.id, self.cl.id,
                          manifests=[K8S_DOC])
        self.assertEqual(out["documents"], 3)
        self.assertEqual(out["secrets_observed"], 1)
        # Deployment: privileged/hostnet/caps/root/no-limits/secret-env/
        # unpinned/no-probes (8) + Service LoadBalancer (1)
        # + no NetworkPolicy in namespace (1)
        self.assertEqual(out["findings"], 10)
        fl = self.s.findings(self.org.id, namespace="prod")
        self.assertGreaterEqual(len(fl), 9)
        rules = {r["rule_id"] for r in fl}
        self.assertIn("K8S-NO-NETWORKPOLICY-015", rules)
        self.assertIn("K8S-NO-PROBES-016", rules)
        secs = self.s.secrets_observed(self.org.id, self.proj.id,
                                       self.cl.id)
        self.assertEqual(len(secs), 1)
        self.assertEqual(secs[0]["name"], "db-creds")
        self.assertEqual(secs[0]["key_names"], ["password", "token"])
        # secret VALUES never stored anywhere
        blob = json.dumps(secs) + str(self.conn().execute(
            "SELECT summary FROM scans").fetchall())
        self.assertNotIn("c3VwZXItc2VjcmV0", blob)
        self.assertNotIn("never-store-this-value", blob)

    def test_unsupported_kind_explicit(self):
        with self.assertRaises(ksec.KubernetesAssessmentError) as cm:
            self.s.scan(self.org.id, self.proj.id, self.cl.id,
                        manifests=["kind: CustomResourceDefinition"
                                   "\nmetadata: {name: x}"])
        self.assertEqual(cm.exception.code, "k8s_manifest_invalid")

    def test_yaml_alias_bomb_rejected(self):
        bomb = "a: &a [1,2,3]\n" + "".join(
            f"k{i}: *a\n" for i in range(2200)) + "kind: Pod\n"
        with self.assertRaises(ksec.KubernetesAssessmentError) as cm:
            ksec.parse_manifest(bomb)
        self.assertEqual(cm.exception.code, "parser_failure")

    def test_oversized_manifest_rejected(self):
        with self.assertRaises(ksec.KubernetesAssessmentError) as cm:
            ksec.parse_manifest("kind: Pod\n" + "x" * 600000)
        self.assertEqual(cm.exception.code, "parser_failure")

    def test_cross_tenant_blocked(self):
        with self.assertRaises(errors.NotFoundError):
            self.s.cluster_get(self.org2.id, self.cl.id)

    def test_rbac_binding_and_network_rules(self):
        rbac_doc = """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: super
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: User
    name: ops@acme
---
kind: RoleBinding
metadata:
  name: anon-read
  namespace: prod
roleRef:
  kind: Role
  name: viewer
subjects:
  - kind: User
    name: system:anonymous
---
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
          readinessProbe:
            httpGet: {path: /healthz, port: 8080}
          livenessProbe:
            httpGet: {path: /healthz, port: 8080}
---
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: prod
spec:
  podSelector: {}
"""
        out = self.s.scan(self.org.id, self.proj.id, self.cl.id,
                          manifests=[rbac_doc])
        rules = {r["rule_id"] for r in self.s.findings(self.org.id)}
        self.assertIn("K8S-CLUSTER-ADMIN-013", rules)
        self.assertIn("K8S-ANON-ACCESS-014", rules)
        # NetworkPolicy present in prod + probes present ⇒ those rules
        # must NOT fire (default ns has no workloads)
        self.assertNotIn("K8S-NO-NETWORKPOLICY-015", rules)
        self.assertNotIn("K8S-NO-PROBES-016", rules)


# ============================================================================
# IaC security (§26–§28)
# ============================================================================
TF_DOC = r'''
provider "aws" {
  region = "us-east-1"
}
resource "aws_s3_bucket" "assets" {
  bucket = "acme-assets"
  acl    = "public-read"
}
resource "aws_db_instance" "main" {
  engine              = "postgres"
  publicly_accessible = true
  storage_encrypted   = false
  master_password     = "Sup3rS3cret!Pass"
}
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_iam_policy" "admin" {
  policy = jsonencode({Statement = [{Effect = "Allow", Action = "*", Resource = "*"}]})
}
module "vpc" {
  source = "github.com/acme/vpc-module"
}
'''


class TestIacSecurity(Phase9Base):
    def setUp(self):
        super().setUp()
        self.s = isec.IacSecurityService(self.svc)

    def test_terraform_scan(self):
        out = self.s.scan(self.org.id, self.proj.id,
                          files=[{"name": "main.tf", "content": TF_DOC}],
                          source_name="repo")
        self.assertEqual(out["files"], 1)
        self.assertGreaterEqual(out["findings"], 6)
        fl = self.s.findings(self.org.id, source_name="repo")
        self.assertEqual(len(fl), out["findings"])
        rules = {r["rule_id"] for r in fl}
        self.assertIn("IAC-SECRET-HARDCODED-001", rules)
        self.assertIn("IAC-PUBLIC-STORAGE-002", rules)
        self.assertIn("IAC-SG-ANY-OPEN-004", rules)
        self.assertIn("IAC-IAM-WILDCARD-005", rules)

    def test_secret_values_never_persisted(self):
        self.s.scan(self.org.id, self.proj.id,
                    files=[{"name": "main.tf", "content": TF_DOC}],
                    source_name="repo")
        conn = self.conn()
        blob = str(conn.execute("SELECT group_concat(evidence) FROM "
                                "findings").fetchone()) + \
            str(conn.execute("SELECT group_concat(raw) FROM findings"
                             ).fetchone())
        self.assertNotIn("Sup3rS3cret", blob)
        # the marker survives redaction as the generic redactor marker
        self.assertIn("[REDACTED]", blob)
        recs = self.s.scan_records(self.org.id, self.proj.id)
        self.assertEqual(recs[0]["status"], "completed")
        self.assertGreaterEqual(recs[0]["secret_count"], 1)

    def test_cloudformation_scan(self):
        cfn = ("AWSTemplateFormatVersion: '2010-09-09'\nResources:\n"
               "  B:\n    Type: AWS::S3::Bucket\n    Properties:\n"
               "      AccessControl: PublicRead\n")
        out = self.s.scan(self.org.id, self.proj.id,
                          files=[{"name": "stack.yaml",
                                  "content": cfn}], source_name="cf")
        self.assertEqual(out["findings"], 3)  # public + no-enc + no-log

    def test_explicit_failures(self):
        with self.assertRaises(isec.IacAssessmentError) as cm:
            self.s.scan(self.org.id, self.proj.id, files=[])
        self.assertEqual(cm.exception.code, "iac_source_unavailable")
        with self.assertRaises(isec.IacAssessmentError) as cm:
            self.s.scan(self.org.id, self.proj.id,
                        files=[{"name": "a.tf", "content": "x"}] * 100)
        self.assertEqual(cm.exception.code, "iac_file_limit_exceeded")
        with self.assertRaises(isec.IacAssessmentError) as cm:
            self.s.scan(self.org.id, self.proj.id,
                        files=[{"name": "big.tf",
                                "content": "x" * 300000}])
        self.assertEqual(cm.exception.code, "parser_failure")

    def test_cross_tenant_isolation(self):
        out = self.s.scan(self.org.id, self.proj.id,
                          files=[{"name": "a.tf",
                                  "content": TF_DOC}], source_name="r2")
        fl2 = self.s.findings(self.org2.id, source_name="r2")
        self.assertEqual(len(fl2), 0)


# ============================================================================
# RBAC matrix (§42)
# ============================================================================
class TestPhase9Rbac(Phase9Base):
    def test_matrix_consistent(self):
        union = set()
        for r in rbac_mod.ROLE_ORDER:
            union |= rbac_mod.ROLE_PERMISSIONS[r]
        self.assertEqual(rbac_mod.PERMISSIONS - union, set())
        self.assertEqual(union - rbac_mod.PERMISSIONS, set())

    def test_role_tiers(self):
        p = rbac_mod.ROLE_PERMISSIONS
        self.assertIn("cloud.read", p["viewer"])
        self.assertIn("cloud.scan.run", p["analyst"])
        self.assertNotIn("cloud.scan.run", p["viewer"])
        self.assertIn("cloud.account.create", p["security_manager"])
        self.assertNotIn("cloud.account.create", p["analyst"])
        self.assertIn("cloud.account.delete", p["admin"])
        self.assertNotIn("cloud.account.delete", p["security_manager"])
        self.assertIn("kubernetes.cluster.delete", p["owner"])

    def test_has_permission(self):
        self.assertTrue(rbac_mod.has_permission(("analyst",),
                                                "iac.scan.run"))
        self.assertFalse(rbac_mod.has_permission(("viewer",),
                                                 "iac.scan.run"))


# ============================================================================
# In-process job profiles (§45: worker dispatcher)
# ============================================================================
class TestInProcessJobs(Phase9Base):
    def _run_job(self, scan, profile, payload, worker_id="w"):
        js = jobs_mod.JobService(self.svc, self.reg)
        job = js.create_job(scan.id, profile, payload)
        rt = worker_mod.WorkerRuntime(self.svc, None, js, self.reg,
                                      worker_id=worker_id,
                                      heartbeat_interval=0.5)
        rt.run_forever(max_jobs=1)
        return js.job_get(job.id)

    def _stage_ref(self, scan_id):
        rows = self.svc.db.query(
            "SELECT result_reference FROM scan_stages WHERE scan_id=? "
            "ORDER BY created_at DESC LIMIT 1", (scan_id,))
        return rows[0]["result_reference"] if rows else ""

    def test_cloud_scan_job(self):
        s = cs.CloudSecurityService(self.svc)
        acct = s.account_create(self.org.id, provider="fixture",
                                account_identifier="111122223333",
                                credential_ref="env:T")
        scan = self.svc.scan_create(self.proj.id, "cloud-scan",
                                    scope_ref="111122223333")
        job = self._run_job(scan, "cloud-scan",
                            {"account_id": acct.id})
        self.assertEqual(job.status, "completed")
        ref = self._stage_ref(scan.id)
        self.assertIn("phase9.findings:11", ref)
        self.assertIn("phase9.assets:10", ref)
        self.assertEqual(self.svc.db.query(
            "SELECT COUNT(*) n FROM findings WHERE scan_id=?",
            (scan.id,))[0]["n"], 11)

    def test_missing_entity_explicit_failure(self):
        scan = self.svc.scan_create(self.proj.id, "cloud-scan", "")
        job = self._run_job(scan, "cloud-scan", {})
        self.assertEqual(job.status, "failed")
        self.assertEqual(job.error_code, "payload_rejected")

    def test_iac_job_with_staged_material(self):
        scan = self.svc.scan_create(self.proj.id, "iac-scan", "")
        self.svc.scan_save_raw(scan.id, {"files": [{"name": "a.tf",
                                                    "content": TF_DOC}]})
        job = self._run_job(scan, "iac-scan", {"source_name": "repo-j"})
        self.assertEqual(job.status, "completed")
        self.assertIn("phase9.findings:", self._stage_ref(scan.id))

    def test_posture_snapshot_job(self):
        s = cs.CloudSecurityService(self.svc)
        acct = s.account_create(self.org.id, provider="fixture",
                                account_identifier="111122223333",
                                credential_ref="env:T")
        s.scan(self.org.id, self.proj.id, acct.id)
        scan = self.svc.scan_create(self.proj.id, "posture-snapshot", "")
        job = self._run_job(scan, "posture-snapshot", {})
        self.assertEqual(job.status, "completed")
        self.assertIn("phase9.open_findings:11",
                      self._stage_ref(scan.id))

    def test_in_process_profiles_registered(self):
        names = {p["name"] for p in self.reg.list_profiles()
                 if p["in_process"]}
        # Phase 13: `integration-delivery` joins the in-process family
        # (federation-bulk precedent) — pin updated transparently.
        self.assertEqual(names, {
            "cloud-scan", "cloud-inventory", "container-scan",
            "kubernetes-scan", "iac-scan", "posture-snapshot",
            "federation-bulk", "integration-delivery"})
        for name in names:
            with self.assertRaises(errors.ValidationError):
                self.reg.build_argv(name, "x", {}, "/tmp", 60)
        self.assertTrue(self.reg.IN_PROCESS_PROFILES)


# ============================================================================
# DevSecOps gate + SARIF interop (§32, §38)
# ============================================================================
class TestGateAndSarif(Phase9Base):
    def test_gate_fails_on_phase9_findings(self):
        s = cs.CloudSecurityService(self.svc)
        acct = s.account_create(self.org.id, provider="fixture",
                                account_identifier="111122223333",
                                credential_ref="env:T")
        dso = dso_mod.DevSecOpsService(self.svc, registry=self.reg)
        gate = dso.gate_create(self.proj.id, "p9", {"version": 1,
            "description": "p9 gate",
            "conditions": [
                {"key": "max_open_critical", "op": "<=", "value": 0,
                 "blocking": True},
                {"key": "require_scan_success", "op": "==", "value": True,
                 "blocking": True}]}, actor="test")
        run = dso.run_create(self.proj.id, gate["id"], "cloud-scan",
                             target="111122223333",
                             extra_payload={"account_id": acct.id},
                             run_key="p9t-1", actor="ci")
        js = jobs_mod.JobService(self.svc, self.reg)
        worker_mod.WorkerRuntime(self.svc, None, js, self.reg,
                                 worker_id="w", heartbeat_interval=0.5
                                 ).run_forever(max_jobs=1)
        res = dso.evaluate(run["run"]["id"], actor="ci")
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["summary"]["active_findings"], 11)
        self.assertEqual(res["summary"]["open_critical"], 3)
        self.assertGreater(res["summary"]["total_risk"], 0)
        self.assertTrue(any(v["key"] == "max_open_critical"
                            for v in res["violations"]))

    def test_sarif_export(self):
        s = cs.CloudSecurityService(self.svc)
        acct = s.account_create(self.org.id, provider="fixture",
                                account_identifier="111122223333",
                                credential_ref="env:T")
        s.scan(self.org.id, self.proj.id, acct.id)
        rows = self.svc.db.query(
            "SELECT * FROM findings WHERE rule_id LIKE 'CLOUD-%' LIMIT 3")
        findings = [{"id": r["id"], "title": r["title"],
                     "description": r["description"],
                     "severity": r["severity"],
                     "remediation": r["remediation"]} for r in rows]
        sarif = sarif_export.to_sarif(
            {"tool": "cloud-security", "target": "fixture/a",
             "findings": findings})
        self.assertEqual(sarif["version"], "2.1.0")
        runs = sarif["runs"][0]
        self.assertEqual(len(runs["results"]), 3)
        self.assertEqual(
            len(runs["tool"]["driver"]["rules"]), 3)


# ============================================================================
# Dashboard snapshot isolation (§41)
# ============================================================================
class TestAuditFailuresAreCounted(Phase9Base):
    def test_audit_write_failure_is_not_silent(self):
        """§34: an audit write failure must not be silently swallowed —
        the operation completes but the failure is logged + counted."""
        import metrics as metrics_mod
        s = cs.CloudSecurityService(self.svc)
        before = metrics_mod.snapshot()["counters"].get("audit_failures", 0)

        def boom(*a, **k):
            raise RuntimeError("audit backend unavailable")

        self.svc.audit = boom
        # account creation must still succeed (audit must not break the
        # operation) — the failure is surfaced via log + metric
        a = s.account_create(self.org.id, provider="fixture",
                             account_identifier="111122223333",
                             credential_ref="env:T")
        self.assertTrue(a.id)
        after = metrics_mod.snapshot()["counters"].get("audit_failures", 0)
        self.assertGreater(after, before)


class TestDashboardSnapshot(Phase9Base):
    def test_phase9_api_payload(self):
        s = cs.CloudSecurityService(self.svc)
        acct = s.account_create(self.org.id, provider="fixture",
                                account_identifier="111122223333",
                                credential_ref="env:T",
                                credential_secret="S3CR3T-KEY-1234567890")
        s.scan(self.org.id, self.proj.id, acct.id)
        isec.IacSecurityService(self.svc).scan(
            self.org.id, self.proj.id,
            files=[{"name": "a.tf", "content": TF_DOC}],
            source_name="api")
        payload = dash_mod.load_phase9_api(self.svc.db_path, self.org.id)
        self.assertEqual(len(payload["accounts"]), 1)
        iac_findings = self.svc.db.query(
            "SELECT COUNT(*) n FROM findings WHERE rule_id LIKE 'IAC-%'"
            )[0]["n"]
        db_findings = self.svc.db.query(
            "SELECT COUNT(*) n FROM findings WHERE rule_id LIKE 'CLOUD-%' "
            "OR rule_id LIKE 'IAC-%' OR rule_id LIKE 'CONT-%' OR "
            "rule_id LIKE 'K8S-%'")[0]["n"]
        self.assertEqual(db_findings, 11 + iac_findings)   # cloud + iac only
        self.assertEqual(len(payload["findings"]), db_findings)
        self.assertGreaterEqual(len(payload["iac"]), 1)
        # never any secret material
        blob = json.dumps(payload)
        self.assertNotIn("S3CR3T", blob)
        self.assertNotIn("Sup3rS3cret", blob)
        # org isolation
        other = dash_mod.load_phase9_api(self.svc.db_path, self.org2.id)
        self.assertEqual(other["accounts"], [])
        self.assertEqual(other["findings"], [])

    def test_snapshot_counts_and_org_isolation(self):
        s = cs.CloudSecurityService(self.svc)
        acct = s.account_create(self.org.id, provider="fixture",
                                account_identifier="111122223333",
                                credential_ref="env:T")
        s.scan(self.org.id, self.proj.id, acct.id)
        isec.IacSecurityService(self.svc).scan(
            self.org.id, self.proj.id,
            files=[{"name": "a.tf", "content": TF_DOC}],
            source_name="dash")
        snap = dash_mod.load_phase9_snapshot(self.svc.db_path, self.org.id)
        self.assertIn("fixture|active", snap["totals"]["accounts"])
        self.assertEqual(snap["findings"]["CLOUD"]["Critical"]["open"], 3)
        self.assertEqual(snap["findings"]["IAC"]["High"]["open"], 4)
        html = dash_mod.phase9_page(snap)
        self.assertIn("Phase 9", html)
        # other tenant sees nothing (accounts key absent, zero counts)
        snap2 = dash_mod.load_phase9_snapshot(self.svc.db_path,
                                              self.org2.id)
        self.assertNotIn("accounts", snap2["totals"])
        self.assertEqual(snap2["totals"]["images"],
                         {"total": 0, "scanned": 0})
        self.assertEqual(snap2["findings"]["CLOUD"], {})


# ============================================================================
# §50 — deterministic scale
# ============================================================================
class TestDeterministicScale(Phase9Base):
    def test_iac_scale_deterministic(self):
        # 60 files × 8 resources each = 480 resources; ceiling is explicit
        files = []
        for i in range(60):
            body = f'resource "aws_s3_bucket" "b{i}" {{\n  acl = "public-read"\n}}\n'
            for j in range(3):
                body += (f'resource "aws_db_instance" "d{i}_{j}" {{\n'
                         f'  publicly_accessible = true\n}}\n')
                body += (f'resource "aws_security_group" "s{i}_{j}" {{\n'
                         f'  ingress {{\n    from_port = 22\n    protocol '
                         f'= "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }}\n'
                         f'}}\n')
            files.append({"name": f"infra/f{i}.tf", "content": body})
        s = isec.IacSecurityService(self.svc)
        out1 = s.scan(self.org.id, self.proj.id, files=files,
                      source_name="scale")
        self.assertEqual(out1["files"], 60)
        self.assertEqual(out1["resources"], 420)   # 60 × 7 resources
        ids1 = {r["fingerprint"] for r in self.svc.db.query(
            "SELECT fingerprint FROM findings ORDER BY fingerprint")}
        # second run: byte-identical fingerprints (determinism)
        out2 = s.scan(self.org.id, self.proj.id, files=files,
                      source_name="scale")
        self.assertEqual(out2["findings"], out1["findings"])
        ids2 = {r["fingerprint"] for r in self.svc.db.query(
            "SELECT fingerprint FROM findings ORDER BY fingerprint")}
        self.assertEqual(ids1, ids2)

    def test_container_scale_bounded(self):
        s = csec.ContainerSecurityService(self.svc)
        img = s.image_register(self.org.id, repository="ghcr.io/a/b",
                               digest="sha256:" + "b" * 64)
        pkgs = [{"name": f"pkg-{i}", "version": "1.0"} for i in range(5000)]
        out = s.scan(self.org.id, self.proj.id, img.id, packages=pkgs)
        self.assertEqual(out["packages"], 5000)
        self.assertEqual(out["assets"], 1)


# ============================================================================
# §49 — failure injection (explicit, never silent)
# ============================================================================
class TestCloudFailureInjection(Phase9Base):
    def _register_boom_provider(self, code):
        """Register a deterministic failing provider (in-memory, test-only).
        Raises AssessmentError with the given explicit code."""
        safe = "".join(c for c in code if c.isalnum())[:8]
        pid = f"boom{int(hash(code) % 10**6):06d}{safe}"

        class _Boom(cs.CloudProvider):
            provider_id = pid
            display_name = "boom test provider"

            def inventory(self):
                raise cs.AssessmentError(
                    code, f"boom: {code}")

            def close(self):  # noqa: D401
                pass

        cs.register_provider(_Boom)
        return _Boom.provider_id

    def test_permission_denied_explicit(self):
        pid = self._register_boom_provider("cloud_permission_denied")
        s = cs.CloudSecurityService(self.svc)
        a = s.account_create(self.org.id, provider=pid,
                             account_identifier="999999999999",
                             credential_ref="env:T")
        with self.assertRaises(cs.AssessmentError) as cm:
            s.inventory(self.org.id, a.id)
        self.assertEqual(cm.exception.code, "cloud_permission_denied")

    def test_unexpected_provider_error_mapped(self):
        class _Explode(cs.CloudProvider):
            provider_id = "explode"
            display_name = "explode test provider"

            def inventory(self):
                raise RuntimeError("provider exploded")

        cs.register_provider(_Explode)
        s = cs.CloudSecurityService(self.svc)
        a = s.account_create(self.org.id, provider="explode",
                             account_identifier="999999999998",
                             credential_ref="env:T")
        with self.assertRaises(cs.AssessmentError) as cm:
            s.inventory(self.org.id, a.id)
        self.assertEqual(cm.exception.code, "inventory_failed")

    def test_missing_project_explicit(self):
        s = cs.CloudSecurityService(self.svc)
        acct = s.account_create(self.org.id, provider="fixture",
                                account_identifier="111122223333",
                                credential_ref="env:T")
        with self.assertRaises(errors.NotFoundError):
            s.scan(self.org.id, "no-such-project", acct.id)

    def test_missing_account_explicit(self):
        s = cs.CloudSecurityService(self.svc)
        with self.assertRaises(errors.NotFoundError):
            s.inventory(self.org.id, "00000000-0000-0000-0000-000000000000")


# ============================================================================
# §44 — concurrency: deterministic final state
# ============================================================================
class TestCloudConcurrency(Phase9Base):
    def test_4_concurrent_scans_single_final_state(self):
        import threading
        s = cs.CloudSecurityService(self.svc)
        acct = s.account_create(self.org.id, provider="fixture",
                                account_identifier="111122223333",
                                credential_ref="env:T")
        errors_list = []

        def worker_fn():
            try:
                s.scan(self.org.id, self.proj.id, acct.id)
            except Exception as e:                     # noqa: BLE001
                errors_list.append(repr(e))

        threads = [threading.Thread(target=worker_fn)
                   for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors_list, [])
        self.assertEqual(self.svc.db.query(
            "SELECT COUNT(*) n FROM findings", ())[0]["n"], 11)
        self.assertEqual(self.svc.db.query(
            "SELECT COUNT(*) n FROM assets", ())[0]["n"], 10)

    def test_duplicate_ingestion_idempotent(self):
        s = cs.CloudSecurityService(self.svc)
        acct = s.account_create(self.org.id, provider="fixture",
                                account_identifier="111122223333",
                                credential_ref="env:T")
        for _ in range(4):
            s.scan(self.org.id, self.proj.id, acct.id)
        self.assertEqual(self.svc.db.query(
            "SELECT COUNT(*) n FROM findings", ())[0]["n"], 11)
        self.assertEqual(self.svc.db.query(
            "SELECT COUNT(*) n FROM assets", ())[0]["n"], 10)


# ============================================================================
# Lifecycle: destructive ops (org-scoped) + audit
# ============================================================================
class TestLifecycle(Phase9Base):
    def test_account_delete_audited(self):
        s = cs.CloudSecurityService(self.svc)
        a = s.account_create(self.org.id, provider="fixture",
                             account_identifier="111122223333",
                             credential_ref="env:T")
        out = s.account_delete(self.org.id, a.id)
        self.assertEqual(out["deleted"], a.id)
        with self.assertRaises(errors.NotFoundError):
            s.account_get(self.org.id, a.id)
        acts = [r["action"] for r in self.svc.db.query(
            "SELECT action FROM audit_events WHERE action="
            "'cloud.account.deleted'")]
        self.assertEqual(len(acts), 1)

    def test_image_delete_org_scoped(self):
        s = csec.ContainerSecurityService(self.svc)
        img = s.image_register(self.org.id, repository="ghcr.io/a/b",
                               digest="sha256:" + "c" * 64)
        with self.assertRaises(errors.NotFoundError):
            s.image_delete(self.org2.id, img.id)
        s.image_delete(self.org.id, img.id)
        with self.assertRaises(errors.NotFoundError):
            s.image_get(self.org.id, img.id)

    def test_cluster_delete_org_scoped(self):
        s = ksec.KubernetesSecurityService(self.svc)
        cl = s.cluster_register(self.org.id, name="prod")
        with self.assertRaises(errors.NotFoundError):
            s.cluster_delete(self.org2.id, cl.id)
        s.cluster_delete(self.org.id, cl.id)
        with self.assertRaises(errors.NotFoundError):
            s.cluster_get(self.org.id, cl.id)

    def test_iac_record_delete_org_scoped(self):
        s = isec.IacSecurityService(self.svc)
        out = s.scan(self.org.id, self.proj.id,
                     files=[{"name": "a.tf", "content": TF_DOC}],
                     source_name="del")
        rec = s.scan_records(self.org.id, self.proj.id)[0]
        with self.assertRaises(errors.NotFoundError):
            s.record_delete(self.org2.id, self.proj.id, rec["id"])
        s.record_delete(self.org.id, self.proj.id, rec["id"])
        self.assertEqual(s.scan_records(self.org.id, self.proj.id), [])


# ============================================================================
# §30 — monitoring integration (existing scheduler accepts Phase-9 profiles)
# ============================================================================
class TestMonitoringReference(Phase9Base):
    def test_monitoring_policy_with_phase9_profile(self):
        import monitor as mon_mod
        mon = mon_mod.MonitoringService(self.svc, registry=self.reg)
        pol = mon.create(
            self.proj.id, "nightly-cloud", scan_profile="cloud-scan",
            schedule_type="interval", interval_minutes=1440,
            targets=["111122223333"], actor="test")
        self.assertEqual(pol["scan_profile"], "cloud-scan")
        self.assertEqual(pol["enabled"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
# ============================================================================
#  Phase-10 suite — security operations: threat-intel IOC catalog + safe
#  feed import (json/csv/stix), external attack surface (ingest, certificate
#  intelligence, inventory), TI correlation -> findings, prioritization
#  (risk reuse), threat clusters, investigation cases + timeline, security-
#  event enrichment, tenant isolation and rate limiting. Fully offline,
#  deterministic, temp SQLite per test class.
# ============================================================================
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = os.path.join(ROOT, "python")
sys.path.insert(0, PY)
sys.path.insert(0, HERE)

import errors
import models
import platform_service as pf

import rbac
from security_operations import (SecurityOperations, enrich_security_event,
                                 normalize_indicator, classify_indicator)


class Phase10Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="p10t_")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.svc = pf.PlatformService(os.path.join(self.dir, "t.db"))
        self.ops = SecurityOperations(self.svc)
        self.org = self.svc.org_create("TenantA")
        self.proj = self.svc.project_create(self.org.id, "Core")
        self.org2 = self.svc.org_create("TenantB")
        self.proj2 = self.svc.project_create(self.org2.id, "Core2")


# ---------------------------------------------------------------------------
# 1. Indicator normalization / classification
# ---------------------------------------------------------------------------
class NormalizeTests(Phase10Base):
    def test_classify_domain_and_ip(self):
        self.assertEqual(("example.com", "domain"),
                         normalize_indicator("Example.COM"))
        self.assertEqual(("203.0.113.5", "ipv4"),
                         normalize_indicator("203.0.113.5"))
        self.assertEqual(("2001:db8::1", "ipv6"),
                         normalize_indicator("2001:DB8::1"))
        self.assertEqual("domain", classify_indicator("evilbad.com"))
        self.assertEqual("hostname", classify_indicator("evil.example.com"))
        self.assertEqual("ipv4", classify_indicator("198.51.100.4"))

    def test_classify_hash_email_url(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        self.assertEqual("hash_md5", classify_indicator(md5))
        self.assertEqual(("d41d8cd98f00b204e9800998ecf8427e", "hash_md5"),
                         normalize_indicator(md5))
        self.assertEqual("email",
                         classify_indicator("badguy@example.com"))
        self.assertEqual("url",
                         classify_indicator("https://evil.example.com/x"))
        # URL normalization strips default port + lowercases host
        v, t = normalize_indicator("HTTPS://EVIL.Example.COM:443/a#f")
        self.assertEqual("url", t)
        self.assertEqual("https://evil.example.com:443/a#f", v)

    def test_rejects_unrecognized(self):
        for bad in ("", "   ", "not-an-indicator??", "a" * 600,
                    "https://user:pw@example.com/"):
            with self.assertRaises(errors.ValidationError):
                normalize_indicator(bad)

    def test_type_mismatch_rejected(self):
        with self.assertRaises(errors.ValidationError):
            normalize_indicator("203.0.113.9", "domain")
        with self.assertRaises(errors.ValidationError):
            normalize_indicator("d41d8cd98f00b204e9800998ecf8427e",
                                "hash_sha256")
        with self.assertRaises(errors.ValidationError):
            normalize_indicator("example.com", "bogus_type")


# ---------------------------------------------------------------------------
# 2. IOC catalog lifecycle
# ---------------------------------------------------------------------------
class IocCatalogTests(Phase10Base):
    def test_add_get_list_count(self):
        r = self.ops.iocs.add(self.org.id, "evilbad.com",
                              source="feed-a", confidence_level="high",
                              reference="https://ref.example/i1",
                              valid_until="2030-01-01T00:00:00Z",
                              actor="tester")
        self.assertEqual(r["indicator"], "evilbad.com")
        self.assertEqual(r["ioc_type"], "domain")
        self.assertEqual(r["source"], "feed-a")
        self.assertEqual(r["confidence_level"], "high")
        self.assertEqual(r["status"], "active")
        self.assertEqual(r["reference"], "https://ref.example/i1")
        self.assertEqual(self.ops.iocs.count(self.org.id), 1)
        rows = self.ops.iocs.list(self.org.id, ioc_type="domain",
                                  source="feed-a")
        self.assertEqual(len(rows), 1)
        self.assertEqual(self.ops.iocs.count(self.org.id,
                                             ioc_type="ipv4"), 0)

    def test_add_same_indicator_same_source_no_duplicate(self):
        self.ops.iocs.add(self.org.id, "evil.example.com", source="feed-a")
        self.ops.iocs.add(self.org.id, "Evil.Example.COM", source="feed-a")
        self.assertEqual(self.ops.iocs.count(self.org.id), 1)

    def test_add_validation(self):
        with self.assertRaises(errors.ValidationError):
            self.ops.iocs.add(self.org.id, "bad value")
        with self.assertRaises(errors.ValidationError):
            self.ops.iocs.add(self.org.id, "203.0.113.9",
                              confidence_level="hyper")
        with self.assertRaises(errors.ValidationError):
            self.ops.iocs.add(self.org.id, "203.0.113.9",
                              valid_until="not-a-date")
        with self.assertRaises(errors.NotFoundError):
            self.ops.iocs.add("no-such-org", "203.0.113.9")

    def test_update_revoke_sweep(self):
        iid = self.ops.iocs.add(self.org.id, "203.0.113.9",
                                confidence_level="medium")["id"]
        u = self.ops.iocs.update(self.org.id, iid,
                                 confidence_level="confirmed",
                                 status="active",
                                 reference="re-123")
        self.assertEqual(u["confidence_level"], "confirmed")
        with self.assertRaises(errors.ValidationError):
            self.ops.iocs.update(self.org.id, iid, status="bogus")
        rv = self.ops.iocs.revoke(self.org.id, iid, reason="false positive")
        self.assertEqual(rv["status"], "revoked")
        with self.assertRaises(errors.ValidationError):
            self.ops.iocs.revoke(self.org.id, iid, reason="   ")
        # expiry sweep: past valid_until -> expired
        eid = self.ops.iocs.add(self.org.id, "198.51.100.5",
                                valid_until="2020-01-01T00:00:00Z")["id"]
        res = self.ops.iocs.sweep_expiry(self.org.id,
                                         now="2021-01-01T00:00:00Z")
        self.assertEqual(res["expired"], 1)
        self.assertEqual(self.ops.iocs.get(self.org.id, eid)["status"],
                         "expired")

    def test_sources_and_export(self):
        self.ops.iocs.add(self.org.id, "a.example.com", source="s1")
        self.ops.iocs.add(self.org.id, "b.example.com", source="s1")
        self.ops.iocs.add(self.org.id, "203.0.113.1", source="s2",
                          confidence_level="confirmed")
        srcs = self.ops.iocs.sources(self.org.id)
        self.assertEqual({s["source"] for s in srcs}, {"s1", "s2"})
        exp = self.ops.iocs.export(self.org.id, status="active")
        self.assertEqual(exp["count"], 3)
        self.assertEqual({i["type"] for i in exp["indicators"]},
                         {"hostname", "ipv4"})
        self.assertFalse(exp["truncated"])
        # export never includes reference (metadata only)
        self.assertNotIn("reference", exp["indicators"][0])
        # typed export
        exp2 = self.ops.iocs.export(self.org.id, ioc_type="ipv4")
        self.assertEqual(exp2["count"], 1)

    def test_tenant_isolation(self):
        iid = self.ops.iocs.add(self.org.id, "203.0.113.9")["id"]
        with self.assertRaises(errors.NotFoundError):
            self.ops.iocs.get(self.org2.id, iid)
        with self.assertRaises(errors.NotFoundError):
            self.ops.iocs.update(self.org2.id, iid, status="active")
        with self.assertRaises(errors.NotFoundError):
            self.ops.iocs.revoke(self.org2.id, iid, reason="x")
        self.assertEqual(self.ops.iocs.list(self.org2.id), [])
        self.assertEqual(self.ops.iocs.count(self.org2.id), 0)
        # audit trail recorded in the owning tenant
        rows = self.svc.db.query(
            "SELECT action FROM audit_events WHERE org_id=?",
            (self.org.id,))
        self.assertTrue(any("ioc." in r["action"] or
                            "feed." in r["action"] for r in rows))


# ---------------------------------------------------------------------------
# 3. Feed import (json / csv / stix) + rate limiting
# ---------------------------------------------------------------------------
class FeedImportTests(Phase10Base):
    def test_import_json_auto(self):
        r = self.ops.iocs.import_feed(
            self.org.id, name="json-feed",
            data='[{"indicator":"203.0.113.9","type":"ipv4",'
                  '"confidence_level":"confirmed"},'
                  '{"value":"evil.example.com","type":"domain"},'
                  '{"value":"BAD VALUE"}]',
            actor="tester")
        self.assertEqual(r["format"], "auto")
        self.assertEqual(r["imported"], 2)
        self.assertEqual(r["skipped"], 1)
        self.assertEqual(r["records_seen"], 3)
        self.assertTrue(r["errors"])
        self.assertEqual(self.ops.iocs.count(self.org.id), 2)

    def test_import_csv(self):
        csv_data = ("indicator,type,confidence_level\n"
                    "198.51.100.7,ipv4,high\n"
                    "198.51.100.8,ipv4,low\n")
        r = self.ops.iocs.import_feed(self.org.id, name="csv-feed",
                                      data=csv_data, fmt="csv")
        self.assertEqual(r["imported"], 2)
        self.assertEqual(r["skipped"], 0)

    def test_import_stix_bundle(self):
        stix = {
            "type": "bundle",
            "objects": [
                {"type": "indicator",
                 "pattern": "[ipv4-addr:value = '198.51.100.42']"},
                {"type": "indicator",
                 "pattern": "[domain-name:value = 'x.example.com']"},
                {"type": "indicator",
                 "pattern": "AND [ NOT SUPPORTED ]"},
            ],
        }
        import json as _json
        r = self.ops.iocs.import_feed(self.org.id, name="stix-feed",
                                      data=_json.dumps(stix), fmt="stix")
        self.assertEqual(r["imported"], 2)
        self.assertEqual(r["skipped"], 0)  # unsupported pattern dropped at
        self.assertEqual(r["records_seen"], 2)  # parse time, before import
        got = {i["indicator"] for i in self.ops.iocs.list(self.org.id)}
        self.assertEqual(got, {"198.51.100.42", "x.example.com"})

    def test_import_dedup_and_bad_structure(self):
        data = '[{"value":"203.0.113.9","type":"ipv4"}]'
        self.ops.iocs.import_feed(self.org.id, name="f1", data=data)
        r = self.ops.iocs.import_feed(self.org.id, name="f2", data=data)
        self.assertEqual(r["imported"], 1)   # dedup: no second row
        self.assertEqual(self.ops.iocs.count(self.org.id), 1)
        with self.assertRaises(errors.ValidationError):
            self.ops.iocs.import_feed(self.org.id, name="bad",
                                      data='{"not":"a list"}')
        with self.assertRaises(errors.ValidationError):
            self.ops.iocs.import_feed(self.org.id, name="bad",
                                      data="not json at all")
        with self.assertRaises(errors.ValidationError):
            self.ops.iocs.import_feed(self.org.id, name="bad",
                                      data='[{"value":"1.2.3.4"}]',
                                      fmt="yaml")
        with self.assertRaises(errors.ValidationError):
            self.ops.iocs.import_feed(self.org.id, name="", data="[]")
        with self.assertRaises(errors.ValidationError):
            self.ops.iocs.import_feed(self.org.id, name="big",
                                      data="x" * (2 * 1024 * 1024 + 1))
        with self.assertRaises(errors.ValidationError):
            self.ops.iocs.import_feed(self.org.id, name="pickle",
                                      data="pickle payload")

    def test_import_rate_limited(self):
        data = '[{"value":"203.0.113.%d","type":"ipv4"}]'
        for i in range(10):
            self.ops.iocs.import_feed(
                self.org.id, name=f"f{i}", data=data % i)
        with self.assertRaises(errors.RateLimitedError):
            self.ops.iocs.import_feed(self.org.id, name="f10",
                                      data=data % 10)


# ---------------------------------------------------------------------------
# 4. External attack surface
# ---------------------------------------------------------------------------
class AttackSurfaceTests(Phase10Base):
    def test_ingest_creates_assets_and_events(self):
        r = self.ops.surface.ingest(
            self.org.id, self.proj.id,
            entries=[
                {"type": "domain", "value": "Example.COM"},
                {"type": "hostname", "value": "www.example.com",
                 "parent": "example.com"},
                {"type": "ip", "value": "203.0.113.9"},
                {"type": "ipv6", "value": "2001:db8::7"},
                {"type": "url", "value": "https://app.example.com/"},
                {"type": "service", "value": "www.example.com:443"},
                {"type": "bogus_type", "value": "x"},
                {"type": "domain", "value": ""},
            ],
            source="easm", actor="tester")
        self.assertEqual(r["accepted"], 6)
        self.assertEqual(r["rejected"], 2)
        self.assertEqual(r["observed"], 6)
        self.assertTrue(r["errors"])
        inv = self.ops.surface.inventory(self.org.id, self.proj.id)
        self.assertEqual(inv["count"], 6)
        types = {a["asset_type"] for a in inv["assets"]}
        self.assertTrue({"domain", "hostname", "ip", "ipv6", "url",
                         "service"} <= types)
        # parent relation materialized
        rel = self.svc.db.query_one(
            "SELECT * FROM asset_relations WHERE rel_type='subdomain_of'")
        self.assertIsNotNone(rel)
        # discovery events emitted once
        ev = self.svc.db.query_one(
            "SELECT COUNT(*) c FROM security_events WHERE event_type LIKE "
            "'%.discovered'")
        self.assertGreaterEqual(ev["c"], 4)

    def test_ingest_idempotent_observations(self):
        entries = [{"type": "hostname", "value": "www.example.com",
                    "parent": "example.com"}]
        self.ops.surface.ingest(self.org.id, self.proj.id, entries=entries,
                                source="s1")
        r2 = self.ops.surface.ingest(self.org.id, self.proj.id,
                                     entries=entries, source="s1")
        self.assertEqual(r2["accepted"], 1)
        # no duplicate discovery event for the same observation
        ev = self.svc.db.query_one(
            "SELECT COUNT(*) c FROM security_events WHERE "
            "event_type='hostname.discovered'")
        self.assertEqual(ev["c"], 1)

    def test_inventory_filter_and_tenant(self):
        self.ops.surface.ingest(
            self.org.id, self.proj.id,
            entries=[{"type": "domain", "value": "example.com"},
                     {"type": "ip", "value": "203.0.113.9"}])
        inv = self.ops.surface.inventory(self.org.id, self.proj.id,
                                         asset_type="domain")
        self.assertEqual(inv["count"], 1)
        self.assertEqual(inv["assets"][0]["value"], "example.com")
        with self.assertRaises(errors.NotFoundError):
            self.ops.surface.ingest(self.org2.id, self.proj.id,
                                    entries=[{"type": "ip",
                                              "value": "203.0.113.9"}])
        with self.assertRaises(errors.NotFoundError):
            self.ops.surface.inventory(self.org2.id, self.proj.id)

    def test_certificate_rules(self):
        # cleaning cert: RSA-2048/SHA-256, SANs cover the asset
        r = self.ops.surface.certificate_register(
            self.org.id, self.proj.id, asset_id="",
            subject="CN=www.example.com", issuer="CN=Test CA",
            sans=["www.example.com"], valid_from="2020-01-01T00:00:00Z",
            valid_to="2030-01-01T00:00:00Z",
            fingerprint="AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:"
                        "AA:BB:CC:DD", key_algorithm="rsa-2048",
            signature_algorithm="sha256withrsa", actor="easm")
        self.assertEqual(r["checks_run"], 5)
        self.assertEqual(r["findings"], [])
        # weak algorithm + mismatched SAN + unexpected SAN
        self.ops.surface.ingest(
            self.org.id, self.proj.id,
            entries=[{"type": "hostname", "value": "api.example.com"}])
        asset = self.ops.surface.inventory(
            self.org.id, self.proj.id, asset_type="hostname")["assets"][0]
        r2 = self.ops.surface.certificate_register(
            self.org.id, self.proj.id, asset_id=asset["id"],
            subject="CN=api.example.com", issuer="CN=Test CA",
            sans=["api.other.org"],
            valid_from="2020-01-01T00:00:00Z",
            valid_to="2030-01-01T00:00:00Z",
            fingerprint="00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:"
                        "00:11:22:33", key_algorithm="rsa",
            signature_algorithm="sha1withrsa", actor="easm")
        self.assertEqual(len(r2["findings"]), 3)
        frows = self.svc.db.query(
            "SELECT rule_id FROM findings WHERE project_id=?",
            (self.proj.id,))
        rules = {f["rule_id"] for f in frows}
        self.assertTrue({"AS-CERT-WEAK-004", "AS-CERT-MISMATCH-003",
                         "AS-CERT-UNEXPECTED-SAN-005"} <= rules)

    def test_certificate_rejects_private_keys(self):
        with self.assertRaises(errors.ValidationError):
            self.ops.surface.certificate_register(
                self.org.id, self.proj.id, asset_id="",
                subject="CN=x", issuer="CN=CA",
                sans=["private_key_do_not_store"], valid_from="2020-01-01",
                valid_to="2030-01-01", fingerprint="A" * 40)


# ---------------------------------------------------------------------------
# 5. TI correlation -> findings
# ---------------------------------------------------------------------------
class ThreatCorrelationTests(Phase10Base):
    def _seed(self):
        self.ops.iocs.add(self.org.id, "203.0.113.99",
                          confidence_level="confirmed")
        self.ops.surface.ingest(
            self.org.id, self.proj.id,
            entries=[{"type": "ip", "value": "203.0.113.99"},
                     {"type": "hostname", "value": "payload.example.com"}])

    def test_match_finds_and_dedups(self):
        self._seed()
        r = self.ops.correlation.match(self.org.id, self.proj.id)
        self.assertEqual(r["new_matches"], 1)
        self.assertEqual(r["existing_matches"], 0)
        self.assertEqual(r["findings_created"], 1)
        self.assertEqual(r["iocs_evaluated"], 1)
        # dedup: second run finds nothing new
        r2 = self.ops.correlation.match(self.org.id, self.proj.id)
        self.assertEqual(r2["new_matches"], 0)
        self.assertEqual(r2["existing_matches"], 1)
        self.assertEqual(r2["findings_created"], 0)
        self.assertEqual(self.ops.correlation.matches_count(self.org.id), 1)
        m = self.ops.correlation.matches_list(self.org.id)[0]
        self.assertEqual(m["indicator"], "203.0.113.99")
        self.assertEqual(m["ioc_type"], "ipv4")
        f = self.svc.db.query_one(
            "SELECT * FROM findings WHERE project_id=?", (self.proj.id,))
        self.assertEqual(f["category"], "threat_intel")
        self.assertEqual(f["rule_id"], "TI-IOC-IPV4")
        self.assertIn(f["lifecycle"], ("open", "under_investigation"))
        # ioc.matched event issued once for the new match only
        ev = self.svc.db.query_one(
            "SELECT COUNT(*) c FROM security_events WHERE "
            "event_type='ioc.matched'")
        self.assertEqual(ev["c"], 1)

    def test_match_confidence_gate(self):
        self.ops.iocs.add(self.org.id, "198.51.100.66",
                          confidence_level="low")
        self.ops.surface.ingest(
            self.org.id, self.proj.id,
            entries=[{"type": "ip", "value": "198.51.100.66"}])
        r = self.ops.correlation.match(self.org.id, self.proj.id,
                                       min_confidence="high")
        self.assertEqual(r["findings_created"], 0)
        r2 = self.ops.correlation.match(self.org.id, self.proj.id,
                                        min_confidence="low")
        self.assertEqual(r2["findings_created"], 1)

    def test_match_tenant_isolation(self):
        self.ops.iocs.add(self.org.id, "203.0.113.99",
                          confidence_level="confirmed")
        self.ops.surface.ingest(
            self.org2.id, self.proj2.id,
            entries=[{"type": "ip", "value": "203.0.113.99"}])
        # same IOC family exists in org2? No — org2 has no IOCs, so the
        # cross-tenant asset is scanned with an empty catalog.
        r = self.ops.correlation.match(self.org2.id, self.proj2.id)
        self.assertEqual(r["findings_created"], 0)
        with self.assertRaises(errors.NotFoundError):
            self.ops.correlation.match(self.org2.id, self.proj.id)


# ---------------------------------------------------------------------------
# 6. Prioritization + threat clusters
# ---------------------------------------------------------------------------
class ThreatPriorityClusterTests(Phase10Base):
    def test_prioritize_uses_asset_context(self):
        self.ops.iocs.add(self.org.id, "203.0.113.99",
                          confidence_level="confirmed")
        self.ops.surface.ingest(
            self.org.id, self.proj.id,
            entries=[{"type": "ip", "value": "203.0.113.99"}])
        self.ops.correlation.match(self.org.id, self.proj.id)
        asset = self.ops.surface.inventory(
            self.org.id, self.proj.id, asset_type="ip")["assets"][0]
        self.svc.db.execute(
            "UPDATE assets SET criticality='high', exposure='internet_facing' "
            "WHERE id=?", (asset["id"],))
        rows = self.ops.prioritization.prioritize(self.org.id, self.proj.id)
        self.assertEqual(len(rows), 1)
        top = rows[0]
        self.assertGreater(top["risk_score"], 0)
        self.assertEqual(top["asset_criticality"], "high")
        self.assertEqual(top["asset_exposure"], "internet_facing")
        self.assertEqual(top["rule_id"], "TI-IOC-IPV4")
        self.assertIn(top["risk_level"], ("low", "medium", "high",
                                          "critical", "info"))

    def test_prioritize_sorted_deterministic(self):
        for ip in ("203.0.113.1", "203.0.113.2"):
            self.ops.iocs.add(self.org.id, ip,
                              confidence_level="confirmed")
        self.ops.surface.ingest(
            self.org.id, self.proj.id,
            entries=[{"type": "ip", "value": "203.0.113.1"},
                     {"type": "ip", "value": "203.0.113.2"}])
        self.ops.correlation.match(self.org.id, self.proj.id)
        rows = self.ops.prioritization.prioritize(self.org.id, self.proj.id)
        self.assertEqual(len(rows), 2)
        scores = [r["risk_score"] for r in rows]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_cluster_build_list_members(self):
        # Two IOCs sharing a signal (same registrable domain family)
        self.ops.iocs.add(self.org.id, "bad.example.com",
                          confidence_level="confirmed")
        self.ops.iocs.add(self.org.id, "sub.bad.example.com",
                          confidence_level="confirmed")
        self.ops.surface.ingest(
            self.org.id, self.proj.id,
            entries=[
                {"type": "domain", "value": "bad.example.com"},
                {"type": "hostname", "value": "sub.bad.example.com"}])
        self.ops.correlation.match(self.org.id, self.proj.id)
        res = self.ops.clusters.build(self.org.id, self.proj.id)
        self.assertGreaterEqual(res.get("clusters_updated", 0), 1)
        clusters = self.ops.clusters.list(self.org.id,
                                          project_id=self.proj.id)
        self.assertGreaterEqual(len(clusters), 1)
        c = clusters[0]
        self.assertIn("label", c)
        self.assertGreaterEqual(c["member_count"], 2)
        members = self.ops.clusters.members(self.org.id, c["id"])
        self.assertEqual(len(members), c["member_count"])
        self.assertEqual({m["ref_type"] for m in members}, {"finding"})
        # deterministic rebuild: no new clusters
        res2 = self.ops.clusters.build(self.org.id, self.proj.id)
        self.assertEqual(res2.get("clusters_updated", 0), 0)

    def test_cluster_tenant_isolation(self):
        with self.assertRaises(errors.NotFoundError):
            self.ops.clusters.members(self.org2.id, "no-such-cluster")
        clusters = self.ops.clusters.list(self.org2.id)
        self.assertEqual(clusters, [])


# ---------------------------------------------------------------------------
# 7. Investigation cases
# ---------------------------------------------------------------------------
class InvestigationCaseTests(Phase10Base):
    def test_create_get_list_update(self):
        c = self.ops.cases.create(self.org.id, self.proj.id,
                                  title="Suspicious traffic",
                                  description="IOC hit on edge",
                                  priority="High", owner="analyst-1",
                                  actor="tester")
        self.assertEqual(c["title"], "Suspicious traffic")
        self.assertEqual(c["priority"], "high")      # normalized
        self.assertEqual(c["status"], "open")
        self.assertEqual(c["owner"], "analyst-1")
        self.assertEqual(c["refs"], [])
        got = self.ops.cases.get(self.org.id, c["id"])
        self.assertEqual(got["id"], c["id"])
        self.assertEqual(len(self.ops.cases.list(self.org.id)), 1)
        self.assertEqual(
            len(self.ops.cases.list(self.org.id, status="open")), 1)
        self.assertEqual(
            len(self.ops.cases.list(self.org.id, status="closed")), 0)
        u = self.ops.cases.update(self.org.id, c["id"],
                                  title="Escalated", priority="critical")
        self.assertEqual(u["title"], "Escalated")
        self.assertEqual(u["priority"], "critical")

    def test_create_validation(self):
        with self.assertRaises(errors.ValidationError):
            self.ops.cases.create(self.org.id, self.proj.id, title="ab")
        with self.assertRaises(errors.ValidationError):
            self.ops.cases.create(self.org.id, self.proj.id,
                                  title="ok title", priority="p0")
        with self.assertRaises(errors.NotFoundError):
            self.ops.cases.create(self.org2.id, self.proj.id,
                                  title="cross tenant")
        with self.assertRaises(errors.NotFoundError):
            self.ops.cases.get(self.org.id, "no-such-case")

    def test_assign_close_transitions_timeline(self):
        c = self.ops.cases.create(self.org.id, self.proj.id,
                                  title="Case A", actor="tester")
        a = self.ops.cases.assign(self.org.id, c["id"], "sec-ops-1",
                                  actor="tester")
        self.assertEqual(a["owner"], "sec-ops-1")
        st = self.ops.cases.set_status(self.org.id, c["id"], "investigating",
                                       actor="tester")
        self.assertEqual(st["status"], "investigating")
        st2 = self.ops.cases.set_status(self.org.id, c["id"], "open",
                                        actor="tester")
        self.assertEqual(st2["status"], "open")
        cl = self.ops.cases.close(self.org.id, c["id"], reason="resolved",
                                  actor="tester")
        self.assertEqual(cl["status"], "closed")
        self.assertNotEqual(cl["closed_at"], "")
        self.assertEqual(cl["closed_reason"], "resolved")
        # closed state only reopens explicitly
        with self.assertRaises(errors.LifecycleError):
            self.ops.cases.set_status(self.org.id, c["id"], "investigating",
                                      actor="tester")
        ro = self.ops.cases.set_status(self.org.id, c["id"], "open",
                                       actor="tester")
        self.assertEqual(ro["status"], "open")
        tl = self.ops.cases.timeline(self.org.id, c["id"])
        self.assertGreaterEqual(len(tl), 6)
        kinds = {e["entry_type"] for e in tl}
        self.assertTrue({"case.created", "case.assigned",
                         "case.status_changed"} <= kinds)
        with self.assertRaises(errors.NotFoundError):
            self.ops.cases.timeline(self.org.id, "nope")

    def test_link_unlink_reference(self):
        c = self.ops.cases.create(self.org.id, self.proj.id,
                                  title="Linked case")
        iid = self.ops.iocs.add(self.org.id, "203.0.113.9")["id"]
        l = self.ops.cases.link(self.org.id, c["id"], "ioc", iid,
                                note="seen in SIEM", actor="tester")
        self.assertEqual(len(l["refs"]), 1)
        self.assertEqual(l["refs"][0]["ref_type"], "ioc")
        self.assertEqual(l["refs"][0]["ref_id"], iid)
        # cross-tenant reference rejected (no existence leak)
        with self.assertRaises(errors.NotFoundError):
            other = self.ops.iocs.add(self.org2.id, "198.51.100.9")["id"]
            self.ops.cases.link(self.org.id, c["id"], "ioc", other)
        u = self.ops.cases.unlink(self.org.id, c["id"], "ioc", iid)
        self.assertEqual(u["refs"], [])

    def test_case_tenant_isolation(self):
        c = self.ops.cases.create(self.org.id, self.proj.id,
                                  title="Tenant case")
        with self.assertRaises(errors.NotFoundError):
            self.ops.cases.get(self.org2.id, c["id"])
        with self.assertRaises(errors.NotFoundError):
            self.ops.cases.close(self.org2.id, c["id"], reason="x")
        self.assertEqual(self.ops.cases.list(self.org2.id), [])

    def test_case_events_emitted(self):
        c = self.ops.cases.create(self.org.id, self.proj.id,
                                  title="Event case")
        self.ops.cases.assign(self.org.id, c["id"], "analyst-2")
        self.ops.cases.close(self.org.id, c["id"], reason="done")
        ev = self.svc.db.query(
            "SELECT event_type FROM security_events WHERE project_id=?",
            (self.proj.id,))
        kinds = {e["event_type"] for e in ev}
        self.assertTrue({"case.created", "case.assigned",
                         "case.closed"} <= kinds)


# ---------------------------------------------------------------------------
# 8. Security-event enrichment (read side)
# ---------------------------------------------------------------------------
class EnrichmentTests(Phase10Base):
    def test_enrich_security_event(self):
        self.ops.iocs.add(self.org.id, "203.0.113.99",
                          confidence_level="confirmed")
        self.ops.surface.ingest(
            self.org.id, self.proj.id,
            entries=[{"type": "ip", "value": "203.0.113.99"}])
        self.ops.correlation.match(self.org.id, self.proj.id)
        asset = self.ops.surface.inventory(
            self.org.id, self.proj.id, asset_type="ip")["assets"][0]
        f = self.svc.db.query_one(
            "SELECT * FROM findings WHERE project_id=?", (self.proj.id,))
        ev = {"id": "ev-1", "project_id": self.proj.id,
              "asset_id": asset["id"], "event_type": "finding.created"}
        out = enrich_security_event(self.svc, self.proj.id, ev)
        self.assertEqual(out["event_type"], "finding.created")
        self.assertIn("threat_context", out)
        ctx = out["threat_context"]
        self.assertGreaterEqual(len(ctx["iocs"]), 1)
        self.assertEqual(ctx["iocs"][0]["indicator"], "203.0.113.99")
        self.assertEqual(ctx["iocs"][0]["finding_id"], f["id"])
        # plain event (no asset) still yields the context envelope
        out2 = enrich_security_event(self.svc, self.proj.id,
                                     {"id": "ev-2", "event_type": "scan.done",
                                      "asset_id": ""})
        self.assertEqual(out2["threat_context"]["iocs"], [])


# ---------------------------------------------------------------------------
# 9. Dashboard panel (read-only snapshot + api payload + rendered page)
# ---------------------------------------------------------------------------
class Phase10DashboardTests(Phase10Base):
    def _seed(self):
        self.ops.iocs.add(self.org.id, "203.0.113.99",
                          confidence_level="confirmed")
        self.ops.surface.ingest(
            self.org.id, self.proj.id,
            entries=[{"type": "ip", "value": "203.0.113.99"},
                     {"type": "hostname", "value": "www.example.com"}])
        self.ops.correlation.match(self.org.id, self.proj.id)
        self.ops.cases.create(self.org.id, self.proj.id,
                              title="Dashboard case", priority="high")

    def test_snapshot_counts(self):
        self._seed()
        import dashboard as db
        snap = db.load_phase10_snapshot(
            os.path.join(self.dir, "t.db"), self.org.id)
        self.assertNotIn("error", snap)
        self.assertEqual(sum(int(n) for d in snap["indicators"].values()
                             for n in d.values()), 1)
        self.assertGreaterEqual(snap["matches"], 1)
        self.assertGreaterEqual(snap["assets"].get("ip", 0), 1)
        self.assertEqual(snap["clusters"], 0)  # single IOC: no cluster
        self.assertGreaterEqual(
            sum(int(n) for d in snap["cases"].values() for n in d.values()),
            1)
        # org filter: other tenant sees nothing
        snap2 = db.load_phase10_snapshot(
            os.path.join(self.dir, "t.db"), self.org2.id)
        self.assertEqual(sum(int(n) for d in snap2["indicators"].values()
                             for n in d.values()), 0)
        self.assertEqual(snap2["matches"], 0)

    def test_api_payload(self):
        self._seed()
        import dashboard as db
        payload = db.load_phase10_api(
            os.path.join(self.dir, "t.db"), self.org.id)
        self.assertNotIn("error", payload)
        self.assertEqual(len(payload["iocs"]), 1)
        self.assertEqual(payload["iocs"][0]["indicator"], "203.0.113.99")
        self.assertEqual(len(payload["cases"]), 1)
        self.assertEqual(payload["cases"][0]["title"], "Dashboard case")
        self.assertEqual(len(payload["findings"]), 1)
        self.assertTrue(payload["findings"][0]["rule_id"].startswith("TI-"))

    def test_page_renders_and_escapes(self):
        self._seed()
        import dashboard as db
        # untrusted strings are HTML-escaped by the panel helpers
        self.assertEqual(db.esc("<script>x</script>"),
                         "&lt;script&gt;x&lt;/script&gt;")
        self.assertNotIn("<script>", db.esc("\" onmouseover='x' <script>"))
        snap = db.load_phase10_snapshot(
            os.path.join(self.dir, "t.db"), self.org.id)
        html = db.phase10_page(snap)
        self.assertIn("Phase 10", html)
        self.assertIn("threat indicators", html)
        self.assertIn("/api/scans", html)          # nav chain present
        err = db.phase10_page({"error": "x"})
        self.assertIn("unavailable", err)


# ---------------------------------------------------------------------------
# 10. Reporting integration: threat_intel section in report snapshots
# ---------------------------------------------------------------------------
class Phase10ReportingTests(Phase10Base):
    def _seed(self):
        self.ops.iocs.add(self.org.id, "203.0.113.99",
                          confidence_level="confirmed")
        self.ops.iocs.add(self.org.id, "198.51.100.5",
                          confidence_level="low")
        self.ops.surface.ingest(
            self.org.id, self.proj.id,
            entries=[{"type": "ip", "value": "203.0.113.99"}])
        self.ops.correlation.match(self.org.id, self.proj.id)
        self.ops.cases.create(self.org.id, self.proj.id,
                              title="Report case", priority="critical")

    def test_analytics_threat_summary(self):
        self._seed()
        import analytics as an
        svc = pf.PlatformService(os.path.join(self.dir, "t.db"))
        res = an.AnalyticsService(svc).threat_summary(self.proj.id)
        self.assertEqual(res["iocs"], 2)
        self.assertEqual(res["iocs_active"], 2)
        self.assertEqual(res["matches"], 1)
        self.assertGreaterEqual(res["clusters"], 0)
        self.assertEqual(res["cases_by_status"].get("open"), 1)
        self.assertEqual(res["open_ti_findings"], 1)
        self.assertGreaterEqual(res["open_ti_by_severity"].get("High", 0), 1)
        # unknown project fails closed
        with self.assertRaises(errors.NotFoundError):
            an.AnalyticsService(svc).threat_summary("no-such-project")

    def test_snapshot_includes_threat_intel(self):
        self._seed()
        import reporting as rep
        svc = pf.PlatformService(os.path.join(self.dir, "t.db"))
        r = rep.ReportService(svc)
        snap = r.snapshot(self.proj.id, "executive", data_cutoff="2030-01-01")
        self.assertIn("threat_intel", snap)
        ti = snap["threat_intel"]
        self.assertEqual(ti["iocs"], 2)
        self.assertEqual(ti["matches"], 1)
        # tenant isolation: other org's project has no TI section data
        snap2 = r.snapshot(self.proj2.id, "executive",
                           data_cutoff="2030-01-01")
        self.assertEqual(snap2["threat_intel"]["iocs"], 0)
        self.assertEqual(snap2["threat_intel"]["matches"], 0)
        # deterministic: same cutoff -> same hash
        snap3 = r.snapshot(self.proj.id, "executive",
                           data_cutoff="2030-01-01")
        self.assertEqual(snap["metadata"]["report_hash"],
                         snap3["metadata"]["report_hash"])


# ---------------------------------------------------------------------------
# 10. Phase-10 RBAC permissions are registered + tiered
# ---------------------------------------------------------------------------
class RbacPhase10Tests(Phase10Base):
    PERMS = {
        "attack_surface.read", "attack_surface.scan",
        "threat_intel.read", "threat_intel.create",
        "threat_intel.import", "threat_intel.export",
        "cases.read", "cases.create", "cases.update",
        "cases.assign", "cases.close",
    }

    def test_phase10_permissions_registered(self):
        missing = {p for p in self.PERMS if p not in rbac.PERMISSIONS}
        self.assertEqual(missing, set())

    def test_role_tiers_monotonic(self):
        viewer = set(rbac.ROLE_PERMISSIONS["viewer"])
        analyst = set(rbac.ROLE_PERMISSIONS["analyst"])
        mgr = set(rbac.ROLE_PERMISSIONS["security_manager"])
        self.assertTrue(viewer <= analyst)
        self.assertTrue(analyst <= mgr)
        # manager-only capabilities (never in analyst tier)
        for p in ("threat_intel.import", "threat_intel.export",
                  "cases.assign", "cases.close"):
            self.assertIn(p, mgr)
            self.assertNotIn(p, analyst)


if __name__ == "__main__":
    unittest.main(verbosity=2)

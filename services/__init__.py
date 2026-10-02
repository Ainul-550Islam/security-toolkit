"""Foundation services: engine registry, health and capability reporting.

These services coordinate foundation components only. They do NOT duplicate
the domain services in ``python/`` (scanning, findings, cases, integrations,
federation); those remain authoritative for their domains.
"""

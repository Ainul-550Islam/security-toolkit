"""Stable contracts between Python, Rust, C++ and future TypeScript layers.

These are Protocols and dataclasses only: no implementations, no I/O, no
imports of the legacy ``python/`` package. An implementation living in any
language satisfies a contract by shape, so a Rust engine and a Python engine
are interchangeable to the registry.
"""

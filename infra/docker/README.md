# infra/docker

**No Dockerfile is shipped yet.** This documents the requirements any image
must satisfy, so that when one is written it is reviewed against a standard
rather than improvised.

## Requirements

1. **Non-root.** Create an unprivileged user and `USER` to it. A security
   scanner running as root in a container that mounts source is an escalation
   waiting to happen.
2. **Multi-stage build.** Build dependencies (compilers, `cargo`, `cmake`)
   must not ship in the runtime layer.
3. **Runtime deps only.** Install `requirements.txt` (currently empty).
   **Never** install `requirements-dev.txt` — linters and test frameworks have
   no place in production.
4. **No secrets in the image.** No `ENV` with credentials, no copied `.env`,
   no keys. Secrets are injected at runtime.
5. **`.dockerignore`** must exclude `.env`, `data/`, `results/`, `*.key`,
   `*.pem`, `.git/`, `__pycache__/`, `build/`, `target/` and `node_modules/`.
6. **Read-only root filesystem** where possible, with a writable volume for
   `data/`.
7. **Pinned base image** by digest, not a floating tag.
8. **Health check** against `/api/v1/livez` — never `/readyz`, which fails on
   a dependency outage and would restart a healthy container.
9. **Drop capabilities:** `--cap-drop=ALL`, `--security-opt=no-new-privileges`.

## Configuration

Pass `SECTOOLKIT_*` variables at run time. In production the application
refuses to start with debug enabled, authentication disabled, TLS disabled, or
bound to all interfaces.

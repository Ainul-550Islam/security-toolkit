# infra/kubernetes

**No manifests are shipped yet.** This documents what they must contain.

## Probes

```yaml
livenessProbe:
  httpGet: { path: /api/v1/livez, port: 8000 }
  initialDelaySeconds: 10
  periodSeconds: 20
readinessProbe:
  httpGet: { path: /api/v1/readyz, port: 8000 }
  periodSeconds: 10
```

Liveness **must** point at `/livez`. `/readyz` consults dependencies, so using
it for liveness converts a brief database outage into a cluster-wide restart
loop.

## Pod security

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities: { drop: ["ALL"] }
  seccompProfile: { type: RuntimeDefault }
```

## Secrets

Inject through a `Secret` mounted as environment variables with the
`SECTOOLKIT_SECRET_` prefix, or through a CSI driver backed by Vault/KMS.

* Never place credentials in a `ConfigMap`.
* Never bake them into the image.
* The provider selector is `SECTOOLKIT_SECRETS_PROVIDER` (plural); the
  singular prefix is reserved for material.

## Network

The application binds `127.0.0.1` by default and **refuses** `0.0.0.0` in
production. Expose it through a Service and ingress that terminates TLS, not
by widening the process bind address. Apply a default-deny `NetworkPolicy` and
allow only required egress.

## Resources

Set both requests and limits. An unbounded scanner pod can starve its node.

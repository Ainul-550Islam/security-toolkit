"""OpenAPI 3.1 generation from the concrete, registered route table."""

from __future__ import annotations

from typing import Any

from core.version import API_VERSION, APP_TITLE, VERSION


class OpenApiDocument:
    """Generate an honest document containing only implemented routes."""

    def __init__(self, router: Any) -> None:
        self.router = router

    def generate(self) -> dict[str, Any]:
        paths: dict[str, dict[str, Any]] = {}
        for route in sorted(self.router.routes, key=lambda item: (item.path, sorted(item.methods))):
            for method in sorted(route.methods):
                operation: dict[str, Any] = {
                    "operationId": route.operation_id,
                    "summary": route.summary,
                    "tags": list(route.tags),
                    "responses": self._responses(route),
                    "security": (
                        [{route.security_scheme: []}]
                        if route.security_scheme
                        else [{"bearerAuth": []}] if route.auth_required else []
                    ),
                }
                if route.request_schema is not None:
                    operation["requestBody"] = {
                        "required": True,
                        "content": {
                            "application/json": {"schema": route.request_schema}
                        },
                    }
                if route.scope_kind:
                    operation["x-tenant-scope"] = {
                        "kind": route.scope_kind,
                        "parameter": route.scope_parameter,
                    }
                parameters = self._path_parameters(route.path)
                if parameters:
                    operation["parameters"] = parameters
                paths.setdefault(route.path, {})[method.lower()] = operation
        return {
            "openapi": "3.1.0",
            "info": {
                "title": APP_TITLE,
                "version": VERSION,
                "description": "Versioned API contract generated from implemented handlers.",
                "x-api-version": API_VERSION,
            },
            "paths": paths,
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "description": "Opaque session or scoped API credential.",
                    },
                    "platformAdminKey": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-Platform-Admin-Token",
                        "description": "Out-of-band platform operator token; never a tenant role or tenant API credential.",
                    }
                },
                "schemas": {
                    "ApiError": {
                        "type": "object",
                        "required": ["error"],
                        "properties": {
                            "error": {
                                "type": "object",
                                "required": ["code", "message", "request_id"],
                                "properties": {
                                    "code": {"type": "string"},
                                    "message": {"type": "string"},
                                    "request_id": {"type": "string"},
                                    "fields": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "required": ["field", "code", "message"],
                                            "properties": {
                                                "field": {"type": "string"},
                                                "code": {"type": "string"},
                                                "message": {"type": "string"},
                                            },
                                            "additionalProperties": False,
                                        },
                                    },
                                },
                                "additionalProperties": False,
                            }
                        },
                        "additionalProperties": False,
                    }
                },
            },
        }

    @staticmethod
    def _path_parameters(path: str) -> list[dict[str, Any]]:
        import re

        names = re.findall(r"\{([A-Za-z][A-Za-z0-9_]*)\}", path)
        return [
            {
                "name": name,
                "in": "path",
                "required": True,
                "schema": {"type": "string", "minLength": 1, "maxLength": 128},
            }
            for name in names
        ]

    @staticmethod
    def _responses(route: Any) -> dict[str, Any]:
        declared = dict(getattr(route, "responses", {}) or {})
        if "200" not in declared and "204" not in declared:
            declared.setdefault("200", "Successful response")
        output: dict[str, Any] = {}
        for status, description in sorted(declared.items()):
            response: dict[str, Any] = {"description": str(description)}
            if status not in {"204", "304"}:
                response["content"] = {
                    "application/json": {"schema": route.response_schema}
                }
            output[str(status)] = response
        for status, description in (
            ("400", "Invalid request"),
            ("401", "Authentication required or invalid"),
            ("403", "Forbidden"),
            ("404", "Resource not found"),
            ("405", "Method not allowed"),
            ("409", "Conflict"),
            ("429", "Rate limited"),
            ("500", "Internal error"),
            ("503", "Service unavailable"),
        ):
            output.setdefault(status, {
                "description": description,
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ApiError"}}},
            })
        return output


__all__ = ["OpenApiDocument"]

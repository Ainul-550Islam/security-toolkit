from __future__ import annotations

import os
import re
import sys
import unittest
from typing import Any, cast

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON_DIR = os.path.join(ROOT, "python")
if PYTHON_DIR not in sys.path:
    sys.path.insert(0, PYTHON_DIR)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from api.middleware import HttpResponse  # noqa: E402
from api.router import ApiRouter, ApiServices, RouteMatch, RouteSpec, create_router  # noqa: E402


def _services() -> ApiServices:
    return ApiServices(
        platform=object(),
        identity=object(),
        authorization=object(),
        health=object(),
        capabilities=object(),
    )


def _route(
    path: str,
    methods: tuple[str, ...] = ("GET",),
    *,
    operation_id: str = "getItem",
    scope_kind: str = "",
    scope_parameter: str = "",
) -> RouteSpec:
    return RouteSpec(
        path=path,
        methods=frozenset(methods),
        handler=lambda _request, _params: HttpResponse(200, {"ok": True}),
        operation_id=operation_id,
        summary=operation_id,
        scope_kind=scope_kind,
        scope_parameter=scope_parameter,
    )


class ApiRouterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.router = ApiRouter(_services())

    def test_route_parameter_matches_one_bounded_segment(self) -> None:
        self.router.register(_route("/api/v1/items/{item_id}"))

        result = self.router.resolve("get", "/api/v1/items/item_123-abc")

        self.assertIsInstance(result, RouteMatch)
        self.assertEqual(result.path_params, {"item_id": "item_123-abc"})
        self.assertEqual(result.route.parameter_names, ("item_id",))
        self.assertEqual(result.route.api_version, "v1")
        self.assertIsInstance(self.router.resolve("GET", "/api/v1/items/a/b"), HttpResponse)

    def test_dot_segments_are_not_captured_as_route_parameters(self) -> None:
        self.router.register(_route("/api/v1/{collection}/items/{item_id}"))

        for path in (
            "/api/v1/../items/item-1",
            "/api/v1/records/items/.",
            "/api/v1/records/items/..",
        ):
            with self.subTest(path=path):
                result = self.router.resolve("GET", path)
                self.assertIsInstance(result, HttpResponse)
                self.assertEqual(result.status, 404)
                self.assertEqual(result.body["error"]["code"], "not_found")

    def test_encoded_and_malformed_percent_paths_are_never_decoded(self) -> None:
        self.router.register(_route("/api/v1/items/{item_id}"))

        rejected_paths = (
            "/api/v1/items/%2f",
            "/api/v1/items/%2F",
            "/api/v1/items/%ZZ",
            "/api/v1/items/%",
            "/api/v1/items/%252e%252e",
            "/api/v1/items//item-1",
            "/api/v1/items/",
        )
        for path in rejected_paths:
            with self.subTest(path=path):
                result = self.router.resolve("GET", path)
                self.assertIsInstance(result, HttpResponse)
                self.assertEqual(result.status, 404)

    def test_malformed_route_parameter_expressions_are_rejected(self) -> None:
        invalid_paths = (
            "/api/v1/items/{bad-name}",
            "/api/v1/items/{item_id",
            "/api/v1/items/item_id}",
            "/api/v1/items/{}",
            "/api/v1/items//{item_id}",
            "/api/v1/items/{item_id}/",
        )

        for path in invalid_paths:
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    _route(path)

    def test_valid_embedded_route_parameters_remain_supported(self) -> None:
        self.router.register(_route(
            "/api/v1/items/prefix-{item_id}.json",
            operation_id="getItemDocument",
        ))

        result = self.router.resolve("GET", "/api/v1/items/prefix-record_123.json")

        self.assertIsInstance(result, RouteMatch)
        self.assertEqual(result.path_params, {"item_id": "record_123"})

    def test_oversized_route_template_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _route("/api/v1/" + "a" * 2049)

    def test_non_callable_route_handler_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "handler must be callable"):
            RouteSpec(
                path="/api/v1/items",
                methods=frozenset({"GET"}),
                handler=cast(Any, None),
                operation_id="getItems",
                summary="Get items",
            )

    def test_static_dot_segments_are_rejected_at_registration(self) -> None:
        for path in ("/api/v1/items/.", "/api/v1/items/.."):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    _route(path)

    def test_same_method_static_and_parameter_route_shadowing_is_rejected(self) -> None:
        self.router.register(_route(
            "/api/v1/items/{item_id}", operation_id="getItemById"
        ))

        with self.assertRaisesRegex(ValueError, "overlap"):
            self.router.register(_route(
                "/api/v1/items/featured", operation_id="getFeaturedItems"
            ))
        self.assertEqual(len(self.router.routes), 1)

    def test_overlapping_embedded_templates_are_rejected(self) -> None:
        self.router.register(_route(
            "/api/v1/items/{item_id}.json", operation_id="getItemJson"
        ))

        with self.assertRaisesRegex(ValueError, "overlap"):
            self.router.register(_route(
                "/api/v1/items/archive.{extension}",
                operation_id="getArchivedItem",
            ))

    def test_disjoint_embedded_templates_with_same_method_are_allowed(self) -> None:
        self.router.register(_route(
            "/api/v1/items/{item_id}.json", operation_id="getItemJson"
        ))
        self.router.register(_route(
            "/api/v1/items/{item_id}.xml", operation_id="getItemXml"
        ))

        json_result = self.router.resolve("GET", "/api/v1/items/record-1.json")
        xml_result = self.router.resolve("GET", "/api/v1/items/record-1.xml")

        self.assertIsInstance(json_result, RouteMatch)
        self.assertEqual(json_result.route.operation_id, "getItemJson")
        self.assertIsInstance(xml_result, RouteMatch)
        self.assertEqual(xml_result.route.operation_id, "getItemXml")

    def test_implicit_head_is_included_when_detecting_route_conflicts(self) -> None:
        self.router.register(_route("/api/v1/items/{item_id}", operation_id="getItem"))

        with self.assertRaises(ValueError):
            self.router.register(_route(
                "/api/v1/items/{item_id}",
                ("HEAD",),
                operation_id="headItem",
            ))

    def test_duplicate_route_shape_and_method_are_rejected_atomically(self) -> None:
        self.router.register(_route(
            "/api/v1/items/{item_id}", operation_id="getItemById"
        ))

        with self.assertRaisesRegex(ValueError, "already registered"):
            self.router.register(_route(
                "/api/v1/items/{record_id}", operation_id="getRecordById"
            ))
        self.assertEqual(len(self.router.routes), 1)

        self.router.register(_route(
            "/api/v1/other", operation_id="getRecordById"
        ))
        self.assertEqual(len(self.router.routes), 2)

    def test_duplicate_operation_id_is_rejected(self) -> None:
        self.router.register(_route("/api/v1/items", operation_id="listItems"))

        with self.assertRaisesRegex(ValueError, "operation_id"):
            self.router.register(_route("/api/v1/records", operation_id="listItems"))
        self.assertEqual(len(self.router.routes), 1)

    def test_overlapping_paths_with_disjoint_methods_remain_supported(self) -> None:
        self.router.register(_route(
            "/api/v1/items/{item_id}", operation_id="getItemById"
        ))
        self.router.register(_route(
            "/api/v1/items/featured", ("POST",), operation_id="createFeaturedItem"
        ))

        get_result = self.router.resolve("GET", "/api/v1/items/featured")
        post_result = self.router.resolve("POST", "/api/v1/items/featured")

        self.assertIsInstance(get_result, RouteMatch)
        self.assertEqual(get_result.route.operation_id, "getItemById")
        self.assertIsInstance(post_result, RouteMatch)
        self.assertEqual(post_result.route.operation_id, "createFeaturedItem")

    def test_405_allow_header_includes_implicit_head_and_all_declared_methods(self) -> None:
        self.router.register(_route("/api/v1/items", operation_id="getItems"))
        self.router.register(_route(
            "/api/v1/items", ("POST",), operation_id="createItems"
        ))

        result = self.router.resolve("DELETE", "/api/v1/items")

        self.assertIsInstance(result, HttpResponse)
        self.assertEqual(result.status, 405)
        self.assertEqual(result.body["error"]["code"], "method_not_allowed")
        self.assertEqual(dict(result.headers)["Allow"], "GET, HEAD, POST")

    def test_unknown_route_is_a_safe_404(self) -> None:
        self.router.register(_route("/api/v1/livez", operation_id="livez"))

        result = self.router.resolve("GET", "/api/v1/unknown")

        self.assertIsInstance(result, HttpResponse)
        self.assertEqual(result.status, 404)
        self.assertEqual(result.body["error"]["code"], "not_found")

    def test_unknown_version_prefix_is_a_safe_404(self) -> None:
        self.router.register(_route("/api/v1/livez", operation_id="livez"))

        result = self.router.resolve("GET", "/api/v10/livez")

        self.assertIsInstance(result, HttpResponse)
        self.assertEqual(result.status, 404)
        self.assertEqual(result.body["error"]["code"], "not_found")

    def test_scope_metadata_must_reference_a_declared_parameter(self) -> None:
        scoped_route = _route(
            "/api/v1/projects/{project_id}/assets",
            operation_id="listProjectAssets",
            scope_kind="project",
            scope_parameter="tenant_id",
        )

        with self.assertRaisesRegex(ValueError, "scope parameter"):
            self.router.register(scoped_route)
        self.assertEqual(self.router.routes, ())

    def test_registered_health_admin_and_tenant_scope_metadata_is_preserved(self) -> None:
        router = create_router(_services())
        second_router = create_router(_services())
        self.assertEqual(len(router.routes), 118)
        operations = {route.operation_id for route in router.routes}
        self.assertTrue({
            "createProject", "getOrganization", "listRoles",
            "listCurrentUserSessions", "getNotificationPreferences",
            "listScanEvidence", "getAssetDiscoverySummary",
            "getProjectRisk", "ensureFindingRemediation",
            "searchProjectSecurityRecords",
        }.issubset(operations))
        self.assertTrue(all(route.path.startswith("/api/v1/") for route in router.routes))
        self.assertTrue(all(route.api_version == "v1" for route in router.routes))
        self.assertTrue(all(callable(route.handler) for route in router.routes))
        for route in router.routes:
            sample_path = re.sub(r"\{[A-Za-z][A-Za-z0-9_]*\}", "route-param", route.path)
            methods = set(route.methods)
            if "GET" in route.methods:
                methods.add("HEAD")
            for method in sorted(methods):
                with self.subTest(path=route.path, method=method):
                    resolved = router.resolve(method, sample_path)
                    self.assertIsInstance(resolved, RouteMatch)
                    self.assertIs(resolved.route, route)
        self.assertEqual(
            len({route.operation_id for route in router.routes}),
            len(router.routes),
        )
        self.assertEqual(
            tuple((route.path, tuple(sorted(route.methods)), route.operation_id)
                  for route in router.routes),
            tuple((route.path, tuple(sorted(route.methods)), route.operation_id)
                  for route in second_router.routes),
        )

        public_health_paths = {
            "/api/v1/livez",
            "/api/v1/readyz",
            "/api/v1/healthz",
        }
        for path in public_health_paths:
            with self.subTest(path=path):
                route = next(
                    route for route in router.routes
                    if route.path == path and "GET" in route.methods
                )
                self.assertFalse(route.auth_required)
                self.assertFalse(route.security_scheme)
                self.assertFalse(route.scope_kind)

        metadata_route = next(
            route for route in router.routes if route.path == "/api/v1/metadata"
        )
        self.assertTrue(metadata_route.auth_required)
        self.assertEqual(metadata_route.permission, "configuration.read")

        admin_health = next(
            route for route in router.routes if route.path == "/api/v1/admin/health"
        )
        self.assertFalse(admin_health.auth_required)
        self.assertEqual(admin_health.security_scheme, "platformAdminKey")

        tenant_projects = [
            route for route in router.routes
            if route.path == "/api/v1/tenants/{tenant_id}/projects"
        ]
        project_assets = [
            route for route in router.routes
            if route.path == "/api/v1/projects/{project_id}/assets"
        ]
        self.assertEqual(len(tenant_projects), 2)
        self.assertEqual(len(project_assets), 2)
        for route in tenant_projects:
            self.assertEqual((route.scope_kind, route.scope_parameter), ("organization", "tenant_id"))
        for route in project_assets:
            self.assertEqual((route.scope_kind, route.scope_parameter), ("project", "project_id"))
        for route in router.routes:
            if route.scope_kind:
                self.assertIn("{" + route.scope_parameter + "}", route.path)


if __name__ == "__main__":
    unittest.main()

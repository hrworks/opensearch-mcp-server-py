# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

import asyncio
import contextlib
import logging
import uvicorn
from mcp.server import Server
from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend, RequireAuthMiddleware
from mcp.server.auth.routes import build_resource_metadata_url, create_protected_resource_routes
from mcp.server.sse import SseServerTransport
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.types import CallToolResult, Tool
from mcp_server_opensearch.client_context import ClientNameMiddleware
from mcp_server_opensearch.clusters_information import load_clusters_from_yaml
from mcp_server_opensearch.global_state import set_config_file_path, set_mode, set_profile
from mcp_server_opensearch.oauth import JwtTokenVerifier, OAuthConfig, load_oauth_config
from mcp_server_opensearch.server_instructions import get_server_instructions
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import request_response
from starlette.routing import Mount, Route
from starlette.types import Receive, Scope, Send
from tools.config import apply_custom_tool_config
from tools.tool_filter import get_tools
from tools.tool_generator import generate_tools_from_openapi
from tools.tools import TOOL_REGISTRY
from typing import AsyncIterator


async def create_mcp_server(
    mode: str = 'single',
    profile: str = '',
    config_file_path: str = '',
    cli_tool_overrides: dict | None = None,
) -> Server:
    """Create and configure the MCP server instance."""
    # Set the global mode
    set_mode(mode)

    # Set the global profile if provided
    if profile:
        set_profile(profile)

    # Set the global config file path
    if config_file_path:
        set_config_file_path(config_file_path)

    # Load clusters from YAML file
    if mode == 'multi':
        await load_clusters_from_yaml(config_file_path)

    # Server instructions guide the LLM on dynamic connection params (single mode only)
    server = Server('opensearch-mcp-server', instructions=get_server_instructions())
    # Call tool generator
    await generate_tools_from_openapi()
    # Apply custom tool config (custom name and description)
    customized_registry = apply_custom_tool_config(
        TOOL_REGISTRY, config_file_path, cli_tool_overrides or {}
    )
    # Get enabled tools (tool filter)
    enabled_tools = await get_tools(
        tool_registry=customized_registry, config_file_path=config_file_path
    )
    logging.info(f'Enabled tools: {list(enabled_tools.keys())}')

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        tools = []
        for tool_name, tool_info in enabled_tools.items():
            tools.append(
                Tool(
                    name=tool_info.get('display_name', tool_name),
                    description=tool_info['description'],
                    inputSchema=tool_info['input_schema'],
                )
            )
        return tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> CallToolResult:
        from mcp_server_opensearch.tool_executor import execute_tool

        return await execute_tool(name, arguments, enabled_tools)

    return server


class _ASGIApp:
    """ASGI app object wrapping a handler, so Starlette's Route treats it as a raw ASGI endpoint."""

    def __init__(self, handler):
        self._handler = handler

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self._handler(scope, receive, send)


def _create_protected_resource_routes_raw(
    resource_url: AnyHttpUrl,
    issuer_url: str,
    scopes_supported: list[str] | None = None,
) -> list[Route]:
    """
    Build RFC 9728 Protected Resource Metadata routes without Pydantic URL normalization.

    Pydantic's AnyHttpUrl always appends a trailing slash to bare-host URLs
    (e.g. "https://accounts.google.com" → "https://accounts.google.com/").
    This breaks RFC 8414 issuer equality checks in OAuth clients that compare
    the PRM authorization_server value against the OIDC metadata issuer field —
    a mismatch causes the client to abort the OAuth flow with an auth error.

    By serializing the authorization_servers list as a plain JSON string we
    preserve the exact issuer URL from config without Pydantic normalization.
    """
    import json as _json
    from urllib.parse import urlparse as _urlparse
    from starlette.responses import JSONResponse

    parsed = _urlparse(str(resource_url))
    resource_path = parsed.path if parsed.path != '/' else ''
    well_known_path = f'{parsed.scheme}://{parsed.netloc}/.well-known/oauth-protected-resource{resource_path}'
    route_path = _urlparse(well_known_path).path

    metadata: dict = {
        'resource': str(resource_url),
        'authorization_servers': [issuer_url],  # exact string, no Pydantic normalization
        'bearer_methods_supported': ['header'],
        'resource_name': 'OpenSearch MCP Server',
    }
    if scopes_supported:
        metadata['scopes_supported'] = scopes_supported

    metadata_json = _json.dumps(metadata)

    async def handle(request: Request) -> Response:
        return JSONResponse(content=_json.loads(metadata_json))

    cors_handler = CORSMiddleware(
        app=request_response(handle),
        allow_origins='*',
        allow_methods=['GET', 'OPTIONS'],
        allow_headers=[],
    )

    return [Route(route_path, endpoint=cors_handler, methods=['GET', 'OPTIONS'])]


class MCPStarletteApp:
    """Starlette application wrapper for the MCP server."""

    def __init__(
        self,
        mcp_server: Server,
        stateless: bool = True,
        oauth_config: OAuthConfig | None = None,
    ):
        """Initialize the MCP Starlette application."""
        self.mcp_server = mcp_server
        self.oauth_config = oauth_config
        self.sse = SseServerTransport('/messages/')
        self.session_manager = StreamableHTTPSessionManager(
            app=self.mcp_server,
            event_store=None,
            json_response=False,
            stateless=stateless,
        )

    async def handle_sse(self, request: Request) -> Response:
        """Handle SSE connection requests."""
        async with self.sse.connect_sse(
            request.scope,
            request.receive,
            request._send,
        ) as (read_stream, write_stream):
            await self.mcp_server.run(
                read_stream,
                write_stream,
                self.mcp_server.create_initialization_options(),
            )

        # Done to prevent 'NoneType' errors. For more details: https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/server/sse.py#L33-L37
        return Response()

    async def handle_health(self, request: Request) -> Response:
        """Handle health check requests."""
        return Response('OK', status_code=200)

    @contextlib.asynccontextmanager
    async def lifespan(self, app: Starlette) -> AsyncIterator[None]:
        """Context manager for session manager lifecycle.

        Ensures proper startup and shutdown of the session manager.
        """
        from mcp_server_opensearch.logging_config import start_memory_monitor

        async with self.session_manager.run():
            logging.info('Application started with StreamableHTTP session manager!')
            monitor_task = start_memory_monitor()
            try:
                yield
            finally:
                monitor_task.cancel()
                try:
                    await monitor_task
                except (asyncio.CancelledError, Exception):
                    pass
                logging.info('Application shutting down...')

    async def handle_streamable_http(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Handle streamable HTTP requests."""
        await self.session_manager.handle_request(scope, receive, send)

    def create_app(self) -> Starlette:
        """Create the Starlette application with routes."""
        # Serve bare '/mcp' via Route (a Mount alone 307-redirects '/mcp' to '/mcp/'); Mount handles sub-paths.
        streamable_http_app = _ASGIApp(self.handle_streamable_http)
        middleware: list[Middleware] = []
        routes: list[Route | Mount] = []

        if self.oauth_config and self.oauth_config.enabled:
            token_verifier = JwtTokenVerifier(self.oauth_config)
            middleware = [
                Middleware(AuthenticationMiddleware, backend=BearerAuthBackend(token_verifier)),
                Middleware(AuthContextMiddleware),
            ]
            resource_url = AnyHttpUrl(self.oauth_config.resource_url)
            resource_metadata_url = build_resource_metadata_url(resource_url)
            required_scopes = self.oauth_config.required_scopes

            routes.extend(
                [
                    Route(
                        '/sse',
                        endpoint=RequireAuthMiddleware(
                            self.handle_sse,
                            required_scopes,
                            resource_metadata_url,
                        ),
                        methods=['GET'],
                    ),
                    Route('/health', endpoint=self.handle_health, methods=['GET']),
                    Mount(
                        '/messages/',
                        app=RequireAuthMiddleware(
                            self.sse.handle_post_message,
                            required_scopes,
                            resource_metadata_url,
                        ),
                    ),
                    # Route for bare /mcp to avoid 307 redirect
                    Route(
                        '/mcp',
                        endpoint=RequireAuthMiddleware(
                            streamable_http_app,
                            required_scopes,
                            resource_metadata_url,
                        ),
                    ),
                    Mount(
                        '/mcp',
                        app=RequireAuthMiddleware(
                            streamable_http_app,
                            required_scopes,
                            resource_metadata_url,
                        ),
                    ),
                ]
            )
            # HRW Fork Fix: Pydantic's AnyHttpUrl normalizes URLs by appending a
            # trailing slash (e.g. "https://accounts.google.com" → "https://accounts.google.com/").
            # This causes issuer validation to fail because Google's OIDC metadata reports
            # issuer = "https://accounts.google.com" (no slash), while the PRM would advertise
            # "https://accounts.google.com/" — breaking the RFC 8414 issuer equality check.
            # Fix: build the metadata JSON manually so authorization_servers contains the
            # exact issuer string from config, bypassing Pydantic URL normalization.
            routes.extend(
                _create_protected_resource_routes_raw(
                    resource_url=resource_url,
                    issuer_url=self.oauth_config.issuer_url,
                    scopes_supported=required_scopes,
                )
            )
        else:
            routes.extend(
                [
                    Route('/sse', endpoint=self.handle_sse, methods=['GET']),
                    Route('/health', endpoint=self.handle_health, methods=['GET']),
                    Mount('/messages/', app=self.sse.handle_post_message),
                    Route('/mcp', endpoint=streamable_http_app),
                    Mount('/mcp', app=streamable_http_app),
                ]
            )

        app = Starlette(
            routes=routes,
            middleware=middleware,
            lifespan=self.lifespan,
        )
        app.add_middleware(ClientNameMiddleware)
        return app


async def serve(
    host: str = '127.0.0.1',
    port: int = 9900,
    mode: str = 'single',
    profile: str = '',
    config_file_path: str = '',
    cli_tool_overrides: dict | None = None,
    stateless: bool = True,
) -> None:
    """Start the MCP server in streaming HTTP mode."""
    mcp_server = await create_mcp_server(mode, profile, config_file_path, cli_tool_overrides)
    oauth_config = load_oauth_config(host, port)
    app_handler = MCPStarletteApp(mcp_server, stateless=stateless, oauth_config=oauth_config)
    app = app_handler.create_app()

    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
        timeout_graceful_shutdown=10,
    )
    server = uvicorn.Server(config)
    await server.serve()

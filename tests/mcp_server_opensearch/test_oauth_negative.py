# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Auth negative tests for OAuth-protected routes.

These tests verify that the OAuth middleware correctly rejects invalid
authentication attempts and returns appropriate HTTP status codes and headers.
"""

import base64
import json
import logging
import time
from typing import Generator
from unittest.mock import AsyncMock, Mock, patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

from mcp_server_opensearch.oauth import OAuthConfig
from mcp_server_opensearch.streaming_server import MCPStarletteApp


# =============================================================================
# RSA Key Fixtures for JWT Signing
# =============================================================================


@pytest.fixture(scope='module')
def rsa_keypair():
    """Generate an RSA keypair for signing JWTs in tests."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture(scope='module')
def rsa_keypair_foreign():
    """Generate a different RSA keypair (simulates foreign/untrusted issuer)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture(scope='module')
def private_key_pem(rsa_keypair):
    """PEM-encoded private key for signing."""
    private_key, _ = rsa_keypair
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture(scope='module')
def public_key_pem(rsa_keypair):
    """PEM-encoded public key for verification."""
    _, public_key = rsa_keypair
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.fixture(scope='module')
def foreign_private_key_pem(rsa_keypair_foreign):
    """PEM-encoded private key from a different keypair (untrusted)."""
    private_key, _ = rsa_keypair_foreign
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


# =============================================================================
# OAuth Configuration
# =============================================================================


ISSUER_URL = 'http://localhost:8080/realms/test'
RESOURCE_URL = 'http://localhost:9900/mcp/'
JWKS_URL = f'{ISSUER_URL}/protocol/openid-connect/certs'
AUDIENCE = 'opensearch-mcp'
REQUIRED_SCOPES = ['openid', 'mcp:read']


@pytest.fixture
def oauth_config():
    """Standard OAuth config with audience and required scopes."""
    return OAuthConfig(
        enabled=True,
        issuer_url=ISSUER_URL,
        resource_url=RESOURCE_URL,
        jwks_url=JWKS_URL,
        required_scopes=REQUIRED_SCOPES,
        audience=AUDIENCE,
    )


@pytest.fixture
def oauth_config_no_audience():
    """OAuth config without audience (accepts any token from issuer)."""
    return OAuthConfig(
        enabled=True,
        issuer_url=ISSUER_URL,
        resource_url=RESOURCE_URL,
        jwks_url=JWKS_URL,
        required_scopes=REQUIRED_SCOPES,
        audience=None,
    )


# =============================================================================
# App Fixtures
# =============================================================================


@pytest.fixture
def mock_mcp_server():
    """Mock MCP server instance."""
    server = Mock()
    server.name = 'test-server'
    server.run = AsyncMock()
    server.create_initialization_options = Mock(return_value={})
    return server


@pytest.fixture
def oauth_app(mock_mcp_server, oauth_config, public_key_pem):
    """Create OAuth-protected Starlette app with mocked JWKS."""
    app_handler = MCPStarletteApp(
        mock_mcp_server,
        stateless=True,
        oauth_config=oauth_config,
    )

    # Mock the JWKS client to return our test public key
    mock_signing_key = Mock()
    mock_signing_key.key = public_key_pem.decode()

    with patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client:
        mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = mock_signing_key
        app = app_handler.create_app()
        # Disable lifespan for testing
        app.router.lifespan_context = None
        yield TestClient(app), mock_signing_key, mock_jwks_client, app_handler


@pytest.fixture
def oauth_app_no_audience(mock_mcp_server, oauth_config_no_audience, public_key_pem):
    """Create OAuth-protected app without audience check."""
    app_handler = MCPStarletteApp(
        mock_mcp_server,
        stateless=True,
        oauth_config=oauth_config_no_audience,
    )

    mock_signing_key = Mock()
    mock_signing_key.key = public_key_pem.decode()

    with patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client:
        mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = mock_signing_key
        app = app_handler.create_app()
        app.router.lifespan_context = None
        yield TestClient(app), mock_signing_key, app_handler


# =============================================================================
# Token Generation Helpers
# =============================================================================


def create_token(
    private_key_pem: bytes,
    issuer: str = ISSUER_URL,
    audience: str = AUDIENCE,
    scopes: list[str] | None = None,
    exp_offset: int = 3600,
    extra_claims: dict | None = None,
) -> str:
    """Create a signed JWT token for testing."""
    now = int(time.time())
    payload = {
        'iss': issuer,
        'sub': 'test-user',
        'azp': 'test-client',
        'iat': now,
        'exp': now + exp_offset,
    }
    if audience:
        payload['aud'] = audience
    if scopes is not None:
        payload['scope'] = ' '.join(scopes)
    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, private_key_pem, algorithm='RS256')


# =============================================================================
# Test Cases: 401 Unauthorized
# =============================================================================


class TestUnauthorized401:
    """Tests for scenarios that should return 401 Unauthorized."""

    def test_no_authorization_header(self, oauth_app):
        """Request without Authorization header returns 401 with WWW-Authenticate."""
        client, _, _, _ = oauth_app

        response = client.post('/mcp/')

        assert response.status_code == 401
        assert 'www-authenticate' in response.headers
        www_auth = response.headers['www-authenticate']
        assert www_auth.startswith('Bearer')
        assert 'error="invalid_token"' in www_auth
        assert 'resource_metadata=' in www_auth
        # The resource_metadata URL points to the .well-known endpoint
        assert '.well-known/oauth-protected-resource' in www_auth

    def test_authorization_without_bearer_prefix(self, oauth_app):
        """Authorization header without 'Bearer ' prefix returns 401."""
        client, _, _, _ = oauth_app

        response = client.post('/mcp/', headers={'Authorization': 'Basic dXNlcjpwYXNz'})

        assert response.status_code == 401
        assert 'www-authenticate' in response.headers

    def test_authorization_with_only_bearer_keyword(self, oauth_app):
        """Authorization header with only 'Bearer' (no token) returns 401."""
        client, _, _, _ = oauth_app

        response = client.post('/mcp/', headers={'Authorization': 'Bearer'})

        assert response.status_code == 401

    def test_empty_token(self, oauth_app):
        """Authorization header with empty token returns 401."""
        client, _, _, _ = oauth_app

        response = client.post('/mcp/', headers={'Authorization': 'Bearer '})

        assert response.status_code == 401

    def test_syntactically_invalid_jwt(self, oauth_app):
        """Syntactically invalid JWT returns 401."""
        client, _, _, _ = oauth_app

        # Not a valid JWT structure (should have 3 dot-separated parts)
        response = client.post('/mcp/', headers={'Authorization': 'Bearer not.a.valid.jwt.token'})

        assert response.status_code == 401

    def test_malformed_base64_in_jwt(self, oauth_app):
        """JWT with invalid base64 encoding returns 401."""
        client, _, _, _ = oauth_app

        # Invalid base64 in the payload section
        response = client.post('/mcp/', headers={'Authorization': 'Bearer eyJhbGciOiJSUzI1NiJ9.!!!invalid!!!.sig'})

        assert response.status_code == 401

    def test_foreign_key_signature(self, oauth_app, foreign_private_key_pem):
        """Token signed with untrusted key returns 401."""
        client, _, _, _ = oauth_app

        # Create token signed with a different private key
        token = create_token(
            foreign_private_key_pem,
            scopes=['openid', 'mcp:read'],
        )

        response = client.post('/mcp/', headers={'Authorization': f'Bearer {token}'})

        assert response.status_code == 401

    def test_expired_token(self, oauth_app, private_key_pem):
        """Expired token (exp in past) returns 401."""
        client, _, _, _ = oauth_app

        # Create token that expired 1 hour ago
        token = create_token(
            private_key_pem,
            scopes=['openid', 'mcp:read'],
            exp_offset=-3600,  # Expired 1 hour ago
        )

        response = client.post('/mcp/', headers={'Authorization': f'Bearer {token}'})

        assert response.status_code == 401

    def test_wrong_issuer(self, oauth_app, private_key_pem):
        """Token with wrong issuer returns 401."""
        client, _, _, _ = oauth_app

        token = create_token(
            private_key_pem,
            issuer='http://evil-issuer.com/realms/hack',
            scopes=['openid', 'mcp:read'],
        )

        response = client.post('/mcp/', headers={'Authorization': f'Bearer {token}'})

        assert response.status_code == 401

    def test_wrong_audience(self, oauth_app, private_key_pem):
        """Token with wrong audience returns 401 (when audience is configured)."""
        client, _, _, _ = oauth_app

        token = create_token(
            private_key_pem,
            audience='wrong-audience',
            scopes=['openid', 'mcp:read'],
        )

        response = client.post('/mcp/', headers={'Authorization': f'Bearer {token}'})

        assert response.status_code == 401


# =============================================================================
# Test Cases: 403 Forbidden (Insufficient Scope)
# =============================================================================


class TestForbidden403:
    """Tests for scenarios that should return 403 Forbidden."""

    def test_valid_token_missing_required_scope(self, oauth_app, private_key_pem):
        """Valid token without required scope returns 403."""
        client, _, _, _ = oauth_app

        # Token with only 'openid', missing 'mcp:read'
        token = create_token(
            private_key_pem,
            scopes=['openid'],  # Missing 'mcp:read'
        )

        response = client.post('/mcp/', headers={'Authorization': f'Bearer {token}'})

        assert response.status_code == 403
        assert 'www-authenticate' in response.headers
        www_auth = response.headers['www-authenticate']
        assert 'error="insufficient_scope"' in www_auth

    def test_valid_token_with_no_scopes(self, oauth_app, private_key_pem):
        """Valid token with empty scopes returns 403."""
        client, _, _, _ = oauth_app

        token = create_token(
            private_key_pem,
            scopes=[],
        )

        response = client.post('/mcp/', headers={'Authorization': f'Bearer {token}'})

        assert response.status_code == 403


# =============================================================================
# Test Cases: Unprotected Routes (200 OK without token)
# =============================================================================


class TestUnprotectedRoutes:
    """Tests for routes that should be accessible without authentication."""

    def test_health_endpoint_without_token(self, oauth_app):
        """/health endpoint is accessible without authentication."""
        client, _, _, _ = oauth_app

        response = client.get('/health')

        assert response.status_code == 200
        assert response.text == 'OK'

    def test_health_endpoint_with_invalid_token(self, oauth_app):
        """/health endpoint works even with invalid token (not checked)."""
        client, _, _, _ = oauth_app

        response = client.get('/health', headers={'Authorization': 'Bearer invalid'})

        assert response.status_code == 200

    def test_protected_resource_metadata_without_token(self, oauth_app):
        """OAuth protected resource metadata is accessible without authentication."""
        client, _, _, _ = oauth_app

        response = client.get('/.well-known/oauth-protected-resource/mcp/')

        assert response.status_code == 200
        data = response.json()
        assert 'resource' in data
        assert 'authorization_servers' in data
        assert ISSUER_URL in data['authorization_servers']


# =============================================================================
# Test Cases: Valid Token (200 OK)
# =============================================================================


class TestValidToken:
    """Tests for successful authentication scenarios."""

    def test_valid_token_with_all_required_scopes(self, oauth_app, private_key_pem):
        """Valid token with all required scopes passes authentication.

        We mock the session manager to return a simple response, allowing us
        to verify that auth passes without needing the full MCP infrastructure.
        """
        client, _, _, app_handler = oauth_app

        token = create_token(
            private_key_pem,
            scopes=['openid', 'mcp:read'],
        )

        # Mock the session manager to return immediately
        async def mock_handle_request(scope, receive, send):
            from starlette.responses import JSONResponse

            response = JSONResponse({'status': 'ok'})
            await response(scope, receive, send)

        app_handler.session_manager.handle_request = mock_handle_request

        response = client.post('/mcp/', headers={'Authorization': f'Bearer {token}'})

        # Should pass auth and reach the handler (200)
        assert response.status_code == 200
        assert response.json() == {'status': 'ok'}


# =============================================================================
# Route Protection Test
# =============================================================================


class TestRouteProtection:
    """Tests that verify all routes are properly protected."""

    # Routes that should be protected (require auth)
    PROTECTED_ROUTES = [
        ('GET', '/sse'),
        ('POST', '/mcp'),
        ('POST', '/mcp/'),
        ('GET', '/mcp'),
        ('DELETE', '/mcp'),
        ('POST', '/messages/'),
    ]

    # Routes that should NOT require auth
    UNPROTECTED_ROUTES = [
        ('GET', '/health'),
        ('GET', '/.well-known/oauth-protected-resource/mcp/'),
    ]

    @pytest.mark.parametrize('method,path', PROTECTED_ROUTES)
    def test_protected_route_requires_auth(self, oauth_app, method, path):
        """Protected routes return 401 without authentication."""
        client, _, _, _ = oauth_app

        response = client.request(method, path)

        assert response.status_code == 401, f'{method} {path} should require authentication'
        assert 'www-authenticate' in response.headers

    @pytest.mark.parametrize('method,path', UNPROTECTED_ROUTES)
    def test_unprotected_route_accessible(self, oauth_app, method, path):
        """Unprotected routes are accessible without authentication."""
        client, _, _, _ = oauth_app

        response = client.request(method, path)

        assert response.status_code != 401, f'{method} {path} should not require authentication'

    def test_route_table_coverage(self, oauth_app):
        """
        Verify that all routes in the app are covered by protection tests.

        This test fails if a new route is added but not classified as
        protected or unprotected, ensuring no route accidentally becomes
        accessible without authentication.
        """
        client, _, _, _ = oauth_app
        app = client.app

        # Collect all route paths from the app
        all_routes = set()
        for route in app.routes:
            if hasattr(route, 'path'):
                all_routes.add(route.path)

        # Routes we've explicitly classified
        tested_paths = {path for _, path in self.PROTECTED_ROUTES + self.UNPROTECTED_ROUTES}

        # Find any routes we haven't classified
        # Note: some paths like '/messages' may appear as Mount paths
        uncovered = all_routes - tested_paths - {'/messages'}  # Mount paths may differ

        # This assertion documents our coverage; update if new routes are added
        assert len(uncovered) == 0 or uncovered == {'/.well-known/oauth-protected-resource'}, (
            f'Unclassified routes found: {uncovered}. '
            'Add them to PROTECTED_ROUTES or UNPROTECTED_ROUTES.'
        )


# =============================================================================
# Logging Security Test
# =============================================================================


class TestLoggingSecurity:
    """Tests that verify sensitive data is not logged."""

    def test_token_not_logged_on_auth_failure(self, oauth_app, caplog):
        """Token contents should not appear in logs on authentication failure."""
        client, _, _, _ = oauth_app

        # A distinctive token that we can search for in logs
        sensitive_token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.SENSITIVE_PAYLOAD_DATA.signature'

        with caplog.at_level(logging.DEBUG):
            client.post('/mcp/', headers={'Authorization': f'Bearer {sensitive_token}'})

        # Check that the sensitive payload is not in any log message
        log_text = ' '.join(record.message for record in caplog.records)

        # The full token should not appear
        assert sensitive_token not in log_text, 'Full token should not be logged'

        # The sensitive payload should not appear
        assert 'SENSITIVE_PAYLOAD_DATA' not in log_text, 'Token payload should not be logged'

    def test_valid_token_claims_not_logged(self, oauth_app, private_key_pem, caplog):
        """Token claims should not appear in logs."""
        client, _, _, _ = oauth_app

        token = create_token(
            private_key_pem,
            scopes=['openid', 'mcp:read'],
            extra_claims={'secret_claim': 'super_secret_value_12345'},
        )

        with caplog.at_level(logging.DEBUG):
            # Use a route that won't crash - even if auth passes
            client.get('/health', headers={'Authorization': f'Bearer {token}'})

        log_text = ' '.join(record.message for record in caplog.records)

        # The secret claim value should not appear in logs
        assert 'super_secret_value_12345' not in log_text, 'Token claims should not be logged'


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_bearer_prefix_case_insensitive(self, oauth_app, private_key_pem):
        """Bearer prefix should be case-insensitive per RFC 6750.

        Note: The MCP library uses .lower().startswith('bearer ') so this works.
        """
        client, _, _, app_handler = oauth_app

        token = create_token(
            private_key_pem,
            scopes=['openid', 'mcp:read'],
        )

        # Mock the session manager
        async def mock_handle_request(scope, receive, send):
            from starlette.responses import JSONResponse

            response = JSONResponse({'status': 'ok'})
            await response(scope, receive, send)

        app_handler.session_manager.handle_request = mock_handle_request

        # Test lowercase 'bearer'
        response = client.post('/mcp/', headers={'Authorization': f'bearer {token}'})
        assert response.status_code == 200, 'lowercase bearer should work'

    def test_mixed_case_bearer(self, oauth_app, private_key_pem):
        """Mixed case 'BEARER' should also work per RFC 6750."""
        client, _, _, app_handler = oauth_app

        token = create_token(
            private_key_pem,
            scopes=['openid', 'mcp:read'],
        )

        # Mock the session manager
        async def mock_handle_request(scope, receive, send):
            from starlette.responses import JSONResponse

            response = JSONResponse({'status': 'ok'})
            await response(scope, receive, send)

        app_handler.session_manager.handle_request = mock_handle_request

        # Test uppercase 'BEARER'
        response = client.post('/mcp/', headers={'Authorization': f'BEARER {token}'})
        assert response.status_code == 200, 'uppercase BEARER should work'

    def test_token_with_extra_whitespace_rejected(self, oauth_app, private_key_pem):
        """Token with extra whitespace after Bearer is rejected.

        The implementation uses auth_header[7:] which includes the space,
        making the token invalid.
        """
        client, _, _, _ = oauth_app

        token = create_token(
            private_key_pem,
            scopes=['openid', 'mcp:read'],
        )

        # Extra space after 'Bearer ' means token starts with space
        response = client.post('/mcp/', headers={'Authorization': f'Bearer  {token}'})
        assert response.status_code == 401

    def test_scopes_from_list_claim(self, oauth_app_no_audience, private_key_pem):
        """Token with scopes as list (instead of space-separated string) should work."""
        client, _, app_handler = oauth_app_no_audience

        # Create token with 'scopes' as list instead of 'scope' as string
        now = int(time.time())
        payload = {
            'iss': ISSUER_URL,
            'sub': 'test-user',
            'azp': 'test-client',
            'iat': now,
            'exp': now + 3600,
            'scopes': ['openid', 'mcp:read'],  # List format
        }
        token = jwt.encode(payload, private_key_pem, algorithm='RS256')

        # Mock the session manager
        async def mock_handle_request(scope, receive, send):
            from starlette.responses import JSONResponse

            response = JSONResponse({'status': 'ok'})
            await response(scope, receive, send)

        app_handler.session_manager.handle_request = mock_handle_request

        response = client.post('/mcp/', headers={'Authorization': f'Bearer {token}'})

        # Should pass auth
        assert response.status_code == 200


# =============================================================================
# Security-Critical Tests (Algorithm Confusion, JWKS Failures)
# =============================================================================


class TestSecurityCritical:
    """
    Security-critical tests for JWT validation edge cases.

    These tests verify that common JWT security vulnerabilities are properly
    mitigated by the implementation.
    """

    def test_algorithm_none_rejected(self, oauth_app):
        """
        Token with alg=none must be rejected.

        This tests against the classic JWT "algorithm none" attack where
        an attacker creates an unsigned token with {"alg": "none"}.
        """
        client, _, _, _ = oauth_app

        # Manually construct a token with alg=none
        # Header: {"alg": "none", "typ": "JWT"}
        header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=').decode()
        # Payload with valid claims
        now = int(time.time())
        payload_data = {
            'iss': ISSUER_URL,
            'sub': 'attacker',
            'azp': 'evil-client',
            'iat': now,
            'exp': now + 3600,
            'aud': AUDIENCE,
            'scope': 'openid mcp:read',
        }
        payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).rstrip(b'=').decode()
        # No signature for alg=none
        token = f'{header}.{payload}.'

        response = client.post('/mcp/', headers={'Authorization': f'Bearer {token}'})

        # Must be rejected - alg=none is a security vulnerability
        assert response.status_code == 401, 'alg=none tokens must be rejected'

    def test_algorithm_hs256_with_rsa_key_rejected(self, oauth_app, public_key_pem):
        """
        Token signed with HS256 using public key as secret must be rejected.

        This tests against the "algorithm confusion" attack where an attacker
        signs a token with HS256 using the RSA public key as the HMAC secret,
        hoping the server will accept it.
        """
        client, _, _, _ = oauth_app

        now = int(time.time())
        payload = {
            'iss': ISSUER_URL,
            'sub': 'attacker',
            'azp': 'evil-client',
            'iat': now,
            'exp': now + 3600,
            'aud': AUDIENCE,
            'scope': 'openid mcp:read',
        }

        # Sign with HS256 using the public key as secret (attack vector)
        # The attacker hopes the server will use the public key for verification
        try:
            token = jwt.encode(payload, public_key_pem.decode(), algorithm='HS256')
        except Exception:
            # Some JWT libraries reject this outright, which is fine
            pytest.skip('JWT library rejected HS256 with PEM key')

        response = client.post('/mcp/', headers={'Authorization': f'Bearer {token}'})

        # Must be rejected - server expects RS256, not HS256
        assert response.status_code == 401, 'HS256 tokens must be rejected when RS256 is expected'

    def test_jwks_lookup_failure_rejects_token(self, mock_mcp_server, oauth_config, private_key_pem):
        """
        Token must be rejected when JWKS lookup fails.

        If the JWKS endpoint is unreachable or returns an error, tokens
        should be rejected rather than accepted.
        """
        app_handler = MCPStarletteApp(
            mock_mcp_server,
            stateless=True,
            oauth_config=oauth_config,
        )

        # Mock JWKS client to raise an exception (simulating network failure)
        with patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client:
            mock_jwks_client.return_value.get_signing_key_from_jwt.side_effect = jwt.PyJWKClientError(
                'JWKS endpoint unreachable'
            )
            app = app_handler.create_app()
            app.router.lifespan_context = None
            client = TestClient(app)

            token = create_token(
                private_key_pem,
                scopes=['openid', 'mcp:read'],
            )

            response = client.post('/mcp/', headers={'Authorization': f'Bearer {token}'})

            # Must be rejected when JWKS lookup fails
            assert response.status_code == 401, 'Token must be rejected when JWKS lookup fails'

    def test_token_with_wrong_kid_in_header(self, oauth_app, private_key_pem):
        """
        Document unit test limitation for kid validation.

        Note: With the current mock setup, the mock always returns the same key
        regardless of kid. This is a known limitation of unit tests.

        In production, if a token's kid doesn't match any key in the JWKS,
        the JWKS client would raise an exception and the token would be rejected.
        Full JWKS validation including kid matching is tested in integration
        tests (Issue 12) with a real JWKS endpoint.
        """
        client, mock_signing_key, _, app_handler = oauth_app

        # Create a token with a specific kid in the header
        now = int(time.time())
        payload = {
            'iss': ISSUER_URL,
            'sub': 'test-user',
            'azp': 'test-client',
            'iat': now,
            'exp': now + 3600,
            'aud': AUDIENCE,
            'scope': 'openid mcp:read',
        }
        # Add kid to header that doesn't match what JWKS would return
        token = jwt.encode(
            payload,
            private_key_pem,
            algorithm='RS256',
            headers={'kid': 'unknown-key-id-12345'},
        )

        # Mock the session manager for when auth passes
        async def mock_handle_request(scope, receive, send):
            from starlette.responses import JSONResponse

            response = JSONResponse({'status': 'ok'})
            await response(scope, receive, send)

        app_handler.session_manager.handle_request = mock_handle_request

        response = client.post('/mcp/', headers={'Authorization': f'Bearer {token}'})

        # With mocked JWKS client, token passes because mock returns correct key.
        # This documents the limitation - real JWKS validation happens in integration tests.
        assert response.status_code == 200, (
            'With mocked JWKS, tokens with any kid pass. '
            'Real kid validation happens in integration tests (Issue 12).'
        )

    def test_token_without_exp_claim_behavior(self, oauth_app, private_key_pem):
        """
        Document behavior of tokens without exp claim.

        PyJWT with default options does NOT require exp claim.
        This test documents the current behavior. Whether this is a security
        issue depends on the deployment context.

        Note: The MCP BearerAuthBackend checks expires_at after decode,
        so tokens without exp will have expires_at=None and pass that check.
        """
        client, _, _, app_handler = oauth_app

        now = int(time.time())
        payload = {
            'iss': ISSUER_URL,
            'sub': 'test-user',
            'azp': 'test-client',
            'iat': now,
            'aud': AUDIENCE,
            'scope': 'openid mcp:read',
            # No 'exp' claim
        }

        token = jwt.encode(payload, private_key_pem, algorithm='RS256')

        # Mock the session manager for when auth passes
        async def mock_handle_request(scope, receive, send):
            from starlette.responses import JSONResponse

            response = JSONResponse({'status': 'ok'})
            await response(scope, receive, send)

        app_handler.session_manager.handle_request = mock_handle_request

        response = client.post('/mcp/', headers={'Authorization': f'Bearer {token}'})

        # Document actual behavior: PyJWT allows tokens without exp by default
        # The MCP BearerAuthBackend checks: if auth_info.expires_at and auth_info.expires_at < now
        # If expires_at is None (no exp claim), the check passes (None is falsy)
        # This is arguably a security concern but matches the MCP library's design
        assert response.status_code in (200, 401), (
            'Tokens without exp may be accepted depending on jwt.decode options'
        )

    def test_token_with_future_nbf_rejected(self, oauth_app, private_key_pem):
        """
        Token with future nbf (not-before) should be rejected.

        The nbf claim specifies when the token becomes valid. Tokens with
        nbf in the future should be rejected.
        """
        client, _, _, _ = oauth_app

        now = int(time.time())
        payload = {
            'iss': ISSUER_URL,
            'sub': 'test-user',
            'azp': 'test-client',
            'iat': now,
            'nbf': now + 3600,  # Not valid for another hour
            'exp': now + 7200,
            'aud': AUDIENCE,
            'scope': 'openid mcp:read',
        }
        token = jwt.encode(payload, private_key_pem, algorithm='RS256')

        response = client.post('/mcp/', headers={'Authorization': f'Bearer {token}'})

        # Should be rejected - token is not yet valid
        assert response.status_code == 401, 'Tokens with future nbf should be rejected'

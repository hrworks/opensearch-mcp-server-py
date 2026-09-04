# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

import jwt
import pytest
import time
from mcp_server_opensearch.oauth import (
    JwtTokenVerifier,
    OAuthConfig,
    _as_int,
    _extract_scopes,
    _is_truthy,
    _split_scopes,
    load_oauth_config,
)
from unittest.mock import AsyncMock, Mock, patch


class TestIsTruthy:
    """Tests for _is_truthy() helper function."""

    @pytest.mark.parametrize(
        'value,expected',
        [
            ('true', True),
            ('True', True),
            ('TRUE', True),
            ('yes', True),
            ('Yes', True),
            ('YES', True),
            ('on', True),
            ('On', True),
            ('ON', True),
            ('1', True),
            ('  true  ', True),  # whitespace handling
            ('false', False),
            ('False', False),
            ('no', False),
            ('off', False),
            ('0', False),
            ('', False),
            ('  ', False),  # whitespace only
            ('random', False),
            (None, False),
        ],
    )
    def test_is_truthy_values(self, value, expected):
        assert _is_truthy(value) is expected


class TestSplitScopes:
    """Tests for _split_scopes() helper function."""

    @pytest.mark.parametrize(
        'value,expected',
        [
            (None, []),
            ('', []),
            ('  ', []),
            ('openid', ['openid']),
            ('openid profile', ['openid', 'profile']),
            ('openid,profile', ['openid', 'profile']),
            ('openid, profile', ['openid', 'profile']),
            ('openid,profile email', ['openid', 'profile', 'email']),  # mixed separators
            ('  openid  profile  ', ['openid', 'profile']),  # extra whitespace
        ],
    )
    def test_split_scopes_values(self, value, expected):
        assert _split_scopes(value) == expected


class TestExtractScopes:
    """Tests for _extract_scopes() helper function."""

    def test_extract_scopes_from_scope_string(self):
        """Scope as space-separated string (standard OAuth2)."""
        payload = {'scope': 'openid profile email'}
        assert _extract_scopes(payload) == ['openid', 'profile', 'email']

    def test_extract_scopes_from_scopes_list(self):
        """Scopes as list (some providers use this)."""
        payload = {'scopes': ['openid', 'profile', 'email']}
        assert _extract_scopes(payload) == ['openid', 'profile', 'email']

    def test_extract_scopes_from_scopes_list_with_non_strings(self):
        """Scopes list with non-string elements gets converted."""
        payload = {'scopes': ['openid', 123, True]}
        assert _extract_scopes(payload) == ['openid', '123', 'True']

    def test_extract_scopes_empty_when_neither_present(self):
        """Returns empty list when neither scope nor scopes is present."""
        assert _extract_scopes({}) == []
        assert _extract_scopes({'other': 'data'}) == []

    def test_extract_scopes_prefers_scope_over_scopes(self):
        """When both are present, scope string takes precedence."""
        payload = {'scope': 'openid', 'scopes': ['profile', 'email']}
        assert _extract_scopes(payload) == ['openid']

    def test_extract_scopes_ignores_non_string_scope(self):
        """Non-string scope value falls through to scopes check."""
        payload = {'scope': 123, 'scopes': ['openid']}
        assert _extract_scopes(payload) == ['openid']

    def test_extract_scopes_ignores_non_list_scopes(self):
        """Non-list scopes value returns empty."""
        payload = {'scopes': 'not-a-list'}
        assert _extract_scopes(payload) == []


class TestAsInt:
    """Tests for _as_int() helper function."""

    @pytest.mark.parametrize(
        'value,expected',
        [
            (None, None),
            (12345, 12345),
            ('12345', 12345),
            (12345.0, 12345),
            ('invalid', None),
            ([], None),
            ({}, None),
            (object(), None),
        ],
    )
    def test_as_int_values(self, value, expected):
        assert _as_int(value) == expected


class TestOAuthConfig:
    def test_load_oauth_config_disabled(self, monkeypatch):
        monkeypatch.delenv('MCP_OAUTH_ENABLED', raising=False)

        assert load_oauth_config('127.0.0.1', 9900) is None

    @pytest.mark.parametrize('disabled_value', ['false', 'no', 'off', '0', '', '  '])
    def test_load_oauth_config_disabled_explicit(self, monkeypatch, disabled_value):
        """OAuth is disabled for various falsy values."""
        monkeypatch.setenv('MCP_OAUTH_ENABLED', disabled_value)
        assert load_oauth_config('127.0.0.1', 9900) is None

    @pytest.mark.parametrize('enabled_value', ['true', 'yes', 'on', '1', 'True', 'YES'])
    def test_load_oauth_config_enabled_variants(self, monkeypatch, enabled_value):
        """OAuth is enabled for various truthy values."""
        monkeypatch.setenv('MCP_OAUTH_ENABLED', enabled_value)
        monkeypatch.setenv('MCP_OAUTH_ISSUER_URL', 'http://issuer.example.com')

        config = load_oauth_config('127.0.0.1', 9900)

        assert config is not None
        assert config.enabled is True

    def test_load_oauth_config_defaults(self, monkeypatch):
        monkeypatch.setenv('MCP_OAUTH_ENABLED', 'true')
        monkeypatch.setenv('MCP_OAUTH_ISSUER_URL', 'http://localhost:8080/realms/opensearch/')
        monkeypatch.setenv('MCP_OAUTH_REQUIRED_SCOPES', 'openid,profile email')
        monkeypatch.delenv('MCP_OAUTH_RESOURCE_URL', raising=False)
        monkeypatch.delenv('MCP_OAUTH_JWKS_URL', raising=False)
        monkeypatch.delenv('MCP_OAUTH_AUDIENCE', raising=False)

        config = load_oauth_config('0.0.0.0', 9900)

        assert config is not None
        assert config.enabled is True
        assert config.issuer_url == 'http://localhost:8080/realms/opensearch'
        assert config.resource_url == 'http://localhost:9900/mcp/'
        assert (
            config.jwks_url
            == 'http://localhost:8080/realms/opensearch/protocol/openid-connect/certs'
        )
        assert config.required_scopes == ['openid', 'profile', 'email']
        assert config.audience is None

    def test_load_oauth_config_host_0000_defaults_to_localhost(self, monkeypatch):
        """When host is 0.0.0.0, resource_url defaults to localhost."""
        monkeypatch.setenv('MCP_OAUTH_ENABLED', 'true')
        monkeypatch.setenv('MCP_OAUTH_ISSUER_URL', 'http://issuer.example.com')
        monkeypatch.delenv('MCP_OAUTH_RESOURCE_URL', raising=False)

        config = load_oauth_config('0.0.0.0', 8080)

        assert config.resource_url == 'http://localhost:8080/mcp/'

    def test_load_oauth_config_specific_host_used(self, monkeypatch):
        """When host is not 0.0.0.0, it's used in resource_url."""
        monkeypatch.setenv('MCP_OAUTH_ENABLED', 'true')
        monkeypatch.setenv('MCP_OAUTH_ISSUER_URL', 'http://issuer.example.com')
        monkeypatch.delenv('MCP_OAUTH_RESOURCE_URL', raising=False)

        config = load_oauth_config('192.168.1.100', 8080)

        assert config.resource_url == 'http://192.168.1.100:8080/mcp/'

    def test_load_oauth_config_issuer_trailing_slash_stripped(self, monkeypatch):
        """Trailing slash is stripped from issuer URL."""
        monkeypatch.setenv('MCP_OAUTH_ENABLED', 'true')
        monkeypatch.setenv('MCP_OAUTH_ISSUER_URL', 'http://issuer.example.com/realm/')

        config = load_oauth_config('127.0.0.1', 9900)

        assert config.issuer_url == 'http://issuer.example.com/realm'
        assert config.jwks_url == 'http://issuer.example.com/realm/protocol/openid-connect/certs'

    def test_load_oauth_config_issuer_no_trailing_slash(self, monkeypatch):
        """Issuer without trailing slash works correctly."""
        monkeypatch.setenv('MCP_OAUTH_ENABLED', 'true')
        monkeypatch.setenv('MCP_OAUTH_ISSUER_URL', 'http://issuer.example.com/realm')

        config = load_oauth_config('127.0.0.1', 9900)

        assert config.issuer_url == 'http://issuer.example.com/realm'

    def test_load_oauth_config_with_audience(self, monkeypatch):
        """Audience is set when provided."""
        monkeypatch.setenv('MCP_OAUTH_ENABLED', 'true')
        monkeypatch.setenv('MCP_OAUTH_ISSUER_URL', 'http://issuer.example.com')
        monkeypatch.setenv('MCP_OAUTH_AUDIENCE', 'my-mcp-server')

        config = load_oauth_config('127.0.0.1', 9900)

        assert config.audience == 'my-mcp-server'

    def test_load_oauth_config_empty_audience_becomes_none(self, monkeypatch):
        """Empty or whitespace-only audience becomes None."""
        monkeypatch.setenv('MCP_OAUTH_ENABLED', 'true')
        monkeypatch.setenv('MCP_OAUTH_ISSUER_URL', 'http://issuer.example.com')
        monkeypatch.setenv('MCP_OAUTH_AUDIENCE', '   ')

        config = load_oauth_config('127.0.0.1', 9900)

        assert config.audience is None

    def test_load_oauth_config_requires_issuer(self, monkeypatch):
        monkeypatch.setenv('MCP_OAUTH_ENABLED', 'true')
        monkeypatch.delenv('MCP_OAUTH_ISSUER_URL', raising=False)

        with pytest.raises(ValueError, match='MCP_OAUTH_ISSUER_URL'):
            load_oauth_config('127.0.0.1', 9900)

    def test_load_oauth_config_empty_issuer_raises(self, monkeypatch):
        """Empty or whitespace-only issuer raises ValueError."""
        monkeypatch.setenv('MCP_OAUTH_ENABLED', 'true')
        monkeypatch.setenv('MCP_OAUTH_ISSUER_URL', '   ')

        with pytest.raises(ValueError, match='MCP_OAUTH_ISSUER_URL'):
            load_oauth_config('127.0.0.1', 9900)


class TestJwtTokenVerifier:
    @pytest.mark.asyncio
    async def test_verify_token(self):
        config = OAuthConfig(
            enabled=True,
            issuer_url='http://localhost:8080/realms/opensearch',
            resource_url='http://127.0.0.1:9900/mcp/',
            jwks_url='http://localhost:8080/realms/opensearch/protocol/openid-connect/certs',
            required_scopes=['openid'],
            audience='opensearch-mcp',
        )

        signing_key = Mock()
        signing_key.key = 'public-key'

        with (
            patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client,
            patch('mcp_server_opensearch.oauth.jwt.decode') as mock_decode,
        ):
            mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = signing_key
            mock_decode.return_value = {
                'azp': 'opensearch-mcp',
                'scope': 'openid profile email',
                'exp': 12345,
            }

            verifier = JwtTokenVerifier(config)
            access_token = await verifier.verify_token('encoded-token')

        assert access_token is not None
        assert access_token.token == 'encoded-token'
        assert access_token.client_id == 'opensearch-mcp'
        assert access_token.scopes == ['openid', 'profile', 'email']
        assert access_token.expires_at == 12345
        mock_decode.assert_called_once_with(
            'encoded-token',
            'public-key',
            algorithms=['RS256'],
            audience='opensearch-mcp',
            issuer='http://localhost:8080/realms/opensearch',
            options={'verify_aud': True},
        )

    @pytest.mark.asyncio
    async def test_verify_token_returns_none_for_invalid_token(self):
        config = OAuthConfig(
            enabled=True,
            issuer_url='http://localhost:8080/realms/opensearch',
            resource_url='http://127.0.0.1:9900/mcp/',
            jwks_url='http://localhost:8080/realms/opensearch/protocol/openid-connect/certs',
            required_scopes=[],
        )

        with patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client:
            mock_jwks_client.return_value.get_signing_key_from_jwt.side_effect = jwt.PyJWTError(
                'bad token'
            )

            verifier = JwtTokenVerifier(config)
            access_token = await verifier.verify_token('encoded-token')

        assert access_token is None

    @pytest.mark.asyncio
    async def test_verify_token_without_audience_disables_aud_verification(self):
        """SECURITY DOCUMENTATION: Audience bypass when not configured.

        When audience is not configured, any valid token from the issuer is accepted.
        This is intentional for setups where audience restriction is not needed,
        but users should be aware this accepts a broader set of tokens.
        """
        config = OAuthConfig(
            enabled=True,
            issuer_url='http://localhost:8080/realms/opensearch',
            resource_url='http://127.0.0.1:9900/mcp/',
            jwks_url='http://localhost:8080/realms/opensearch/protocol/openid-connect/certs',
            required_scopes=[],
            audience=None,  # No audience configured
        )

        signing_key = Mock()
        signing_key.key = 'public-key'

        with (
            patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client,
            patch('mcp_server_opensearch.oauth.jwt.decode') as mock_decode,
        ):
            mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = signing_key
            mock_decode.return_value = {
                'sub': 'user-123',
                'scope': 'openid',
                'exp': 99999,
            }

            verifier = JwtTokenVerifier(config)
            access_token = await verifier.verify_token('any-valid-token')

        # verify_aud should be False when audience is None
        mock_decode.assert_called_once_with(
            'any-valid-token',
            'public-key',
            algorithms=['RS256'],
            audience=None,
            issuer='http://localhost:8080/realms/opensearch',
            options={'verify_aud': False},
        )
        assert access_token is not None

    @pytest.mark.asyncio
    async def test_verify_token_client_id_fallback_to_client_id(self):
        """When azp is missing, falls back to client_id claim."""
        config = OAuthConfig(
            enabled=True,
            issuer_url='http://localhost:8080/realms/opensearch',
            resource_url='http://127.0.0.1:9900/mcp/',
            jwks_url='http://localhost:8080/realms/opensearch/protocol/openid-connect/certs',
            required_scopes=[],
        )

        signing_key = Mock()
        signing_key.key = 'public-key'

        with (
            patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client,
            patch('mcp_server_opensearch.oauth.jwt.decode') as mock_decode,
        ):
            mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = signing_key
            mock_decode.return_value = {
                'client_id': 'my-client-app',
                'exp': 12345,
            }

            verifier = JwtTokenVerifier(config)
            access_token = await verifier.verify_token('token')

        assert access_token.client_id == 'my-client-app'

    @pytest.mark.asyncio
    async def test_verify_token_client_id_fallback_to_sub(self):
        """When azp and client_id are missing, falls back to sub claim."""
        config = OAuthConfig(
            enabled=True,
            issuer_url='http://localhost:8080/realms/opensearch',
            resource_url='http://127.0.0.1:9900/mcp/',
            jwks_url='http://localhost:8080/realms/opensearch/protocol/openid-connect/certs',
            required_scopes=[],
        )

        signing_key = Mock()
        signing_key.key = 'public-key'

        with (
            patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client,
            patch('mcp_server_opensearch.oauth.jwt.decode') as mock_decode,
        ):
            mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = signing_key
            mock_decode.return_value = {
                'sub': 'user-subject-id',
                'exp': 12345,
            }

            verifier = JwtTokenVerifier(config)
            access_token = await verifier.verify_token('token')

        assert access_token.client_id == 'user-subject-id'

    @pytest.mark.asyncio
    async def test_verify_token_client_id_fallback_to_unknown(self):
        """When all client_id claims are missing, falls back to 'unknown-client'."""
        config = OAuthConfig(
            enabled=True,
            issuer_url='http://localhost:8080/realms/opensearch',
            resource_url='http://127.0.0.1:9900/mcp/',
            jwks_url='http://localhost:8080/realms/opensearch/protocol/openid-connect/certs',
            required_scopes=[],
        )

        signing_key = Mock()
        signing_key.key = 'public-key'

        with (
            patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client,
            patch('mcp_server_opensearch.oauth.jwt.decode') as mock_decode,
        ):
            mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = signing_key
            mock_decode.return_value = {
                'exp': 12345,
                # No azp, client_id, or sub
            }

            verifier = JwtTokenVerifier(config)
            access_token = await verifier.verify_token('token')

        assert access_token.client_id == 'unknown-client'

    @pytest.mark.asyncio
    async def test_verify_token_with_scopes_list(self):
        """Token with scopes as list instead of space-separated string."""
        config = OAuthConfig(
            enabled=True,
            issuer_url='http://localhost:8080/realms/opensearch',
            resource_url='http://127.0.0.1:9900/mcp/',
            jwks_url='http://localhost:8080/realms/opensearch/protocol/openid-connect/certs',
            required_scopes=[],
        )

        signing_key = Mock()
        signing_key.key = 'public-key'

        with (
            patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client,
            patch('mcp_server_opensearch.oauth.jwt.decode') as mock_decode,
        ):
            mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = signing_key
            mock_decode.return_value = {
                'sub': 'user',
                'scopes': ['read', 'write', 'admin'],  # list format
                'exp': 12345,
            }

            verifier = JwtTokenVerifier(config)
            access_token = await verifier.verify_token('token')

        assert access_token.scopes == ['read', 'write', 'admin']

    @pytest.mark.asyncio
    async def test_verify_token_without_exp(self):
        """Token without exp claim returns None for expires_at."""
        config = OAuthConfig(
            enabled=True,
            issuer_url='http://localhost:8080/realms/opensearch',
            resource_url='http://127.0.0.1:9900/mcp/',
            jwks_url='http://localhost:8080/realms/opensearch/protocol/openid-connect/certs',
            required_scopes=[],
        )

        signing_key = Mock()
        signing_key.key = 'public-key'

        with (
            patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client,
            patch('mcp_server_opensearch.oauth.jwt.decode') as mock_decode,
        ):
            mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = signing_key
            mock_decode.return_value = {
                'sub': 'user',
                # No exp claim
            }

            verifier = JwtTokenVerifier(config)
            access_token = await verifier.verify_token('token')

        assert access_token.expires_at is None

    @pytest.mark.asyncio
    async def test_verify_token_with_invalid_exp(self):
        """Token with invalid exp claim returns None for expires_at."""
        config = OAuthConfig(
            enabled=True,
            issuer_url='http://localhost:8080/realms/opensearch',
            resource_url='http://127.0.0.1:9900/mcp/',
            jwks_url='http://localhost:8080/realms/opensearch/protocol/openid-connect/certs',
            required_scopes=[],
        )

        signing_key = Mock()
        signing_key.key = 'public-key'

        with (
            patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client,
            patch('mcp_server_opensearch.oauth.jwt.decode') as mock_decode,
        ):
            mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = signing_key
            mock_decode.return_value = {
                'sub': 'user',
                'exp': 'not-a-number',
            }

            verifier = JwtTokenVerifier(config)
            access_token = await verifier.verify_token('token')

        assert access_token.expires_at is None

    @pytest.mark.asyncio
    async def test_verify_token_decode_error_returns_none(self):
        """jwt.decode raising PyJWTError returns None."""
        config = OAuthConfig(
            enabled=True,
            issuer_url='http://localhost:8080/realms/opensearch',
            resource_url='http://127.0.0.1:9900/mcp/',
            jwks_url='http://localhost:8080/realms/opensearch/protocol/openid-connect/certs',
            required_scopes=[],
        )

        signing_key = Mock()
        signing_key.key = 'public-key'

        with (
            patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client,
            patch('mcp_server_opensearch.oauth.jwt.decode') as mock_decode,
        ):
            mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = signing_key
            mock_decode.side_effect = jwt.PyJWTError('Invalid signature')

            verifier = JwtTokenVerifier(config)
            access_token = await verifier.verify_token('bad-token')

        assert access_token is None


class TestGoogleOpaqueTokenFallback:
    """Tests for the Google tokeninfo fallback path in JwtTokenVerifier."""

    def _google_config(self, audience=None, required_scopes=None, issuer='https://accounts.google.com'):
        return OAuthConfig(
            enabled=True,
            issuer_url=issuer,
            resource_url='http://127.0.0.1:9900/mcp/',
            jwks_url='https://www.googleapis.com/oauth2/v3/certs',
            required_scopes=required_scopes or [],
            audience=audience,
        )

    def _tokeninfo_response(self, overrides=None):
        """Build a default valid Google tokeninfo response dict."""
        future_exp = int(time.time()) + 3600
        data = {
            'aud': 'my-client-id.apps.googleusercontent.com',
            'iss': 'accounts.google.com',
            'sub': '10769150350006150715113082367',
            'email': 'user@example.com',
            'exp': str(future_exp),
            'scope': 'openid email profile',
            'azp': 'my-client-id.apps.googleusercontent.com',
        }
        if overrides:
            data.update(overrides)
        return data

    @pytest.mark.asyncio
    async def test_verify_opaque_token_google_tokeninfo_success(self):
        """Opaque Google token is accepted when tokeninfo returns valid data."""
        config = self._google_config(
            audience='my-client-id.apps.googleusercontent.com',
            required_scopes=['openid', 'email'],
        )
        tokeninfo = self._tokeninfo_response()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = tokeninfo

        with (
            patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client,
            patch('mcp_server_opensearch.oauth.httpx.AsyncClient') as mock_http_client_cls,
        ):
            mock_jwks_client.return_value.get_signing_key_from_jwt.side_effect = jwt.PyJWTError(
                'Not enough segments'
            )
            mock_http_instance = AsyncMock()
            mock_http_instance.__aenter__ = AsyncMock(return_value=mock_http_instance)
            mock_http_instance.__aexit__ = AsyncMock(return_value=False)
            mock_http_instance.get = AsyncMock(return_value=mock_response)
            mock_http_client_cls.return_value = mock_http_instance

            verifier = JwtTokenVerifier(config)
            access_token = await verifier.verify_token('ya29.opaque-token')

        assert access_token is not None
        assert access_token.token == 'ya29.opaque-token'
        assert access_token.client_id == 'my-client-id.apps.googleusercontent.com'
        assert 'openid' in access_token.scopes
        assert 'email' in access_token.scopes
        assert access_token.expires_at == int(tokeninfo['exp'])
        assert access_token.resource == 'http://127.0.0.1:9900/mcp/'

    @pytest.mark.asyncio
    async def test_verify_opaque_token_wrong_audience_rejected(self):
        """Opaque token is rejected when tokeninfo aud does not match configured audience."""
        config = self._google_config(audience='expected-client-id')
        tokeninfo = self._tokeninfo_response({'aud': 'different-client-id'})
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = tokeninfo

        with (
            patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client,
            patch('mcp_server_opensearch.oauth.httpx.AsyncClient') as mock_http_client_cls,
        ):
            mock_jwks_client.return_value.get_signing_key_from_jwt.side_effect = jwt.PyJWTError(
                'Not enough segments'
            )
            mock_http_instance = AsyncMock()
            mock_http_instance.__aenter__ = AsyncMock(return_value=mock_http_instance)
            mock_http_instance.__aexit__ = AsyncMock(return_value=False)
            mock_http_instance.get = AsyncMock(return_value=mock_response)
            mock_http_client_cls.return_value = mock_http_instance

            verifier = JwtTokenVerifier(config)
            access_token = await verifier.verify_token('ya29.opaque-token')

        assert access_token is None

    @pytest.mark.asyncio
    async def test_verify_opaque_token_network_error_returns_none(self):
        """Network failure when calling tokeninfo endpoint returns None."""
        import httpx as _httpx
        config = self._google_config()

        with (
            patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client,
            patch('mcp_server_opensearch.oauth.httpx.AsyncClient') as mock_http_client_cls,
        ):
            mock_jwks_client.return_value.get_signing_key_from_jwt.side_effect = jwt.PyJWTError(
                'Not enough segments'
            )
            mock_http_instance = AsyncMock()
            mock_http_instance.__aenter__ = AsyncMock(return_value=mock_http_instance)
            mock_http_instance.__aexit__ = AsyncMock(return_value=False)
            mock_http_instance.get = AsyncMock(
                side_effect=_httpx.ConnectError('Connection refused')
            )
            mock_http_client_cls.return_value = mock_http_instance

            verifier = JwtTokenVerifier(config)
            access_token = await verifier.verify_token('ya29.opaque-token')

        assert access_token is None

    @pytest.mark.asyncio
    async def test_verify_opaque_token_expired_returns_none(self):
        """Opaque token with past exp timestamp is rejected."""
        config = self._google_config()
        past_exp = int(time.time()) - 60
        tokeninfo = self._tokeninfo_response({'exp': str(past_exp)})
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = tokeninfo

        with (
            patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client,
            patch('mcp_server_opensearch.oauth.httpx.AsyncClient') as mock_http_client_cls,
        ):
            mock_jwks_client.return_value.get_signing_key_from_jwt.side_effect = jwt.PyJWTError(
                'Not enough segments'
            )
            mock_http_instance = AsyncMock()
            mock_http_instance.__aenter__ = AsyncMock(return_value=mock_http_instance)
            mock_http_instance.__aexit__ = AsyncMock(return_value=False)
            mock_http_instance.get = AsyncMock(return_value=mock_response)
            mock_http_client_cls.return_value = mock_http_instance

            verifier = JwtTokenVerifier(config)
            access_token = await verifier.verify_token('ya29.opaque-token')

        assert access_token is None

    @pytest.mark.asyncio
    async def test_jwt_token_still_works_regression(self):
        """Regular JWT tokens continue to work through the JWKS path (regression guard)."""
        config = OAuthConfig(
            enabled=True,
            issuer_url='http://localhost:8080/realms/opensearch',
            resource_url='http://127.0.0.1:9900/mcp/',
            jwks_url='http://localhost:8080/realms/opensearch/protocol/openid-connect/certs',
            required_scopes=['openid'],
            audience='opensearch-mcp',
        )
        signing_key = Mock()
        signing_key.key = 'public-key'

        with (
            patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client,
            patch('mcp_server_opensearch.oauth.jwt.decode') as mock_decode,
        ):
            mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = signing_key
            mock_decode.return_value = {
                'azp': 'opensearch-mcp',
                'scope': 'openid profile',
                'exp': 99999999,
            }

            verifier = JwtTokenVerifier(config)
            access_token = await verifier.verify_token('eyJhbGciOiJSUzI1NiJ9.payload.sig')

        assert access_token is not None
        assert access_token.client_id == 'opensearch-mcp'
        assert 'openid' in access_token.scopes
        # Ensure tokeninfo was never called (httpx not used)
        mock_decode.assert_called_once()

    @pytest.mark.asyncio
    async def test_opaque_token_non_google_issuer_no_fallback(self):
        """When issuer is not Google, JWT failure returns None without tokeninfo call."""
        config = OAuthConfig(
            enabled=True,
            issuer_url='http://keycloak.example.com/realms/myapp',
            resource_url='http://127.0.0.1:9900/mcp/',
            jwks_url='http://keycloak.example.com/realms/myapp/protocol/openid-connect/certs',
            required_scopes=[],
        )

        with (
            patch('mcp_server_opensearch.oauth.jwt.PyJWKClient') as mock_jwks_client,
            patch('mcp_server_opensearch.oauth.httpx.AsyncClient') as mock_http_client_cls,
        ):
            mock_jwks_client.return_value.get_signing_key_from_jwt.side_effect = jwt.PyJWTError(
                'Not enough segments'
            )

            verifier = JwtTokenVerifier(config)
            access_token = await verifier.verify_token('ya29.opaque-but-wrong-issuer')

        assert access_token is None
        # httpx.AsyncClient should never have been instantiated
        mock_http_client_cls.assert_not_called()

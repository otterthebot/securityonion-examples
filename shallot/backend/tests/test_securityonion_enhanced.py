"""Enhanced tests for the Security Onion client."""
import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, AsyncMock, ANY
import httpx

from app.core.securityonion import SecurityOnionClient, client as global_client
from app.models.settings import Settings as SettingsModel
from tests.utils import await_mock


@pytest.fixture
def mock_settings_db():
    """Fixture to create a mock database with Security Onion settings."""
    settings_mock = MagicMock(spec=SettingsModel)
    settings_mock.value = json.dumps({
        "apiUrl": "https://securityonion.example.com",
        "clientId": "test_client_id", 
        "clientSecret": "test_client_secret",
        "verifySSL": True
    })
    
    # Mock the database session
    db_mock = AsyncMock()
    return db_mock, settings_mock


@pytest.fixture
def mock_token_response():
    """Fixture to create a mock token response."""
    response_mock = MagicMock(spec=httpx.Response)
    response_mock.status_code = 200
    response_mock.headers = {"content-type": "application/json"}
    response_mock.text = json.dumps({
        "access_token": "test_access_token",
        "expires_in": 3600,
        "token_type": "Bearer"
    })
    response_mock.json.return_value = {
        "access_token": "test_access_token",
        "expires_in": 3600,
        "token_type": "Bearer"
    }
    return response_mock


@pytest.fixture
def mock_health_response():
    """Fixture to create a mock health response."""
    response_mock = MagicMock(spec=httpx.Response)
    response_mock.status_code = 200
    response_mock.headers = {"content-type": "application/json"}
    response_mock.text = json.dumps({"status": "ok"})
    response_mock.json.return_value = {"status": "ok"}
    return response_mock


@pytest.fixture
def security_onion_client():
    """Return a fresh instance of the SecurityOnionClient."""
    return SecurityOnionClient()


@pytest.mark.asyncio
async def test_initialization_success(mock_settings_db, mock_token_response, mock_health_response, security_onion_client):
    """Test successful initialization of the Security Onion client."""
    db_mock, settings_mock = mock_settings_db

    # Mock the database session and get_setting at the import location
    with patch('app.database.AsyncSessionLocal', return_value=db_mock), \
         patch('app.core.securityonion.get_setting', AsyncMock(return_value=settings_mock)), \
         patch('app.core.securityonion.httpx.AsyncClient') as mock_http_class:

        # Setup mock HTTP client that supports post/get
        mock_http_client = AsyncMock()
        mock_http_client.post = AsyncMock(return_value=mock_token_response)
        mock_http_client.get = AsyncMock(return_value=mock_health_response)
        mock_http_class.return_value = mock_http_client

        # Initialize the client
        await security_onion_client.initialize()

        # Verify the client is connected
        assert security_onion_client._connected is True
        assert security_onion_client._last_error is None
        assert security_onion_client._base_url == "https://securityonion.example.com/"
        assert security_onion_client._client_id == "test_client_id"
        assert security_onion_client._client_secret == "test_client_secret"
        assert security_onion_client._verify_ssl is True


@pytest.mark.asyncio
async def test_initialization_missing_settings(mock_settings_db, security_onion_client):
    """Test initialization with missing settings."""
    db_mock, _ = mock_settings_db

    with patch('app.database.AsyncSessionLocal', return_value=db_mock), \
         patch('app.core.securityonion.get_setting', AsyncMock(return_value=None)):

        await security_onion_client.initialize()

        assert security_onion_client._connected is False
        assert security_onion_client._last_error == "Security Onion settings not found"


@pytest.mark.asyncio
async def test_initialization_invalid_settings_json(mock_settings_db, security_onion_client):
    """Test initialization with invalid settings JSON."""
    db_mock, settings_mock = mock_settings_db
    settings_mock.value = "invalid json"

    with patch('app.database.AsyncSessionLocal', return_value=db_mock), \
         patch('app.core.securityonion.get_setting', AsyncMock(return_value=settings_mock)):

        await security_onion_client.initialize()

        assert security_onion_client._connected is False
        assert "Invalid settings format" in security_onion_client._last_error


@pytest.mark.asyncio
async def test_initialization_missing_required_fields(mock_settings_db, security_onion_client):
    """Test initialization with missing required fields."""
    db_mock, settings_mock = mock_settings_db
    settings_mock.value = json.dumps({
        "apiUrl": "https://securityonion.example.com",
        # Missing clientId and clientSecret
    })

    with patch('app.database.AsyncSessionLocal', return_value=db_mock), \
         patch('app.core.securityonion.get_setting', AsyncMock(return_value=settings_mock)):

        await security_onion_client.initialize()

        assert security_onion_client._connected is False
        assert "Missing required settings" in security_onion_client._last_error


@pytest.mark.asyncio
async def test_initialization_url_formatting(mock_settings_db, mock_token_response, mock_health_response, security_onion_client):
    """Test URL formatting during initialization."""
    db_mock, settings_mock = mock_settings_db

    url_tests = [
        "securityonion.example.com",
        "https://securityonion.example.com",
        "https://securityonion.example.com/",
        "https://securityonion.example.com//",
    ]

    for test_url in url_tests:
        settings_mock.value = json.dumps({
            "apiUrl": test_url,
            "clientId": "test_client_id",
            "clientSecret": "test_client_secret"
        })

        with patch('app.database.AsyncSessionLocal', return_value=db_mock), \
             patch('app.core.securityonion.get_setting', AsyncMock(return_value=settings_mock)), \
             patch('app.core.securityonion.httpx.AsyncClient') as mock_http_class:

            mock_http_client = AsyncMock()
            mock_http_client.post = AsyncMock(return_value=mock_token_response)
            mock_http_client.get = AsyncMock(return_value=mock_health_response)
            mock_http_class.return_value = mock_http_client

            await security_onion_client.initialize()

            assert security_onion_client._base_url.startswith("https://")
            assert security_onion_client._base_url.endswith("/")
            assert "//" not in security_onion_client._base_url[8:]


@pytest.mark.asyncio
async def test_initialization_exception(mock_settings_db, security_onion_client):
    """Test initialization with an exception."""
    db_mock, settings_mock = mock_settings_db

    with patch('app.database.AsyncSessionLocal', return_value=db_mock), \
         patch('app.core.securityonion.get_setting', AsyncMock(side_effect=Exception("Test error"))):

        await security_onion_client.initialize()

        assert security_onion_client._connected is False
        assert "Initialization error: Test error" in security_onion_client._last_error


@pytest.mark.asyncio
async def test_test_connection_success(mock_token_response, mock_health_response, security_onion_client):
    """Test successful connection test."""
    security_onion_client._client = AsyncMock()
    security_onion_client._base_url = "https://securityonion.example.com/"
    security_onion_client._client_id = "test_client_id"
    security_onion_client._client_secret = "test_client_secret"

    security_onion_client._client.post = AsyncMock(return_value=mock_token_response)
    security_onion_client._client.get = AsyncMock(return_value=mock_health_response)

    result = await security_onion_client.test_connection()

    assert result is True
    assert security_onion_client._connected is True
    assert security_onion_client._last_error is None


@pytest.mark.asyncio
async def test_test_connection_no_client(security_onion_client):
    """Test connection test with no client initialized."""
    # Ensure client is not initialized
    security_onion_client._client = None
    
    # Test the connection
    result = await security_onion_client.test_connection()
    
    # Verify the result
    assert result is False
    assert "Client not initialized" in security_onion_client._last_error


@pytest.mark.asyncio
async def test_test_connection_token_failure(security_onion_client):
    """Test connection test with token failure."""
    security_onion_client._client = AsyncMock()
    security_onion_client._base_url = "https://securityonion.example.com/"
    security_onion_client._client_id = "test_client_id"
    security_onion_client._client_secret = "test_client_secret"

    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=False)):
        result = await security_onion_client.test_connection()

        assert result is False
        assert security_onion_client._connected is False


@pytest.mark.asyncio
async def test_test_connection_health_failure(mock_token_response, security_onion_client):
    """Test connection test with health endpoint failure."""
    security_onion_client._client = AsyncMock()
    security_onion_client._base_url = "https://securityonion.example.com/"
    security_onion_client._client_id = "test_client_id"
    security_onion_client._client_secret = "test_client_secret"

    error_response = MagicMock(spec=httpx.Response)
    error_response.status_code = 500
    error_response.headers = {"content-type": "application/json"}
    error_response.text = json.dumps({"detail": "Internal server error"})
    error_response.json.return_value = {"detail": "Internal server error"}

    security_onion_client._client.post = AsyncMock(return_value=mock_token_response)
    security_onion_client._client.get = AsyncMock(return_value=error_response)

    result = await security_onion_client.test_connection()

    assert result is False
    assert security_onion_client._connected is False
    assert "Internal server error" in security_onion_client._last_error


@pytest.mark.asyncio
async def test_test_connection_health_exception(mock_token_response, security_onion_client):
    """Test connection test with health endpoint exception."""
    security_onion_client._client = AsyncMock()
    security_onion_client._base_url = "https://securityonion.example.com/"
    security_onion_client._client_id = "test_client_id"
    security_onion_client._client_secret = "test_client_secret"

    security_onion_client._client.post = AsyncMock(return_value=mock_token_response)
    security_onion_client._client.get = AsyncMock(side_effect=Exception("Connection error"))

    result = await security_onion_client.test_connection()

    assert result is False
    assert security_onion_client._connected is False
    assert "Connection error" in security_onion_client._last_error


@pytest.mark.asyncio
async def test_ensure_token_existing_valid_token(security_onion_client):
    """Test _ensure_token with existing valid token."""
    # Setup client with valid token
    security_onion_client._access_token = "valid_token"
    security_onion_client._token_expires = datetime.utcnow() + timedelta(hours=1)
    
    # Test ensure token
    result = await security_onion_client._ensure_token()
    
    # Verify result
    assert result is True


@pytest.mark.asyncio
async def test_ensure_token_expired_token(mock_token_response, security_onion_client):
    """Test _ensure_token with expired token."""
    security_onion_client._client = AsyncMock()
    security_onion_client._base_url = "https://securityonion.example.com/"
    security_onion_client._client_id = "test_client_id"
    security_onion_client._client_secret = "test_client_secret"
    security_onion_client._access_token = "expired_token"
    security_onion_client._token_expires = datetime.utcnow() - timedelta(hours=1)

    security_onion_client._client.post = AsyncMock(return_value=mock_token_response)

    result = await security_onion_client._ensure_token()

    assert result is True
    assert security_onion_client._access_token == "test_access_token"


@pytest.mark.asyncio
async def test_ensure_token_no_token(mock_token_response, security_onion_client):
    """Test _ensure_token with no existing token."""
    security_onion_client._client = AsyncMock()
    security_onion_client._base_url = "https://securityonion.example.com/"
    security_onion_client._client_id = "test_client_id"
    security_onion_client._client_secret = "test_client_secret"
    security_onion_client._access_token = None
    security_onion_client._token_expires = None

    security_onion_client._client.post = AsyncMock(return_value=mock_token_response)

    result = await security_onion_client._ensure_token()

    assert result is True
    assert security_onion_client._access_token == "test_access_token"


@pytest.mark.asyncio
async def test_ensure_token_different_paths(mock_token_response, security_onion_client):
    """Test _ensure_token with different token endpoint paths."""
    security_onion_client._client = AsyncMock()
    security_onion_client._base_url = "https://securityonion.example.com/"
    security_onion_client._client_id = "test_client_id"
    security_onion_client._client_secret = "test_client_secret"
    security_onion_client._access_token = None
    security_onion_client._token_expires = None

    error_response = MagicMock(spec=httpx.Response)
    error_response.status_code = 404
    error_response.headers = {"content-type": "application/json"}
    error_response.text = json.dumps({"detail": "Not found"})
    error_response.json.return_value = {"detail": "Not found"}

    security_onion_client._client.post = AsyncMock(side_effect=[
        error_response,
        mock_token_response
    ])

    result = await security_onion_client._ensure_token()

    assert result is True
    assert security_onion_client._access_token == "test_access_token"


@pytest.mark.asyncio
async def test_ensure_token_failure(security_onion_client):
    """Test _ensure_token with all paths failing."""
    security_onion_client._client = AsyncMock()
    security_onion_client._base_url = "https://securityonion.example.com/"
    security_onion_client._client_id = "test_client_id"
    security_onion_client._client_secret = "test_client_secret"
    security_onion_client._access_token = None
    security_onion_client._token_expires = None

    error_response = MagicMock(spec=httpx.Response)
    error_response.status_code = 401
    error_response.headers = {"content-type": "application/json"}
    error_response.text = json.dumps({"detail": "Unauthorized"})
    error_response.json.return_value = {"detail": "Unauthorized"}

    security_onion_client._client.post = AsyncMock(return_value=error_response)

    result = await security_onion_client._ensure_token()

    assert result is False
    assert "Unauthorized" in security_onion_client._last_error


@pytest.mark.asyncio
async def test_ensure_token_exception(security_onion_client):
    """Test _ensure_token with exception."""
    # Setup client with no token
    security_onion_client._client = AsyncMock()
    security_onion_client._base_url = "https://securityonion.example.com/"
    security_onion_client._client_id = "test_client_id"
    security_onion_client._client_secret = "test_client_secret"
    security_onion_client._access_token = None
    security_onion_client._token_expires = None
    
    # Mock token request exception
    with patch.object(security_onion_client._client, 'post', side_effect=Exception("Connection error")):
        
        # Test ensure token
        result = await security_onion_client._ensure_token()
        
        # Verify result
        assert result is False
        assert "Connection error" in security_onion_client._last_error


def test_get_headers(security_onion_client):
    """Test _get_headers method."""
    # Setup client with token
    security_onion_client._access_token = "test_token"
    
    # Get headers
    headers = security_onion_client._get_headers()
    
    # Verify headers
    assert headers["Authorization"] == "Bearer test_token"
    assert headers["Content-Type"] == "application/json"


def test_get_status(security_onion_client):
    """Test get_status method."""
    # Test connected status
    security_onion_client._connected = True
    security_onion_client._last_error = None
    status = security_onion_client.get_status()
    assert status["connected"] is True
    assert status["error"] is None
    
    # Test disconnected status with error
    security_onion_client._connected = False
    security_onion_client._last_error = "Connection error"
    status = security_onion_client.get_status()
    assert status["connected"] is False
    assert status["error"] == "Connection error"


def test_get_status_exception(security_onion_client):
    """Test get_status with exception."""
    # Create a property that raises when bool() is called
    class BadBool:
        def __bool__(self):
            raise RuntimeError("cannot convert to bool")

    security_onion_client._connected = BadBool()
    security_onion_client._last_error = "test"

    status = security_onion_client.get_status()
    assert status["connected"] is False
    assert "Status error:" in status["error"]


@pytest.mark.asyncio
async def test_get_event(mock_token_response, security_onion_client):
    """Test get_event method."""
    # Setup client
    security_onion_client._client = AsyncMock()
    security_onion_client._base_url = "https://securityonion.example.com/"
    security_onion_client._client_id = "test_client_id"
    security_onion_client._client_secret = "test_client_secret"
    security_onion_client._access_token = "test_token"
    security_onion_client._token_expires = datetime.utcnow() + timedelta(hours=1)
    
    # Create mock event response
    event_response = MagicMock(spec=httpx.Response)
    event_response.status_code = 200
    event_response.json.return_value = {
        "events": [
            {
                "id": "event123",
                "type": "alert",
                "timestamp": "2023-01-01T12:00:00Z"
            }
        ]
    }
    
    # Mock client responses
    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=True)):
        security_onion_client._client.get = AsyncMock(return_value=event_response)

        event = await security_onion_client.get_event("event123")

        assert event is not None
        assert event["id"] == "event123"
        assert event["type"] == "alert"


@pytest.mark.asyncio
async def test_get_event_not_found(security_onion_client):
    """Test get_event with event not found."""
    security_onion_client._client = AsyncMock()
    security_onion_client._access_token = "test_token"
    security_onion_client._token_expires = datetime.utcnow() + timedelta(hours=1)

    empty_response = MagicMock(spec=httpx.Response)
    empty_response.status_code = 200
    empty_response.json.return_value = {"events": []}

    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=True)):
        security_onion_client._client.get = AsyncMock(return_value=empty_response)
        event = await security_onion_client.get_event("nonexistent")
        assert event is None


@pytest.mark.asyncio
async def test_get_event_token_failure(security_onion_client):
    """Test get_event with token failure."""
    security_onion_client._client = AsyncMock()

    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=False)):
        event = await security_onion_client.get_event("event123")
        assert event is None


@pytest.mark.asyncio
async def test_get_event_exception(security_onion_client):
    """Test get_event with exception."""
    security_onion_client._client = AsyncMock()
    security_onion_client._access_token = "test_token"
    security_onion_client._token_expires = datetime.utcnow() + timedelta(hours=1)

    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=True)):
        security_onion_client._client.get = AsyncMock(side_effect=Exception("API error"))
        event = await security_onion_client.get_event("event123")
        assert event is None
        assert "Failed to get event: API error" in security_onion_client._last_error


@pytest.mark.asyncio
async def test_create_case(security_onion_client):
    """Test create_case method."""
    # Setup client
    security_onion_client._client = AsyncMock()
    security_onion_client._access_token = "test_token"
    security_onion_client._token_expires = datetime.utcnow() + timedelta(hours=1)
    
    # Create mock case response
    case_response = MagicMock(spec=httpx.Response)
    case_response.status_code = 200
    case_response.json.return_value = {
        "id": "case123",
        "title": "Test Case",
        "status": "New"
    }
    
    # Case data
    case_data = {
        "title": "Test Case",
        "description": "Test case description",
        "priority": "High"
    }
    
    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=True)):
        security_onion_client._client.post = AsyncMock(return_value=case_response)

        case = await security_onion_client.create_case(case_data)

        assert case is not None
        assert case["id"] == "case123"
        assert case["title"] == "Test Case"

        security_onion_client._client.post.assert_called_once_with(
            "connect/case/",
            headers=ANY,
            json=case_data
        )


@pytest.mark.asyncio
async def test_create_case_token_failure(security_onion_client):
    """Test create_case with token failure."""
    security_onion_client._client = AsyncMock()
    case_data = {"title": "Test Case", "description": "Test case description"}

    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=False)):
        case = await security_onion_client.create_case(case_data)
        assert case is None


@pytest.mark.asyncio
async def test_create_case_failure(security_onion_client):
    """Test create_case with API failure."""
    security_onion_client._client = AsyncMock()
    security_onion_client._access_token = "test_token"
    security_onion_client._token_expires = datetime.utcnow() + timedelta(hours=1)

    error_response = MagicMock(spec=httpx.Response)
    error_response.status_code = 400
    error_response.json.return_value = {"error": "Bad request"}

    case_data = {"title": "Test Case", "description": "Test case description"}

    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=True)):
        security_onion_client._client.post = AsyncMock(return_value=error_response)
        case = await security_onion_client.create_case(case_data)
        assert case is None


@pytest.mark.asyncio
async def test_create_case_exception(security_onion_client):
    """Test create_case with exception."""
    security_onion_client._client = AsyncMock()
    security_onion_client._access_token = "test_token"
    security_onion_client._token_expires = datetime.utcnow() + timedelta(hours=1)

    case_data = {"title": "Test Case", "description": "Test case description"}

    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=True)):
        security_onion_client._client.post = AsyncMock(side_effect=Exception("API error"))
        case = await security_onion_client.create_case(case_data)
        assert case is None
        assert "Failed to create case: API error" in security_onion_client._last_error


@pytest.mark.asyncio
async def test_search_events(security_onion_client):
    """Test search_events method."""
    # Setup client
    security_onion_client._client = AsyncMock()
    security_onion_client._access_token = "test_token"
    security_onion_client._token_expires = datetime.utcnow() + timedelta(hours=1)
    
    # Create mock search response
    search_response = MagicMock(spec=httpx.Response)
    search_response.status_code = 200
    search_response.json.return_value = {
        "events": [
            {
                "id": "event1",
                "type": "alert",
                "timestamp": "2023-01-01T12:00:00Z"
            },
            {
                "id": "event2",
                "type": "alert",
                "timestamp": "2023-01-01T12:30:00Z"
            }
        ],
        "totalEvents": 2
    }
    
    # Mock client responses
    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=True)), \
         patch.object(security_onion_client._client, 'get', AsyncMock(return_value=search_response)):
        
        # Search events
        events = await security_onion_client.search_events("tags:alert")
        
        # Verify result
        assert len(events) == 2
        assert events[0]["id"] == "event1"
        assert events[1]["id"] == "event2"
        
        # Verify request params
        call_args = security_onion_client._client.get.call_args[1]
        assert call_args["params"]["query"] == "tags:alert"
        assert "range" in call_args["params"]
        assert call_args["params"]["eventLimit"] == 100  # Default


@pytest.mark.asyncio
async def test_search_events_custom_params(security_onion_client):
    """Test search_events with custom parameters."""
    # Setup client
    security_onion_client._client = AsyncMock()
    security_onion_client._access_token = "test_token"
    security_onion_client._token_expires = datetime.utcnow() + timedelta(hours=1)
    
    # Create mock search response
    search_response = MagicMock(spec=httpx.Response)
    search_response.status_code = 200
    search_response.json.return_value = {"events": []}
    
    # Mock client responses
    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=True)), \
         patch.object(security_onion_client._client, 'get', AsyncMock(return_value=search_response)):
        
        # Search events with custom params
        await security_onion_client.search_events("source.ip:192.168.1.1", time_range="48h", limit=10)
        
        # Verify request params
        call_args = security_onion_client._client.get.call_args[1]
        assert call_args["params"]["query"] == "source.ip:192.168.1.1"
        assert call_args["params"]["eventLimit"] == 10


@pytest.mark.asyncio
async def test_search_events_token_failure(security_onion_client):
    """Test search_events with token failure."""
    # Setup client
    security_onion_client._client = AsyncMock()
    
    # Mock token failure
    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=False)):
        
        # Search events
        events = await security_onion_client.search_events("tags:alert")
        
        # Verify result
        assert events == []


@pytest.mark.asyncio
async def test_search_events_api_failure(security_onion_client):
    """Test search_events with API failure."""
    # Setup client
    security_onion_client._client = AsyncMock()
    security_onion_client._access_token = "test_token"
    security_onion_client._token_expires = datetime.utcnow() + timedelta(hours=1)
    
    # Create mock error response
    error_response = MagicMock(spec=httpx.Response)
    error_response.status_code = 500
    error_response.json.return_value = {"error": "Server error"}
    
    # Mock client responses
    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=True)), \
         patch.object(security_onion_client._client, 'get', AsyncMock(return_value=error_response)):
        
        # Search events
        events = await security_onion_client.search_events("tags:alert")
        
        # Verify result
        assert events == []


@pytest.mark.asyncio
async def test_search_events_exception(security_onion_client):
    """Test search_events with exception."""
    # Setup client
    security_onion_client._client = AsyncMock()
    security_onion_client._access_token = "test_token"
    security_onion_client._token_expires = datetime.utcnow() + timedelta(hours=1)
    
    # Mock client responses
    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=True)), \
         patch.object(security_onion_client._client, 'get', side_effect=Exception("API error")):
        
        # Search events
        events = await security_onion_client.search_events("tags:alert")
        
        # Verify result
        assert events == []
        assert "Failed to search events: API error" in security_onion_client._last_error


@pytest.mark.asyncio
async def test_add_event_to_case(security_onion_client):
    """Test add_event_to_case method."""
    # Setup client
    security_onion_client._client = AsyncMock()
    security_onion_client._access_token = "test_token"
    security_onion_client._token_expires = datetime.utcnow() + timedelta(hours=1)
    
    # Create mock success response
    success_response = MagicMock(spec=httpx.Response)
    success_response.status_code = 200
    
    # Event fields
    event_fields = {
        "id": "event123",
        "title": "Alert Title",
        "description": "Alert description"
    }
    
    # Mock client responses
    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=True)), \
         patch.object(security_onion_client._client, 'post', AsyncMock(return_value=success_response)):
        
        # Add event to case
        result = await security_onion_client.add_event_to_case("case123", event_fields)
        
        # Verify result
        assert result is True
        
        # Verify request
        security_onion_client._client.post.assert_called_once_with(
            "connect/case/events",
            headers=ANY,
            json={
                "caseId": "case123",
                "fields": event_fields
            }
        )


@pytest.mark.asyncio
async def test_add_event_to_case_token_failure(security_onion_client):
    """Test add_event_to_case with token failure."""
    # Setup client
    security_onion_client._client = AsyncMock()
    
    # Event fields
    event_fields = {
        "id": "event123",
        "title": "Alert Title"
    }
    
    # Mock token failure
    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=False)):
        
        # Add event to case
        result = await security_onion_client.add_event_to_case("case123", event_fields)
        
        # Verify result
        assert result is False


@pytest.mark.asyncio
async def test_add_event_to_case_api_failure(security_onion_client):
    """Test add_event_to_case with API failure."""
    # Setup client
    security_onion_client._client = AsyncMock()
    security_onion_client._access_token = "test_token"
    security_onion_client._token_expires = datetime.utcnow() + timedelta(hours=1)
    
    # Create mock error response
    error_response = MagicMock(spec=httpx.Response)
    error_response.status_code = 400
    
    # Event fields
    event_fields = {
        "id": "event123",
        "title": "Alert Title"
    }
    
    # Mock client responses
    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=True)), \
         patch.object(security_onion_client._client, 'post', AsyncMock(return_value=error_response)):
        
        # Add event to case
        result = await security_onion_client.add_event_to_case("case123", event_fields)
        
        # Verify result
        assert result is False


@pytest.mark.asyncio
async def test_add_event_to_case_api_accepted(security_onion_client):
    """Test add_event_to_case with 202 Accepted response."""
    # Setup client
    security_onion_client._client = AsyncMock()
    security_onion_client._access_token = "test_token"
    security_onion_client._token_expires = datetime.utcnow() + timedelta(hours=1)
    
    # Create mock accepted response
    accepted_response = MagicMock(spec=httpx.Response)
    accepted_response.status_code = 202
    
    # Event fields
    event_fields = {
        "id": "event123",
        "title": "Alert Title"
    }
    
    # Mock client responses
    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=True)), \
         patch.object(security_onion_client._client, 'post', AsyncMock(return_value=accepted_response)):
        
        # Add event to case
        result = await security_onion_client.add_event_to_case("case123", event_fields)
        
        # Verify result
        assert result is True


@pytest.mark.asyncio
async def test_add_event_to_case_exception(security_onion_client):
    """Test add_event_to_case with exception."""
    # Setup client
    security_onion_client._client = AsyncMock()
    security_onion_client._access_token = "test_token"
    security_onion_client._token_expires = datetime.utcnow() + timedelta(hours=1)
    
    # Event fields
    event_fields = {
        "id": "event123",
        "title": "Alert Title"
    }
    
    # Mock client responses
    with patch.object(security_onion_client, '_ensure_token', AsyncMock(return_value=True)), \
         patch.object(security_onion_client._client, 'post', side_effect=Exception("API error")):
        
        # Add event to case
        result = await security_onion_client.add_event_to_case("case123", event_fields)
        
        # Verify result
        assert result is False
        assert "Failed to add event to case: API error" in security_onion_client._last_error


@pytest.mark.asyncio
async def test_close(security_onion_client):
    """Test close method."""
    # Setup client
    security_onion_client._client = AsyncMock()
    
    # Close client
    await security_onion_client.close()
    
    # Verify client was closed
    security_onion_client._client.aclose.assert_called_once()


@pytest.mark.asyncio
async def test_close_no_client(security_onion_client):
    """Test close method with no client."""
    # Setup client with no client
    security_onion_client._client = None
    
    # Close client should not raise exception
    await security_onion_client.close()


@pytest.mark.asyncio
async def test_global_client_instance():
    """Test the global client instance."""
    # Verify global client is an instance of SecurityOnionClient
    assert isinstance(global_client, SecurityOnionClient)
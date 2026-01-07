"""Tests for the web inspection interface."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from instanton.inspector.replay import (
    ReplayConfig,
    ReplayResult,
    RequestReplayer,
)
from instanton.inspector.storage import (
    CapturedRequest,
    CapturedResponse,
    RequestFilter,
    RequestStatus,
    TrafficStorage,
)


class TestCapturedRequest:
    """Tests for CapturedRequest model."""

    def test_basic_request(self):
        """Test basic request creation."""
        req = CapturedRequest(
            method="GET",
            path="/api/users",
            headers={"Content-Type": "application/json"},
            body=b"",
        )
        assert req.method == "GET"
        assert req.path == "/api/users"
        assert req.content_type == "application/json"
        assert req.content_length == 0
        assert req.status == RequestStatus.PENDING

    def test_json_body_parsing(self):
        """Test JSON body is automatically parsed."""
        body = b'{"name": "test", "value": 123}'
        req = CapturedRequest(
            method="POST",
            path="/api/data",
            headers={"Content-Type": "application/json"},
            body=body,
        )
        assert req.body_json is not None
        assert req.body_json["name"] == "test"
        assert req.body_json["value"] == 123

    def test_query_params_extraction(self):
        """Test query parameters are extracted from path."""
        req = CapturedRequest(
            method="GET",
            path="/api/search?q=test&page=1",
            headers={},
            body=b"",
        )
        assert req.query_params["q"] == "test"
        assert req.query_params["page"] == "1"

    def test_body_preview(self):
        """Test body preview truncation."""
        long_body = b"x" * 2000
        req = CapturedRequest(
            method="POST",
            path="/",
            headers={"Content-Type": "text/plain"},
            body=long_body,
        )
        preview = req.get_body_preview(max_length=100)
        assert len(preview) <= 103  # 100 + "..."
        assert preview.endswith("...")

    def test_fingerprint(self):
        """Test request fingerprint generation."""
        req1 = CapturedRequest(method="GET", path="/api", headers={}, body=b"")
        req2 = CapturedRequest(method="GET", path="/api", headers={}, body=b"")
        req3 = CapturedRequest(method="POST", path="/api", headers={}, body=b"")

        assert req1.get_fingerprint() == req2.get_fingerprint()
        assert req1.get_fingerprint() != req3.get_fingerprint()

    def test_to_dict(self):
        """Test serialization to dict."""
        req = CapturedRequest(
            method="GET",
            path="/",
            headers={"X-Test": "value"},
            body=b"test",
            source_ip="192.168.1.1",
        )
        data = req.to_dict()

        assert data["method"] == "GET"
        assert data["path"] == "/"
        assert data["headers"]["X-Test"] == "value"
        assert data["body"] == "test"
        assert data["source_ip"] == "192.168.1.1"


class TestCapturedResponse:
    """Tests for CapturedResponse model."""

    def test_basic_response(self):
        """Test basic response creation."""
        resp = CapturedResponse(
            request_id=uuid4(),
            status_code=200,
            status_text="OK",
            headers={"Content-Type": "text/html"},
            body=b"<html></html>",
        )
        assert resp.status_code == 200
        assert resp.status_text == "OK"
        assert resp.content_type == "text/html"
        assert resp.content_length == 13

    def test_json_body_parsing(self):
        """Test JSON response body is parsed."""
        resp = CapturedResponse(
            request_id=uuid4(),
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=b'{"status": "ok"}',
        )
        assert resp.body_json is not None
        assert resp.body_json["status"] == "ok"


class TestRequestFilter:
    """Tests for RequestFilter."""

    def test_method_filter(self):
        """Test filtering by HTTP method."""
        filter = RequestFilter(method="GET")
        req_get = CapturedRequest(method="GET", path="/", headers={}, body=b"")
        req_post = CapturedRequest(method="POST", path="/", headers={}, body=b"")

        assert filter.matches(req_get, None)
        assert not filter.matches(req_post, None)

    def test_path_pattern_filter(self):
        """Test filtering by path pattern."""
        filter = RequestFilter(path_pattern=r"/api/.*")
        req_match = CapturedRequest(method="GET", path="/api/users", headers={}, body=b"")
        req_no_match = CapturedRequest(method="GET", path="/web/page", headers={}, body=b"")

        assert filter.matches(req_match, None)
        assert not filter.matches(req_no_match, None)

    def test_status_filter(self):
        """Test filtering by request status."""
        filter = RequestFilter(status=RequestStatus.SUCCESS)
        req_success = CapturedRequest(
            method="GET", path="/", headers={}, body=b"", status=RequestStatus.SUCCESS
        )
        req_pending = CapturedRequest(
            method="GET", path="/", headers={}, body=b"", status=RequestStatus.PENDING
        )

        assert filter.matches(req_success, None)
        assert not filter.matches(req_pending, None)

    def test_status_code_filter(self):
        """Test filtering by response status code."""
        filter = RequestFilter(status_code=200)
        req = CapturedRequest(method="GET", path="/", headers={}, body=b"")
        resp_200 = CapturedResponse(request_id=req.id, status_code=200)
        resp_404 = CapturedResponse(request_id=req.id, status_code=404)

        assert filter.matches(req, resp_200)
        assert not filter.matches(req, resp_404)

    def test_body_contains_filter(self):
        """Test filtering by body content."""
        filter = RequestFilter(body_contains="error")
        req_match = CapturedRequest(method="POST", path="/", headers={}, body=b"An error occurred")
        req_no_match = CapturedRequest(method="POST", path="/", headers={}, body=b"Success")

        assert filter.matches(req_match, None)
        assert not filter.matches(req_no_match, None)

    def test_combined_filters(self):
        """Test multiple filter criteria."""
        filter = RequestFilter(method="POST", path_pattern=r"/api/.*")
        req_match = CapturedRequest(method="POST", path="/api/data", headers={}, body=b"")
        req_wrong_method = CapturedRequest(method="GET", path="/api/data", headers={}, body=b"")
        req_wrong_path = CapturedRequest(method="POST", path="/web/page", headers={}, body=b"")

        assert filter.matches(req_match, None)
        assert not filter.matches(req_wrong_method, None)
        assert not filter.matches(req_wrong_path, None)


class TestTrafficStorage:
    """Tests for TrafficStorage."""

    @pytest.fixture
    def storage(self):
        return TrafficStorage(max_requests=100)

    @pytest.mark.asyncio
    async def test_add_request(self, storage):
        """Test adding a request."""
        req = CapturedRequest(method="GET", path="/", headers={}, body=b"")
        await storage.add_request(req)

        retrieved = await storage.get_request(req.id)
        assert retrieved is not None
        assert retrieved.method == "GET"

    @pytest.mark.asyncio
    async def test_add_response(self, storage):
        """Test adding a response."""
        req = CapturedRequest(method="GET", path="/", headers={}, body=b"")
        await storage.add_request(req)

        resp = CapturedResponse(request_id=req.id, status_code=200)
        await storage.add_response(resp)

        # Request status should be updated
        retrieved = await storage.get_request(req.id)
        assert retrieved.status == RequestStatus.SUCCESS

        # Response should be retrievable
        retrieved_resp = await storage.get_response(req.id)
        assert retrieved_resp is not None
        assert retrieved_resp.status_code == 200

    @pytest.mark.asyncio
    async def test_get_entry(self, storage):
        """Test getting a complete entry."""
        req = CapturedRequest(method="GET", path="/", headers={}, body=b"")
        await storage.add_request(req)

        resp = CapturedResponse(request_id=req.id, status_code=200)
        await storage.add_response(resp)

        entry = await storage.get_entry(req.id)
        assert entry is not None
        assert entry.request.method == "GET"
        assert entry.response.status_code == 200

    @pytest.mark.asyncio
    async def test_list_requests(self, storage):
        """Test listing requests."""
        for i in range(5):
            req = CapturedRequest(method="GET", path=f"/path{i}", headers={}, body=b"")
            await storage.add_request(req)

        entries = await storage.list_requests(limit=3)
        assert len(entries) == 3

    @pytest.mark.asyncio
    async def test_list_with_filter(self, storage):
        """Test listing with filter."""
        for method in ["GET", "POST", "GET", "PUT"]:
            req = CapturedRequest(method=method, path="/", headers={}, body=b"")
            await storage.add_request(req)

        filter = RequestFilter(method="GET")
        entries = await storage.list_requests(filter=filter)
        assert len(entries) == 2
        assert all(e.request.method == "GET" for e in entries)

    @pytest.mark.asyncio
    async def test_eviction(self):
        """Test LRU eviction when at capacity."""
        storage = TrafficStorage(max_requests=3)

        ids = []
        for i in range(5):
            req = CapturedRequest(method="GET", path=f"/path{i}", headers={}, body=b"")
            await storage.add_request(req)
            ids.append(req.id)

        # First two should be evicted
        assert await storage.get_request(ids[0]) is None
        assert await storage.get_request(ids[1]) is None
        # Last three should exist
        assert await storage.get_request(ids[2]) is not None
        assert await storage.get_request(ids[3]) is not None
        assert await storage.get_request(ids[4]) is not None

    @pytest.mark.asyncio
    async def test_body_truncation(self):
        """Test large body truncation."""
        storage = TrafficStorage(max_body_size=100)

        large_body = b"x" * 200
        req = CapturedRequest(method="POST", path="/", headers={}, body=large_body)
        await storage.add_request(req)

        retrieved = await storage.get_request(req.id)
        assert len(retrieved.body) == 100

    @pytest.mark.asyncio
    async def test_get_stats(self, storage):
        """Test statistics."""
        for status in [RequestStatus.SUCCESS, RequestStatus.SUCCESS, RequestStatus.ERROR]:
            req = CapturedRequest(method="GET", path="/", headers={}, body=b"", status=status)
            await storage.add_request(req)

        stats = await storage.get_stats()
        assert stats["total_requests"] == 3
        assert stats["success"] == 2
        assert stats["error"] == 1

    @pytest.mark.asyncio
    async def test_clear(self, storage):
        """Test clearing storage."""
        for i in range(5):
            req = CapturedRequest(method="GET", path=f"/path{i}", headers={}, body=b"")
            await storage.add_request(req)

        await storage.clear()

        entries = await storage.list_requests()
        assert len(entries) == 0

    @pytest.mark.asyncio
    async def test_delete_request(self, storage):
        """Test deleting a specific request."""
        req = CapturedRequest(method="GET", path="/", headers={}, body=b"")
        await storage.add_request(req)

        deleted = await storage.delete_request(req.id)
        assert deleted

        retrieved = await storage.get_request(req.id)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_subscription(self, storage):
        """Test real-time subscription."""
        queue = storage.subscribe()

        req = CapturedRequest(method="GET", path="/", headers={}, body=b"")
        await storage.add_request(req)

        # Should receive notification
        entry = await asyncio.wait_for(queue.get(), timeout=1.0)
        assert entry.request.id == req.id

        storage.unsubscribe(queue)


class TestReplayConfig:
    """Tests for ReplayConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = ReplayConfig()
        assert config.connect_timeout == 5.0
        assert config.read_timeout == 30.0
        assert config.max_retries == 0
        assert config.follow_redirects
        assert not config.verify_ssl
        assert config.capture_result

    def test_custom_config(self):
        """Test custom configuration."""
        config = ReplayConfig(
            connect_timeout=10.0,
            max_retries=3,
            target_host="localhost",
            target_port=3000,
            modify_method="PUT",
            modify_path="/new-path",
        )
        assert config.connect_timeout == 10.0
        assert config.max_retries == 3
        assert config.target_host == "localhost"
        assert config.target_port == 3000
        assert config.modify_method == "PUT"
        assert config.modify_path == "/new-path"


class TestReplayResult:
    """Tests for ReplayResult."""

    def test_success_result(self):
        """Test successful replay result."""
        result = ReplayResult(
            success=True,
            original_request_id=uuid4(),
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=b'{"status": "ok"}',
            duration_ms=50.5,
        )
        assert result.success
        assert result.status_code == 200
        assert result.error is None

    def test_failure_result(self):
        """Test failed replay result."""
        result = ReplayResult(
            success=False,
            original_request_id=uuid4(),
            error="Connection refused",
            duration_ms=100.0,
        )
        assert not result.success
        assert result.error == "Connection refused"
        assert result.status_code is None

    def test_to_dict(self):
        """Test serialization."""
        req_id = uuid4()
        result = ReplayResult(
            success=True,
            original_request_id=req_id,
            status_code=200,
        )
        data = result.to_dict()

        assert data["success"] is True
        assert data["original_request_id"] == str(req_id)
        assert data["status_code"] == 200


class TestRequestReplayer:
    """Tests for RequestReplayer."""

    @pytest.fixture
    def storage(self):
        return TrafficStorage()

    @pytest.fixture
    def replayer(self, storage):
        return RequestReplayer(storage=storage, default_target="http://localhost:8000")

    @pytest.mark.asyncio
    async def test_replay_not_found(self, replayer):
        """Test replaying non-existent request."""
        result = await replayer.replay(uuid4())
        assert not result.success
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_build_url_default(self, replayer):
        """Test URL building with defaults."""
        req = CapturedRequest(method="GET", path="/api/test", headers={}, body=b"")
        config = ReplayConfig()
        url = replayer._build_url(req, config)
        assert url == "http://localhost:8000"

    @pytest.mark.asyncio
    async def test_build_url_custom(self, replayer):
        """Test URL building with custom target."""
        req = CapturedRequest(method="GET", path="/api/test", headers={}, body=b"")
        config = ReplayConfig(
            target_host="example.com",
            target_port=3000,
            target_scheme="https",
        )
        url = replayer._build_url(req, config)
        assert url == "https://example.com:3000"

    @pytest.mark.asyncio
    async def test_close(self, replayer):
        """Test closing the replayer."""
        await replayer.close()
        # Should not raise
        await replayer.close()


class TestIntegration:
    """Integration tests for the inspector module."""

    @pytest.mark.asyncio
    async def test_full_request_lifecycle(self):
        """Test complete request/response capture lifecycle."""
        storage = TrafficStorage()

        # Capture request
        req = CapturedRequest(
            method="POST",
            path="/api/webhook",
            headers={"Content-Type": "application/json", "X-Custom": "value"},
            body=b'{"event": "test"}',
            source_ip="192.168.1.100",
        )
        await storage.add_request(req)

        # Simulate processing time
        await asyncio.sleep(0.01)

        # Capture response
        resp = CapturedResponse(
            request_id=req.id,
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=b'{"success": true}',
        )
        await storage.add_response(resp)

        # Verify entry
        entry = await storage.get_entry(req.id)
        assert entry is not None
        assert entry.request.body_json["event"] == "test"
        assert entry.response.body_json["success"] is True
        assert entry.request.status == RequestStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_replay_request_found(self):
        """Test that replay finds stored request."""
        storage = TrafficStorage()
        replayer = RequestReplayer(storage=storage)

        # Store a request
        req = CapturedRequest(
            method="GET",
            path="/api/test",
            headers={"Accept": "application/json"},
            body=b"",
        )
        await storage.add_request(req)

        # Replay will fail to connect but should find the request
        result = await replayer.replay(req.id)
        # Connection will fail but error should be connection-related, not "not found"
        assert "not found" not in result.error.lower()

        await replayer.close()

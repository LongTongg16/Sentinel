import asyncio
from collections.abc import Iterator

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.deployment import DeploymentSettings
from backend.main import (
    app,
    get_http_header_collector,
    get_scan_admission_controller,
    get_tls_collector,
)
from backend.scan_admission import (
    ScanAdmissionController,
    ScanCapacityExceeded,
    ScanRateLimitExceeded,
)
from backend.tls_models import (
    FailureCode,
    FailureStage,
    TlsCollectionFailure,
)


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_deployment_settings_parse_origins_and_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SENTINEL_ALLOWED_ORIGINS",
        " https://sentinel.example/,https://admin.example ",
    )
    monkeypatch.setenv("SENTINEL_MAX_CONCURRENT_SCANS", "3")
    monkeypatch.setenv("SENTINEL_SCAN_QUEUE_TIMEOUT_SECONDS", "1.5")
    monkeypatch.setenv("SENTINEL_RATE_LIMIT_REQUESTS", "12")
    monkeypatch.setenv("SENTINEL_RATE_LIMIT_WINDOW_SECONDS", "30")

    settings = DeploymentSettings.from_environment()

    assert settings.allowed_origins == (
        "https://sentinel.example",
        "https://admin.example",
    )
    assert settings.max_concurrent_scans == 3
    assert settings.scan_queue_timeout_seconds == 1.5
    assert settings.rate_limit_requests == 12
    assert settings.rate_limit_window_seconds == 30


def test_deployment_settings_use_bounded_default_queue_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SENTINEL_SCAN_QUEUE_TIMEOUT_SECONDS", raising=False)

    settings = DeploymentSettings.from_environment()

    assert settings.scan_queue_timeout_seconds == 1.0


@pytest.mark.parametrize(
    "origin",
    [
        "*",
        "https://*.example.com",
        "https://user@example.com",
        "https://sentinel.example/path",
        "https://example.com?",
        "https://example.com#",
        "https://example.com:",
    ],
)
def test_deployment_settings_reject_unsafe_origins(
    monkeypatch: pytest.MonkeyPatch,
    origin: str,
) -> None:
    monkeypatch.setenv("SENTINEL_ALLOWED_ORIGINS", origin)

    with pytest.raises(ValueError, match="SENTINEL_ALLOWED_ORIGINS"):
        DeploymentSettings.from_environment()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("SENTINEL_MAX_CONCURRENT_SCANS", "0"),
        ("SENTINEL_RATE_LIMIT_REQUESTS", "-1"),
        ("SENTINEL_RATE_LIMIT_WINDOW_SECONDS", "not-a-number"),
    ],
)
def test_deployment_settings_reject_invalid_integer_limits(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: str,
) -> None:
    monkeypatch.setenv(name, value)

    with pytest.raises(ValueError, match=name):
        DeploymentSettings.from_environment()


@pytest.mark.parametrize(
    "value",
    ["not-a-number", "0", "-0.1", "nan", "inf", "-inf"],
)
def test_deployment_settings_reject_invalid_queue_timeout(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("SENTINEL_SCAN_QUEUE_TIMEOUT_SECONDS", value)

    with pytest.raises(
        ValueError,
        match="SENTINEL_SCAN_QUEUE_TIMEOUT_SECONDS",
    ):
        DeploymentSettings.from_environment()


def test_health_is_minimal_and_does_not_require_cors_origin(
    client: TestClient,
) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_cors_allows_local_frontend_preflight(client: TestClient) -> None:
    response = client.options(
        "/api/v1/tls/leaf-certificate",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == (
        "http://localhost:5173"
    )
    assert response.headers["access-control-allow-methods"] == "POST"
    assert "access-control-allow-credentials" not in response.headers


def test_cors_rejects_unconfigured_origin(client: TestClient) -> None:
    response = client.options(
        "/api/v1/tls/leaf-certificate",
        headers={
            "Origin": "https://unconfigured.example",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_scan_admission_bounds_parallel_work_and_times_out_waiter() -> None:
    async def exercise_controller() -> None:
        controller = ScanAdmissionController(
            max_concurrent_scans=2,
            scan_queue_timeout_seconds=0.01,
            rate_limit_requests=10,
            rate_limit_window_seconds=60,
        )
        release = asyncio.Event()
        two_started = asyncio.Event()
        active = 0
        maximum_active = 0

        async def worker() -> None:
            nonlocal active, maximum_active
            controller.record_request()
            async with controller.scan_slot():
                active += 1
                maximum_active = max(maximum_active, active)
                if active == 2:
                    two_started.set()
                await release.wait()
                active -= 1

        tasks = [asyncio.create_task(worker()) for _ in range(2)]
        await asyncio.wait_for(two_started.wait(), timeout=1)

        assert active == 2
        assert maximum_active == 2

        with pytest.raises(ScanCapacityExceeded):
            async with controller.scan_slot():
                pytest.fail("timed-out waiter obtained scan capacity")

        release.set()
        await asyncio.gather(*tasks)
        assert maximum_active == 2

    asyncio.run(exercise_controller())


def test_scan_slot_releases_permit_after_normal_completion() -> None:
    async def exercise_controller() -> None:
        controller = ScanAdmissionController(
            max_concurrent_scans=1,
            scan_queue_timeout_seconds=0.01,
            rate_limit_requests=10,
            rate_limit_window_seconds=60,
        )

        async with controller.scan_slot():
            pass

        async with controller.scan_slot():
            pass

    asyncio.run(exercise_controller())


def test_scan_slot_releases_permit_after_collector_exception() -> None:
    async def exercise_controller() -> None:
        controller = ScanAdmissionController(
            max_concurrent_scans=1,
            scan_queue_timeout_seconds=0.01,
            rate_limit_requests=10,
            rate_limit_window_seconds=60,
        )

        with pytest.raises(RuntimeError, match="collector failed"):
            async with controller.scan_slot():
                raise RuntimeError("collector failed")

        async with controller.scan_slot():
            pass

    asyncio.run(exercise_controller())


def test_scan_slot_releases_permit_when_holder_is_cancelled() -> None:
    async def exercise_controller() -> None:
        controller = ScanAdmissionController(
            max_concurrent_scans=1,
            scan_queue_timeout_seconds=0.1,
            rate_limit_requests=10,
            rate_limit_window_seconds=60,
        )
        entered = asyncio.Event()
        hold = asyncio.Event()

        async def holder() -> None:
            async with controller.scan_slot():
                entered.set()
                await hold.wait()

        task = asyncio.create_task(holder())
        await asyncio.wait_for(entered.wait(), timeout=1)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

        async with controller.scan_slot():
            pass

    asyncio.run(exercise_controller())


def test_rate_limit_prunes_expired_entries_and_bounds_storage() -> None:
    current_time = 0.0
    controller = ScanAdmissionController(
        max_concurrent_scans=1,
        scan_queue_timeout_seconds=0.01,
        rate_limit_requests=2,
        rate_limit_window_seconds=10,
        clock=lambda: current_time,
    )

    controller.record_request()
    controller.record_request()
    for _ in range(20):
        with pytest.raises(ScanRateLimitExceeded):
            controller.record_request()

    assert len(controller._request_times) == 2

    current_time = 10.0
    controller.record_request()

    assert len(controller._request_times) == 1


def test_scan_routes_share_rate_limit_but_health_remains_available(
    client: TestClient,
) -> None:
    controller = ScanAdmissionController(
        max_concurrent_scans=2,
        scan_queue_timeout_seconds=0.01,
        rate_limit_requests=1,
        rate_limit_window_seconds=60,
    )

    async def invalid_target_collector(
        hostname: str,
        *,
        overall_timeout: float,
    ) -> TlsCollectionFailure:
        del hostname, overall_timeout
        return TlsCollectionFailure(
            stage=FailureStage.TARGET_VALIDATION,
            code=FailureCode.INVALID_HOSTNAME,
        )

    app.dependency_overrides[get_scan_admission_controller] = (
        lambda: controller
    )
    app.dependency_overrides[get_tls_collector] = (
        lambda: invalid_target_collector
    )

    accepted = client.post(
        "/api/v1/tls/leaf-certificate",
        json={"hostname": "example.com"},
    )
    rejected = client.post(
        "/api/v1/http/security-headers",
        json={"hostname": "example.com"},
    )
    health = client.get("/health")

    assert accepted.status_code == 422
    assert rejected.status_code == 429
    assert rejected.json() == {
        "detail": "Scan request rate limit exceeded. Please try again later."
    }
    assert int(rejected.headers["retry-after"]) >= 1
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}


def test_tls_and_http_share_capacity_without_blocking_health() -> None:
    async def exercise_routes() -> None:
        controller = ScanAdmissionController(
            max_concurrent_scans=1,
            scan_queue_timeout_seconds=0.01,
            rate_limit_requests=10,
            rate_limit_window_seconds=60,
        )
        tls_started = asyncio.Event()
        release_tls = asyncio.Event()
        http_collector_called = False

        async def blocking_tls_collector(
            hostname: str,
            *,
            overall_timeout: float,
        ) -> TlsCollectionFailure:
            del hostname, overall_timeout
            tls_started.set()
            await release_tls.wait()
            return TlsCollectionFailure(
                stage=FailureStage.TARGET_VALIDATION,
                code=FailureCode.INVALID_HOSTNAME,
            )

        async def unexpected_http_collector(
            hostname: str,
            *,
            overall_timeout: float,
        ) -> None:
            nonlocal http_collector_called
            del hostname, overall_timeout
            http_collector_called = True
            raise AssertionError("capacity-rejected collector was invoked")

        app.dependency_overrides[get_scan_admission_controller] = (
            lambda: controller
        )
        app.dependency_overrides[get_tls_collector] = (
            lambda: blocking_tls_collector
        )
        app.dependency_overrides[get_http_header_collector] = (
            lambda: unexpected_http_collector
        )

        transport = httpx.ASGITransport(app=app)
        try:
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as client:
                tls_request = asyncio.create_task(
                    client.post(
                        "/api/v1/tls/leaf-certificate",
                        json={"hostname": "example.com"},
                    )
                )
                await asyncio.wait_for(tls_started.wait(), timeout=1)

                http_response, health_response = await asyncio.gather(
                    client.post(
                        "/api/v1/http/security-headers",
                        json={"hostname": "example.com"},
                    ),
                    client.get("/health"),
                )

                release_tls.set()
                tls_response = await asyncio.wait_for(tls_request, timeout=1)
        finally:
            release_tls.set()
            app.dependency_overrides.clear()

        assert tls_response.status_code == 422
        assert http_response.status_code == 503
        assert http_response.json() == {
            "detail": (
                "Scan capacity is temporarily unavailable. "
                "Please try again later."
            )
        }
        assert http_collector_called is False
        assert health_response.status_code == 200
        assert health_response.json() == {"status": "ok"}

    asyncio.run(exercise_routes())

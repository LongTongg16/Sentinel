from collections.abc import Callable, Iterator
import ipaddress

import pytest
from fastapi.testclient import TestClient

from backend.main import (
    TLS_COLLECTION_OVERALL_TIMEOUT,
    app,
    get_tls_collector,
)
from backend.tls_collector import CollectionResult
from backend.tls_models import (
    FailureCode,
    FailureStage,
    TlsCollectionFailure,
    ValidatedTarget,
    VerifiedLeafCertificate,
)


class FakeCollector:
    def __init__(self, result: CollectionResult) -> None:
        self.result = result
        self.calls: list[tuple[str, float]] = []

    async def __call__(
        self,
        hostname: str,
        *,
        overall_timeout: float,
    ) -> CollectionResult:
        self.calls.append((hostname, overall_timeout))
        return self.result


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def override_collector(collector: FakeCollector) -> Callable[[], FakeCollector]:
    return lambda: collector


def test_tls_leaf_certificate_success_returns_public_certificate_fields(
    client: TestClient,
) -> None:
    collector = FakeCollector(
        VerifiedLeafCertificate(
            target=ValidatedTarget(hostname="example.com"),
            connected_ip=ipaddress.ip_address("93.184.216.34"),
            certificate_der=b"private certificate bytes",
            certificate_sha256="a" * 64,
        )
    )
    app.dependency_overrides[get_tls_collector] = override_collector(collector)

    response = client.post(
        "/api/v1/tls/leaf-certificate",
        json={"hostname": "example.com"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "success",
        "hostname": "example.com",
        "connected_ip": "93.184.216.34",
        "certificate_sha256": "a" * 64,
    }
    assert "certificate_der" not in response.json()
    assert collector.calls == [
        ("example.com", TLS_COLLECTION_OVERALL_TIMEOUT)
    ]


@pytest.mark.parametrize(
    ("stage", "code", "expected_status"),
    [
        (
            FailureStage.TARGET_VALIDATION,
            FailureCode.INVALID_HOSTNAME,
            422,
        ),
        (FailureStage.DNS, FailureCode.BLOCKED_ADDRESS, 403),
        (FailureStage.DNS, FailureCode.DNS_FAILURE, 502),
        (FailureStage.DNS, FailureCode.NO_ADDRESSES, 502),
        (FailureStage.CONNECT, FailureCode.CONNECT_FAILURE, 502),
        (
            FailureStage.TLS_HANDSHAKE,
            FailureCode.TLS_VERIFICATION_FAILED,
            502,
        ),
        (FailureStage.TLS_HANDSHAKE, FailureCode.TLS_FAILURE, 502),
        (
            FailureStage.CERTIFICATE,
            FailureCode.MISSING_PEER_CERTIFICATE,
            502,
        ),
        (
            FailureStage.CERTIFICATE,
            FailureCode.OVERALL_TIMEOUT,
            504,
        ),
    ],
)
def test_tls_leaf_certificate_failure_mapping(
    client: TestClient,
    stage: FailureStage,
    code: FailureCode,
    expected_status: int,
) -> None:
    collector = FakeCollector(TlsCollectionFailure(stage=stage, code=code))
    app.dependency_overrides[get_tls_collector] = override_collector(collector)

    response = client.post(
        "/api/v1/tls/leaf-certificate",
        json={"hostname": "example.com"},
    )

    assert response.status_code == expected_status
    assert response.json() == {
        "status": "failure",
        "stage": stage.value,
        "code": code.value,
    }
    assert collector.calls == [
        ("example.com", TLS_COLLECTION_OVERALL_TIMEOUT)
    ]

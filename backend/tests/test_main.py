from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
import ipaddress

import pytest
from fastapi.testclient import TestClient

from backend.main import (
    TLS_COLLECTION_OVERALL_TIMEOUT,
    app,
    get_current_time,
    get_tls_collector,
)
from backend.tests.fixtures.certificate_factory import create_certificate_der
from backend.tls_collector import CollectionResult
from backend.tls_models import (
    FailureCode,
    FailureStage,
    TlsCollectionFailure,
    ValidatedTarget,
    VerifiedLeafCertificate,
)

NOW = datetime(2026, 7, 24, tzinfo=timezone.utc)
VALID_FROM = datetime(2026, 7, 1, tzinfo=timezone.utc)
EXPIRES_AT = NOW + timedelta(days=30)


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
    app.dependency_overrides[get_current_time] = lambda: NOW
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def override_collector(collector: FakeCollector) -> Callable[[], FakeCollector]:
    return lambda: collector


def test_tls_leaf_certificate_success_returns_public_certificate_fields(
    client: TestClient,
) -> None:
    certificate_der = create_certificate_der(
        subject_common_name="example.com",
        issuer_common_name="Sentinel Test CA",
        valid_from=VALID_FROM,
        expires_at=EXPIRES_AT,
        dns_names=("example.com", "www.example.com"),
        serial_number=0x1234ABCD,
    )
    collector = FakeCollector(
        VerifiedLeafCertificate(
            target=ValidatedTarget(hostname="example.com"),
            connected_ip=ipaddress.ip_address("93.184.216.34"),
            certificate_der=certificate_der,
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
        "subject": "CN=example.com",
        "issuer": "CN=Sentinel Test CA",
        "valid_from": "2026-07-01T00:00:00Z",
        "expires_at": "2026-08-23T00:00:00Z",
        "days_remaining": 30,
        "dns_names": ["example.com", "www.example.com"],
        "serial_number": "1234abcd",
        "signature_algorithm": "sha256",
        "public_key_type": "rsa",
        "public_key_size": 2048,
        "findings": [
            {
                "code": "healthy_certificate",
                "severity": "info",
                "message": (
                    "The certificate passed the configured certificate "
                    "health checks."
                ),
            }
        ],
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
            FailureCode.CERTIFICATE_PARSE_FAILED,
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


def test_tls_leaf_certificate_parse_failure_has_stable_typed_response(
    client: TestClient,
) -> None:
    collector = FakeCollector(
        VerifiedLeafCertificate(
            target=ValidatedTarget(hostname="example.com"),
            connected_ip=ipaddress.ip_address("93.184.216.34"),
            certificate_der=b"not a DER certificate",
            certificate_sha256="a" * 64,
        )
    )
    app.dependency_overrides[get_tls_collector] = override_collector(collector)

    response = client.post(
        "/api/v1/tls/leaf-certificate",
        json={"hostname": "example.com"},
    )

    assert response.status_code == 502
    assert response.json() == {
        "status": "failure",
        "stage": "certificate",
        "code": "certificate_parse_failed",
    }
    assert collector.calls == [
        ("example.com", TLS_COLLECTION_OVERALL_TIMEOUT)
    ]

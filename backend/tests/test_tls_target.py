import ipaddress
import socket

import pytest

from backend.tls_models import ValidatedTarget
from backend.tls_target import (
    BlockedAddressError,
    InvalidAddressRecordError,
    InvalidTargetError,
    NoAddressesError,
    approve_resolved_addresses,
    is_globally_routable,
    validate_target,
)


def ipv4_record(address: str) -> tuple:
    return (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (address, 443),
    )


def ipv6_record(address: str) -> tuple:
    return (
        socket.AF_INET6,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (address, 443, 0, 0),
    )


def test_validate_target_normalizes_ascii_hostname() -> None:
    assert validate_target("EXAMPLE.COM.") == ValidatedTarget(
        hostname="example.com",
        port=443,
    )


@pytest.mark.parametrize(
    "hostname",
    [
        "",
        "https://example.com",
        "user@example.com",
        "example.com/path",
        "example.com:8443",
        "127.0.0.1",
        "::1",
        "bad label.example",
        "-bad.example",
        "bad-.example",
        "tést.example",
        f"{'a' * 64}.example",
    ],
)
def test_validate_target_rejects_unsupported_input(hostname: str) -> None:
    with pytest.raises(InvalidTargetError):
        validate_target(hostname)


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "0.0.0.0",
        "192.0.2.1",
        "fc00::1",
        "::1",
        "fe80::1",
        "ff02::1",
        "::",
        "2001:db8::1",
    ],
)
def test_address_policy_rejects_non_global_categories(address: str) -> None:
    assert is_globally_routable(ipaddress.ip_address(address)) is False


def test_6to4_ipv6_uses_embedded_ipv4_policy() -> None:
    assert is_globally_routable(
        ipaddress.ip_address("2002:7f00:1::")
    ) is False

    assert is_globally_routable(
        ipaddress.ip_address("2002:0808:0808::")
    ) is True

def test_approve_resolved_addresses_preserves_sockaddr_shapes() -> None:
    target = validate_target("example.com")

    approved = approve_resolved_addresses(
        target,
        [
            ipv4_record("8.8.8.8"),
            ipv6_record("2606:4700:4700::1111"),
        ],
    )

    ipv4, ipv6 = approved.addresses
    assert ipv4.sockaddr == ("8.8.8.8", 443)
    assert len(ipv4.sockaddr) == 2
    assert ipv6.sockaddr == ("2606:4700:4700::1111", 443, 0, 0)
    assert len(ipv6.sockaddr) == 4


def test_mixed_public_and_blocked_answers_reject_entire_target() -> None:
    target = validate_target("example.com")

    with pytest.raises(BlockedAddressError):
        approve_resolved_addresses(
            target,
            [ipv4_record("8.8.8.8"), ipv4_record("127.0.0.1")],
        )


def test_no_supported_addresses_is_rejected() -> None:
    target = validate_target("example.com")

    with pytest.raises(NoAddressesError):
        approve_resolved_addresses(target, [])


@pytest.mark.parametrize(
    "record",
    [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("8.8.8.8", 443, 0, 0),
        ),
        (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("2606:4700:4700::1111", 443),
        ),
        ipv4_record("2606:4700:4700::1111"),
        ipv6_record("8.8.8.8"),
    ],
)
def test_rejects_invalid_addrinfo_family_version_or_shape(record: tuple) -> None:
    target = validate_target("example.com")

    with pytest.raises(InvalidAddressRecordError):
        approve_resolved_addresses(target, [record])

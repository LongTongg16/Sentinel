import asyncio
import ipaddress
import re
import socket
from collections.abc import Sequence
from typing import Protocol, TypeAlias

from backend.tls_models import (
    ApprovedAddress,
    ApprovedTarget,
    IPAddress,
    ValidatedTarget,
)


AddrInfo: TypeAlias = tuple[
    socket.AddressFamily,
    socket.SocketKind,
    int,
    str,
    tuple,
]

_HOSTNAME_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_MAX_HOSTNAME_LENGTH = 253


class InvalidTargetError(ValueError):
    pass


class InvalidAddressRecordError(ValueError):
    pass


class BlockedAddressError(ValueError):
    pass


class NoAddressesError(ValueError):
    pass


class Resolver(Protocol):
    async def resolve(self, target: ValidatedTarget) -> Sequence[AddrInfo]:
        """Resolve a validated hostname once and return numeric address records."""


class SystemResolver:
    async def resolve(self, target: ValidatedTarget) -> Sequence[AddrInfo]:
        loop = asyncio.get_running_loop()
        return await loop.getaddrinfo(
            target.hostname,
            target.port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )


def validate_target(hostname: str) -> ValidatedTarget:
    normalized = hostname.rstrip(".").lower()
    if not normalized or len(normalized) > _MAX_HOSTNAME_LENGTH:
        raise InvalidTargetError("hostname length is invalid")

    try:
        normalized.encode("ascii")
    except UnicodeEncodeError as error:
        raise InvalidTargetError("hostname must be ASCII") from error

    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        raise InvalidTargetError("IP literals are not supported")

    labels = normalized.split(".")
    if any(not _HOSTNAME_LABEL.fullmatch(label) for label in labels):
        raise InvalidTargetError("hostname syntax is invalid")

    return ValidatedTarget(hostname=normalized)


def is_globally_routable(address: IPAddress) -> bool:
    """Return whether the address is permitted for outbound collection.

    Sentinel permits only globally routable unicast addresses. It explicitly
    rejects private, loopback, link-local, multicast, unspecified, and reserved
    addresses. Other non-global ranges are also rejected. For IPv4-mapped IPv6,
    policy is applied to the embedded IPv4 address.
    """

    policy_address: IPAddress = address

    if isinstance(address, ipaddress.IPv6Address):
        mapped_address = address.ipv4_mapped

        if mapped_address is not None:
            policy_address = mapped_address
        else:
            six_to_four_address = address.sixtofour

            if six_to_four_address is not None:
                policy_address = six_to_four_address
                
    explicitly_blocked = (
        policy_address.is_private
        or policy_address.is_loopback
        or policy_address.is_link_local
        or policy_address.is_multicast
        or policy_address.is_unspecified
        or policy_address.is_reserved
    )
    return policy_address.is_global and not explicitly_blocked


def approve_resolved_addresses(
    target: ValidatedTarget,
    records: Sequence[AddrInfo],
) -> ApprovedTarget:
    approved: list[ApprovedAddress] = []
    seen: set[tuple[socket.AddressFamily, str, int, int]] = set()

    for family, socket_kind, _protocol, _canonical_name, sockaddr in records:
        if socket_kind != socket.SOCK_STREAM:
            continue

        if family == socket.AF_INET:
            if (
                not isinstance(sockaddr, tuple)
                or len(sockaddr) != 2
                or not isinstance(sockaddr[0], str)
                or not isinstance(sockaddr[1], int)
                or sockaddr[1] != target.port
            ):
                raise InvalidAddressRecordError("invalid IPv4 sockaddr")
            try:
                address = ipaddress.ip_address(sockaddr[0])
            except ValueError as error:
                raise InvalidAddressRecordError(
                    "invalid IPv4 address"
                ) from error
            if not isinstance(address, ipaddress.IPv4Address):
                raise InvalidAddressRecordError(
                    "AF_INET record did not contain an IPv4 address"
                )
            normalized_sockaddr = (address.compressed, target.port)
            identity = (family, address.compressed, 0, 0)
        elif family == socket.AF_INET6:
            if (
                not isinstance(sockaddr, tuple)
                or len(sockaddr) != 4
                or not isinstance(sockaddr[0], str)
                or not isinstance(sockaddr[1], int)
                or sockaddr[1] != target.port
                or not isinstance(sockaddr[2], int)
                or not isinstance(sockaddr[3], int)
            ):
                raise InvalidAddressRecordError("invalid IPv6 sockaddr")
            try:
                address = ipaddress.ip_address(sockaddr[0])
            except ValueError as error:
                raise InvalidAddressRecordError(
                    "invalid IPv6 address"
                ) from error
            if not isinstance(address, ipaddress.IPv6Address):
                raise InvalidAddressRecordError(
                    "AF_INET6 record did not contain an IPv6 address"
                )
            flowinfo = sockaddr[2]
            scope_id = sockaddr[3]
            normalized_sockaddr = (
                address.compressed,
                target.port,
                flowinfo,
                scope_id,
            )
            identity = (family, address.compressed, flowinfo, scope_id)
        else:
            continue

        if not is_globally_routable(address):
            raise BlockedAddressError(f"address is not globally routable: {address}")

        if identity in seen:
            continue
        seen.add(identity)
        approved.append(
            ApprovedAddress(
                ip=address,
                family=family,
                sockaddr=normalized_sockaddr,
            )
        )

    if not approved:
        raise NoAddressesError("no supported addresses were resolved")

    return ApprovedTarget(target=target, addresses=tuple(approved))

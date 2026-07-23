from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from socket import AddressFamily


IPAddress = IPv4Address | IPv6Address
IPv4SockAddr = tuple[str, int]
IPv6SockAddr = tuple[str, int, int, int]
SockAddr = IPv4SockAddr | IPv6SockAddr


@dataclass(frozen=True)
class ValidatedTarget:
    hostname: str
    port: int = 443


@dataclass(frozen=True)
class ApprovedAddress:
    ip: IPAddress
    family: AddressFamily
    sockaddr: SockAddr


@dataclass(frozen=True)
class ApprovedTarget:
    target: ValidatedTarget
    addresses: tuple[ApprovedAddress, ...]


@dataclass(frozen=True)
class VerifiedLeafCertificate:
    target: ValidatedTarget
    connected_ip: IPAddress
    certificate_der: bytes
    certificate_sha256: str


class FailureStage(str, Enum):
    TARGET_VALIDATION = "target_validation"
    DNS = "dns"
    CONNECT = "connect"
    TLS_HANDSHAKE = "tls_handshake"
    CERTIFICATE = "certificate"


class FailureCode(str, Enum):
    INVALID_HOSTNAME = "invalid_hostname"
    DNS_FAILURE = "dns_failure"
    NO_ADDRESSES = "no_addresses"
    BLOCKED_ADDRESS = "blocked_address"
    CONNECT_FAILURE = "connect_failure"
    TLS_VERIFICATION_FAILED = "tls_verification_failed"
    TLS_FAILURE = "tls_failure"
    MISSING_PEER_CERTIFICATE = "missing_peer_certificate"
    OVERALL_TIMEOUT = "overall_timeout"


@dataclass(frozen=True)
class TlsCollectionFailure:
    stage: FailureStage
    code: FailureCode

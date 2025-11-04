import os
import random
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from scapy.all import (
    BOOTP,
    DHCP,
    Ether,
    IP,
    UDP,
    conf,
    get_if_hwaddr,
    srp1,
)
from scapy.utils import mac2str
import socket


@dataclass
class DhcpLease:
    """Captured information returned by the DHCP server."""

    assigned_ip: str
    server_id: Optional[str]
    lease_time: Optional[int]
    subnet_mask: Optional[str]
    router: Optional[str]
    dns_servers: List[str]
    raw_options: Dict[str, object]


class DhcpHandshakeError(RuntimeError):
    """Raised when the DHCP four-way handshake cannot be completed."""


def perform_handshake(
    interface: Optional[str] = None,
    *,
    timeout: float = 5.0,
    retries: int = 3,
) -> DhcpLease:
    """
    Perform the DHCP discover → offer → request → ack handshake.

    Parameters
    ----------
    interface:
        Network interface name to use. Defaults to the Scapy configured interface.
    timeout:
        Seconds to wait for each server response.
    retries:
        Number of times to retry the discover/offer cycle before giving up.
    """
    _ensure_root_privileges()
    conf.checkIPaddr = False
    iface = interface or conf.iface
    if not iface:
        raise DhcpHandshakeError("Missing network interface; pass --iface or configure Scapy.")

    client_mac = get_if_hwaddr(iface)
    for attempt in range(retries):
        xid = random.randint(0, 0xFFFFFFFF)
        offer = _send_and_receive(
            _build_dhcp_packet(
                message_type="discover",
                mac_address=client_mac,
                xid=xid,
            ),
            iface=iface,
            timeout=timeout,
        )
        if offer is None or BOOTP not in offer:
            continue
        offer_bootp = offer[BOOTP]
        if offer_bootp.xid != xid:
            continue

        requested_ip = offer_bootp.yiaddr
        options = _options_to_dict(offer[DHCP].options) if DHCP in offer else {}
        server_id = _first_option(options, "server_id")

        request_packet = _build_dhcp_packet(
            message_type="request",
            mac_address=client_mac,
            xid=xid,
            requested_ip=requested_ip,
            server_id=server_id,
        )
        ack = _send_and_receive(
            request_packet,
            iface=iface,
            timeout=timeout,
        )
        if ack is None or BOOTP not in ack:
            continue
        ack_bootp = ack[BOOTP]
        if ack_bootp.xid != xid:
            continue

        ack_options = _options_to_dict(ack[DHCP].options) if DHCP in ack else {}
        return DhcpLease(
            assigned_ip=ack_bootp.yiaddr,
            server_id=_to_ipv4_str(_first_option(ack_options, "server_id")),
            lease_time=_first_option(ack_options, "lease_time"),
            subnet_mask=_to_ipv4_str(_first_option(ack_options, "subnet_mask")),
            router=_normalize_router(_first_option(ack_options, "router")),
            dns_servers=_normalize_dns(_first_option(ack_options, "name_server")),
            raw_options=ack_options,
        )

    raise DhcpHandshakeError(
        f"No DHCP ACK received after {retries} discover/request attempts on {iface}."
    )


def _send_and_receive(packet, *, iface: str, timeout: float):
    return srp1(
        packet,
        iface=iface,
        timeout=timeout,
        retry=0,
        verbose=False,
    )


def _build_dhcp_packet(
    *,
    message_type: str,
    mac_address: str,
    xid: int,
    requested_ip: Optional[str] = None,
    server_id: Optional[str] = None,
):
    params = [1, 3, 6, 15, 51, 54, 58, 59]
    options: List[Tuple[str, object]] = [("message-type", message_type)]
    if requested_ip:
        options.append(("requested_addr", requested_ip))
    if server_id:
        options.append(("server_id", server_id))
    options.append(("param_req_list", params))
    options.append("end")

    bootp = BOOTP(
        op=1,
        chaddr=_mac_to_chaddr(mac_address),
        xid=xid,
        flags=0x8000,
        ciaddr="0.0.0.0",
        yiaddr="0.0.0.0",
        siaddr="0.0.0.0",
        giaddr="0.0.0.0",
    )
    return (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_address)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / bootp
        / DHCP(options=options)
    )


def _options_to_dict(options: Iterable):
    parsed: Dict[str, object] = {}
    for entry in options:
        if isinstance(entry, tuple) and len(entry) >= 2:
            key = entry[0]
            value = entry[1]
            parsed[key] = value
    return parsed


def _first_option(options: Dict[str, object], key: str):
    value = options.get(key)
    if isinstance(value, (list, tuple)) and len(value) == 1:
        return value[0]
    return value


def _normalize_router(value):
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    return _to_ipv4_str(value)


def _normalize_dns(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [_to_ipv4_str(v) for v in value if v is not None]
    converted = _to_ipv4_str(value)
    return [converted] if converted else []


def _ensure_root_privileges():
    if hasattr(os, "geteuid"):
        if os.geteuid() != 0:
            raise PermissionError("Scapy DHCP handshake must run as root or with CAP_NET_RAW.")


def _mac_to_chaddr(mac_address: str) -> bytes:
    return mac2str(mac_address) + b"\x00" * 10


def _to_ipv4_str(value):
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)) and len(value) == 4:
        return socket.inet_ntoa(value)
    return str(value)

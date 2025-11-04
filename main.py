import argparse
import sys
from typing import Optional

from dhcp_clients.client import DhcpHandshakeError, DhcpLease, perform_handshake


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Use Scapy to run the DHCP discover/offer/request/ack handshake."
    )
    parser.add_argument(
        "--iface",
        help="network interface to use (defaults to Scapy's configured interface)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="seconds to wait for each DHCP response (default: 5)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="number of handshake retries before failing (default: 3)",
    )
    args = parser.parse_args(argv)

    try:
        lease = perform_handshake(
            args.iface,
            timeout=args.timeout,
            retries=args.retries,
        )
    except PermissionError as exc:
        parser.error(str(exc))
    except DhcpHandshakeError as exc:
        print(f"DHCP handshake failed: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted by user.", file=sys.stderr)
        return 130

    _print_lease(lease)
    return 0


def _print_lease(lease: DhcpLease) -> None:
    print("DHCP handshake succeeded.")
    print(f"Assigned IP: {lease.assigned_ip}")
    print(f"Server ID: {lease.server_id or 'n/a'}")
    print(f"Lease Time: {lease.lease_time or 'n/a'}")
    print(f"Subnet Mask: {lease.subnet_mask or 'n/a'}")
    print(f"Router: {lease.router or 'n/a'}")
    print(f"DNS Servers: {', '.join(lease.dns_servers) if lease.dns_servers else 'n/a'}")
    if lease.raw_options:
        print("Raw Options:")
        for key, value in lease.raw_options.items():
            print(f"  {key}: {value}")


if __name__ == "__main__":
    sys.exit(main())

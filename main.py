import argparse
import sys
from typing import Optional

from dhcp_clients.client import DhcpHandshakeError, DhcpLease, perform_handshake
from dhcp_clients.simulator import SimulationResult, simulate_dhcp_clients


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
    parser.add_argument(
        "--clients",
        type=int,
        default=1,
        help="number of DHCP clients to simulate (default: 1)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=10,
        help="maximum number of concurrent simulated clients (default: 10)",
    )
    parser.add_argument(
        "--mac-prefix",
        help="MAC address prefix (e.g. 02:00:00) used for simulated clients",
    )
    parser.add_argument(
        "--client-mac",
        help="explicit MAC address for single-client mode",
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="optional seed when deriving simulated MAC addresses",
    )
    args = parser.parse_args(argv)

    try:
        if args.clients <= 1:
            if args.clients <= 0:
                parser.error("--clients must be positive.")
            if args.client_mac and args.mac_prefix:
                parser.error("Use either --client-mac or --mac-prefix, not both.")
            lease = perform_handshake(
                args.iface,
                timeout=args.timeout,
                retries=args.retries,
                client_mac=args.client_mac,
            )
            _print_lease(lease)
        else:
            if args.client_mac:
                parser.error("--client-mac may only be used when --clients=1.")
            result = simulate_dhcp_clients(
                count=args.clients,
                concurrency=args.concurrency,
                interface=args.iface,
                timeout=args.timeout,
                retries=args.retries,
                mac_prefix=args.mac_prefix,
                random_seed=args.seed,
            )
            _print_simulation(result)
    except PermissionError as exc:
        parser.error(str(exc))
    except DhcpHandshakeError as exc:
        print(f"DHCP handshake failed: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        print("Interrupted by user.", file=sys.stderr)
        return 130

    return 0


def _print_lease(lease: DhcpLease) -> None:
    print("DHCP handshake succeeded.")
    print(f"Assigned IP: {lease.assigned_ip}")
    print(f"Server ID: {lease.server_id or 'n/a'}")
    print(f"Lease Time: {lease.lease_time or 'n/a'}")
    print(f"Subnet Mask: {lease.subnet_mask or 'n/a'}")
    print(f"Router: {lease.router or 'n/a'}")
    print(
        f"DNS Servers: {', '.join(lease.dns_servers) if lease.dns_servers else 'n/a'}"
    )
    if lease.raw_options:
        print("Raw Options:")
        for key, value in lease.raw_options.items():
            print(f"  {key}: {value}")


def _print_simulation(result: SimulationResult) -> None:
    print(f"Simulated DHCP clients: {result.total}")
    print(f"Successful handshakes: {result.succeeded}")
    print(f"Failed handshakes: {result.failed}")

    sample_successes = 5
    sample_failures = 10

    if result.successes:
        print("Sample leases:")
        for mac, lease in result.successes[:sample_successes]:
            server = lease.server_id or "n/a"
            print(f"  {mac} -> {lease.assigned_ip} (server {server})")
        remaining = len(result.successes) - sample_successes
        if remaining > 0:
            print(f"  ... {remaining} more successful leases")

    if result.failures:
        print("Failures:")
        for mac, error in result.failures[:sample_failures]:
            print(f"  {mac}: {error}")
        remaining = len(result.failures) - sample_failures
        if remaining > 0:
            print(f"  ... {remaining} more failures")


if __name__ == "__main__":
    sys.exit(main())

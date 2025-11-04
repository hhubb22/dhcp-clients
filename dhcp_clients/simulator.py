from __future__ import annotations

import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Generator, Iterable, List, Optional, Sequence, Tuple

from .client import DhcpLease, DhcpHandshakeError, perform_handshake


@dataclass
class SimulationResult:
    """Summary of a bulk DHCP simulation run."""

    successes: List[Tuple[str, DhcpLease]]
    failures: List[Tuple[str, str]]

    @property
    def total(self) -> int:
        return len(self.successes) + len(self.failures)

    @property
    def succeeded(self) -> int:
        return len(self.successes)

    @property
    def failed(self) -> int:
        return len(self.failures)

    @property
    def success_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return self.succeeded / self.total


def simulate_dhcp_clients(
    *,
    count: int,
    concurrency: int,
    interface: Optional[str],
    timeout: float,
    retries: int,
    mac_prefix: Optional[str] = None,
    random_seed: Optional[int] = None,
) -> SimulationResult:
    """
    Run multiple DHCP handshakes concurrently with distinct client identities.

    Parameters
    ----------
    count:
        Total number of simulated clients (i.e., DHCP handshakes) to run.
    concurrency:
        Maximum number of simultaneous handshakes in-flight.
    interface:
        Network interface name to use for the raw frames.
    timeout:
        Seconds to wait for each server response.
    retries:
        Number of times to retry the discover/offer cycle before giving up.
    mac_prefix:
        Optional MAC prefix (1-5 octets) used as the starting bytes of every
        simulated client address.
    random_seed:
        Optional seed to randomise the MAC address space starting point.
    """
    if count <= 0:
        raise ValueError("count must be positive.")
    if concurrency <= 0:
        raise ValueError("concurrency must be positive.")

    mac_iter = _iter_mac_addresses(count, mac_prefix, random_seed)
    successes: List[Tuple[str, DhcpLease]] = []
    failures: List[Tuple[str, str]] = []
    max_workers = min(count, concurrency)

    def _worker(mac: str) -> DhcpLease:
        return perform_handshake(
            interface,
            timeout=timeout,
            retries=retries,
            client_mac=mac,
        )

    mac_source = iter(mac_iter)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        pending = {}

        while len(pending) < max_workers:
            try:
                mac = next(mac_source)
            except StopIteration:
                break
            pending[executor.submit(_worker, mac)] = mac

        while pending:
            future = next(as_completed(list(pending.keys())))
            mac = pending.pop(future)
            try:
                lease = future.result()
                successes.append((mac, lease))
            except KeyboardInterrupt:
                raise
            except DhcpHandshakeError as exc:
                failures.append((mac, str(exc)))
            except PermissionError as exc:
                failures.append((mac, str(exc)))
            except Exception as exc:  # noqa: BLE001
                failures.append((mac, f"unexpected error: {exc}"))

            try:
                mac = next(mac_source)
            except StopIteration:
                continue
            pending[executor.submit(_worker, mac)] = mac

    return SimulationResult(successes=successes, failures=failures)


def _iter_mac_addresses(
    count: int,
    mac_prefix: Optional[str],
    random_seed: Optional[int],
) -> Generator[str, None, None]:
    base_bytes = _parse_mac_prefix(mac_prefix) if mac_prefix else [0x02]
    if len(base_bytes) > 6:
        raise ValueError("MAC prefix may contain at most 6 octets.")

    remaining_octets = 6 - len(base_bytes)
    available = 1 << (remaining_octets * 8)
    if count > available:
        raise ValueError(
            f"Cannot create {count} unique MAC addresses from the provided prefix."
        )

    start_offset = 0
    if random_seed is not None and remaining_octets > 0:
        rng = random.Random(random_seed)
        start_offset = rng.randrange(0, available - count + 1)

    base_value = _mac_bytes_to_int(base_bytes) << (remaining_octets * 8)
    for offset in range(count):
        mac_value = base_value + start_offset + offset
        yield _mac_int_to_str(mac_value)


def _parse_mac_prefix(prefix: Optional[str]) -> List[int]:
    if not prefix:
        return []
    parts = prefix.split(":")
    if not parts or any(part == "" for part in parts):
        raise ValueError("Invalid MAC prefix format.")
    if len(parts) > 6:
        raise ValueError("MAC prefix may contain at most 6 octets.")
    bytes_: List[int] = []
    for part in parts:
        if len(part) > 2:
            raise ValueError("Each MAC prefix octet must be one or two hex digits.")
        value = int(part, 16)
        if not 0 <= value <= 0xFF:
            raise ValueError("MAC prefix bytes must be between 00 and FF.")
        bytes_.append(value)
    return bytes_


def _mac_bytes_to_int(bytes_: Sequence[int]) -> int:
    value = 0
    for byte in bytes_:
        value = (value << 8) | byte
    return value


def _mac_int_to_str(value: int) -> str:
    octets = [(value >> (8 * shift)) & 0xFF for shift in reversed(range(6))]
    return ":".join(f"{octet:02x}" for octet in octets)

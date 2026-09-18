#!/usr/bin/env python3
"""Check introduced public content for common private-data and secret shapes.

Findings contain only path, line, and rule ID. Matched content is never
printed because it may itself be sensitive.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

MAX_TEXT_BYTES = 2 * 1024 * 1024
DOCUMENTATION_IPV4 = tuple(
    ipaddress.ip_network(value)
    for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
DOCUMENTATION_IPV6 = ipaddress.ip_network("2001:db8::/32")
SAFE_UUIDS = {
    "00000000-0000-0000-0000-000000000000",
    "11111111-2222-3333-4444-555555555555",
    "ab0b0ac4-aae9-4958-a04d-8ec36fe1b2f9",
}
FORBIDDEN_SUFFIXES = {
    ".7z",
    ".apk",
    ".cap",
    ".db",
    ".der",
    ".gz",
    ".jks",
    ".key",
    ".p12",
    ".pcap",
    ".pcapng",
    ".pfx",
    ".sqlite",
    ".sqlite3",
    ".tar",
    ".tgz",
    ".zip",
}

PATTERNS = (
    (
        "PEM_PRIVATE_KEY",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    (
        "EMAIL_ADDRESS",
        re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}"),
    ),
    (
        "MAC_ADDRESS",
        re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])"),
    ),
    (
        "PRIVATE_DNS",
        re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+(?:corp|home|internal|lan|local)\b"),
    ),
    ("HOME_PATH", re.compile(r"(?<![A-Za-z0-9._-])/(?:Users|home)/[^\s'\"`]+")),
    (
        "CREDENTIAL_URL",
        re.compile(
            r"(?i)\bhttps?://(?:[^\s/@:]+:[^\s/@]+@|[^\s?#]+[?&](?:access_token|api_key|password|refresh_token|token)=)"
        ),
    ),
    (
        "SECRET_ASSIGNMENT",
        re.compile(
            r"(?i)\b(?:access[_-]?token|api[_-]?key|bearer|owner[_-]?psk|password|passwd|private[_-]?key|psk|refresh[_-]?token|secret)\b\s*(?::|=)\s*(?:b|br|f|r|rb)?['\"][^'\"]+['\"]"
        ),
    ),
    (
        "SERIAL_ASSIGNMENT",
        re.compile(
            r"(?i)\b(?:device[_-]?)?serial(?:number|num)?\b\s*(?::|=)\s*['\"][^'\"]+['\"]"
        ),
    ),
    (
        "REAL_TIMESTAMP",
        re.compile(
            r"\b20[0-9]{2}-[01][0-9]-[0-3][0-9][T ][0-2][0-9]:[0-5][0-9](?::[0-6][0-9](?:\.[0-9]+)?)?(?:Z|[+-][0-2][0-9]:?[0-5][0-9])?\b"
        ),
    ),
    (
        "QR_PAYLOAD",
        re.compile(r"(?i)\b(?:qr[_-]?payload|setup[_-]?payload)\b\s*(?::|=)"),
    ),
)
UUID_PATTERN = r"(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![0-9a-f])"
UUID_RE = re.compile(UUID_PATTERN, re.IGNORECASE)
PUBLIC_GITHUB_ATTACHMENT_RE = re.compile(
    rf"https://github\.com/user-attachments/assets/(?P<uuid>{UUID_PATTERN})",
    re.IGNORECASE,
)
IPV4_RE = re.compile(
    r"(?<![0-9.])(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}(?![0-9.])"
)
IPV6_RE = re.compile(
    r"(?i)(?<![0-9a-f:])(?:\[)?(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:%[A-Za-z0-9_.-]+)?(?:\])?(?![0-9a-f:])"
)


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    rule_id: str

    def render(self) -> str:
        return f"{self.path}:{self.line}:{self.rule_id}"


def _safe_ipv4(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return (
        address.is_loopback
        or address.is_unspecified
        or any(address in network for network in DOCUMENTATION_IPV4)
    )


def _safe_ipv6(value: str) -> bool:
    address = ipaddress.ip_address(value.strip("[]").split("%", 1)[0])
    return (
        address.is_loopback
        or address.is_unspecified
        or address in DOCUMENTATION_IPV6
        # An address in an IETF-reserved block is not assignable to a host,
        # so it cannot be the leak this rule exists to catch. Excluding them
        # also clears a false positive on C++ and Rust scope operators: a
        # scope operator preceded by a hex letter matches IPV6_RE, parses as
        # an address in the all-zero reserved block, and is nobody's device.
        # Global unicast, link-local and unique-local all sit outside the
        # reserved set and stay flagged; see the tests for each.
        or address.is_reserved
    )


def scan_text(path: str, text: str) -> list[Finding]:
    findings: set[Finding] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        public_attachment_uuids = {
            match.group("uuid").lower()
            for match in PUBLIC_GITHUB_ATTACHMENT_RE.finditer(line)
        }
        for rule_id, pattern in PATTERNS:
            if pattern.search(line):
                findings.add(Finding(path, line_number, rule_id))
        for match in UUID_RE.finditer(line):
            value = match.group(0).lower()
            if value not in SAFE_UUIDS and value not in public_attachment_uuids:
                findings.add(Finding(path, line_number, "UUID"))
        for match in IPV4_RE.finditer(line):
            if not _safe_ipv4(match.group(0)):
                findings.add(Finding(path, line_number, "NON_DOCUMENTATION_IPV4"))
        for match in IPV6_RE.finditer(line):
            try:
                safe = _safe_ipv6(match.group(0))
            except ValueError:
                continue
            if not safe:
                findings.add(Finding(path, line_number, "NON_DOCUMENTATION_IPV6"))
    return sorted(findings)


def scan_file(path: Path, display_path: str) -> list[Finding]:
    if path.is_symlink():
        return [Finding(display_path, 0, "SYMLINK")]
    if path.suffix.casefold() in FORBIDDEN_SUFFIXES:
        return [Finding(display_path, 0, "FORBIDDEN_FILE_TYPE")]
    data = path.read_bytes()
    if len(data) > MAX_TEXT_BYTES:
        return [Finding(display_path, 0, "FILE_TOO_LARGE")]
    if b"\x00" in data:
        return [Finding(display_path, 0, "BINARY_CONTENT")]
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return [Finding(display_path, 0, "NON_UTF8_CONTENT")]
    return scan_text(display_path, text)


def _changed_paths(base: str) -> list[str]:
    commands = (
        [
            "git",
            "diff",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
            f"{base}..HEAD",
            "--",
        ],
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z", "--"],
        ["git", "diff", "--name-only", "--diff-filter=ACMR", "-z", "--"],
    )
    changed = [
        subprocess.run(command, capture_output=True, check=True) for command in commands
    ]
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        capture_output=True,
        check=True,
    )
    return sorted(
        {
            value.decode("utf-8")
            for output in (*(result.stdout for result in changed), untracked.stdout)
            for value in output.split(b"\0")
            if value
        }
    )


def _local_changed_paths() -> set[str]:
    commands = (
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z", "--"],
        ["git", "diff", "--name-only", "--diff-filter=ACMR", "-z", "--"],
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
    )
    outputs = (
        subprocess.run(command, capture_output=True, check=True).stdout
        for command in commands
    )
    return {
        value.decode("utf-8")
        for output in outputs
        for value in output.split(b"\0")
        if value
    }


HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@")


def _introduced_lines(base: str, path: str) -> set[int]:
    result = subprocess.run(
        [
            "git",
            "diff",
            "--no-color",
            "--no-ext-diff",
            "--unified=0",
            "--diff-filter=ACMR",
            f"{base}..HEAD",
            "--",
            path,
        ],
        capture_output=True,
        check=True,
        text=True,
    )
    lines: set[int] = set()
    for value in result.stdout.splitlines():
        match = HUNK_RE.match(value)
        if match is None:
            continue
        start = int(match.group("start"))
        count = int(match.group("count") or 1)
        lines.update(range(start, start + count))
    return lines


def check_changed(base: str) -> list[Finding]:
    """Scan introduced committed lines and all local-only file content."""
    local_paths = _local_changed_paths()
    findings: list[Finding] = []
    for path in _changed_paths(base):
        path_findings = scan_file(Path(path), path)
        if path in local_paths:
            findings.extend(path_findings)
            continue
        introduced = _introduced_lines(base, path)
        findings.extend(
            finding
            for finding in path_findings
            if finding.line == 0 or finding.line in introduced
        )
    return sorted(set(findings))


def check_paths(paths: Iterable[str]) -> list[Finding]:
    findings: list[Finding] = []
    for value in paths:
        findings.extend(scan_file(Path(value), value))
    return sorted(set(findings))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--changed-since")
    args = parser.parse_args()
    try:
        paths = _changed_paths(args.changed_since) if args.changed_since else args.paths
        if not paths:
            raise ValueError("no paths selected")
        findings = (
            check_changed(args.changed_since)
            if args.changed_since
            else check_paths(paths)
        )
    except (OSError, UnicodeDecodeError, subprocess.SubprocessError, ValueError):
        print("share-safety scan failed closed:SCAN_ERROR")
        return 2
    for finding in findings:
        print(finding.render())
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())

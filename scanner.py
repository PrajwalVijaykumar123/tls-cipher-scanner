#!/usr/bin/env python3
"""
TLS/SSL Cipher Suite Scanner

Connects to a host:port and performs a series of real TLS handshakes to
find out exactly which protocol versions and cipher categories the
server is willing to negotiate - the same category of check as
Qualys SSL Labs or `testssl.sh`, built from first principles on top of
Python's own ssl module. This checks configuration *strength*, not
certificate validity or expiry (a different, already-covered concern).

Usage:
    python3 scanner.py example.com
    python3 scanner.py example.com --port 8443
    python3 scanner.py example.com --json report.json
"""

import ssl
import sys
import json
import socket
import warnings
import argparse

# Probing SSLv3/TLSv1.0/TLSv1.1 on purpose is the entire point of this
# tool - silence the (correct, but here irrelevant) deprecation warnings
# ssl raises for setting those as min/max version.
warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*TLSVersion.*deprecated.*")

# Every TLSVersion the ssl module is willing to construct a context for -
# order matters for the summary (oldest first).
PROTOCOL_VERSIONS = [
    ("SSLv3", getattr(ssl.TLSVersion, "SSLv3", None)),
    ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]

DEPRECATED_PROTOCOLS = {"SSLv3", "TLSv1.0", "TLSv1.1"}

# OpenSSL cipher-string macros for well-known weak categories, and why
# each one is weak. Each is tried as its own isolated cipher list (with
# @SECLEVEL=0 so the *client* is willing to offer it) - if the server
# accepts a handshake using only ciphers from that category, the server
# is willing to negotiate something in that weak category.
WEAK_CIPHER_CATEGORIES = [
    ("eNULL", "NULL ciphers - no encryption at all; the 'secure' channel carries plaintext."),
    ("aNULL", "Anonymous ciphers (ADH/AECDH) - no authentication, trivially vulnerable to MITM."),
    ("EXPORT", "1990s US export-grade crypto, deliberately weakened to ~40-56 bit keys."),
    ("RC4", "RC4 stream cipher - has known practical biases/attacks (e.g. BEAST-adjacent, RC4 NOMORE)."),
    ("DES", "(Single) DES - 56-bit key, brute-forceable with commodity hardware."),
    ("3DES", "3DES/DES-CBC3 - vulnerable to the SWEET32 birthday attack on 64-bit block ciphers."),
    ("MD5", "MD5-based MAC - MD5 is cryptographically broken for collision resistance."),
]


def probe_protocol(host, port, version_const, timeout):
    """Attempts a handshake pinned to exactly one protocol version.
    Returns (supported: bool, detail: str)."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version_const
        ctx.maximum_version = version_const
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return True, tls.cipher()[0]
    except ssl.SSLError as e:
        return False, str(e)
    except (OSError, ValueError) as e:
        return False, str(e)


def probe_weak_cipher_category(host, port, cipher_string, timeout):
    """Attempts a TLS <=1.2 handshake restricted to one weak cipher
    category. Returns (accepted: bool, negotiated_cipher_or_error)."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2  # these categories are all <=TLS1.2 constructs
        ctx.set_ciphers(f"{cipher_string}:@SECLEVEL=0")
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return True, tls.cipher()[0]
    except ssl.SSLError as e:
        return False, str(e)
    except (OSError, ValueError) as e:
        return False, str(e)


def scan(host, port=443, timeout=5):
    result = {"host": host, "port": port, "protocols": [], "weak_ciphers": [], "errors": []}

    any_connected = False
    for name, const in PROTOCOL_VERSIONS:
        if const is None:
            result["protocols"].append({"protocol": name, "supported": None, "detail": "not available in this client's OpenSSL build"})
            continue
        supported, detail = probe_protocol(host, port, const, timeout)
        any_connected = any_connected or supported
        result["protocols"].append({"protocol": name, "supported": supported, "detail": detail})

    if not any_connected:
        result["errors"].append(
            "Could not complete a TLS handshake with any protocol version - host may be unreachable, "
            "not actually running TLS on this port, or using a protocol this client doesn't support at all."
        )
        return result

    for cipher_string, reason in WEAK_CIPHER_CATEGORIES:
        accepted, detail = probe_weak_cipher_category(host, port, cipher_string, timeout)
        if accepted:
            result["weak_ciphers"].append({"category": cipher_string, "reason": reason, "negotiated_cipher": detail})

    return result


def grade(result):
    supported = {p["protocol"] for p in result["protocols"] if p["supported"]}
    if not supported:
        return "F", "No successful handshake"
    if result["weak_ciphers"]:
        return "F", "Server will negotiate a cryptographically weak/broken cipher"
    if supported & DEPRECATED_PROTOCOLS:
        return "C", f"Deprecated protocol(s) still accepted: {', '.join(sorted(supported & DEPRECATED_PROTOCOLS))}"
    if "TLSv1.3" not in supported:
        return "B", "TLSv1.2 is fine, but TLSv1.3 is not offered"
    return "A", "Only modern protocols, no weak ciphers negotiated"


def print_report(result):
    print(f"\n{result['host']}:{result['port']}")

    if result["errors"]:
        for e in result["errors"]:
            print(f"  [ERROR] {e}")
        return

    g, reason = grade(result)
    print(f"  Grade: {g}  ({reason})")
    print()
    print("  Protocol support:")
    for p in result["protocols"]:
        if p["supported"] is None:
            print(f"    {p['protocol']:<10} not testable by this client")
        elif p["supported"]:
            tag = "  (DEPRECATED)" if p["protocol"] in DEPRECATED_PROTOCOLS else ""
            print(f"    {p['protocol']:<10} ACCEPTED{tag}  -> {p['detail']}")
        else:
            print(f"    {p['protocol']:<10} rejected")

    if result["weak_ciphers"]:
        print("\n  Weak cipher categories the server will negotiate:")
        for w in result["weak_ciphers"]:
            print(f"    [{w['category']}] {w['reason']}")
            print(f"        negotiated: {w['negotiated_cipher']}")
    else:
        print("\n  No weak cipher categories (NULL/anonymous/export/RC4/DES/3DES/MD5) were accepted.")


def main():
    parser = argparse.ArgumentParser(description="Scan a TLS server for weak protocol versions and cipher suites.")
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument("--port", type=int, default=443, help="Target port (default: 443)")
    parser.add_argument("--timeout", type=float, default=5, help="Per-attempt connection timeout in seconds")
    parser.add_argument("--json", metavar="FILE", help="Also write a JSON report to FILE")
    args = parser.parse_args()

    result = scan(args.host, port=args.port, timeout=args.timeout)
    print_report(result)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\nJSON report written to {args.json}")

    if result["errors"]:
        sys.exit(2)
    g, _ = grade(result)
    sys.exit(1 if g in ("D", "F") else 0)


if __name__ == "__main__":
    main()

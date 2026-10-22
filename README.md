# TLS/SSL Cipher Suite Scanner

Connects to a TLS server and performs a series of real handshakes to find out exactly which protocol versions and cipher categories it's willing to negotiate — the same category of check as Qualys SSL Labs or `testssl.sh`, built on Python's own `ssl` module. This checks configuration **strength** — a different, complementary concern to this portfolio's `ssl-cert-expiry-monitor`, which checks certificate **expiry** and says nothing about whether the server would still accept a 1990s export-grade cipher.

## What This Project Does

- **Protocol version probing**: attempts a real handshake pinned to exactly one protocol version at a time (SSLv3 through TLSv1.3) to find the server's actual accepted range — not just what it advertises, but what it will really negotiate
- **Weak cipher category probing**: for each of seven well-known weak cipher families — NULL encryption, anonymous (no-auth) ciphers, export-grade, RC4, DES, 3DES, and MD5-based MACs — attempts a handshake restricted to *only* that category, so a successful connection proves the server will genuinely use something from it, not just that the category exists in some abstract list
- **A letter grade** (A–F) summarizing the findings: F for any weak cipher or a fully failed handshake, C for still accepting a deprecated protocol (SSLv3/TLS1.0/1.1) even with no weak ciphers, B for TLS1.2-only, A for TLS1.3 with no weak ciphers
- **JSON output** for feeding into other tooling

## Why probe by restricting to one category at a time, rather than reading the server's full cipher list

A server's default handshake usually negotiates its *strongest* mutually-supported cipher — so simply connecting once and looking at `cipher()` would show something like `ECDHE-RSA-AES256-GCM-SHA384` even on a server that's also willing to fall back to `NULL-MD5` for a client that only offers that. The only way to know whether a weak fallback genuinely exists is to be a client that offers *nothing else* and see whether the server still completes the handshake. That's what each category probe does: construct a client context whose only usable ciphers are from one specific weak family, and attempt a real handshake with it.

## Example Output

```
127.0.0.1:24444
  Grade: F  (Server will negotiate a cryptographically weak/broken cipher)

  Protocol support:
    SSLv3      rejected
    TLSv1.0    rejected
    TLSv1.1    rejected
    TLSv1.2    ACCEPTED  -> ECDHE-RSA-AES256-GCM-SHA384
    TLSv1.3    rejected

  Weak cipher categories the server will negotiate:
    [eNULL] NULL ciphers - no encryption at all; the 'secure' channel carries plaintext.
        negotiated: ECDHE-RSA-NULL-SHA
    [aNULL] Anonymous ciphers (ADH/AECDH) - no authentication, trivially vulnerable to MITM.
        negotiated: AECDH-AES256-SHA
    [MD5] MD5-based MAC - MD5 is cryptographically broken for collision resistance.
        negotiated: NULL-MD5
```

(Real output — an actual handshake against the test suite's deliberately-weakened local server, genuinely completing with `AECDH-AES256-SHA` and `NULL-MD5`, not a mocked or hypothetical result.)

## Tech Stack

- Python 3.11, standard library only (`ssl`, `socket`, `json`, `argparse`)

## Setup

```bash
python3 scanner.py example.com
python3 scanner.py example.com --port 8443
python3 scanner.py internal-service.local --port 9443 --json report.json
```

Exit code is `1` on grade D/F, `2` if no handshake could be completed at all (unreachable host, not actually TLS on that port), `0` otherwise.

**A note on client-side limitations**: this scanner's findings are bounded by what its own OpenSSL build can still construct a handshake for. Modern OpenSSL (3.x) has fully *removed*, not just disabled, some legacy ciphers (RC4 and 3DES were both unavailable in the build this was developed and tested against) — so on such a build, a report that RC4 is "rejected" may mean the server doesn't support it, or may mean this client literally cannot offer it to find out. The protocol/cipher report notes this distinction where it applies.

## Testing

A real network TLS server's configuration can change at any time (and most production servers are correctly hardened, which is the opposite of useful for testing weak-finding detection), so for a deterministic test, `test_fixtures/test_servers.py` starts two real local TLS servers using Python's own `ssl` module and a real self-signed certificate: a properly hardened one (TLSv1.2/1.3 only, default strong ciphers) and a deliberately misconfigured one (lowers OpenSSL's security level and explicitly re-enables anonymous and NULL-encryption ciphers that are off by default in any current OpenSSL build):

```bash
sh test_fixtures/run_test.sh
```

This runs the real `scanner.py` against both real servers over real sockets — not mocked `ssl.SSLContext` calls — and verifies: the hardened server is graded A with all deprecated protocols correctly rejected, the weak server is graded F with the specific weak categories it actually accepts named and a real negotiated cipher name shown for each, and an unreachable host produces a clean error rather than a crash.

## Architecture

```
For each protocol version (SSLv3 .. TLSv1.3):
  construct a client SSLContext pinned to exactly that version
  attempt a real handshake -> accepted/rejected + negotiated cipher
        |
        v
For each weak cipher category (eNULL, aNULL, EXPORT, RC4, DES, 3DES, MD5):
  construct a client SSLContext whose cipher list is ONLY that category
  attempt a real handshake -> if it succeeds, the server will use it
        |
        v
Grade (A-F) derived from: any successful handshake at all? any weak
ciphers accepted? any deprecated protocol still accepted? is TLSv1.3 offered?
        |
        v
Console report + optional JSON report; exit code reflects the grade
```

## Project Structure

```
tls-cipher-scanner/
├── scanner.py                    # Protocol + cipher-category probing, grading, CLI
├── requirements.txt                # No external deps - stdlib only
└── test_fixtures/
    ├── test_servers.py           # Real local TLS servers: hardened and deliberately weak
    └── run_test.sh                 # Generates a cert, starts both, runs scanner.py, verifies output
```

## What I Learned

- A server's single default handshake tells you its *best* cipher, never its *worst* - finding the weakest thing a server will still accept requires actively constraining the client to offer nothing else, which is a fundamentally different (and more adversarial) testing posture than a normal TLS client ever takes
- Modern OpenSSL's security-level mechanism (`@SECLEVEL=0` through `@SECLEVEL=5`) exists specifically to let a *testing* tool deliberately ask for weak ciphers a normal client would never request - without it, this scanner's own client-side code couldn't even construct the probe connections needed to find out what a server will do
- "Removed from the library" and "disabled by default but still present" are different facts with the same symptom (a cipher category reports as unavailable), and a scanner has to be honest that it can't fully tell them apart from the client side alone - a build where RC4 was compiled out entirely looks identical, from this tool's perspective, to a server that genuinely rejects RC4
- TLS1.0/1.1 being rejected by a server context that explicitly set `minimum_version = TLSv1` (as the test's weak-server fixture does) was a real, slightly surprising finding during development: OpenSSL 3.x's default provider refuses to fully enable those protocols even when a context asks for them, unless a legacy provider is explicitly loaded - a good illustration of how "the code says it's allowed" and "the underlying crypto library will actually do it" can diverge

## Next Steps

- Certificate chain and signature algorithm inspection (SHA-1 signatures, weak key sizes) as a complement to the existing expiry-only checker in this portfolio
- Forward secrecy verification - confirm the negotiated key exchange is ephemeral (ECDHE/DHE) rather than static RSA key exchange, which TLS1.2 still permits
- A `--starttls` mode for protocols that upgrade a plaintext connection to TLS mid-stream (SMTP, IMAP, FTP) rather than starting TLS immediately
- Compression/renegotiation checks (CRIME, and insecure renegotiation) for a more complete legacy-vulnerability picture

"""
Starts two real local TLS servers for the test suite - using Python's
own ssl module, a real self-signed certificate, and a real listening
socket:

  - a "hardened" server: TLSv1.2 and TLSv1.3 only, default (strong)
    cipher selection
  - a "weak" server: deliberately lowers OpenSSL's security level and
    explicitly enables anonymous-Diffie-Hellman and NULL-encryption
    ciphers, which are off by default in any modern OpenSSL build.
    This server is a deliberately-misconfigured test fixture - it is
    not representative of how to run a real TLS server, and exists
    only so the scanner's weak-cipher detection path can be exercised
    against a real accepted handshake instead of a mocked response.

Both require a certificate; generate one with:
    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
        -days 1 -nodes -subj "/CN=localhost"
"""

import ssl
import socket
import threading


def _serve_forever(sock, ctx):
    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        try:
            tls_conn = ctx.wrap_socket(conn, server_side=True)
            tls_conn.close()
        except ssl.SSLError:
            pass
        except OSError:
            pass


def start_hardened_server(port, certfile, keyfile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(20)

    t = threading.Thread(target=_serve_forever, args=(sock, ctx), daemon=True)
    t.start()
    return sock


def start_weak_server(port, certfile, keyfile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    # Deliberately weakened for testing only: lower OpenSSL's security
    # level and explicitly allow anonymous and NULL-encryption ciphers,
    # both disabled by default in any OpenSSL build from the last
    # decade. A real server would never do this.
    ctx.set_ciphers("ALL:eNULL:aNULL:@SECLEVEL=0")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(20)

    t = threading.Thread(target=_serve_forever, args=(sock, ctx), daemon=True)
    t.start()
    return sock

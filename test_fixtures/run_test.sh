#!/bin/sh
# Generates a real self-signed certificate, starts two real local TLS
# servers (a hardened one and a deliberately weak one, both using
# Python's own ssl module over real sockets), and runs the real
# scanner.py against each - no mocked TLS handshakes.
set -e
cd "$(dirname "$0")/.."

CERT=/tmp/tcs_cert.pem
KEY=/tmp/tcs_key.pem
openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" -days 1 -nodes -subj "/CN=localhost" 2>/dev/null

python3 -c "
import sys, time
sys.path.insert(0, 'test_fixtures')
from test_servers import start_hardened_server, start_weak_server
start_hardened_server(24443, '$CERT', '$KEY')
start_weak_server(24444, '$CERT', '$KEY')
time.sleep(60)
" &
SERVER_PID=$!
sleep 1

echo "== Hardened server (TLSv1.2/1.3 only, strong ciphers): expect grade A =="
set +e
python3 scanner.py 127.0.0.1 --port 24443 --json /tmp/tcs_hardened.json > /tmp/tcs_hardened_out.txt 2>&1
EXIT_HARDENED=$?
set -e
cat /tmp/tcs_hardened_out.txt

grep -q "Grade: A" /tmp/tcs_hardened_out.txt && echo "PASS: hardened server graded A" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
grep -q "TLSv1.0 \+rejected" /tmp/tcs_hardened_out.txt && echo "PASS: TLSv1.0 correctly rejected" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
grep -q "TLSv1.3 \+ACCEPTED" /tmp/tcs_hardened_out.txt && echo "PASS: TLSv1.3 correctly accepted" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
grep -q "No weak cipher categories" /tmp/tcs_hardened_out.txt && echo "PASS: no weak ciphers negotiated" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
[ "$EXIT_HARDENED" = "0" ] && echo "PASS: exit code 0 for a well-configured server" || { echo "FAIL: expected exit 0, got $EXIT_HARDENED"; kill $SERVER_PID; exit 1; }

echo
echo "== Weak server (aNULL/eNULL ciphers enabled): expect grade F with specific weak ciphers named =="
set +e
python3 scanner.py 127.0.0.1 --port 24444 --json /tmp/tcs_weak.json > /tmp/tcs_weak_out.txt 2>&1
EXIT_WEAK=$?
set -e
cat /tmp/tcs_weak_out.txt

grep -q "Grade: F" /tmp/tcs_weak_out.txt && echo "PASS: weak server graded F" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
grep -q "\[eNULL\]" /tmp/tcs_weak_out.txt && echo "PASS: NULL-encryption cipher category detected" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
grep -q "\[aNULL\]" /tmp/tcs_weak_out.txt && echo "PASS: anonymous (no-auth) cipher category detected" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
grep -q "AECDH\|ADH" /tmp/tcs_weak_out.txt && echo "PASS: real negotiated anonymous-DH cipher name shown" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
[ "$EXIT_WEAK" = "1" ] && echo "PASS: exit code 1 for a weak server" || { echo "FAIL: expected exit 1, got $EXIT_WEAK"; kill $SERVER_PID; exit 1; }

echo
echo "== Unreachable host: expect a clean error, not a crash =="
set +e
python3 scanner.py 127.0.0.1 --port 24499 --timeout 1 > /tmp/tcs_unreachable.txt 2>&1
EXIT_UNREACHABLE=$?
set -e
cat /tmp/tcs_unreachable.txt
[ "$EXIT_UNREACHABLE" = "2" ] && echo "PASS: unreachable host reported as a clean error" || { echo "FAIL: expected exit 2, got $EXIT_UNREACHABLE"; kill $SERVER_PID; exit 1; }

kill $SERVER_PID 2>/dev/null || true
rm -f "$CERT" "$KEY" /tmp/tcs_hardened.json /tmp/tcs_weak.json /tmp/tcs_hardened_out.txt /tmp/tcs_weak_out.txt /tmp/tcs_unreachable.txt
echo
echo "All tests passed."

#!/bin/sh
# Regenerates the TLS test fixtures under tests/data/. Run from the
# repo root. The certificates are deliberately long-lived (~100 years)
# so CI never rots, EC P-256 self-signed with CA:TRUE so each doubles
# as its own trust anchor, and SAN localhost/127.0.0.1 so hostname
# verification passes for the loopback e2e suites.
#
# tests/data/test_cert.pem + test_key.pem predate this script (they
# were committed as opaque blobs); the command below reproduces their
# profile. Regenerating them is safe for the test suite — no test
# pins bytes, only the trust relationships — but is rarely needed.
# The *_untrusted pair exists so mTLS tests can present a certificate
# that does NOT chain to the trusted bundle; the two pairs must never
# be generated from the same key.
set -eu

gen() {
    # $1 = output basename, $2 = CN
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "tests/data/${1}_key.pem" -out "tests/data/${1}_cert.pem" \
        -days 36500 -nodes -subj "/CN=${2}" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        -addext "basicConstraints=critical,CA:TRUE"
}

gen_padded() {
    # $1 = middle of the file names, $2 = CN, $3 = how many long SAN
    # entries to add. A padded certificate makes the server's handshake
    # flight larger: 70 entries is a 5.4 KB certificate, and a flight of
    # five 1200-byte datagrams. That is more than the server may send
    # for one ClientHello before the client's address is validated
    # (RFC 9000 section 8.1), which tests/e2e/handshake_loss.zig needs.
    # File names follow the pair that predates this function:
    # test_cert_${1}.pem + test_key_${1}_cert.pem.
    san="DNS:localhost,IP:127.0.0.1"
    i=1
    while [ "$i" -le "$3" ]; do
        san="${san},DNS:long-subject-alternative-name-number-${i}.handshake-flight-padding.test"
        i=$((i + 1))
    done
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "tests/data/test_key_${1}_cert.pem" -out "tests/data/test_cert_${1}.pem" \
        -days 36500 -nodes -subj "/CN=${2}" \
        -addext "subjectAltName=${san}" \
        -addext "basicConstraints=critical,CA:TRUE"
    chmod 644 "tests/data/test_key_${1}_cert.pem"
}

# gen test nullq-test   # the original pair; uncomment to regenerate
gen test_untrusted nullq-test-untrusted
# The padded pairs; uncomment to regenerate. `wide` (a flight of two
# datagrams) predates this function and has 24 entries.
# gen_padded huge nullq-test-huge-certificate 70

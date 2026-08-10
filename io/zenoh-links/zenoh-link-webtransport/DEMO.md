# WebTransport link — end-to-end demo

This walks through running `zenohd` with a `webtransport/...` listener and
exchanging data between `z_pub` and `z_sub` over it, using the
`zenoh-link-webtransport` crate (feature `transport_webtransport`).

## 1. Generate demo certificates

The WebTransport/QUIC listener needs a TLS certificate + private key. For
browser interop the certificate must be either WebPKI-valid or usable with
`serverCertificateHashes` — which requires an ECDSA P-256 key with a validity
period of 14 days or less. The commands below produce exactly that shape, and
additionally mark the certificate as an end-entity leaf cert (not a CA), which
rustls' WebPKI verifier requires — a plain self-signed `openssl req -x509`
certificate defaults to `CA:TRUE` and will be rejected with
`invalid peer certificate: CaUsedAsEndEntity`.

```bash
mkdir -p ~/dojang/zenoh/.demo-certs && cd ~/dojang/zenoh/.demo-certs

openssl ecparam -name prime256v1 -genkey -noout -out key.pem

openssl req -new -x509 -key key.pem -out cert.pem -days 13 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth"
```

`.demo-certs/` is gitignored — never commit generated certs/keys.

## 2. Build

```bash
cargo build -p zenohd -F transport_webtransport
cargo build -p zenoh-examples -F transport_webtransport --example z_sub --example z_pub
```

Binaries land at `target/debug/zenohd`, `target/debug/examples/z_sub`,
`target/debug/examples/z_pub`.

## 3. Run the demo

Three terminals (or backgrounded processes), from the repo root.

**Router** — note the endpoint-config keys are `listen_certificate_file` and
`listen_private_key_file` (the `_file` suffix is required; there is no bare
`listen_certificate`/`listen_private_key` config key):

```bash
./target/debug/zenohd -l 'webtransport/127.0.0.1:7447#listen_certificate_file=.demo-certs/cert.pem;listen_private_key_file=.demo-certs/key.pem'
```

Expected log line confirming the listener is up:

```
INFO ... zenoh::net::runtime::orchestrator: Zenoh can be reached at: webtransport/127.0.0.1:7447
```

**Subscriber** — likewise the client-side key is `root_ca_certificate_file`:

```bash
./target/debug/examples/z_sub -m client \
  -e 'webtransport/localhost:7447#root_ca_certificate_file=.demo-certs/cert.pem'
```

**Publisher:**

```bash
./target/debug/examples/z_pub -m client \
  -e 'webtransport/localhost:7447#root_ca_certificate_file=.demo-certs/cert.pem'
```

### Expected output

`z_pub` prints:

```
Putting Data ('demo/example/zenoh-rs-pub': '[   0] Pub from Rust!')...
Putting Data ('demo/example/zenoh-rs-pub': '[   1] Pub from Rust!')...
```

`z_sub` prints matching receives, confirming end-to-end delivery over the
WebTransport link:

```
>> [Subscriber] Received PUT ('demo/example/zenoh-rs-pub': '[   0] Pub from Rust!')
>> [Subscriber] Received PUT ('demo/example/zenoh-rs-pub': '[   1] Pub from Rust!')
```

### Fallback: config file instead of URI fragment

If the `#key=value;...` endpoint-config-in-URI syntax fights your shell's
quoting, set the same paths in a JSON5 config file instead and pass a plain
endpoint:

```json5
// demo-router.json5
{
  listen: { endpoints: ["webtransport/127.0.0.1:7447"] },
  transport: {
    link: {
      tls: {
        listen_certificate: ".demo-certs/cert.pem",
        listen_private_key: ".demo-certs/key.pem",
      },
    },
  },
}
```

```bash
./target/debug/zenohd -c demo-router.json5
```

(and correspondingly `root_ca_certificate` under `transport.link.tls` in a
client-side config file, with `-l 'webtransport/127.0.0.1:7447'`).

## 4. Browser certificate note

A real browser `WebTransport` client requires one of:

- A certificate chaining to a WebPKI-trusted root (e.g. issued by a public CA,
  or via a locally-trusted dev CA such as `mkcert`), **or**
- `serverCertificateHashes` pinning, which the browser only accepts for
  certificates that are: ECDSA (P-256 recommended), have a validity period of
  **14 days or less**, and are **not older than 14 days** at connection time.

The cert-generation recipe in step 1 (ECDSA P-256, 13-day validity, end-entity
`basicConstraints=CA:FALSE`) satisfies the `serverCertificateHashes` path: a
browser client can connect via
`new WebTransport(url, { serverCertificateHashes: [{ algorithm: "sha-256", value: <sha256 of cert.pem's DER> }] })`.
It does not chain to a public root, so it will not satisfy the plain WebPKI
path without also importing it as a locally-trusted CA.

## 5. Cleanup

Kill the three processes (`zenohd`, `z_sub`, `z_pub`) when done; no persistent
state is left behind by the demo other than the log output.

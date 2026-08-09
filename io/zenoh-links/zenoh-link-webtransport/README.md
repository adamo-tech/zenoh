# zenoh-link-webtransport

Native Zenoh unicast link over a WebTransport session. The initial implementation
uses the first bidirectional WebTransport stream as a reliable byte stream and
carries the standard Zenoh transport wire format without an application relay
protocol.

Listener endpoints require `listen_certificate_file` and
`listen_private_key_file` endpoint configuration entries. Client endpoints use
the platform trust store by default, or `server_certificate_hash` for a pinned
short-lived WebTransport certificate.

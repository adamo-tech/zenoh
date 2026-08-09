# zenoh-link-webtransport

Native Zenoh unicast link over a WebTransport session. The initial implementation
uses the first bidirectional WebTransport stream as a reliable byte stream and
carries the standard Zenoh transport wire format without an application relay
protocol.

Listener endpoints require `listen_certificate_file` and
`listen_private_key_file` endpoint configuration entries. Client endpoints use
the platform trust store by default, or `server_certificate_hash` for a pinned
short-lived WebTransport certificate.

Listeners can authenticate ES256 bearer tokens during the HTTP/3 handshake by
setting both `jwt_public_key_file` and `jwt_audience`. The token is supplied in
the request query as `token`; it is not a Zenoh protocol field. Its OAuth-style
`scope` claim contains space-delimited grants shaped as
`zenoh:<action>:<key-expression>`, where action is an ACL message name or `*`.
The router enforces those authenticated grants in both ingress and egress even
when its configured ACL policy is otherwise disabled. Invalid or empty grants
fail closed.

Embedded listeners whose NAT mapping was discovered before the Zenoh session
opens can call `register_prebound_server_socket`. The next listener created on
that socket's local address takes ownership of the exact UDP socket, preserving
STUN and port-mapping state.

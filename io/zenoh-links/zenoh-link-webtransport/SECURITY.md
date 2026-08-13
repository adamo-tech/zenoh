# Native WebTransport security contract

The browser API cannot provide a TLS client certificate. This link therefore
authenticates the HTTP/3 CONNECT with a short-lived ES256 ticket before it
accepts the Zenoh byte stream.

The listener fails closed unless every authentication setting is present. A
ticket must have a valid signature and exact issuer, audience, and browser
origin. It must also contain `sub`, `org`, `iat`, `exp`, and `jti`. The `org`
claim is restricted to a DNS-label-shaped slug and becomes the link identity;
normal Zenoh default-deny ACL policy remains the sole source of permissions.
Tickets do not contain authorization rules.

Each `jti` is accepted once per relay process. A relay restart clears this
bounded in-memory replay cache, so production ticket lifetimes must remain
short and callers must not persist tickets. Failed stream establishment still
consumes the ticket.

The token is transported only in the encrypted CONNECT query because browser
WebTransport cannot set request headers. Implementations must never log the
request path or token.


# Signed Interaction Gateway Demo

An edge Worker that verifies timestamped Ed25519 requests before parsing a small interaction payload. A signed ping receives a pong; a signed lookup receives synthetic context for documentation IP addresses.

## Run

Run `node --test` with Node.js 18 or newer. To preview the Worker locally, install Wrangler and run `wrangler dev`. Supply a test Ed25519 public key as `PUBLIC_KEY_HEX` through local secret configuration. Never place a production key or account identifier in this repository.

The client signs the exact UTF-8 string `<unix-seconds>.<raw-json-body>` and sends the lowercase hex signature in `x-demo-signature` and the timestamp in `x-demo-timestamp`. The timestamp must be within five minutes. Supported interactions are `{"type":"ping"}` and `{"type":"lookup","query":"192.0.2.10"}`.

## Safety boundary

There is no external lookup, application registration, messaging, account binding, or production route. Requests have no side effects, so a repeated valid request only repeats the same sample response. A real integration would need persistent replay control and abuse protection before it could perform actions. The default public Worker subdomain is disabled.

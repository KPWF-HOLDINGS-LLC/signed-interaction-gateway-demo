import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import worker from "../src/index.js";

globalThis.crypto = webcrypto;
const target = "https://example.invalid/interaction";
const hex = bytes => Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, "0")).join("");
const keyPair = await webcrypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
const publicKey = hex(await webcrypto.subtle.exportKey("raw", keyPair.publicKey));

async function signedRequest(body, timestamp = String(Math.floor(Date.now() / 1000))) {
  const signature = await webcrypto.subtle.sign("Ed25519", keyPair.privateKey, new TextEncoder().encode(`${timestamp}.${body}`));
  return new Request(target, { method: "POST", headers: {
    "content-type": "application/json", "x-demo-timestamp": timestamp, "x-demo-signature": hex(signature)
  }, body });
}

test("missing public key fails closed", async () => {
  assert.equal((await worker.fetch(new Request(target, { method: "POST" }), {})).status, 503);
});

test("valid signed ping and lookup return synthetic data", async () => {
  const ping = await worker.fetch(await signedRequest('{"type":"ping"}'), { PUBLIC_KEY_HEX: publicKey });
  assert.deepEqual(await ping.json(), { type: "pong" });
  const lookup = await worker.fetch(await signedRequest('{"type":"lookup","query":"192.0.2.10"}'), { PUBLIC_KEY_HEX: publicKey });
  assert.equal((await lookup.json()).context.network, "Documentation network A");
});

test("rejects stale, invalid, and altered requests", async () => {
  const stale = await worker.fetch(await signedRequest('{"type":"ping"}', "1000000000"), { PUBLIC_KEY_HEX: publicKey });
  assert.equal(stale.status, 401);
  const altered = await signedRequest('{"type":"ping"}');
  altered.headers.set("x-demo-signature", "0".repeat(128));
  assert.equal((await worker.fetch(altered, { PUBLIC_KEY_HEX: publicKey })).status, 401);
  const bad = await worker.fetch(await signedRequest('{"type":"lookup","query":"not-an-ip"}'), { PUBLIC_KEY_HEX: publicKey });
  assert.equal(bad.status, 400);
});

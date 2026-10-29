const MAX_BODY_BYTES = 4096;
const WINDOW_SECONDS = 300;
const FIXTURES = Object.freeze({
  "192.0.2.10": { network: "Documentation network A", country: "ZZ" },
  "2001:db8::10": { network: "Documentation IPv6 network", country: "ZZ" }
});

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
}

function fromHex(value, expectedLength) {
  if (typeof value !== "string" || value.length !== expectedLength * 2 || !/^[0-9a-f]+$/i.test(value)) return null;
  return Uint8Array.from(value.match(/.{2}/g), part => parseInt(part, 16));
}

async function readSmallBody(request) {
  const reader = request.body?.getReader();
  if (!reader) return { error: "body_required", status: 400 };
  let length = 0;
  const parts = [];
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_BODY_BYTES) {
        await reader.cancel();
        return { error: "body_too_large", status: 413 };
      }
      parts.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.byteLength; }
  try { return { text: new TextDecoder("utf-8", { fatal: true }).decode(bytes) }; }
  catch { return { error: "invalid_encoding", status: 400 }; }
}

export function isValidIp(value) {
  if (typeof value !== "string" || value.length > 45 || value !== value.trim()) return false;
  if (value.includes(":")) {
    if (!/^[0-9a-fA-F:]+$/.test(value) || value.includes(":::")) return false;
    const parts = value.split("::");
    if (parts.length > 2) return false;
    const groups = parts.flatMap(part => part ? part.split(":") : []);
    if (groups.some(group => !/^[0-9a-fA-F]{1,4}$/.test(group))) return false;
    return parts.length === 2 ? groups.length < 8 : groups.length === 8;
  }
  const parts = value.split(".");
  return parts.length === 4 && parts.every(part => /^(0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255);
}

export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (request.method === "GET" && path === "/health") return json({ ok: true });
    if (path !== "/interaction") return json({ error: "not_found" }, 404);
    if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);

    const publicKeyBytes = fromHex(env?.PUBLIC_KEY_HEX, 32);
    if (!publicKeyBytes) return json({ error: "unavailable" }, 503);
    const timestamp = request.headers.get("x-demo-timestamp");
    const signature = fromHex(request.headers.get("x-demo-signature"), 64);
    if (!/^\d{10}$/.test(timestamp || "") || !signature || Math.abs(Date.now() / 1000 - Number(timestamp)) > WINDOW_SECONDS) {
      return json({ error: "unauthorized" }, 401);
    }
    if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) return json({ error: "content_type_required" }, 415);
    const body = await readSmallBody(request);
    if (body.error) return json({ error: body.error }, body.status);

    let verified = false;
    try {
      const publicKey = await crypto.subtle.importKey("raw", publicKeyBytes, "Ed25519", false, ["verify"]);
      verified = await crypto.subtle.verify("Ed25519", publicKey, signature, new TextEncoder().encode(`${timestamp}.${body.text}`));
    } catch { return json({ error: "unavailable" }, 503); }
    if (!verified) return json({ error: "unauthorized" }, 401);

    let interaction;
    try { interaction = JSON.parse(body.text); } catch { return json({ error: "invalid_json" }, 400); }
    if (!interaction || typeof interaction !== "object" || Array.isArray(interaction)) return json({ error: "invalid_interaction" }, 400);
    if (interaction.type === "ping") return json({ type: "pong" });
    if (interaction.type !== "lookup" || !isValidIp(interaction.query)) return json({ error: "invalid_interaction" }, 400);

    return json({ type: "result", address: interaction.query, context: FIXTURES[interaction.query] || null, source: "synthetic_documentation_fixtures" });
  }
};

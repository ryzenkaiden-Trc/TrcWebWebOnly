const PLANS = {
  free:     { life: 3 * 3600,  cooldown: 24 * 3600, license: false, minWait: 20 },
  standard: { life: 10 * 3600, cooldown: 5 * 3600,  license: true,  minWait: 0 },
};

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const enc = new TextEncoder();

function rand(n) {
  let out = "";
  while (out.length < n) {
    const buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    for (const b of buf) {
      if (b < 248 && out.length < n) out += ALPHABET[b % 62];
    }
  }
  return out;
}
const newKey = () => "TRCKEY_" + rand(24);
const newCode = () => "TRCPASS_" + rand(16);

const corsHeaders = (env) => ({
  "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN || "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Vary": "Origin",
});
const json = (env, data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...corsHeaders(env) },
  });

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function makeToken(env, plan) {
  const body = btoa(JSON.stringify({ p: plan, t: Date.now(), n: rand(8) }));
  return body + "." + (await hmac(env.SESSION_SECRET, body));
}
async function readToken(env, token) {
  if (typeof token !== "string" || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  if (!safeEqual(sig, await hmac(env.SESSION_SECRET, body))) return null;
  try { return JSON.parse(atob(body)); } catch { return null; }
}

const kvGet = async (env, k) => {
  const v = await env.KEYS.get(k);
  return v ? JSON.parse(v) : null;
};

async function saveKey(env, key, rec) {
  const opts = {
    metadata: {
      plan: rec.plan, created: rec.created, expires: rec.expires,
      bound: !!rec.hwid, revoked: !!rec.revoked, note: rec.note || "", discord: rec.discord || "",
    },
  };
  if (rec.expires) opts.expirationTtl = Math.max(60, Math.ceil((rec.expires - Date.now()) / 1000) + 300);
  await env.KEYS.put("key:" + key, JSON.stringify(rec), opts);
}

function badReason(rec) {
  if (!rec) return "Key not found or expired.";
  if (rec.revoked) return "This key was revoked.";
  if (rec.expires && Date.now() > rec.expires) return "This key has expired.";
  return null;
}

async function setRole(env, discordId, grant) {
  if (!/^\d{15,22}$/.test(String(discordId || ""))) return false;
  if (!env.DISCORD_BOT_TOKEN || !env.DISCORD_GUILD_ID || !env.PREMIUM_ROLE_ID) return false;
  const r = await fetch(
    `https://discord.com/api/v10/guilds/${env.DISCORD_GUILD_ID}/members/${discordId}/roles/${env.PREMIUM_ROLE_ID}`,
    { method: grant ? "PUT" : "DELETE", headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` } }
  );
  return r.status === 204;
}

async function generate(env, req) {
  const { plan, token, license } = await req.json().catch(() => ({}));
  const P = PLANS[plan];
  if (!P) return json(env, { error: "Unknown plan." }, 400);

  const now = Date.now();
  let owner;
  if (P.license) {
    const code = String(license || "").trim();
    const lic = code ? await kvGet(env, "lic:" + code) : null;
    if (!lic || lic.plan !== plan) return json(env, { error: "Invalid access code." }, 403);
    if (lic.revoked) return json(env, { error: "This access code was revoked." }, 403);
    if (lic.expires && now > lic.expires) return json(env, { error: "This access code has expired." }, 403);
    owner = "lic:" + code;
  } else {
    const t = await readToken(env, token);
    if (!t || t.p !== plan) return json(env, { error: "Session expired. Refresh the page." }, 400);
    const age = (now - t.t) / 1000;
    if (age > 1800) return json(env, { error: "Session expired. Refresh the page." }, 400);
    if (age < P.minWait) return json(env, { error: "Finish the checkpoints first.", wait: Math.ceil(P.minWait - age) }, 429);
    owner = "ip:" + (req.headers.get("CF-Connecting-IP") || "unknown");
  }

  const cdKey = `cd:${plan}:${owner}`;
  const lastKey = `last:${plan}:${owner}`;
  const cd = await kvGet(env, cdKey);
  if (cd && now < cd.until) {
    const cur = await kvGet(env, "key:" + cd.key);
    const alive = cur && !badReason(cur);
    return json(env, {
      error: "cooldown", retryAt: cd.until,
      key: alive ? cd.key : null, expires: alive ? cur.expires : null, plan,
    }, 429);
  }

  const prev = await env.KEYS.get(lastKey);
  if (prev) await env.KEYS.delete("key:" + prev);

  const key = newKey();
  const expires = now + P.life * 1000;
  await saveKey(env, key, { plan, created: now, expires, owner, hwid: null });
  await env.KEYS.put(lastKey, key, { expirationTtl: P.life + 300 });
  await env.KEYS.put(cdKey, JSON.stringify({ until: now + P.cooldown * 1000, key }), { expirationTtl: Math.max(60, P.cooldown) });

  return json(env, { ok: true, key, plan, expires, resetAt: now + P.cooldown * 1000 });
}

async function status(env, req) {
  const { key } = await req.json().catch(() => ({}));
  const rec = await kvGet(env, "key:" + String(key || "").trim());
  const reason = badReason(rec);
  if (reason) return json(env, { valid: false, reason });
  return json(env, { valid: true, plan: rec.plan, expires: rec.expires, bound: !!rec.hwid });
}

async function verify(env, url) {
  const key = String(url.searchParams.get("key") || "").trim();
  const hwid = String(url.searchParams.get("hwid") || "").trim();
  if (!hwid) return json(env, { valid: false, reason: "Missing device id." });
  const rec = await kvGet(env, "key:" + key);
  const reason = badReason(rec);
  if (reason) return json(env, { valid: false, reason });
  if (!rec.hwid) {
    rec.hwid = hwid;
    await saveKey(env, key, rec);
  } else if (rec.hwid !== hwid) {
    return json(env, { valid: false, reason: "This key is bound to another device." });
  }
  return json(env, { valid: true, plan: rec.plan, expires: rec.expires });
}

async function admin(env, req, url) {
  const auth = req.headers.get("Authorization") || "";
  if (!env.ADMIN_TOKEN || !safeEqual(auth, "Bearer " + env.ADMIN_TOKEN)) return json(env, { error: "Unauthorized." }, 401);
  const action = url.pathname.replace("/api/admin/", "");
  const body = req.method === "POST" ? await req.json().catch(() => ({})) : {};
  const now = Date.now();

  if (action === "premium") {
    const key = newKey();
    const rec = { plan: "premium", created: now, expires: null, owner: "admin", hwid: null,
      discord: String(body.discord || ""), note: String(body.note || "") };
    await saveKey(env, key, rec);
    const role = await setRole(env, rec.discord, true);
    return json(env, { ok: true, key, role });
  }

  if (action === "license") {
    const days = Number(body.days) > 0 ? Number(body.days) : null;
    const code = newCode();
    const rec = { plan: "standard", created: now, expires: days ? now + days * 86400000 : null, note: String(body.note || "") };
    const opts = { metadata: { plan: rec.plan, created: rec.created, expires: rec.expires, note: rec.note, revoked: false } };
    if (days) opts.expirationTtl = Math.ceil(days * 86400) + 300;
    await env.KEYS.put("lic:" + code, JSON.stringify(rec), opts);
    return json(env, { ok: true, code, expires: rec.expires });
  }

  if (action === "revoke") {
    const id = String(body.id || "").trim();
    if (id.startsWith("TRCKEY_")) {
      const rec = await kvGet(env, "key:" + id);
      if (!rec) return json(env, { error: "Key not found." }, 404);
      rec.revoked = true;
      await saveKey(env, id, rec);
      if (rec.plan === "premium" && rec.discord) await setRole(env, rec.discord, false);
      return json(env, { ok: true });
    }
    if (id.startsWith("TRCPASS_")) {
      const rec = await kvGet(env, "lic:" + id);
      if (!rec) return json(env, { error: "Access code not found." }, 404);
      rec.revoked = true;
      const opts = { metadata: { plan: rec.plan, created: rec.created, expires: rec.expires, note: rec.note || "", revoked: true } };
      if (rec.expires) opts.expirationTtl = Math.max(60, Math.ceil((rec.expires - now) / 1000) + 300);
      await env.KEYS.put("lic:" + id, JSON.stringify(rec), opts);
      return json(env, { ok: true });
    }
    return json(env, { error: "Paste a TRCKEY_ key or a TRCPASS_ code." }, 400);
  }

  if (action === "resethwid") {
    const id = String(body.id || "").trim();
    const rec = await kvGet(env, "key:" + id);
    if (!rec) return json(env, { error: "Key not found." }, 404);
    rec.hwid = null;
    await saveKey(env, id, rec);
    return json(env, { ok: true });
  }

  if (action === "list") {
    const type = url.searchParams.get("type") === "lic" ? "lic:" : "key:";
    const l = await env.KEYS.list({ prefix: type, limit: 1000 });
    return json(env, { items: l.keys.map((k) => ({ id: k.name.slice(4), ...(k.metadata || {}) })) });
  }

  return json(env, { error: "Unknown action." }, 404);
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(env) });
    const url = new URL(req.url);
    try {
      if (url.pathname === "/api/session" && req.method === "POST") {
        const { plan } = await req.json().catch(() => ({}));
        const P = PLANS[plan];
        if (!P || P.license) return json(env, { error: "Unknown plan." }, 400);
        return json(env, { token: await makeToken(env, plan), minWait: P.minWait });
      }
      if (url.pathname === "/api/generate" && req.method === "POST") return await generate(env, req);
      if (url.pathname === "/api/status" && req.method === "POST") return await status(env, req);
      if (url.pathname === "/api/verify" && req.method === "GET") return await verify(env, url);
      if (url.pathname.startsWith("/api/admin/")) return await admin(env, req, url);
      return json(env, { error: "Not found." }, 404);
    } catch (e) {
      return json(env, { error: "Server error." }, 500);
    }
  },
};

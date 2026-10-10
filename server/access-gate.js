const crypto = require("node:crypto");


const parseCookies = (header) => {
  const raw = typeof header === "string" ? header : "";
  if (!raw.trim()) return {};
  const out = {};
  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!key) continue;
    out[key] = value;
  }
  return out;
};

/** Constant-time string comparison to prevent timing attacks. */
const safeCompare = (a, b) => {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) {
    // Compare against self to burn constant time, then return false
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
};

/** Simple in-memory rate limiter for auth attempts. */
const createRateLimiter = (maxAttempts = 10, windowMs = 60_000) => {
  const attempts = new Map();
  const cleanup = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of attempts) {
      if (now - entry.start > windowMs) attempts.delete(key);
    }
  }, windowMs);
  cleanup.unref();

  return {
    isLimited(ip) {
      const entry = attempts.get(ip);
      if (!entry) return false;
      return entry.count >= maxAttempts;
    },
    recordFailure(ip) {
      const now = Date.now();
      const entry = attempts.get(ip);
      if (!entry || now - entry.start > windowMs) {
        attempts.set(ip, { count: 1, start: now });
        return;
      }
      entry.count++;
    },
    reset(ip) {
      attempts.delete(ip);
    },
  };
};

/**
 * Resolve client IP for rate limiting.
 * When TRUSTED_PROXY=1 is set, the first value of X-Forwarded-For is used.
 * Only set TRUSTED_PROXY=1 when this server sits behind a reverse proxy that
 * you control (nginx, Caddy, Vercel edge). Without it, X-Forwarded-For is
 * ignored to prevent spoofing by direct clients.
 */
const resolveClientIp = (req) => {
  if (process.env.TRUSTED_PROXY === "1") {
    const forwarded = req.headers?.["x-forwarded-for"];
    if (typeof forwarded === "string") {
      const first = forwarded.split(",")[0]?.trim();
      if (first) return first;
    }
  }
  return req.socket?.remoteAddress || "unknown";
};


const LOGIN_PATH = "/studio-login";
const COOKIE_MAX_AGE_S = 365 * 24 * 60 * 60;

const escapeHtml = (value) =>
  String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

/** Only same-origin relative paths are allowed as post-login destinations. */
const safeNext = (value) => {
  const v = String(value || "/");
  if (!v.startsWith("/") || v.startsWith("//") || v.startsWith(LOGIN_PATH)) return "/";
  return v;
};

const isHttpsRequest = (req) => {
  if (req.socket?.encrypted) return true;
  const proto = req.headers?.["x-forwarded-proto"];
  return typeof proto === "string" && proto.split(",")[0].trim() === "https";
};

const renderLoginPage = (next, error) => `<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hermes3D - acesso</title>
<style>
  :root{color-scheme:light dark}
  body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6}
  form{width:min(320px,calc(100vw - 32px));display:grid;gap:12px;padding:24px;border:1px solid #2a2f3a;border-radius:12px;background:#161a21}
  h1{margin:0 0 4px;font-size:18px;font-weight:500}
  label{font-size:14px;color:#a9b0bc}
  input{padding:10px 12px;border-radius:8px;border:1px solid #2a2f3a;background:#0f1115;color:inherit;font-size:16px}
  input:focus{outline:2px solid #5b8def;outline-offset:1px}
  button{padding:10px 12px;border:0;border-radius:8px;background:#5b8def;color:#fff;font-size:15px;cursor:pointer}
  .err{margin:0;color:#ff7b72;font-size:14px}
</style></head><body>
<form method="post" action="${LOGIN_PATH}">
  <h1>Hermes3D</h1>
  <label for="token">Senha de acesso</label>
  <input id="token" name="token" type="password" autocomplete="current-password" required autofocus>
  <input type="hidden" name="next" value="${escapeHtml(next)}">
  ${error ? `<p class="err" role="alert">${escapeHtml(error)}</p>` : ""}
  <button type="submit">Entrar</button>
</form></body></html>`;

const readFormBody = (req, limitBytes = 4096) =>
  new Promise((resolve) => {
    let body = "";
    let tooBig = false;
    req.on("data", (chunk) => {
      if (tooBig) return;
      body += chunk;
      if (body.length > limitBytes) tooBig = true;
    });
    req.on("end", () => resolve(tooBig ? new URLSearchParams() : new URLSearchParams(body)));
    req.on("error", () => resolve(new URLSearchParams()));
  });

function createAccessGate(options) {
  const token = String(options?.token ?? "").trim();
  const cookieName = String(options?.cookieName ?? "studio_access").trim() || "studio_access";

  const enabled = Boolean(token);
  const rateLimiter = createRateLimiter(10, 60_000);

  const getAuthState = (req) => {
    if (!enabled) return { authorized: true, limited: false };
    const ip = resolveClientIp(req);
    const cookieHeader = req.headers?.cookie;
    const cookies = parseCookies(cookieHeader);
    const authorized = safeCompare(cookies[cookieName] || "", token);
    if (authorized) {
      rateLimiter.reset(ip);
      return { authorized: true, limited: false };
    }
    if (rateLimiter.isLimited(ip)) {
      return { authorized: false, limited: true };
    }
    if (!cookies[cookieName]) return { authorized: false, limited: false };
    rateLimiter.recordFailure(ip);
    return { authorized: false, limited: rateLimiter.isLimited(ip) };
  };

  const sendLogin = (res, statusCode, next, error) => {
    res.statusCode = statusCode;
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.end(renderLoginPage(next, error));
  };

  const handleLogin = (req, res, url) => {
    if (req.method === "GET") {
      sendLogin(res, 200, safeNext(url.searchParams.get("next")), "");
      return true;
    }
    if (req.method !== "POST") {
      res.statusCode = 405;
      res.setHeader("Allow", "GET, POST");
      res.end();
      return true;
    }
    const ip = resolveClientIp(req);
    readFormBody(req).then((form) => {
      const next = safeNext(form.get("next"));
      if (rateLimiter.isLimited(ip)) {
        sendLogin(res, 429, next, "Muitas tentativas. Espere um minuto e tente de novo.");
        return;
      }
      if (!safeCompare(String(form.get("token") || ""), token)) {
        rateLimiter.recordFailure(ip);
        sendLogin(res, 401, next, "Senha incorreta.");
        return;
      }
      rateLimiter.reset(ip);
      const cookie = [
        `${cookieName}=${token}`,
        "Path=/",
        `Max-Age=${COOKIE_MAX_AGE_S}`,
        "HttpOnly",
        "SameSite=Lax",
        ...(isHttpsRequest(req) ? ["Secure"] : []),
      ].join("; ");
      res.statusCode = 303;
      res.setHeader("Set-Cookie", cookie);
      res.setHeader("Location", next);
      res.end();
    });
    return true;
  };

  const handleHttp = (req, res) => {
    if (!enabled) return false;
    const url = new URL(req.url || "/", "http://localhost");
    if (url.pathname === LOGIN_PATH) return handleLogin(req, res, url);
    const auth = getAuthState(req);
    if (!auth.authorized) {
      const statusCode = auth.limited ? 429 : 401;
      if (url.pathname.startsWith("/api/")) {
        res.statusCode = statusCode;
        res.setHeader("Content-Type", "application/json");
        res.end(
          JSON.stringify({
            error: auth.limited
              ? "Too many failed studio access attempts. Wait a minute and retry."
              : "Studio access token required. Send the configured Studio access cookie and retry.",
          })
        );
      } else if (req.method === "GET" || req.method === "HEAD") {
        res.statusCode = 302;
        res.setHeader("Location", `${LOGIN_PATH}?next=${encodeURIComponent(safeNext(req.url))}`);
        res.end();
      } else {
        res.statusCode = statusCode;
        res.setHeader("Content-Type", "text/plain");
        res.end("Studio access required.");
      }
      return true;
    }
    return false;
  };

  const allowUpgrade = (req) => {
    if (!enabled) return true;
    return getAuthState(req).authorized;
  };

  return { enabled, handleHttp, allowUpgrade };
}

module.exports = { createAccessGate };

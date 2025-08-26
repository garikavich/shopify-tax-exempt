import crypto from "crypto";
import jwt from "jsonwebtoken";

const SHOP        = process.env.SHOPIFY_SHOP;               // webgoapp.myshopify.com
const TOKEN       = process.env.SHOPIFY_ADMIN_TOKEN;
const VERSION     = process.env.SHOPIFY_API_VERSION || "2025-07";
const APP_SECRET  = process.env.SHOPIFY_API_SECRET;
const DISABLE_SIG = process.env.DISABLE_PROXY_SIGNATURE === "1";

// ── HMAC проверки App Proxy (каждая пара отдельно, sort, join(""))
function verifyProxySignature(reqUrl) {
  if (DISABLE_SIG) return true;

  const q = reqUrl.split("?")[1] || "";
  const pairs = [];
  let sentSig = "";

  for (const part of q.split("&").filter(Boolean)) {
    const [rawK, rawV = ""] = part.split("=");
    if (rawK === "signature") { sentSig = rawV; continue; }
    const k = decodeURIComponent(rawK);
    const v = decodeURIComponent(rawV);
    pairs.push(`${k}=${v}`);
  }

  const stringToSign = pairs.sort().join(""); // без разделителей
  const expected = crypto.createHmac("sha256", APP_SECRET).update(stringToSign).digest("hex");

  // Можно оставить лог на время отладки
  // console.log({ stringToSign, expected, sentSig, match: expected === sentSig });

  return sentSig && sentSig === expected;
}

// ── JWT из Checkout UI Extensions (useSessionToken) → sub = gid://shopify/Customer/<id>
function verifySessionToken(req) {
  const auth = req.headers.authorization || "";
  const m = auth.match(/^Bearer (.+)$/);
  if (!m) return null;
  try {
    return jwt.verify(m[1], APP_SECRET, { algorithms: ["HS256"] });
  } catch {
    return null;
  }
}

async function adminGraphql(query, variables) {
  const res = await fetch(`https://${SHOP}/admin/api/${VERSION}/graphql.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": TOKEN,
    },
    body: JSON.stringify({ query, variables }),
  });
  return res.json();
}

export default async function handler(req, res) {
  console.log("proxy hit:", req.method, req.url);

  // CORS для UI extensions (воркер, меняющийся origin)
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.status(204).end();

  // HMAC подпись App Proxy (обязательна)
  if (!verifyProxySignature(req.url)) {
    return res.status(401).json({ ok: false, message: "Bad signature" });
  }

  // Базовая гигиена: проверим shop и «свежесть» timestamp (±5 минут)
  const url = new URL(`https://${SHOP}${req.url}`);
  const shopParam = url.searchParams.get("shop");
  const ts = Number(url.searchParams.get("timestamp") || 0);
  const now = Math.floor(Date.now() / 1000);
  if (shopParam && shopParam !== SHOP) {
    return res.status(400).json({ ok: false, message: "Wrong shop" });
  }
  if (!ts || Math.abs(now - ts) > 300) {
    return res.status(400).json({ ok: false, message: "Stale request" });
  }

  // JWT от Checkout UI (гарантирует корректный customer в claims)
  const tok = verifySessionToken(req);
  // Пинг можно допустить и без токена (для отладки), но боевые вызовы — только с токеном
  const isPing = url.searchParams.get("ping") === "1";
  if (!tok && !isPing) {
    return res.status(401).json({ ok: false, message: "Bad session token" });
  }

  if (isPing) {
    // лёгкий healthcheck
    return res.json({ ok: true });
  }

  const customerId = tok?.sub; // gid://shopify/Customer/...
  if (!customerId?.startsWith?.("gid://shopify/Customer/")) {
    return res.status(400).json({ ok: false, message: "No customer in token" });
  }

  const enable = url.searchParams.get("enable") === "1";

  const q = enable
    ? `mutation($id:ID!){
         customerAddTaxExemptions(customerId:$id,
           taxExemptions:[EU_REVERSE_CHARGE_EXEMPTION_RULE]){ userErrors{message } }
       }`
    : `mutation($id:ID!){
         customerRemoveTaxExemptions(customerId:$id,
           taxExemptions:[EU_REVERSE_CHARGE_EXEMPTION_RULE]){ userErrors{message } }
       }`;

  const r = await adminGraphql(q, { id: customerId });
  const errs =
    r?.data?.customerAddTaxExemptions?.userErrors ||
    r?.data?.customerRemoveTaxExemptions?.userErrors || [];
  if (errs.length) return res.status(400).json({ ok: false, message: errs[0].message });

  return res.json({ ok: true });
}

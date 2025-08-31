import crypto from "crypto";
import jwt from "jsonwebtoken";

const SHOP        = process.env.SHOPIFY_SHOP;               // webgoapp.myshopify.com
const TOKEN       = process.env.SHOPIFY_ADMIN_TOKEN;
const VERSION     = process.env.SHOPIFY_API_VERSION || "2025-07";
const APP_SECRET  = process.env.SHOPIFY_API_SECRET;
const DISABLE_SIG = process.env.DISABLE_PROXY_SIGNATURE === "1";

// --- App Proxy HMAC (только если есть signature в query)
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
  return sentSig && sentSig === expected;
}

// --- JWT из Checkout UI (Authorization: Bearer <token>)
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
  // CORS для UI extensions
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.status(204).end();

  const url = new URL(req.url, "https://dummy.local"); // только чтобы распарсить query локально
  const hasSignature = url.searchParams.has("signature");
  const isPing = url.searchParams.get("ping") === "1";

  // Режим 1: App Proxy (есть signature)
  if (hasSignature) {
    if (!verifyProxySignature(req.url)) {
      return res.status(401).json({ ok:false, message:"Bad signature" });
    }
    if (isPing) return res.json({ ok:true }); // пинг прокси
    // в прокси-режиме customerId может приходить в query (но лучше не использовать его для чувствительных операций)
    const customerId = url.searchParams.get("customerId");
    if (!customerId) return res.status(400).json({ ok:false, message:"customerId required" });

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
    if (errs.length) return res.status(400).json({ ok:false, message: errs[0].message });

    return res.json({ ok:true });
  }

  // Режим 2: Прямой вызов из Checkout UI (JWT)
  const tok = verifySessionToken(req);
  if (!tok) {
    // ping можно разрешить и без токена для простого «живой/неживой» (по желанию)
    if (isPing) return res.json({ ok:true });
    return res.status(401).json({ ok:false, message:"Bad session token" });
  }

  if (isPing) return res.json({ ok:true });

  // customerId берём только из токена!
  const customerId = tok?.sub; // gid://shopify/Customer/...
  if (!customerId?.startsWith?.("gid://shopify/Customer/")) {
    return res.status(400).json({ ok:false, message:"No customer in token" });
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
  if (errs.length) return res.status(400).json({ ok:false, message: errs[0].message });

  return res.json({ ok:true });
}

import crypto from "crypto";
import jwt from "jsonwebtoken";

const SHOP        = process.env.SHOPIFY_SHOP;               // webgoapp.myshopify.com
const TOKEN       = process.env.SHOPIFY_ADMIN_TOKEN;        // Admin API access token
const VERSION     = process.env.SHOPIFY_API_VERSION || "2025-07";
const APP_SECRET  = process.env.SHOPIFY_API_SECRET;
const DISABLE_SIG = process.env.DISABLE_PROXY_SIGNATURE === "1";

// --- Подпись App Proxy (fallback для ping через /apps/...)
function verifyProxySignature(reqUrl) {
  if (DISABLE_SIG) return true;

  const q = reqUrl.split("?")[1] || "";
  const parts = q.split("&").filter(Boolean);

  let sentSig = "";
  const pairs = [];
  for (const part of parts) {
    const [rawK, rawV = ""] = part.split("=");
    if (rawK === "signature") { sentSig = rawV; continue; }
    const k = decodeURIComponent(rawK);
    const v = decodeURIComponent(rawV);
    pairs.push(`${k}=${v}`);
  }
  const stringToSign = pairs.sort().join(""); // без разделителей
  const expected = crypto.createHmac("sha256", APP_SECRET).update(stringToSign).digest("hex");

  // Можно оставить лог на время отладки:
  // console.log({ stringToSign, expected, sentSig, match: expected === sentSig });

  return sentSig && sentSig === expected;
}

// --- JWT из Checkout UI Extensions (useSessionToken)
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
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.status(204).end();

  // 1) Путь с JWT (из Checkout UI) — основной
  const tok = verifySessionToken(req);
  if (tok) {
    const url = new URL(`https://${SHOP}${req.url}`);
    const enable = url.searchParams.get("enable") === "1";

    const customerId = tok?.sub; // gid://shopify/Customer/...
    if (!customerId?.startsWith?.("gid://shopify/Customer/")) {
      return res.status(400).json({ ok: false, message: "No customer in token" });
    }

    const q = `
  mutation($input: CustomerInput!) {
    customerUpdate(input: $input) {
      userErrors { field message }
      customer { id taxExempt }
    }
  }
`;

    const r = await adminGraphql(q, vars);
const vars = { input: { id: customerId, taxExempt: enable } };
   console.log('[customerUpdate]', {
  vars,
  data: r?.data,
  errors: r?.errors,
  userErrors: r?.data?.customerUpdate?.userErrors,
});

    console.log('customerUpdate RAW:', JSON.stringify(r, null, 2));


    if ((r?.data?.customerUpdate?.userErrors || []).length) {
  return res.status(400).json({ ok:false, message: r.data.customerUpdate.userErrors[0].message });
}

return res.json({ ok:true, taxExempt: r?.data?.customerUpdate?.customer?.taxExempt });
  }

  // 2) Fallback: ping через App Proxy (для отладки)
  if (!verifyProxySignature(req.url)) {
    return res.status(401).json({ ok:false, message:"Bad signature" });
  }
  const url = new URL(`https://${SHOP}${req.url}`);
  if (url.searchParams.get("ping") === "1") return res.json({ ok:true });

  return res.status(400).json({ ok:false, message:"Use Authorization: Bearer <token>" });
}

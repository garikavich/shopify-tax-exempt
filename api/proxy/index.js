import crypto from "crypto";

const SHOP = process.env.SHOPIFY_SHOP;
const TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const VERSION = process.env.SHOPIFY_API_VERSION || "2025-07";
const APP_SECRET = process.env.SHOPIFY_API_SECRET;
const DISABLE_SIG = process.env.DISABLE_PROXY_SIGNATURE === "1";

// Подпись App Proxy: HMAC-SHA256(secret, concat(sorted key=value[,value2]))
function verifyProxySignature(reqUrl) {
  if (DISABLE_SIG) return true;

  const qIndex = reqUrl.indexOf("?");
  const rawQuery = qIndex === -1 ? "" : reqUrl.slice(qIndex + 1);

  /** @type {Record<string,string[]>} */
  const kv = {};
  let sentSig = "";

  for (const part of rawQuery.split("&").filter(Boolean)) {
    const i = part.indexOf("=");
    const rawKey = i === -1 ? part : part.slice(0, i);
    const rawVal = i === -1 ? "" : part.slice(i + 1);

    if (rawKey === "signature") {
      sentSig = rawVal;
      continue;
    }
    const key = decodeURIComponent(rawKey);
    const val = decodeURIComponent(rawVal);
    (kv[key] ||= []).push(val);
  }

  const pieces = Object.keys(kv)
    .sort()
    .map((k) => `${k}=${kv[k].join(",")}`);

  const stringToSign = pieces.join(""); // без разделителей
  const expected = crypto.createHmac("sha256", APP_SECRET).update(stringToSign).digest("hex");

  // можно логнуть один раз для проверки:
  console.log({ stringToSign, expected, sentSig, match: expected === sentSig });

  return sentSig && expected === sentSig;
}

async function adminGraphql(query, variables) {
  const res = await fetch(`https://${SHOP}/admin/api/${VERSION}/graphql.json`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Shopify-Access-Token": TOKEN },
    body: JSON.stringify({ query, variables }),
  });
  return res.json();
}

export default async function handler(req, res) {
  console.log('proxy hit:', req.method, req.url);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  // healthcheck через App Proxy
  if (req.url.includes("ping=1")) {
    return verifyProxySignature(req.url)
      ? res.json({ ok: true })
      : res.status(401).json({ ok: false, message: "Bad signature" });
  }

  if (!verifyProxySignature(req.url)) {
    return res.status(401).json({ ok: false, message: "Bad signature" });
  }

  const url = new URL(`https://${SHOP}${req.url}`);
  const enable = url.searchParams.get("enable") === "1";
  const customerId = url.searchParams.get("customerId");
  if (!customerId) return res.status(400).json({ ok: false, message: "customerId required" });

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

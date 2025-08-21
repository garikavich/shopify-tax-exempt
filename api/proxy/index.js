import crypto from "crypto";

const SHOP = process.env.SHOPIFY_SHOP;
const TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const VERSION = process.env.SHOPIFY_API_VERSION || "2025-07";
const APP_SECRET = process.env.SHOPIFY_API_SECRET; // из Partner → API access
const DISABLE_SIG = process.env.DISABLE_PROXY_SIGNATURE === "1";

function verifyProxySignature(reqUrl) {
  if (DISABLE_SIG) return true;

  // reqUrl выглядит как: "/api/proxy?foo=1&signature=abc123&bar=2"
  const qIndex = reqUrl.indexOf("?");
  const rawQuery = qIndex === -1 ? "" : reqUrl.slice(qIndex + 1);

  // Сохраняем исходный порядок и кодировку параметров
  const parts = rawQuery.split("&").filter(Boolean);

  // забираем присланную Shopify подпись и убираем её из строки
  let sentSig = "";
  const filtered = [];
  for (const p of parts) {
    if (p.startsWith("signature=")) {
      sentSig = p.slice("signature=".length);
    } else {
      filtered.push(p);
    }
  }

  // исходный путь, который Shopify подписывает
  const stringToSign = "/apps/b2b-vat" + (filtered.length ? "?" + filtered.join("&") : "");
  const expected = crypto.createHmac("sha256", APP_SECRET).update(stringToSign).digest("hex");

  return sentSig && sentSig === expected;
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
  // ping для быстрой проверки маршрута/подписи
  if (req.url.includes("ping=1")) {
    if (!verifyProxySignature(req.url)) return res.status(401).json({ ok: false, message: "Bad signature" });
    return res.json({ ok: true });
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

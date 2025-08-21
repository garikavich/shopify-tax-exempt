import crypto from "crypto";

const SHOP = process.env.SHOPIFY_SHOP;
const TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const VERSION = process.env.SHOPIFY_API_VERSION || "2025-07";
const APP_SECRET = process.env.SHOPIFY_API_SECRET;
const DISABLE_SIG = process.env.DISABLE_PROXY_SIGNATURE === "1";

// HMAC по исходному shopify-пути '/apps/b2b-vat'
function verifyProxySignature(url) {
  if (DISABLE_SIG) return true;
  const u = new URL(url, `https://${SHOP}`);
  const signature = u.searchParams.get("signature");
  u.searchParams.delete("signature");
  const qs = u.searchParams.toString();
  const pathFromShopify = "/apps/b2b-vat" + (qs ? `?${qs}` : "");
  const expected = crypto.createHmac("sha256", APP_SECRET).update(pathFromShopify).digest("hex");
  return signature && signature === expected;
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
  // Сначала разберём URL один раз
  const url = new URL(`https://${SHOP}${req.url}`);

  // Лёгкий ping, чтобы проверить подпись/маршрут
  if (url.searchParams.get("ping") === "1") {
    if (!verifyProxySignature(req.url)) {
      return res.status(401).json({ ok: false, message: "Bad signature" });
    }
    return res.json({ ok: true });
  }

  // Все остальные запросы — только с валидной подписью
  if (!verifyProxySignature(req.url)) {
    return res.status(401).json({ ok: false, message: "Bad signature" });
  }

  const enable = url.searchParams.get("enable") === "1";
  const customerId = url.searchParams.get("customerId");
  if (!customerId) return res.status(400).json({ ok: false, message: "customerId required" });

  // Можно оставить exemptions, либо переключиться на общий флаг taxExempt:true/false
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

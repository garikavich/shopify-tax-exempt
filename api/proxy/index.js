import crypto from "crypto";

const SHOP = process.env.SHOPIFY_SHOP;
const TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const VERSION = process.env.SHOPIFY_API_VERSION || "2025-07";
const APP_SECRET = process.env.SHOPIFY_API_SECRET;
const DISABLE_SIG = process.env.DISABLE_PROXY_SIGNATURE === "1";

// --- NEW: строгая верификация по сырой строке
function verifyProxySignature(reqUrl) {
  if (DISABLE_SIG) return true;

  // reqUrl типа "/api/proxy?ping=1&signature=abc&foo=2" или "/api/proxy/?..."
  const qIndex = reqUrl.indexOf("?");
  const rawQuery = qIndex === -1 ? "" : reqUrl.slice(qIndex + 1);

  // вытащим присланную подпись и уберём её из query как есть (без декодирования/сортировки)
  let sentSig = "";
  const filteredParts = [];
  for (const part of rawQuery.split("&").filter(Boolean)) {
    if (part.startsWith("signature=")) {
      sentSig = part.slice("signature=".length);
    } else {
      filteredParts.push(part);
    }
  }
  const qsNoSig = filteredParts.join("&");

  // Shopify может вызывать как /apps/b2b-vat, так и /apps/b2b-vat/
  const candidates = [
    "/apps/b2b-vat" + (qsNoSig ? `?${qsNoSig}` : ""),
    "/apps/b2b-vat/" + (qsNoSig ? `?${qsNoSig}` : ""),
  ];

  const expectedMatches = candidates.some((s) => {
    const digest = crypto.createHmac("sha256", APP_SECRET).update(s).digest("hex");
    return sentSig && sentSig.toLowerCase() === digest;
  });
  console.log({ reqUrl, qsNoSig, candidates, sentSig });
  return expectedMatches;
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
  // разберём URL один раз
  const url = new URL(`https://${SHOP}${req.url}`);

  // ping — быстро проверяем подпись/маршрут
  if (url.searchParams.get("ping") === "1") {
    if (!verifyProxySignature(req.url)) {
      return res.status(401).json({ ok: false, message: "Bad signature" });
    }
    return res.json({ ok: true });
  }

  if (!verifyProxySignature(req.url)) {
    return res.status(401).json({ ok: false, message: "Bad signature" });
  }

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

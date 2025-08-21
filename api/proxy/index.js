import crypto from "crypto";

const SHOP = process.env.SHOPIFY_SHOP;
const TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const VERSION = process.env.SHOPIFY_API_VERSION || "2025-07";
const APP_SECRET = process.env.SHOPIFY_API_SECRET;
const DISABLE_SIG = process.env.DISABLE_PROXY_SIGNATURE === "1";

// --- verify signature: raw order + sorted-order fallback
function verifyProxySignature(reqUrl) {
  if (DISABLE_SIG) return true;

  const qIndex = reqUrl.indexOf("?");
  const rawQuery = qIndex === -1 ? "" : reqUrl.slice(qIndex + 1);

  let sentSig = "";
  let pathPrefixEnc = "";
  const keptParts = [];

  for (const part of rawQuery.split("&").filter(Boolean)) {
    if (part.startsWith("signature=")) {
      sentSig = part.slice("signature=".length);
    } else {
      keptParts.push(part);
      if (part.startsWith("path_prefix=")) {
        pathPrefixEnc = part.slice("path_prefix=".length);
      }
    }
  }

  const pathPrefix = decodeURIComponent(pathPrefixEnc || "/apps/b2b-vat");
  const withSlash = pathPrefix.endsWith("/") ? pathPrefix : pathPrefix + "/";

  // 1) как пришло
  const qsRaw = keptParts.join("&");
  // 2) отсортированный по ключам
  const qsSorted = keptParts
    .slice()
    .sort((a, b) => a.split("=")[0].localeCompare(b.split("=")[0]))
    .join("&");

  const candidates = [
    pathPrefix + (qsRaw ? `?${qsRaw}` : ""),
    withSlash   + (qsRaw ? `?${qsRaw}` : ""),
    pathPrefix + (qsSorted ? `?${qsSorted}` : ""),
    withSlash   + (qsSorted ? `?${qsSorted}` : ""),
  ];

  // Раскомментируй одну строку на время отладки:
  // console.log({ reqUrl, pathPrefix, qsRaw, qsSorted, sentSig, candidates });

  return candidates.some((s) => {
    const digest = crypto.createHmac("sha256", APP_SECRET).update(s).digest("hex");
    return sentSig && sentSig === digest;
  });
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
  const url = new URL(`https://${SHOP}${req.url}`);

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

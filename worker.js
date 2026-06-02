/**
 * Cloudflare Worker — R2 Multipart Upload Signer
 * 
 * SETUP:
 *  1. Crie um bucket R2 no dashboard do Cloudflare
 *  2. Em "R2 > Manage R2 API Tokens", crie um token com permissão de escrita
 *  3. No wrangler.toml, adicione as variáveis de ambiente (secrets):
 *       R2_ACCESS_KEY_ID
 *       R2_SECRET_ACCESS_KEY
 *       R2_BUCKET_NAME
 *       R2_ACCOUNT_ID
 *       ALLOWED_ORIGIN  (URL do seu app HTML, ex: https://meusite.com)
 *
 *  4. wrangler secret put R2_ACCESS_KEY_ID
 *     wrangler secret put R2_SECRET_ACCESS_KEY
 *     etc.
 *
 * ENDPOINTS:
 *  POST /init-multipart      → inicia upload, retorna uploadId
 *  POST /presign-part        → retorna URL assinada para uma parte
 *  POST /complete-multipart  → finaliza o upload
 *  DELETE /abort-multipart   → cancela o upload
 */

const PART_SIZE = 10 * 1024 * 1024; // 10MB (mínimo aceito pelo R2)

export default {
  async fetch(request, env) {
    // CORS preflight
    if (request.method === "OPTIONS") {
      return corsResponse(null, 204, env);
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === "/init-multipart" && request.method === "POST") {
        return await initMultipart(request, env);
      }
      if (path === "/presign-part" && request.method === "POST") {
        return await presignPart(request, env);
      }
      if (path === "/complete-multipart" && request.method === "POST") {
        return await completeMultipart(request, env);
      }
      if (path === "/abort-multipart" && request.method === "DELETE") {
        return await abortMultipart(request, env);
      }
      return corsResponse({ error: "Not found" }, 404, env);
    } catch (e) {
      console.error(e);
      return corsResponse({ error: e.message }, 500, env);
    }
  },
};

// ─── Handlers ────────────────────────────────────────────────────────────────

async function initMultipart(request, env) {
  const { key, contentType } = await request.json();
  if (!key) return corsResponse({ error: "key is required" }, 400, env);

  const endpoint = r2Endpoint(env);
  const ct = contentType || "video/mp4";

  const signedReq = await signRequest(
    new Request(`${endpoint}/${encodeURIComponent(key)}?uploads`, {
      method: "POST",
      headers: { "Content-Type": ct },
    }),
    env
  );

  const res = await fetch(signedReq);
  const xml = await res.text();

  if (!res.ok) return corsResponse({ error: xml }, res.status, env);

  const uploadId = extractXml(xml, "UploadId");
  return corsResponse({ uploadId, key }, 200, env);
}

async function presignPart(request, env) {
  const { key, uploadId, partNumber } = await request.json();
  const endpoint = r2Endpoint(env);

  const url = `${endpoint}/${encodeURIComponent(key)}?partNumber=${partNumber}&uploadId=${encodeURIComponent(uploadId)}`;

  const presignedUrl = await presignUrl("PUT", url, env, 3600);
  return corsResponse({ presignedUrl }, 200, env);
}

async function completeMultipart(request, env) {
  const { key, uploadId, parts } = await request.json();
  // parts = [{ partNumber, etag }, ...]

  const endpoint = r2Endpoint(env);
  const url = `${endpoint}/${encodeURIComponent(key)}?uploadId=${encodeURIComponent(uploadId)}`;

  const body = buildCompleteXml(parts);

  const signedReq = await signRequest(
    new Request(url, {
      method: "POST",
      headers: { "Content-Type": "application/xml" },
      body,
    }),
    env
  );

  const res = await fetch(signedReq);
  const xml = await res.text();

  if (!res.ok) return corsResponse({ error: xml }, res.status, env);
  return corsResponse({ location: extractXml(xml, "Location") }, 200, env);
}

async function abortMultipart(request, env) {
  const { key, uploadId } = await request.json();
  const endpoint = r2Endpoint(env);
  const url = `${endpoint}/${encodeURIComponent(key)}?uploadId=${encodeURIComponent(uploadId)}`;

  const signedReq = await signRequest(
    new Request(url, { method: "DELETE" }),
    env
  );

  const res = await fetch(signedReq);
  if (!res.ok) {
    const xml = await res.text();
    return corsResponse({ error: xml }, res.status, env);
  }
  return corsResponse({ aborted: true }, 200, env);
}

// ─── AWS Signature V4 ─────────────────────────────────────────────────────────

function r2Endpoint(env) {
  return `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com/${env.R2_BUCKET_NAME}`;
}

async function signRequest(request, env) {
  const url = new URL(request.url);
  const now = new Date();
  const dateStamp = iso8601Date(now);
  const amzDate = iso8601DateTime(now);
  const region = "auto";
  const service = "s3";

  const headersToSign = {
    host: url.host,
    "x-amz-date": amzDate,
    "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
  };

  if (request.headers.get("Content-Type")) {
    headersToSign["content-type"] = request.headers.get("Content-Type");
  }

  const sortedKeys = Object.keys(headersToSign).sort();
  const canonicalHeaders = sortedKeys.map((k) => `${k}:${headersToSign[k]}\n`).join("");
  const signedHeaders = sortedKeys.join(";");

  const canonicalQueryString = url.searchParams.toString()
    .split("&")
    .sort()
    .join("&");

  const canonicalRequest = [
    request.method,
    url.pathname,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    "UNSIGNED-PAYLOAD",
  ].join("\n");

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest),
  ].join("\n");

  const signingKey = await getSigningKey(env.R2_SECRET_ACCESS_KEY, dateStamp, region, service);
  const signature = await hmacHex(signingKey, stringToSign);

  const authHeader = `AWS4-HMAC-SHA256 Credential=${env.R2_ACCESS_KEY_ID}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const newHeaders = new Headers(request.headers);
  newHeaders.set("Authorization", authHeader);
  newHeaders.set("x-amz-date", amzDate);
  newHeaders.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
  newHeaders.set("host", url.host);

  return new Request(request.url, {
    method: request.method,
    headers: newHeaders,
    body: request.body,
  });
}

async function presignUrl(method, urlString, env, expiresIn = 3600) {
  const url = new URL(urlString);
  const now = new Date();
  const dateStamp = iso8601Date(now);
  const amzDate = iso8601DateTime(now);
  const region = "auto";
  const service = "s3";

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;

  url.searchParams.set("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
  url.searchParams.set("X-Amz-Credential", `${env.R2_ACCESS_KEY_ID}/${credentialScope}`);
  url.searchParams.set("X-Amz-Date", amzDate);
  url.searchParams.set("X-Amz-Expires", String(expiresIn));
  url.searchParams.set("X-Amz-SignedHeaders", "host");

  const canonicalQueryString = Array.from(url.searchParams.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");

  const canonicalRequest = [
    method,
    url.pathname,
    canonicalQueryString,
    `host:${url.host}\n`,
    "host",
    "UNSIGNED-PAYLOAD",
  ].join("\n");

  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest),
  ].join("\n");

  const signingKey = await getSigningKey(env.R2_SECRET_ACCESS_KEY, dateStamp, region, service);
  const signature = await hmacHex(signingKey, stringToSign);

  url.searchParams.set("X-Amz-Signature", signature);
  return url.toString();
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

async function sha256Hex(message) {
  const data = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return bufToHex(hashBuffer);
}

async function hmac(key, message) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw", typeof key === "string" ? new TextEncoder().encode(key) : key,
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  return crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(message));
}

async function hmacHex(key, message) {
  return bufToHex(await hmac(key, message));
}

async function getSigningKey(secret, dateStamp, region, service) {
  const kDate = await hmac("AWS4" + secret, dateStamp);
  const kRegion = await hmac(kDate, region);
  const kService = await hmac(kRegion, service);
  return hmac(kService, "aws4_request");
}

function bufToHex(buffer) {
  return Array.from(new Uint8Array(buffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ─── Date helpers ─────────────────────────────────────────────────────────────

function iso8601Date(d) {
  return d.toISOString().slice(0, 10).replace(/-/g, "");
}
function iso8601DateTime(d) {
  return d.toISOString().replace(/[-:]/g, "").slice(0, 15) + "Z";
}

// ─── XML helpers ──────────────────────────────────────────────────────────────

function extractXml(xml, tag) {
  const match = xml.match(new RegExp(`<${tag}>(.*?)</${tag}>`));
  return match ? match[1] : null;
}

function buildCompleteXml(parts) {
  const partsXml = parts
    .sort((a, b) => a.partNumber - b.partNumber)
    .map((p) => `<Part><PartNumber>${p.partNumber}</PartNumber><ETag>${p.etag}</ETag></Part>`)
    .join("");
  return `<CompleteMultipartUpload>${partsXml}</CompleteMultipartUpload>`;
}

// ─── CORS ─────────────────────────────────────────────────────────────────────

function corsResponse(body, status, env) {
  const headers = {
    "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN || "*",
    "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json",
  };
  return new Response(body ? JSON.stringify(body) : null, { status, headers });
}

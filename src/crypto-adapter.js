// 双端加密适配层：浏览器（含 Worker）走 WebCrypto，Node 优先 WebCrypto、回退 node:crypto。
// 仅支持 Ed25519 验签与 SHA-256 摘要。

const encoder = new TextEncoder();

async function getSubtle() {
  if (globalThis.crypto?.subtle) return globalThis.crypto.subtle;
  try {
    const { webcrypto } = await import('node:crypto');
    return webcrypto?.subtle ?? null;
  } catch {
    return null;
  }
}

export function bytesToHex(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function base64UrlEncode(bytes) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64url');
  }
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export async function sha256Hex(data) {
  const bytes = typeof data === 'string' ? encoder.encode(data) : data;
  const subtle = await getSubtle();
  if (subtle) {
    const digest = await subtle.digest('SHA-256', bytes);
    return bytesToHex(new Uint8Array(digest));
  }
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(bytes).digest('hex');
}

// Ed25519 验签：公钥 32 字节、签名 64 字节、消息为任意字节串。
// 永不抛异常——验签不通过或环境不支持均返回 false。
export async function ed25519Verify(publicKeyBytes, signatureBytes, messageBytes) {
  const subtle = await getSubtle();
  if (subtle) {
    try {
      const key = await subtle.importKey('raw', publicKeyBytes, 'Ed25519', false, ['verify']);
      return await subtle.verify('Ed25519', key, signatureBytes, messageBytes);
    } catch {
      // 当前 WebCrypto 不支持 Ed25519 时回退 node:crypto
    }
  }
  try {
    const { createPublicKey, verify } = await import('node:crypto');
    const jwk = { kty: 'OKP', crv: 'Ed25519', x: base64UrlEncode(publicKeyBytes) };
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    return verify(null, messageBytes, key, signatureBytes);
  } catch {
    return false;
  }
}

// 测试与示例数据构造辅助（仅 Node 使用）：真实 Ed25519 密钥生成与签名。

import { generateKeyPairSync, sign as cryptoSign, createHash } from 'node:crypto';
import { canonicalize } from '../src/canonical-json.js';

export function genKey(label) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { label, privateKey, publicHex: Buffer.from(raw).toString('hex') };
}

export function keyObjectOf(key) {
  return { keytype: 'ed25519', scheme: 'ed25519', keyval: { public: key.publicHex } };
}

// 与复核引擎一致：密钥标识 = 规范公钥对象的 SHA-256
export function keyidOf(key) {
  return createHash('sha256').update(canonicalize(keyObjectOf(key)), 'utf8').digest('hex');
}

export function signOver(key, signedObj) {
  const message = Buffer.from(canonicalize(signedObj), 'utf8');
  return cryptoSign(null, message, key.privateKey).toString('hex');
}

export function addSignature(metadata, key) {
  metadata.signatures.push({ keyid: keyidOf(key), sig: signOver(key, metadata.signed) });
  return metadata;
}

export function makeRoot({
  version,
  keys,
  rootKeys,
  rootThreshold,
  targetsKeys,
  targetsThreshold,
  expires = '2030-01-01T00:00:00Z',
}) {
  return {
    signed: {
      _type: 'root',
      spec_version: '1.0.0',
      version,
      expires,
      keys: keys.map(keyObjectOf),
      roles: {
        root: { keyids: rootKeys.map(keyidOf), threshold: rootThreshold },
        targets: { keyids: targetsKeys.map(keyidOf), threshold: targetsThreshold },
      },
    },
    signatures: [],
  };
}

export function makeTargets({ version = 1, expires = '2030-01-01T00:00:00Z', targets } = {}) {
  return {
    signed: {
      _type: 'targets',
      spec_version: '1.0.0',
      version,
      expires,
      targets: targets ?? {
        'app-1.0.0.bin': {
          length: 4096,
          hashes: { sha256: createHash('sha256').update('demo-payload').digest('hex') },
        },
      },
    },
    signatures: [],
  };
}

// 页面录入的是原始文本，签名只覆盖规范形式，排版空白不影响验签
export const toText = (metadata) => JSON.stringify(metadata, null, 2);

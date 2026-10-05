// 离线复核规则引擎（纯 ES 模块，无依赖，浏览器 Worker 与 Node 共用）。
//
// 规则摘要：
//  - 签名只覆盖「字段名按码点排序后的规范 JSON」UTF-8 字节，且仅针对 signed 对象；
//  - 密钥标识 = 规范公钥对象的 SHA-256（hex）；仅接受 Ed25519；
//  - Root 链按版本连续（v, v+1, ...）导入，首份为锚点（链外信任）；
//  - 候选根须同时获得「前一 Root 的 root 角色」与「自身 root 角色」足额不同签名授权；
//  - 最终 Targets 须由最终根的 targets 角色足额签名且未过期（审查时刻晚于过期时间即拒绝）。

import { canonicalize, parseJsonStrict, MetadataParseError } from './canonical-json.js';
import { sha256Hex, ed25519Verify, hexToBytes } from './crypto-adapter.js';

export const MAX_ROOTS = 6;

const encoder = new TextEncoder();
const HEX_RE = /^[0-9a-f]+$/;

function evidence(code, message, details = {}) {
  return { code, message, ...details };
}

function isHex(value, len) {
  return typeof value === 'string' && value.length === len && HEX_RE.test(value);
}

function parseEvidence(err) {
  if (err instanceof MetadataParseError && err.code === 'DUPLICATE_OBJECT_NAME') {
    return evidence('DUPLICATE_OBJECT_NAME', `重复对象名：${JSON.stringify(err.key)}`, { key: err.key });
  }
  return evidence('INVALID_JSON', `JSON 解析失败：${err.message}`);
}

// ---------- 结构校验 ----------

// 密钥标识取规范公钥对象的 SHA-256；仅接受 Ed25519。
async function buildKeyMap(keyList) {
  if (!Array.isArray(keyList) || keyList.length === 0) {
    return { error: evidence('INVALID_METADATA', 'keys 必须是非空数组') };
  }
  const map = new Map();
  for (const item of keyList) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      return { error: evidence('INVALID_METADATA', '密钥项必须是对象') };
    }
    if (item.keytype !== 'ed25519' || item.scheme !== 'ed25519') {
      return {
        error: evidence('UNSUPPORTED_KEYTYPE', '仅接受 Ed25519 密钥', {
          keytype: item.keytype ?? null,
          scheme: item.scheme ?? null,
        }),
      };
    }
    const pub = item.keyval?.public;
    if (!isHex(pub, 64)) {
      return { error: evidence('INVALID_METADATA', '公钥必须是 32 字节小写 hex 编码') };
    }
    const keyObject = {
      keytype: 'ed25519',
      scheme: 'ed25519',
      keyval: { public: pub.toLowerCase() },
    };
    const keyid = await sha256Hex(encoder.encode(canonicalize(keyObject)));
    if (!map.has(keyid)) map.set(keyid, keyObject);
  }
  return { map };
}

function readRole(signed, roleName, keyMap) {
  const role = signed.roles?.[roleName];
  if (!role || typeof role !== 'object') {
    return { error: evidence('INVALID_METADATA', `缺少 ${roleName} 角色定义`) };
  }
  if (!Number.isInteger(role.threshold) || role.threshold < 1) {
    return { error: evidence('INVALID_METADATA', `${roleName} 角色阈值必须是 ≥1 的整数`) };
  }
  if (!Array.isArray(role.keyids) || role.keyids.length === 0) {
    return { error: evidence('INVALID_METADATA', `${roleName} 角色 keyids 必须是非空数组`) };
  }
  const keyids = [...new Set(role.keyids)];
  for (const keyid of keyids) {
    if (typeof keyid !== 'string' || !keyMap.has(keyid)) {
      return {
        error: evidence('UNKNOWN_ROLE_KEY', `${roleName} 角色引用了未知键`, { keyid: String(keyid) }),
      };
    }
  }
  return { role: { threshold: role.threshold, keyids } };
}

function validateCommonSigned(doc, expectedType) {
  const signed = doc?.signed;
  if (!signed || typeof signed !== 'object' || Array.isArray(signed)) {
    return { error: evidence('INVALID_METADATA', '缺少 signed 对象') };
  }
  if (signed._type !== expectedType) {
    return { error: evidence('INVALID_METADATA', `_type 必须是 ${expectedType}`) };
  }
  if (!Number.isInteger(signed.version) || signed.version < 1) {
    return { error: evidence('INVALID_METADATA', 'version 必须是 ≥1 的整数') };
  }
  if (typeof signed.expires !== 'string' || !Number.isFinite(Date.parse(signed.expires))) {
    return { error: evidence('INVALID_METADATA', 'expires 必须是 ISO 8601 时间字符串') };
  }
  if (!Array.isArray(doc.signatures)) {
    return { error: evidence('INVALID_METADATA', 'signatures 必须是数组') };
  }
  return { signed };
}

async function validateRootDocument(doc) {
  const common = validateCommonSigned(doc, 'root');
  if (common.error) return common;
  const { signed } = common;
  const keys = await buildKeyMap(signed.keys);
  if (keys.error) return keys;
  const rootRole = readRole(signed, 'root', keys.map);
  if (rootRole.error) return rootRole;
  const targetsRole = readRole(signed, 'targets', keys.map);
  if (targetsRole.error) return targetsRole;
  return {
    value: {
      version: signed.version,
      expires: signed.expires,
      signed,
      signatures: doc.signatures,
      keyMap: keys.map,
      rootRole: rootRole.role,
      targetsRole: targetsRole.role,
    },
  };
}

async function loadRoot(text) {
  let doc;
  try {
    doc = parseJsonStrict(text);
  } catch (err) {
    return { error: parseEvidence(err) };
  }
  return validateRootDocument(doc);
}

// ---------- 签名核验 ----------

// 对 signed 对象的规范字节逐条验签。
// thresholdSets：若干授权集合（如 prev/self 两个 root 角色、或 targets 角色）。
// 检查顺序即「首个阻断证据」的判定顺序：重复签名者 → 未知键 → 签名无效（篡改）。
async function verifySignatures({ signedObj, signatures, keyLookup, thresholdSets }) {
  if (signatures.length === 0) {
    return { error: evidence('INSUFFICIENT_SIGNATURES', '签名不足：没有任何签名') };
  }
  const seen = new Set();
  for (const sig of signatures) {
    const keyid = sig?.keyid;
    if (seen.has(keyid)) {
      return { error: evidence('DUPLICATE_SIGNER', '存在重复签名者', { keyid: String(keyid) }) };
    }
    seen.add(keyid);
  }
  const authorized = new Set();
  for (const set of thresholdSets) {
    for (const keyid of set.keyids) authorized.add(keyid);
  }
  for (const sig of signatures) {
    if (!authorized.has(sig?.keyid)) {
      return {
        error: evidence('UNKNOWN_KEY', '签名引用了未知或未获授权的键', { keyid: String(sig?.keyid) }),
      };
    }
  }
  const message = encoder.encode(canonicalize(signedObj));
  const validKeyids = new Set();
  for (const sig of signatures) {
    const keyObject = keyLookup.get(sig.keyid);
    const sigBytes = isHex(sig?.sig, 128) ? hexToBytes(sig.sig) : null;
    const ok =
      keyObject && sigBytes
        ? await ed25519Verify(hexToBytes(keyObject.keyval.public), sigBytes, message)
        : false;
    if (!ok) {
      return {
        error: evidence('BAD_SIGNATURE', '签名校验失败：signed 内容可能被篡改', {
          keyid: String(sig?.keyid),
        }),
      };
    }
    validKeyids.add(sig.keyid);
  }
  const perSet = {};
  for (const set of thresholdSets) {
    perSet[set.name] = {
      required: set.threshold,
      signers: set.keyids.filter((keyid) => validKeyids.has(keyid)),
    };
  }
  return { value: perSet };
}

// ---------- Targets 阶段 ----------

async function verifyTargetsStage(trusted, targetsText, reviewMs) {
  const stage = { stage: 'targets', status: 'rejected', signers: [], required: trusted.targetsRole.threshold };
  let doc;
  try {
    doc = parseJsonStrict(targetsText);
  } catch (err) {
    stage.evidence = parseEvidence(err);
    return stage;
  }
  const common = validateCommonSigned(doc, 'targets');
  if (common.error) {
    stage.evidence = common.error;
    return stage;
  }
  const { signed } = common;
  const targetsMap = signed.targets ?? {};
  if (!targetsMap || typeof targetsMap !== 'object' || Array.isArray(targetsMap)) {
    stage.evidence = evidence('INVALID_METADATA', 'targets 必须是对象');
    return stage;
  }
  for (const [name, meta] of Object.entries(targetsMap)) {
    const bad =
      !meta ||
      typeof meta !== 'object' ||
      !Number.isInteger(meta.length) ||
      meta.length < 0 ||
      !meta.hashes ||
      typeof meta.hashes !== 'object' ||
      Array.isArray(meta.hashes);
    if (bad) {
      stage.evidence = evidence('INVALID_METADATA', `目标 ${JSON.stringify(name)} 的元数据无效`);
      return stage;
    }
  }
  stage.version = signed.version;
  stage.expires = signed.expires;
  stage.targetNames = Object.keys(targetsMap).sort();

  const sigResult = await verifySignatures({
    signedObj: signed,
    signatures: doc.signatures,
    keyLookup: trusted.keyMap,
    thresholdSets: [
      { name: 'targets', keyids: trusted.targetsRole.keyids, threshold: trusted.targetsRole.threshold },
    ],
  });
  if (sigResult.error) {
    stage.evidence = sigResult.error;
    return stage;
  }
  stage.signers = sigResult.value.targets.signers;
  if (stage.signers.length < trusted.targetsRole.threshold) {
    stage.evidence = evidence('TARGETS_THRESHOLD_NOT_MET', '签名不足：targets 角色未达阈值', {
      required: trusted.targetsRole.threshold,
      got: stage.signers.length,
    });
    return stage;
  }
  // 审查时刻晚于过期时间即拒绝，即使签名有效
  stage.expired = reviewMs > Date.parse(signed.expires);
  if (stage.expired) {
    stage.evidence = evidence('TARGETS_EXPIRED', '审查时刻晚于最终 Targets 的过期时间，不予授权', {
      expires: signed.expires,
    });
    return stage;
  }
  stage.status = 'accepted';
  return stage;
}

// ---------- 主流程 ----------

function inputFailure(code, message) {
  return {
    ok: false,
    conclusion: 'REJECT',
    finalRootVersion: null,
    rounds: [],
    targets: null,
    evidence: evidence(code, message),
    summary: { finalRootVersion: null, reason: { code, message } },
  };
}

function failure(rounds, trusted, targetsStage, ev) {
  return {
    ok: false,
    conclusion: 'REJECT',
    finalRootVersion: trusted ? trusted.version : null,
    rounds,
    targets: targetsStage ?? null,
    evidence: ev,
    summary: { finalRootVersion: trusted ? trusted.version : null, reason: ev },
  };
}

export async function verifyReview(input) {
  const reviewTime = input?.reviewTime;
  const rootTexts = Array.isArray(input?.roots)
    ? input.roots.filter((t) => typeof t === 'string' && t.trim() !== '')
    : [];
  const targetsText = input?.targets;

  const reviewMs = Date.parse(reviewTime);
  if (!Number.isFinite(reviewMs)) return inputFailure('INVALID_REVIEW_TIME', '审查时刻无效');
  if (rootTexts.length === 0) return inputFailure('NO_ROOTS', '至少需要一份 Root 元数据');
  if (rootTexts.length > MAX_ROOTS) {
    return inputFailure('TOO_MANY_ROOTS', `至多 ${MAX_ROOTS} 份 Root 元数据`);
  }
  if (typeof targetsText !== 'string' || targetsText.trim() === '') {
    return inputFailure('NO_TARGETS', '缺少 Targets 元数据');
  }

  const rounds = [];

  // 第 0 轮：锚点（链外信任的初始可信根，仅做结构校验）
  const anchor = await loadRoot(rootTexts[0]);
  if (anchor.error) {
    rounds.push({ round: 0, type: 'anchor', status: 'rejected', evidence: anchor.error });
    return failure(rounds, null, null, anchor.error);
  }
  let trusted = anchor.value;
  rounds.push({
    round: 0,
    type: 'anchor',
    status: 'trusted',
    trustedVersion: trusted.version,
    note: '初始可信根（锚点，链外信任）',
  });

  // 轮换轮次：候选根须同时获得前一 Root 与自身 root 角色的足额不同签名授权
  for (let i = 1; i < rootTexts.length; i++) {
    const round = { round: i, type: 'rotation', trustedVersionBefore: trusted.version };
    const candidate = await loadRoot(rootTexts[i]);
    if (candidate.error) {
      round.status = 'rejected';
      round.evidence = candidate.error;
      rounds.push(round);
      return failure(rounds, trusted, null, candidate.error);
    }
    const cand = candidate.value;
    round.candidateVersion = cand.version;
    if (cand.version !== trusted.version + 1) {
      const ev = evidence(
        'VERSION_JUMP',
        `版本跳跃：期望版本 ${trusted.version + 1}，实际 ${cand.version}`,
        { expected: trusted.version + 1, actual: cand.version }
      );
      round.status = 'rejected';
      round.evidence = ev;
      rounds.push(round);
      return failure(rounds, trusted, null, ev);
    }
    const keyLookup = new Map([...trusted.keyMap, ...cand.keyMap]);
    const sigResult = await verifySignatures({
      signedObj: cand.signed,
      signatures: cand.signatures,
      keyLookup,
      thresholdSets: [
        { name: 'prev', keyids: trusted.rootRole.keyids, threshold: trusted.rootRole.threshold },
        { name: 'self', keyids: cand.rootRole.keyids, threshold: cand.rootRole.threshold },
      ],
    });
    if (sigResult.error) {
      round.status = 'rejected';
      round.evidence = sigResult.error;
      rounds.push(round);
      return failure(rounds, trusted, null, sigResult.error);
    }
    round.prev = sigResult.value.prev;
    round.self = sigResult.value.self;
    const prevOk = round.prev.signers.length >= trusted.rootRole.threshold;
    const selfOk = round.self.signers.length >= cand.rootRole.threshold;
    if (prevOk && selfOk) {
      round.status = 'accepted';
      round.trustedVersionAfter = cand.version;
      trusted = cand;
      rounds.push(round);
      continue;
    }
    let ev;
    const detail = {
      prev: { got: round.prev.signers.length, required: trusted.rootRole.threshold },
      self: { got: round.self.signers.length, required: cand.rootRole.threshold },
    };
    if (prevOk) {
      ev = evidence('SELF_THRESHOLD_NOT_MET', '仅旧根达阈值：候选根自身 root 角色签名不足', detail);
    } else if (selfOk) {
      ev = evidence('PREV_THRESHOLD_NOT_MET', '签名不足：前一 Root 的 root 角色授权未达阈值', detail);
    } else if (i === 1) {
      ev = evidence(
        'FIRST_ROUND_DOUBLE_THRESHOLD_FAILED',
        '首轮双阈值失败：前一 Root 与自身 root 角色均未达阈值',
        detail
      );
    } else {
      ev = evidence(
        'DOUBLE_THRESHOLD_FAILED',
        '双阈值失败：前一 Root 与自身 root 角色均未达阈值',
        detail
      );
    }
    round.status = 'rejected';
    round.evidence = ev;
    rounds.push(round);
    return failure(rounds, trusted, null, ev);
  }

  // Targets 阶段：须由最终根的 targets 角色足额签名且未过期
  const targetsStage = await verifyTargetsStage(trusted, targetsText, reviewMs);
  if (targetsStage.status !== 'accepted') {
    return failure(rounds, trusted, targetsStage, targetsStage.evidence);
  }
  return {
    ok: true,
    conclusion: 'ALLOW',
    finalRootVersion: trusted.version,
    rounds,
    targets: targetsStage,
    summary: {
      finalRootVersion: trusted.version,
      targetsVersion: targetsStage.version,
      targetsExpires: targetsStage.expires,
      targetsSigners: targetsStage.signers,
      targetNames: targetsStage.targetNames,
      targetCount: targetsStage.targetNames.length,
    },
  };
}

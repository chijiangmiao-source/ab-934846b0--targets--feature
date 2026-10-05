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

// ---------- Targets 文档解析 ----------

async function parseTargetsDocument(text) {
  let doc;
  try {
    doc = parseJsonStrict(text);
  } catch (err) {
    return { error: parseEvidence(err) };
  }
  const common = validateCommonSigned(doc, 'targets');
  if (common.error) return { error: common.error };
  const { signed } = common;
  const targetsMap = signed.targets ?? {};
  if (!targetsMap || typeof targetsMap !== 'object' || Array.isArray(targetsMap)) {
    return { error: evidence('INVALID_METADATA', 'targets 必须是对象') };
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
      return { error: evidence('INVALID_METADATA', `目标 ${JSON.stringify(name)} 的元数据无效`) };
    }
  }
  return { value: { doc, signed, targetsMap } };
}

// ---------- 委托（delegations） ----------

const RESERVED_ROLE_NAMES = new Set(['root', 'targets', 'snapshot', 'timestamp']);
// TUF 路径规则中允许转义的字符（safe-char / sep-char / '*' / '?'）
const ESCAPABLE_CHARS = new Set([
  ..."-._~@/:=! #$%&'`^+;()*?",
]);

// 把 TUF 路径规则编译为整串匹配的正则：
//  '*'  匹配单层（不含 '/'）任意字节序列；'?' 匹配单层单个字符；
//  '**' 仅允许作为规则末尾（跨层递归匹配）；'\uXXXX' / '\UXXXXXXXX' 与标点转义；
//  其余正则元字符（如未转义的 '['）一律视为非法规则。
function compilePathPattern(pattern) {
  if (typeof pattern !== 'string' || pattern === '') {
    throw new Error('路径规则必须是非空字符串');
  }
  if (pattern.includes('\0')) throw new Error('路径规则不得含 NUL 字符');
  let re = '^';
  let i = 0;
  const addLiteral = (ch) => {
    re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  };
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === '\\') {
      const nx = pattern[i + 1];
      if (nx === 'u' || nx === 'U') {
        const n = nx === 'u' ? 4 : 8;
        const hex = pattern.slice(i + 2, i + 2 + n);
        if (!new RegExp(`^[0-9a-fA-F]{${n}}$`).test(hex)) {
          throw new Error('路径规则含非法 Unicode 转义');
        }
        const cp = parseInt(hex, 16);
        if (cp > 0x10ffff) throw new Error('路径规则含超出 Unicode 范围的码点');
        addLiteral(String.fromCodePoint(cp));
        i += 2 + n;
        continue;
      }
      if (!nx || !ESCAPABLE_CHARS.has(nx)) throw new Error('路径规则含非法转义');
      addLiteral(nx);
      i += 2;
      continue;
    }
    if (c === '*') {
      if (pattern[i + 1] === '*') {
        if (i + 2 !== pattern.length) throw new Error("递归通配 '**' 只能位于路径规则末尾");
        re += '.*';
        i += 2;
        continue;
      }
      re += '[^/]*';
      i += 1;
      continue;
    }
    if (c === '?') {
      re += '[^/]';
      i += 1;
      continue;
    }
    if ('[]|<>'.includes(c)) throw new Error('路径规则含未转义的非法字符');
    addLiteral(c);
    i += 1;
  }
  return new RegExp(re + '$');
}

// 读取顶层 Targets 的 delegations；无 delegations 字段时返回空委托表（行为与旧规则一致）。
async function readDelegations(signed) {
  const delegations = signed.delegations;
  if (delegations === undefined) return { value: { roles: [], keyMap: new Map() } };
  if (!delegations || typeof delegations !== 'object' || Array.isArray(delegations)) {
    return { error: evidence('INVALID_DELEGATION', 'delegations 必须是对象') };
  }
  const invalid = (message, details = {}) =>
    evidence('INVALID_DELEGATION', message, details);
  const keys = await buildKeyMap(delegations.keys);
  if (keys.error) {
    return {
      error: invalid(`委托密钥表无效：${keys.error.message}`, {
        reason: keys.error.code,
      }),
    };
  }
  if (!Array.isArray(delegations.roles) || delegations.roles.length === 0) {
    return { error: invalid('delegations.roles 必须是非空数组') };
  }
  const roles = [];
  const seenNames = new Set();
  for (const item of delegations.roles) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      return { error: invalid('委托角色项必须是对象') };
    }
    const name = item.name;
    if (typeof name !== 'string' || name === '') {
      return { error: invalid('委托角色 name 必须是非空字符串') };
    }
    if (RESERVED_ROLE_NAMES.has(name)) {
      return { error: invalid(`委托角色名 ${JSON.stringify(name)} 与保留角色冲突`, { role: name }) };
    }
    if (seenNames.has(name)) {
      return {
        error: evidence('DUPLICATE_DELEGATED_ROLE', `委托角色重复声明：${JSON.stringify(name)}`, {
          role: name,
        }),
      };
    }
    seenNames.add(name);
    if (!Number.isInteger(item.threshold) || item.threshold < 1) {
      return { error: invalid(`委托角色 ${JSON.stringify(name)} 阈值必须是 ≥1 的整数`, { role: name }) };
    }
    if (!Array.isArray(item.keyids) || item.keyids.length === 0) {
      return { error: invalid(`委托角色 ${JSON.stringify(name)} keyids 必须是非空数组`, { role: name }) };
    }
    const keyids = [...new Set(item.keyids)];
    for (const keyid of keyids) {
      if (typeof keyid !== 'string' || !keys.map.has(keyid)) {
        return { error: invalid(`委托角色 ${JSON.stringify(name)} 引用了未声明的键`, { role: name, keyid: String(keyid) }) };
      }
    }
    if (!Array.isArray(item.paths) || item.paths.length === 0) {
      return { error: invalid(`委托角色 ${JSON.stringify(name)} paths 必须是非空数组`, { role: name }) };
    }
    const patterns = [];
    for (const p of item.paths) {
      let compiled;
      try {
        compiled = compilePathPattern(p);
      } catch (err) {
        return {
          error: invalid(`委托角色 ${JSON.stringify(name)} 的路径规则 ${JSON.stringify(p)} 非法：${err.message}`, {
            role: name,
            path: String(p),
          }),
        };
      }
      patterns.push({ raw: p, regexp: compiled });
    }
    const terminating = item.terminating === undefined ? false : item.terminating;
    if (typeof terminating !== 'boolean') {
      return { error: invalid(`委托角色 ${JSON.stringify(name)} terminating 必须是布尔值`, { role: name }) };
    }
    roles.push({ name, threshold: item.threshold, keyids, patterns, terminating });
  }
  return { value: { roles, keyMap: keys.map } };
}

function matchPath(role, targetName) {
  return role.patterns.find((p) => p.regexp.test(targetName))?.raw ?? null;
}

function digestOf(meta) {
  const alg = Object.prototype.hasOwnProperty.call(meta.hashes, 'sha256')
    ? 'sha256'
    : Object.keys(meta.hashes)[0];
  return { alg, hash: meta.hashes[alg], length: meta.length };
}

// 核验一份命中委托的子 Targets：仅接受父委托声明的 Ed25519 键与该角色阈值。
// 返回 { error } 或 { signers, version, expires, targetsMap, expired }。
async function verifyDelegatedMetadata(entry, delegatedText, reviewMs, keyMap) {
  const parsed = await parseTargetsDocument(delegatedText);
  if (parsed.error) return { error: parsed.error };
  const { doc, signed, targetsMap } = parsed.value;
  const sigResult = await verifySignatures({
    signedObj: signed,
    signatures: doc.signatures,
    keyLookup: keyMap,
    thresholdSets: [{ name: 'delegated', keyids: entry.keyids, threshold: entry.threshold }],
  });
  if (sigResult.error) return { error: sigResult.error };
  const signers = sigResult.value.delegated.signers;
  if (signers.length < entry.threshold) {
    return {
      error: evidence('DELEGATED_THRESHOLD_NOT_MET', `委托角色 ${JSON.stringify(entry.name)} 签名未达阈值`, {
        role: entry.name,
        required: entry.threshold,
        got: signers.length,
      }),
    };
  }
  if (reviewMs > Date.parse(signed.expires)) {
    return {
      error: evidence('DELEGATED_EXPIRED', `审查时刻晚于委托角色 ${JSON.stringify(entry.name)} 元数据的过期时间`, {
        role: entry.name,
        expires: signed.expires,
      }),
    };
  }
  return { value: { signers, version: signed.version, expires: signed.expires, targetsMap } };
}

// ---------- Targets 阶段 ----------

async function verifyTargetsStage(trusted, targetsText, reviewMs, targetName, delegatedText) {
  const stage = {
    stage: 'targets',
    status: 'rejected',
    signers: [],
    required: trusted.targetsRole.threshold,
  };
  const parsed = await parseTargetsDocument(targetsText);
  if (parsed.error) {
    stage.evidence = parsed.error;
    return stage;
  }
  const { doc, signed, targetsMap } = parsed.value;
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

  // 未指定具体目标：维持既有「顶层 Targets 合法即通过」结论
  if (!targetName) return stage;

  stage.targetName = targetName;
  stage.delegationTrace = [];
  const delegationResult = await readDelegations(signed);
  if (delegationResult.error) {
    stage.status = 'rejected';
    stage.evidence = delegationResult.error;
    return stage;
  }
  const trace = stage.delegationTrace;
  let anyMatch = false;

  // 委托按声明顺序匹配目标名；首个命中的角色负责该目标。
  for (const role of delegationResult.value.roles) {
    const matchedPath = matchPath(role, targetName);
    const entry = {
      role: role.name,
      paths: role.patterns.map((p) => p.raw),
      terminating: role.terminating,
      match: matchedPath !== null,
      matchedPath,
    };
    if (matchedPath === null) {
      entry.status = 'skipped';
      trace.push(entry);
      continue;
    }
    anyMatch = true;
    if (!delegatedText) {
      if (role.terminating) {
        entry.status = 'rejected';
        entry.evidence = evidence(
          'DELEGATED_METADATA_REQUIRED',
          `目标命中终止性委托 ${JSON.stringify(role.name)}，但未提供其受委托 Targets 元数据`,
          { role: role.name, matchedPath }
        );
        trace.push(entry);
        stage.status = 'rejected';
        stage.evidence = entry.evidence;
        return stage;
      }
      // 未终止委托且未提供子元数据：跳过，继续后续委托与顶层目标
      entry.status = 'missing';
      trace.push(entry);
      continue;
    }
    const verified = await verifyDelegatedMetadata(role, delegatedText, reviewMs, delegationResult.value.keyMap);
    entry.required = role.threshold;
    if (verified.error) {
      entry.status = 'rejected';
      entry.evidence = verified.error;
      trace.push(entry);
      if (role.terminating) {
        // 命中 terminating 委托：签名 / 格式 / 过期等任何失败都必须停止并拒绝
        stage.status = 'rejected';
        stage.evidence = verified.error;
        return stage;
      }
      continue;
    }
    entry.signers = verified.value.signers;
    entry.version = verified.value.version;
    entry.expires = verified.value.expires;
    const meta = Object.prototype.hasOwnProperty.call(verified.value.targetsMap, targetName)
      ? verified.value.targetsMap[targetName]
      : null;
    if (meta) {
      entry.status = 'accepted';
      trace.push(entry);
      stage.status = 'accepted';
      stage.resolution = {
        target: targetName,
        adoptedRole: role.name,
        matchedPath,
        required: role.threshold,
        signers: verified.value.signers,
        meta,
        ...digestOf(meta),
      };
      return stage;
    }
    // 子元数据中没有该目标
    entry.status = 'rejected';
    entry.evidence = evidence(
      'TARGET_NOT_FOUND',
      `委托角色 ${JSON.stringify(role.name)} 的元数据未声明目标 ${JSON.stringify(targetName)}`,
      { role: role.name, target: targetName }
    );
    trace.push(entry);
    if (role.terminating) {
      stage.status = 'rejected';
      stage.evidence = entry.evidence;
      return stage;
    }
  }

  // 未命中任何可用委托（或未终止委托均未提供目标）：回到顶层 Targets 判定
  if (delegatedText && !anyMatch) {
    // 提供的子元数据没有任何命中的委托为其授权——不得当作允许证据
    stage.status = 'rejected';
    stage.evidence = evidence(
      'DELEGATED_PATH_NOT_MATCHED',
      `所提供的受委托 Targets 元数据无对应授权：没有任何委托路径规则命中 ${JSON.stringify(targetName)}`,
      { target: targetName }
    );
    return stage;
  }
  const topMeta = Object.prototype.hasOwnProperty.call(targetsMap, targetName) ? targetsMap[targetName] : null;
  if (topMeta) {
    stage.status = 'accepted';
    stage.resolution = {
      target: targetName,
      adoptedRole: 'targets',
      matchedPath: null,
      required: trusted.targetsRole.threshold,
      signers: stage.signers,
      meta: topMeta,
      ...digestOf(topMeta),
    };
    return stage;
  }
  stage.status = 'rejected';
  stage.evidence = evidence(
    'TARGET_NOT_FOUND',
    `无可信角色声明目标 ${JSON.stringify(targetName)}：顶层 Targets 与可用委托中均缺失`,
    { target: targetName }
  );
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
  const targetNameRaw = input?.targetName;
  const targetName = typeof targetNameRaw === 'string' ? targetNameRaw.trim() : '';
  const delegatedRaw = input?.delegatedTargets;
  const delegatedText =
    typeof delegatedRaw === 'string' && delegatedRaw.trim() !== '' ? delegatedRaw.trim() : null;

  const reviewMs = Date.parse(reviewTime);
  if (!Number.isFinite(reviewMs)) return inputFailure('INVALID_REVIEW_TIME', '审查时刻无效');
  if (rootTexts.length === 0) return inputFailure('NO_ROOTS', '至少需要一份 Root 元数据');
  if (rootTexts.length > MAX_ROOTS) {
    return inputFailure('TOO_MANY_ROOTS', `至多 ${MAX_ROOTS} 份 Root 元数据`);
  }
  if (typeof targetsText !== 'string' || targetsText.trim() === '') {
    return inputFailure('NO_TARGETS', '缺少 Targets 元数据');
  }
  if (typeof targetNameRaw !== 'undefined' && targetNameRaw !== null && typeof targetNameRaw !== 'string') {
    return inputFailure('INVALID_TARGET_NAME', '目标名必须是字符串');
  }
  if (targetName.includes('\0')) {
    return inputFailure('INVALID_TARGET_NAME', '目标名不得含 NUL 字符');
  }
  if (delegatedText && !targetName) {
    return inputFailure('INVALID_TARGET_QUERY', '提供了受委托 Targets 元数据但未填写目标名');
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

  // Targets 阶段：须由最终根的 targets 角色足额签名且未过期；
  // 指定目标名时，再按声明顺序解析 delegations，判定该目标实际由哪个角色发布
  const targetsStage = await verifyTargetsStage(trusted, targetsText, reviewMs, targetName, delegatedText);
  if (targetsStage.status !== 'accepted') {
    return failure(rounds, trusted, targetsStage, targetsStage.evidence);
  }
  const summary = {
    finalRootVersion: trusted.version,
    targetsVersion: targetsStage.version,
    targetsExpires: targetsStage.expires,
    targetsSigners: targetsStage.signers,
    targetNames: targetsStage.targetNames,
    targetCount: targetsStage.targetNames.length,
  };
  if (targetName) {
    summary.targetName = targetName;
    summary.adoptedRole = targetsStage.resolution.adoptedRole;
    summary.matchedPath = targetsStage.resolution.matchedPath;
    summary.targetSigners = targetsStage.resolution.signers;
    summary.targetSignerRequired = targetsStage.resolution.required;
    summary.targetDigest = `${targetsStage.resolution.alg}:${targetsStage.resolution.hash}`;
    summary.targetLength = targetsStage.resolution.length;
  }
  return {
    ok: true,
    conclusion: 'ALLOW',
    finalRootVersion: trusted.version,
    rounds,
    targets: targetsStage,
    summary,
  };
}

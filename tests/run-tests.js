// 代码规则测试：覆盖规范 JSON、密钥标识、轮换双阈值、全部拒绝分支与过期规则。

import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { verifyReview, MAX_ROOTS } from '../src/verifier.js';
import { canonicalize, parseJsonStrict } from '../src/canonical-json.js';
import { sha256Hex } from '../src/crypto-adapter.js';
import * as h from './helpers.js';
import {
  REVIEW_TIME,
  buildLegitRotation,
  buildOldRootOnly,
  buildExpiredTargets,
} from './scenarios.js';

function assert(cond, msg) {
  if (!cond) throw new Error(`断言失败：${msg}`);
}

function assertEq(actual, expected, msg = '') {
  if (actual !== expected) {
    throw new Error(`断言失败：期望 ${JSON.stringify(expected)}，实际 ${JSON.stringify(actual)}。${msg}`);
  }
}

const tests = [];
function test(name, fn) {
  tests.push({ name, fn });
}

// ---------- 规范 JSON 与严格解析 ----------

test('规范 JSON：字段名按码点排序、无空白、嵌套递归', () => {
  assertEq(canonicalize({ b: 1, a: { d: 2, c: 3 } }), '{"a":{"c":3,"d":2},"b":1}');
  assertEq(canonicalize([{ z: 0, a: [true, null, 'x'] }]), '[{"a":[true,null,"x"],"z":0}]');
  // 码点排序与 UTF-16 码元排序的差异：'�'(U+FFFD) 的码点小于 '😀'(U+1F600)
  assertEq(canonicalize({ '😀': 2, '�': 1 }), '{"�":1,"😀":2}');
  assertEq(canonicalize('a"b\\c'), '"a\\"b\\\\c"');
});

test('密钥标识 = 规范公钥对象的 SHA-256（跨实现一致）', async () => {
  const key = h.genKey('K');
  const viaAdapter = await sha256Hex(new TextEncoder().encode(canonicalize(h.keyObjectOf(key))));
  assertEq(viaAdapter, h.keyidOf(key), 'WebCrypto 与 node:crypto 计算不一致');
  assertEq(viaAdapter.length, 64);
});

test('严格解析：任意层级重复对象名均被拒绝', () => {
  for (const text of ['{"a":1,"a":2}', '{"x":{"b":1,"b":2}}', '[{"k":1},{"k":2,"k":3}]']) {
    let code = null;
    try {
      parseJsonStrict(text);
    } catch (err) {
      code = err.code;
    }
    assertEq(code, 'DUPLICATE_OBJECT_NAME', `应拒绝：${text}`);
  }
  assertEq(parseJsonStrict('{"a":[1,{"b":2}],"c":"d"}').c, 'd');
});

// ---------- 验收示例场景 ----------

test('合法轮换：双阈值逐轮达成，最终允许并给出目标摘要', async () => {
  const { input } = buildLegitRotation();
  const result = await verifyReview(input);
  assert(result.ok, `应允许：${JSON.stringify(result.evidence)}`);
  assertEq(result.conclusion, 'ALLOW');
  assertEq(result.finalRootVersion, 3);
  assertEq(result.rounds.length, 3, '锚点 + 两轮轮换');
  assertEq(result.rounds[0].type, 'anchor');
  assertEq(result.rounds[1].status, 'accepted');
  assertEq(result.rounds[1].prev.signers.length, 2);
  assertEq(result.rounds[1].self.signers.length, 2);
  assertEq(result.rounds[2].status, 'accepted');
  assertEq(result.targets.status, 'accepted');
  assertEq(result.targets.signers.length, 1);
  assert(result.summary.targetNames.includes('app-1.0.0.bin'), '目标摘要应包含目标文件名');
  assertEq(result.summary.targetCount, 1);
});

test('旧根单签拒绝：仅旧根达阈值，保留此前可信根', async () => {
  const { input } = buildOldRootOnly();
  const result = await verifyReview(input);
  assert(!result.ok, '应拒绝');
  assertEq(result.rounds[1].evidence.code, 'SELF_THRESHOLD_NOT_MET');
  assertEq(result.finalRootVersion, 1, '可信根应保留在 v1');
  assertEq(result.targets, null, '链已拒绝，Targets 阶段不应执行');
});

test('过期 Targets：签名有效但审查时刻晚于过期时间，不予授权', async () => {
  const { input } = buildExpiredTargets();
  const result = await verifyReview(input);
  assert(!result.ok, '应拒绝');
  assertEq(result.targets.evidence.code, 'TARGETS_EXPIRED');
  assertEq(result.targets.signers.length, 2, '签名本身足额有效');
  assertEq(result.targets.expired, true);
  assertEq(result.finalRootVersion, 1);
});

test('未过期边界：审查时刻早于或等于过期时间均可授权', async () => {
  const { input } = buildExpiredTargets();
  const before = await verifyReview({ ...input, reviewTime: '2026-05-31T23:59:59Z' });
  assert(before.ok, `过期前应允许：${JSON.stringify(before.evidence)}`);
  const equal = await verifyReview({ ...input, reviewTime: '2026-06-01T00:00:00Z' });
  assert(equal.ok, '恰等于过期时间不算“晚于”，应允许');
});

// ---------- 轮换拒绝分支 ----------

test('首轮双阈值失败：两侧授权均未达阈值', async () => {
  const A = h.genKey('A');
  const B = h.genKey('B');
  const C = h.genKey('C');
  const D = h.genKey('D');
  const Ta = h.genKey('Ta');
  const v1 = h.makeRoot({ version: 1, keys: [A, B, Ta], rootKeys: [A, B], rootThreshold: 2, targetsKeys: [Ta], targetsThreshold: 1 });
  const v2 = h.makeRoot({ version: 2, keys: [C, D, Ta], rootKeys: [C, D], rootThreshold: 2, targetsKeys: [Ta], targetsThreshold: 1 });
  h.addSignature(v2, A); // 前一 Root 仅 1/2
  h.addSignature(v2, C); // 自身仅 1/2
  const targets = h.makeTargets();
  h.addSignature(targets, Ta);
  const result = await verifyReview({ reviewTime: REVIEW_TIME, roots: [h.toText(v1), h.toText(v2)], targets: h.toText(targets) });
  assert(!result.ok, '应拒绝');
  assertEq(result.rounds[1].evidence.code, 'FIRST_ROUND_DOUBLE_THRESHOLD_FAILED');
  assertEq(result.finalRootVersion, 1);
});

test('版本跳跃：候选版本不连续即拒绝', async () => {
  const A = h.genKey('A');
  const B = h.genKey('B');
  const Ta = h.genKey('Ta');
  const v1 = h.makeRoot({ version: 1, keys: [A, B, Ta], rootKeys: [A, B], rootThreshold: 2, targetsKeys: [Ta], targetsThreshold: 1 });
  const v3 = h.makeRoot({ version: 3, keys: [A, B, Ta], rootKeys: [A, B], rootThreshold: 2, targetsKeys: [Ta], targetsThreshold: 1 });
  h.addSignature(v3, A);
  h.addSignature(v3, B);
  const targets = h.makeTargets();
  h.addSignature(targets, Ta);
  const result = await verifyReview({ reviewTime: REVIEW_TIME, roots: [h.toText(v1), h.toText(v3)], targets: h.toText(targets) });
  assert(!result.ok, '应拒绝');
  assertEq(result.rounds[1].evidence.code, 'VERSION_JUMP');
  assertEq(result.rounds[1].evidence.expected, 2);
  assertEq(result.rounds[1].evidence.actual, 3);
});

test('重复签名者：同一密钥标识出现两次即拒绝', async () => {
  const A = h.genKey('A');
  const B = h.genKey('B');
  const Ta = h.genKey('Ta');
  const v1 = h.makeRoot({ version: 1, keys: [A, B, Ta], rootKeys: [A, B], rootThreshold: 2, targetsKeys: [Ta], targetsThreshold: 1 });
  const v2 = h.makeRoot({ version: 2, keys: [A, B, Ta], rootKeys: [A, B], rootThreshold: 2, targetsKeys: [Ta], targetsThreshold: 1 });
  h.addSignature(v2, A);
  h.addSignature(v2, B);
  h.addSignature(v2, B); // 重复签名者
  const targets = h.makeTargets();
  h.addSignature(targets, Ta);
  const result = await verifyReview({ reviewTime: REVIEW_TIME, roots: [h.toText(v1), h.toText(v2)], targets: h.toText(targets) });
  assert(!result.ok, '应拒绝');
  assertEq(result.rounds[1].evidence.code, 'DUPLICATE_SIGNER');
});

test('未知键：签名引用未获授权的键即拒绝', async () => {
  const A = h.genKey('A');
  const B = h.genKey('B');
  const X = h.genKey('X'); // 不在任何角色中
  const Ta = h.genKey('Ta');
  const v1 = h.makeRoot({ version: 1, keys: [A, B, Ta], rootKeys: [A, B], rootThreshold: 2, targetsKeys: [Ta], targetsThreshold: 1 });
  const v2 = h.makeRoot({ version: 2, keys: [A, B, Ta], rootKeys: [A, B], rootThreshold: 2, targetsKeys: [Ta], targetsThreshold: 1 });
  h.addSignature(v2, A);
  h.addSignature(v2, B);
  h.addSignature(v2, X);
  const targets = h.makeTargets();
  h.addSignature(targets, Ta);
  const result = await verifyReview({ reviewTime: REVIEW_TIME, roots: [h.toText(v1), h.toText(v2)], targets: h.toText(targets) });
  assert(!result.ok, '应拒绝');
  assertEq(result.rounds[1].evidence.code, 'UNKNOWN_KEY');
});

test('重复对象名：候选根原始文本含重复键即拒绝', async () => {
  const A = h.genKey('A');
  const B = h.genKey('B');
  const Ta = h.genKey('Ta');
  const v1 = h.makeRoot({ version: 1, keys: [A, B, Ta], rootKeys: [A, B], rootThreshold: 2, targetsKeys: [Ta], targetsThreshold: 1 });
  const v2 = h.makeRoot({ version: 2, keys: [A, B, Ta], rootKeys: [A, B], rootThreshold: 2, targetsKeys: [Ta], targetsThreshold: 1 });
  h.addSignature(v2, A);
  h.addSignature(v2, B);
  const tamperedText = h.toText(v2).replace('"version": 2', '"version": 2, "version": 2');
  assert(tamperedText.includes('"version": 2, "version": 2'), '应构造出重复对象名');
  const targets = h.makeTargets();
  h.addSignature(targets, Ta);
  const result = await verifyReview({ reviewTime: REVIEW_TIME, roots: [h.toText(v1), tamperedText], targets: h.toText(targets) });
  assert(!result.ok, '应拒绝');
  assertEq(result.rounds[1].evidence.code, 'DUPLICATE_OBJECT_NAME');
});

test('篡改 signed 内容：签名后改动内容导致验签失败', async () => {
  const A = h.genKey('A');
  const B = h.genKey('B');
  const Ta = h.genKey('Ta');
  const v1 = h.makeRoot({ version: 1, keys: [A, B, Ta], rootKeys: [A, B], rootThreshold: 2, targetsKeys: [Ta], targetsThreshold: 1 });
  const v2 = h.makeRoot({ version: 2, keys: [A, B, Ta], rootKeys: [A, B], rootThreshold: 2, targetsKeys: [Ta], targetsThreshold: 1 });
  h.addSignature(v2, A);
  h.addSignature(v2, B);
  v2.signed.expires = '2031-01-01T00:00:00Z'; // 签名后篡改
  const targets = h.makeTargets();
  h.addSignature(targets, Ta);
  const result = await verifyReview({ reviewTime: REVIEW_TIME, roots: [h.toText(v1), h.toText(v2)], targets: h.toText(targets) });
  assert(!result.ok, '应拒绝');
  assertEq(result.rounds[1].evidence.code, 'BAD_SIGNATURE');
});

test('签名不足：前一 Root 授权未达阈值', async () => {
  const A = h.genKey('A');
  const B = h.genKey('B');
  const C = h.genKey('C');
  const Ta = h.genKey('Ta');
  const v1 = h.makeRoot({ version: 1, keys: [A, B, Ta], rootKeys: [A, B], rootThreshold: 2, targetsKeys: [Ta], targetsThreshold: 1 });
  // v2 自身角色为 {A,C}：签名 A+C 使自身 2/2 达阈值，前一 Root 仅 A 计 1/2
  const v2 = h.makeRoot({ version: 2, keys: [A, C, Ta], rootKeys: [A, C], rootThreshold: 2, targetsKeys: [Ta], targetsThreshold: 1 });
  h.addSignature(v2, A);
  h.addSignature(v2, C);
  const targets = h.makeTargets();
  h.addSignature(targets, Ta);
  const result = await verifyReview({ reviewTime: REVIEW_TIME, roots: [h.toText(v1), h.toText(v2)], targets: h.toText(targets) });
  assert(!result.ok, '应拒绝');
  assertEq(result.rounds[1].evidence.code, 'PREV_THRESHOLD_NOT_MET');
});

test('空签名：候选根没有任何签名即拒绝', async () => {
  const A = h.genKey('A');
  const B = h.genKey('B');
  const Ta = h.genKey('Ta');
  const v1 = h.makeRoot({ version: 1, keys: [A, B, Ta], rootKeys: [A, B], rootThreshold: 2, targetsKeys: [Ta], targetsThreshold: 1 });
  const v2 = h.makeRoot({ version: 2, keys: [A, B, Ta], rootKeys: [A, B], rootThreshold: 2, targetsKeys: [Ta], targetsThreshold: 1 });
  const targets = h.makeTargets();
  h.addSignature(targets, Ta);
  const result = await verifyReview({ reviewTime: REVIEW_TIME, roots: [h.toText(v1), h.toText(v2)], targets: h.toText(targets) });
  assert(!result.ok, '应拒绝');
  assertEq(result.rounds[1].evidence.code, 'INSUFFICIENT_SIGNATURES');
});

// ---------- Targets 阶段拒绝分支 ----------

test('Targets 签名不足：targets 角色未达阈值', async () => {
  const { input } = buildExpiredTargets();
  const targetsDoc = JSON.parse(input.targets);
  targetsDoc.signatures = targetsDoc.signatures.slice(0, 1); // 阈值 2，仅 1 签
  const result = await verifyReview({ ...input, targets: JSON.stringify(targetsDoc) });
  assert(!result.ok, '应拒绝');
  assertEq(result.targets.evidence.code, 'TARGETS_THRESHOLD_NOT_MET');
  assertEq(result.targets.evidence.got, 1);
  assertEq(result.targets.evidence.required, 2);
});

test('Targets 未知键：签名引用 targets 角色之外的键', async () => {
  const { input } = buildExpiredTargets();
  const X = h.genKey('X');
  const targetsDoc = JSON.parse(input.targets);
  h.addSignature(targetsDoc, X);
  const result = await verifyReview({ ...input, targets: JSON.stringify(targetsDoc) });
  assert(!result.ok, '应拒绝');
  assertEq(result.targets.evidence.code, 'UNKNOWN_KEY');
});

test('Targets 重复对象名：原始文本含重复键即拒绝', async () => {
  const { input } = buildExpiredTargets();
  const tampered = input.targets.replace('"version": 1', '"version": 1, "version": 1');
  const result = await verifyReview({ ...input, targets: tampered });
  assert(!result.ok, '应拒绝');
  assertEq(result.targets.evidence.code, 'DUPLICATE_OBJECT_NAME');
});

// ---------- 结构约束 ----------

test('仅接受 Ed25519：其他密钥类型即拒绝', async () => {
  const { input } = buildExpiredTargets();
  const rootDoc = JSON.parse(input.roots[0]);
  rootDoc.signed.keys[0].keytype = 'rsa';
  const result = await verifyReview({ ...input, roots: [JSON.stringify(rootDoc)] });
  assert(!result.ok, '应拒绝');
  assertEq(result.rounds[0].evidence.code, 'UNSUPPORTED_KEYTYPE');
});

test(`至多 ${MAX_ROOTS} 份 Root：超出即拒绝`, async () => {
  const { input } = buildExpiredTargets();
  const roots = Array.from({ length: MAX_ROOTS + 1 }, () => input.roots[0]);
  const result = await verifyReview({ ...input, roots });
  assert(!result.ok, '应拒绝');
  assertEq(result.evidence.code, 'TOO_MANY_ROOTS');
});

test('录入校验：缺少审查时刻 / Root / Targets 即拒绝', async () => {
  const { input } = buildExpiredTargets();
  assertEq((await verifyReview({ ...input, reviewTime: 'not-a-time' })).evidence.code, 'INVALID_REVIEW_TIME');
  assertEq((await verifyReview({ ...input, roots: [] })).evidence.code, 'NO_ROOTS');
  assertEq((await verifyReview({ ...input, targets: '' })).evidence.code, 'NO_TARGETS');
});

// ---------- 运行器 ----------

export async function runRuleTests(log = console.log) {
  let passed = 0;
  const failures = [];
  for (const { name, fn } of tests) {
    try {
      await fn();
      passed++;
      log(`  ✓ ${name}`);
    } catch (err) {
      failures.push({ name, err });
      log(`  ✗ ${name}\n    ${err.message}`);
    }
  }
  log(`  规则测试合计：${passed} 通过，${failures.length} 失败`);
  return { passed, failed: failures.length, failures };
}

const invokedAsMain =
  process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedAsMain) {
  const { failed } = await runRuleTests();
  process.exit(failed > 0 ? 1 : 0);
}

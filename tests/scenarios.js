// 三个验收示例场景：合法轮换、旧根单签拒绝、过期 Targets。
// 同时供规则测试断言与页面「载入示例」fixtures 使用。

import * as h from './helpers.js';

export const REVIEW_TIME = '2026-10-05T00:00:00Z';

// 合法轮换：v1 → v2 → v3 连续轮换，每轮均满足双阈值；Targets 由最终根 targets 角色足额签名。
export function buildLegitRotation() {
  const A = h.genKey('A');
  const B = h.genKey('B');
  const C = h.genKey('C');
  const D = h.genKey('D');
  const Ta = h.genKey('Ta');
  const Tb = h.genKey('Tb');
  const Tc = h.genKey('Tc');

  const v1 = h.makeRoot({
    version: 1,
    keys: [A, B, Ta, Tb],
    rootKeys: [A, B],
    rootThreshold: 2,
    targetsKeys: [Ta, Tb],
    targetsThreshold: 2,
  });
  h.addSignature(v1, A);
  h.addSignature(v1, B);

  const v2 = h.makeRoot({
    version: 2,
    keys: [B, C, Ta, Tb],
    rootKeys: [B, C],
    rootThreshold: 2,
    targetsKeys: [Ta, Tb],
    targetsThreshold: 2,
  });
  h.addSignature(v2, A); // 前一 Root 授权
  h.addSignature(v2, B); // 前一 Root + 自身
  h.addSignature(v2, C); // 自身授权

  const v3 = h.makeRoot({
    version: 3,
    keys: [C, D, Tc],
    rootKeys: [C, D],
    rootThreshold: 2,
    targetsKeys: [Tc],
    targetsThreshold: 1,
  });
  h.addSignature(v3, B); // 前一 Root 授权
  h.addSignature(v3, C); // 前一 Root + 自身
  h.addSignature(v3, D); // 自身授权

  const targets = h.makeTargets({ version: 1, expires: '2030-01-01T00:00:00Z' });
  h.addSignature(targets, Tc);

  return {
    name: 'legit-rotation',
    title: '合法轮换',
    input: {
      reviewTime: REVIEW_TIME,
      roots: [h.toText(v1), h.toText(v2), h.toText(v3)],
      targets: h.toText(targets),
    },
  };
}

// 旧根单签拒绝：候选 v2 只获得前一 Root 的足额授权，自身 root 角色零授权。
export function buildOldRootOnly() {
  const A = h.genKey('A');
  const B = h.genKey('B');
  const C = h.genKey('C');
  const D = h.genKey('D');
  const Ta = h.genKey('Ta');

  const v1 = h.makeRoot({
    version: 1,
    keys: [A, B, Ta],
    rootKeys: [A, B],
    rootThreshold: 2,
    targetsKeys: [Ta],
    targetsThreshold: 1,
  });
  h.addSignature(v1, A);
  h.addSignature(v1, B);

  const v2 = h.makeRoot({
    version: 2,
    keys: [C, D, Ta],
    rootKeys: [C, D],
    rootThreshold: 2,
    targetsKeys: [Ta],
    targetsThreshold: 1,
  });
  h.addSignature(v2, A); // 仅旧根达阈值
  h.addSignature(v2, B);

  const targets = h.makeTargets({ version: 1, expires: '2030-01-01T00:00:00Z' });
  h.addSignature(targets, Ta);

  return {
    name: 'old-root-only',
    title: '旧根单签拒绝',
    input: {
      reviewTime: REVIEW_TIME,
      roots: [h.toText(v1), h.toText(v2)],
      targets: h.toText(targets),
    },
  };
}

// 过期 Targets：链与签名均有效，但审查时刻晚于 Targets 过期时间。
export function buildExpiredTargets() {
  const A = h.genKey('A');
  const B = h.genKey('B');
  const Ta = h.genKey('Ta');
  const Tb = h.genKey('Tb');

  const v1 = h.makeRoot({
    version: 1,
    keys: [A, B, Ta, Tb],
    rootKeys: [A, B],
    rootThreshold: 2,
    targetsKeys: [Ta, Tb],
    targetsThreshold: 2,
  });
  h.addSignature(v1, A);
  h.addSignature(v1, B);

  const targets = h.makeTargets({ version: 1, expires: '2026-06-01T00:00:00Z' });
  h.addSignature(targets, Ta);
  h.addSignature(targets, Tb);

  return {
    name: 'expired-targets',
    title: '过期 Targets',
    input: {
      reviewTime: REVIEW_TIME,
      roots: [h.toText(v1)],
      targets: h.toText(targets),
    },
  };
}

// 受委托目标允许：Root 链与顶层 Targets 通过后，目标 pkg/app-2.0.0.bin 只能由
// 命中路径规则的委托角色 pkg（threshold 2）发布；实际采用角色与摘要来自子元数据。
export function buildDelegatedTarget() {
  const A = h.genKey('A');
  const B = h.genKey('B');
  const Ta = h.genKey('Ta');
  const D1 = h.genKey('D1');
  const D2 = h.genKey('D2');

  const v1 = h.makeRoot({
    version: 1,
    keys: [A, B, Ta],
    rootKeys: [A, B],
    rootThreshold: 2,
    targetsKeys: [Ta],
    targetsThreshold: 1,
  });
  h.addSignature(v1, A);
  h.addSignature(v1, B);

  const targetName = 'pkg/app-2.0.0.bin';
  const targets = h.makeTargets({
    version: 1,
    expires: '2030-01-01T00:00:00Z',
    targets: { 'other.txt': h.targetMeta('top-level-only') },
    delegations: h.delegationsOf([D1, D2], [
      h.delegationRole('pkg', [D1, D2], { threshold: 2, paths: ['pkg/*'], terminating: true }),
    ]),
  });
  h.addSignature(targets, Ta);

  const delegated = h.makeDelegatedTargets({
    version: 1,
    expires: '2030-01-01T00:00:00Z',
    targets: { [targetName]: h.targetMeta('delegated-payload') },
  });
  h.addSignature(delegated, D1);
  h.addSignature(delegated, D2);

  return {
    name: 'delegated-target',
    title: '委托目标授权',
    input: {
      reviewTime: REVIEW_TIME,
      roots: [h.toText(v1)],
      targets: h.toText(targets),
      targetName,
      delegatedTargets: h.toText(delegated),
    },
  };
}

// 终止性委托失败拒绝：目标命中 terminating 委托，但子元数据签名未达阈值；
// 即使顶层 Targets 含同名目标摘要，也必须停止并拒绝，不得把顶层同名条目当作允许证据。
export function buildDelegatedTerminatingFailure() {
  const A = h.genKey('A');
  const B = h.genKey('B');
  const Ta = h.genKey('Ta');
  const D1 = h.genKey('D1');
  const D2 = h.genKey('D2');

  const v1 = h.makeRoot({
    version: 1,
    keys: [A, B, Ta, D1, D2],
    rootKeys: [A, B],
    rootThreshold: 2,
    targetsKeys: [Ta],
    targetsThreshold: 1,
  });
  h.addSignature(v1, A);
  h.addSignature(v1, B);

  const targetName = 'pkg/app-2.0.0.bin';
  const targets = h.makeTargets({
    version: 1,
    expires: '2030-01-01T00:00:00Z',
    // 顶层同名摘要（诱饵）：terminating 命中失败时不得采用
    targets: { [targetName]: h.targetMeta('top-level-decoy') },
    delegations: h.delegationsOf([D1, D2], [
      h.delegationRole('pkg', [D1, D2], { threshold: 2, paths: ['pkg/*'], terminating: true }),
    ]),
  });
  h.addSignature(targets, Ta);

  const delegated = h.makeDelegatedTargets({
    version: 1,
    expires: '2030-01-01T00:00:00Z',
    targets: { [targetName]: h.targetMeta('delegated-payload') },
  });
  h.addSignature(delegated, D1); // 阈值 2，仅 1 签

  return {
    name: 'delegated-terminating-failure',
    title: '终止委托失败拒绝',
    input: {
      reviewTime: REVIEW_TIME,
      roots: [h.toText(v1)],
      targets: h.toText(targets),
      targetName,
      delegatedTargets: h.toText(delegated),
    },
  };
}

export const scenarioBuilders = [
  buildLegitRotation,
  buildOldRootOnly,
  buildExpiredTargets,
  buildDelegatedTarget,
  buildDelegatedTerminatingFailure,
];

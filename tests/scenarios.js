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

// 委托目标：顶层 Targets 声明两级委托（按声明顺序）——
//   frontend（terminating，路径 app-*，D1+D2 阈值 2）→ misc（非终止，路径 *，D3 阈值 1）。
// 目标 app-2.0.0.bin 只出现在 frontend 的受委托元数据中。
export function buildDelegatedTarget() {
  const A = h.genKey('A');
  const B = h.genKey('B');
  const Ta = h.genKey('Ta');
  const D1 = h.genKey('D1');
  const D2 = h.genKey('D2');
  const D3 = h.genKey('D3');

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

  const targets = h.makeTargets({
    version: 1,
    expires: '2030-01-01T00:00:00Z',
    targets: {
      'base.txt': { length: 10, hashes: { sha256: h.digestOf('base-payload') } },
    },
  });
  targets.signed.delegations = {
    keys: {
      [h.keyidOf(D1)]: h.keyObjectOf(D1),
      [h.keyidOf(D2)]: h.keyObjectOf(D2),
      [h.keyidOf(D3)]: h.keyObjectOf(D3),
    },
    roles: [
      {
        name: 'frontend',
        keyids: [h.keyidOf(D1), h.keyidOf(D2)],
        threshold: 2,
        terminating: true,
        paths: ['app-*'],
      },
      {
        name: 'misc',
        keyids: [h.keyidOf(D3)],
        threshold: 1,
        terminating: false,
        paths: ['*'],
      },
    ],
  };
  h.addSignature(targets, Ta);

  const delegated = h.makeTargets({
    version: 1,
    expires: '2030-01-01T00:00:00Z',
    targets: {
      'app-2.0.0.bin': { length: 2048, hashes: { sha256: h.digestOf('app-2.0.0-payload') } },
    },
  });
  h.addSignature(delegated, D1);
  h.addSignature(delegated, D2);

  return {
    name: 'delegated-target',
    title: '委托目标',
    keys: { A, B, Ta, D1, D2, D3 },
    input: {
      reviewTime: REVIEW_TIME,
      roots: [h.toText(v1)],
      targets: h.toText(targets),
      targetName: 'app-2.0.0.bin',
      delegatedTargets: h.toText(delegated),
    },
  };
}

export const scenarioBuilders = [buildLegitRotation, buildOldRootOnly, buildExpiredTargets, buildDelegatedTarget];

// Compose 验收入口（verify 服务）：
//   1) 页面构建；2) 代码规则测试（合法轮换 / 旧根单签拒绝 / 过期 Targets 等）；
//   3) 健康接口与静态资源 HTTP 冒烟。
// 全部完成后退出，以退出码报告验收状态（0 通过 / 1 失败）。

import { build } from './build.js';
import { runRuleTests } from '../tests/run-tests.js';

const BASE_URL = (process.env.SMOKE_BASE_URL || 'http://127.0.0.1:8080').replace(/\/$/, '');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitForHealth(attempts = 30) {
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(`${BASE_URL}/health`);
      if (res.ok) return;
    } catch {
      // 服务尚未就绪，继续等待
    }
    await sleep(1000);
  }
  throw new Error(`健康接口等待超时：${BASE_URL}/health`);
}

async function expectOk(name, path, check) {
  const res = await fetch(`${BASE_URL}${path}`);
  if (!res.ok) throw new Error(`${name}：HTTP ${res.status}`);
  if (check) await check(res);
  console.log(`  ✓ ${name}（GET ${path} → ${res.status}）`);
}

async function runSmoke() {
  console.log(`== [3/3] 健康接口 HTTP 冒烟（${BASE_URL}）==`);
  await waitForHealth();
  await expectOk('健康接口返回 ok', '/health', async (res) => {
    const body = await res.json();
    if (body?.status !== 'ok') throw new Error(`健康接口返回异常：${JSON.stringify(body)}`);
  });
  await expectOk('静态页面可访问', '/', async (res) => {
    const html = await res.text();
    if (!html.includes('离线复核')) throw new Error('首页内容不符合预期');
  });
  await expectOk('Worker 脚本可访问', '/worker.js');
  await expectOk('复核引擎模块可访问', '/vendor/verifier.js');
  await expectOk('示例 fixture 可访问', '/fixtures/legit-rotation.json', async (res) => {
    const body = await res.json();
    if (!Array.isArray(body?.roots) || body.roots.length === 0 || !body.targets) {
      throw new Error('示例 fixture 结构不完整');
    }
  });
}

async function main() {
  let ok = true;

  console.log('== [1/3] 页面构建 ==');
  try {
    const { dist, fixtures } = await build();
    console.log(`  ✓ 构建完成：${dist}（示例：${fixtures.join(', ')}）`);
  } catch (err) {
    ok = false;
    console.error(`  ✗ 页面构建失败：${err.message}`);
  }

  console.log('== [2/3] 代码规则测试 ==');
  try {
    const { failed } = await runRuleTests();
    if (failed > 0) ok = false;
  } catch (err) {
    ok = false;
    console.error(`  ✗ 规则测试执行异常：${err.message}`);
  }

  try {
    await runSmoke();
  } catch (err) {
    ok = false;
    console.error(`  ✗ 冒烟失败：${err.message}`);
  }

  console.log(ok ? '验收通过（exit 0）' : '验收失败（exit 1）');
  process.exit(ok ? 0 : 1);
}

await main();

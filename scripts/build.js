// 页面构建：拷贝静态资源与共享模块到 dist/，生成示例 fixtures，并校验模块可解析。

import { rm, mkdir, cp, access } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { generateFixtures } from './generate-fixtures.js';

const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export async function build() {
  const dist = path.join(ROOT_DIR, 'dist');
  await rm(dist, { recursive: true, force: true });
  await mkdir(dist, { recursive: true });

  // 静态页面与 Worker
  await cp(path.join(ROOT_DIR, 'web'), dist, { recursive: true });
  // 复核引擎（Worker 以 ./vendor/verifier.js 引入）
  await cp(path.join(ROOT_DIR, 'src'), path.join(dist, 'vendor'), { recursive: true });
  // 页面示例
  const fixtures = await generateFixtures(path.join(dist, 'fixtures'));

  // 构建校验：模块可解析、关键产物存在
  await import(pathToFileURL(path.join(dist, 'vendor', 'verifier.js')).href);
  for (const required of ['index.html', 'app.js', 'worker.js', 'style.css']) {
    await access(path.join(dist, required));
  }
  return { dist, fixtures };
}

const invokedAsMain =
  process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedAsMain) {
  try {
    const { dist, fixtures } = await build();
    console.log(`页面构建完成：${dist}`);
    console.log(`示例 fixtures：${fixtures.join(', ')}`);
  } catch (err) {
    console.error(`页面构建失败：${err.message}`);
    process.exit(1);
  }
}

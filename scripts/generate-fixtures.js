// 示例 fixtures 生成：与规则测试共用同一批场景构造器，产物供页面「载入示例」使用。

import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { scenarioBuilders } from '../tests/scenarios.js';

export async function generateFixtures(outDir) {
  await mkdir(outDir, { recursive: true });
  const names = [];
  for (const build of scenarioBuilders) {
    const scenario = build();
    const payload = {
      name: scenario.name,
      title: scenario.title,
      reviewTime: scenario.input.reviewTime,
      roots: scenario.input.roots,
      targets: scenario.input.targets,
    };
    await writeFile(
      path.join(outDir, `${scenario.name}.json`),
      JSON.stringify(payload, null, 2) + '\n',
      'utf8'
    );
    names.push(scenario.name);
  }
  return names;
}

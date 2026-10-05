// 页面交互：收集录入 → 交给 Worker 离线复核 → 逐轮渲染可信根、达阈值签名者与首个阻断证据。

const MAX_ROOTS = 6;

const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// ---------- 录入区 ----------

function buildRootSlots() {
  const container = $('root-slots');
  for (let i = 0; i < MAX_ROOTS; i++) {
    const label = el('label', 'field');
    const title = i === 0 ? `Root 元数据 #${i + 1}（锚点 · 初始可信根）` : `Root 元数据 #${i + 1}（可留空）`;
    label.appendChild(el('span', null, title));
    const textarea = el('textarea');
    textarea.id = `root-${i}`;
    textarea.rows = 6;
    textarea.spellcheck = false;
    textarea.placeholder = i === 0 ? '版本最低的 Root（按版本升序录入）' : '留空即忽略';
    label.appendChild(textarea);
    container.appendChild(label);
  }
}

function collectInput() {
  const roots = [];
  for (let i = 0; i < MAX_ROOTS; i++) {
    const value = $(`root-${i}`).value.trim();
    if (value) roots.push(value);
  }
  return {
    reviewTime: $('review-time').value.trim(),
    roots,
    targets: $('targets-input').value.trim(),
    targetName: $('target-name').value.trim(),
    delegatedTargets: $('delegated-input').value.trim(),
  };
}

function fillInput({ reviewTime, roots, targets, targetName, delegatedTargets }) {
  $('review-time').value = reviewTime ?? '';
  for (let i = 0; i < MAX_ROOTS; i++) {
    $(`root-${i}`).value = roots?.[i] ?? '';
  }
  $('targets-input').value = targets ?? '';
  $('target-name').value = targetName ?? '';
  $('delegated-input').value = delegatedTargets ?? '';
}

// ---------- Worker ----------

function runInWorker(payload) {
  return new Promise((resolve, reject) => {
    const worker = new Worker('worker.js', { type: 'module' });
    const timer = setTimeout(() => {
      worker.terminate();
      reject(new Error('复核超时'));
    }, 30000);
    worker.onmessage = (event) => {
      clearTimeout(timer);
      worker.terminate();
      if (event.data.ok) resolve(event.data.result);
      else reject(new Error(event.data.error));
    };
    worker.onerror = (event) => {
      clearTimeout(timer);
      worker.terminate();
      reject(new Error(event.message || 'Worker 执行失败'));
    };
    worker.postMessage(payload);
  });
}

// ---------- 渲染 ----------

function keyChip(keyid) {
  return el('code', 'chip', `${keyid.slice(0, 16)}…`);
}

function signerLine(labelText, info) {
  const line = el('div', 'signer-line');
  const reached = info.signers.length >= info.required;
  line.appendChild(el('span', 'signer-label', labelText));
  line.appendChild(el('span', reached ? 'count ok' : 'count bad', `${info.signers.length}/${info.required}`));
  const chips = el('span', 'chips');
  for (const keyid of info.signers) chips.appendChild(keyChip(keyid));
  line.appendChild(chips);
  return line;
}

function evidenceBlock(ev) {
  const box = el('div', 'evidence');
  box.appendChild(el('span', 'evidence-title', '首个阻断证据'));
  box.appendChild(el('code', 'evidence-code', ev.code));
  box.appendChild(el('span', 'evidence-msg', ev.message));
  return box;
}

function statusBadge(ok, okText, badText) {
  return el('span', ok ? 'badge ok' : 'badge bad', ok ? okText : badText);
}

function renderRounds(rounds) {
  const container = $('rounds');
  container.replaceChildren();
  for (const round of rounds) {
    const card = el('div', `card ${round.status}`);
    const head = el('div', 'card-head');
    if (round.type === 'anchor') {
      head.appendChild(el('strong', null, `第 0 轮 · 锚点 · Root v${round.trustedVersion ?? '—'}`));
      head.appendChild(statusBadge(round.status === 'trusted', '可信', '拒绝'));
    } else {
      const transition =
        round.status === 'accepted'
          ? `v${round.trustedVersionBefore} → v${round.trustedVersionAfter}`
          : `v${round.trustedVersionBefore}（保留）`;
      head.appendChild(
        el('strong', null, `第 ${round.round} 轮 · 候选 v${round.candidateVersion ?? '?'} · 可信根 ${transition}`)
      );
      head.appendChild(statusBadge(round.status === 'accepted', '接受', '拒绝'));
    }
    card.appendChild(head);
    if (round.note) card.appendChild(el('p', 'note', round.note));
    if (round.prev) card.appendChild(signerLine('前一 Root root 角色达阈值签名者', round.prev));
    if (round.self) card.appendChild(signerLine('候选自身 root 角色达阈值签名者', round.self));
    if (round.evidence) card.appendChild(evidenceBlock(round.evidence));
    container.appendChild(card);
  }
}

function renderDelegationTrace(trace) {
  const wrap = el('div', 'delegation');
  wrap.appendChild(el('p', 'note strong-note', '顶层 Targets 委托解析（按声明顺序匹配目标名）'));
  if (!trace || trace.length === 0) {
    wrap.appendChild(el('p', 'note', '未产生任何委托解析记录（顶层 Targets 未声明 delegations，或其声明在下方被阻断）。'));
    return wrap;
  }
  for (const entry of trace) {
    const row = el('div', `deleg-row ${entry.status}`);
    const head = el('div', 'deleg-head');
    const term = entry.terminating ? '终止性' : '未终止';
    head.appendChild(el('span', 'deleg-name', `角色 ${entry.role}（${term}）`));
    const statusText = {
      skipped: '路径未命中 · 跳过',
      missing: '命中但未提供子元数据 · 继续',
      rejected: entry.match ? '命中 · 校验失败' : '路径未命中',
      accepted: '命中 · 采用',
    }[entry.status] ?? entry.status;
    const ok = entry.status === 'accepted';
    const neutral = entry.status === 'skipped' || entry.status === 'missing';
    const badge = neutral
      ? el('span', 'badge neutral', statusText)
      : statusBadge(ok, statusText, statusText);
    head.appendChild(badge);
    row.appendChild(head);
    const pathLine = el('p', 'note');
    pathLine.textContent = `路径规则：${entry.paths.join('、')}` +
      (entry.matchedPath ? `　命中：${entry.matchedPath}` : '　（无命中）');
    row.appendChild(pathLine);
    if (entry.signers) {
      row.appendChild(signerLine('委托角色达阈值签名者', {
        required: entry.required,
        signers: entry.signers,
      }));
    }
    if (entry.version) {
      row.appendChild(el('p', 'note', `受委托 Targets v${entry.version}，过期时间 ${entry.expires}`));
    }
    if (entry.evidence) row.appendChild(evidenceBlock(entry.evidence));
    wrap.appendChild(row);
  }
  return wrap;
}

function renderResolution(resolution) {
  if (!resolution) return null;
  const box = el('div', 'resolution');
  box.appendChild(el('p', 'note strong-note', '最终目标判定'));
  const line1 = el('p', 'note');
  line1.appendChild(el('span', null, `目标 ${resolution.target} 实际采用角色：`));
  line1.appendChild(el('code', 'chip', resolution.adoptedRole));
  box.appendChild(line1);
  const line2 = el('p', 'note');
  line2.textContent = resolution.matchedPath
    ? `命中的路径规则：${resolution.matchedPath}`
    : '未命中任何委托路径规则，由顶层 targets 角色直接发布';
  box.appendChild(line2);
  box.appendChild(signerLine('达阈值的不同签名者', {
    required: resolution.required,
    signers: resolution.signers,
  }));
  const alg = Object.prototype.hasOwnProperty.call(resolution.meta.hashes, 'sha256')
    ? 'sha256'
    : Object.keys(resolution.meta.hashes)[0];
  const digest = el('p', 'note digest-line');
  digest.appendChild(el('span', null, '最终目标摘要：'));
  digest.appendChild(el('code', 'chip digest', `${alg}:${resolution.meta.hashes[alg]}`));
  digest.appendChild(el('span', null, `（length ${resolution.meta.length}）`));
  box.appendChild(digest);
  return box;
}

function renderTargetsStage(targets) {
  const container = $('targets-stage');
  container.replaceChildren();
  if (!targets) {
    container.appendChild(el('p', 'note', '未执行：Root 链已被拒绝，保留此前可信根。'));
    return;
  }
  const card = el('div', `card ${targets.status}`);
  const head = el('div', 'card-head');
  head.appendChild(el('strong', null, `Targets v${targets.version ?? '?'}`));
  head.appendChild(statusBadge(targets.status === 'accepted', '通过', '拒绝'));
  card.appendChild(head);
  card.appendChild(signerLine('targets 角色达阈值签名者', {
    required: targets.required,
    signers: targets.signers,
  }));
  if (targets.expires) {
    const expiry = el('p', 'note');
    expiry.textContent = `过期时间 ${targets.expires}` + (targets.expired ? '（审查时刻已晚于过期时间）' : '（未过期）');
    card.appendChild(expiry);
  }
  if (targets.targetNames?.length) {
    const list = el('ul', 'target-list');
    for (const name of targets.targetNames) list.appendChild(el('li', null, name));
    card.appendChild(el('p', 'note', `目标摘要：共 ${targets.targetNames.length} 个目标`));
    card.appendChild(list);
  }
  if (targets.targetName) {
    card.appendChild(renderDelegationTrace(targets.delegationTrace));
    const resolutionNode = renderResolution(targets.resolution);
    if (resolutionNode) card.appendChild(resolutionNode);
  }
  if (targets.evidence) card.appendChild(evidenceBlock(targets.evidence));
  container.appendChild(card);
}

function renderConclusion(result) {
  const container = $('conclusion');
  container.replaceChildren();
  const card = el('div', `card ${result.ok ? 'accepted' : 'rejected'}`);
  const head = el('div', 'card-head');
  head.appendChild(el('strong', null, result.ok ? '结论：允许' : '结论：拒绝'));
  head.appendChild(statusBadge(result.ok, 'ALLOW', 'REJECT'));
  card.appendChild(head);
  card.appendChild(
    el('p', 'note', `最终根版本：v${result.finalRootVersion ?? '—'}`)
  );
  if (result.ok) {
    const summary = result.summary;
    if (summary.targetName) {
      card.appendChild(
        el('p', 'note', `最终目标：${summary.targetName}，实际采用角色 ${summary.adoptedRole}` +
          (summary.matchedPath ? `（命中路径规则 ${summary.matchedPath}）` : '（顶层 targets 直接发布）'))
      );
      card.appendChild(
        el('p', 'note', `最终目标摘要：${summary.targetDigest}（length ${summary.targetLength}）`)
      );
      card.appendChild(
        el('p', 'note', `达阈值的不同签名者：${summary.targetSigners.length}/${summary.targetSignerRequired}`)
      );
    } else {
      card.appendChild(
        el('p', 'note', `最终允许的目标摘要：Targets v${summary.targetsVersion}，共 ${summary.targetCount} 个目标（${summary.targetNames.join('、') || '无'}）`)
      );
    }
  } else if (result.evidence) {
    card.appendChild(evidenceBlock(result.evidence));
  }
  container.appendChild(card);
}

function renderResult(result) {
  renderRounds(result.rounds);
  renderTargetsStage(result.targets);
  renderConclusion(result);
  $('result-panel').hidden = false;
  $('error-panel').hidden = true;
  $('result-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function showError(err) {
  $('error-text').textContent = String(err?.message ?? err);
  $('error-panel').hidden = false;
  $('result-panel').hidden = true;
}

// ---------- 事件 ----------

async function onVerify() {
  $('btn-verify').disabled = true;
  $('busy').hidden = false;
  try {
    const result = await runInWorker(collectInput());
    renderResult(result);
  } catch (err) {
    showError(err);
  } finally {
    $('btn-verify').disabled = false;
    $('busy').hidden = true;
  }
}

async function onLoadFixture(name) {
  try {
    const res = await fetch(`fixtures/${name}.json`);
    if (!res.ok) throw new Error(`示例加载失败：HTTP ${res.status}`);
    fillInput(await res.json());
    $('result-panel').hidden = true;
    $('error-panel').hidden = true;
  } catch (err) {
    showError(err);
  }
}

function init() {
  buildRootSlots();
  $('review-time').value = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  $('btn-verify').addEventListener('click', onVerify);
  $('btn-clear').addEventListener('click', () => {
    fillInput({});
    $('result-panel').hidden = true;
    $('error-panel').hidden = true;
  });
  document.querySelectorAll('[data-fixture]').forEach((btn) => {
    btn.addEventListener('click', () => onLoadFixture(btn.dataset.fixture));
  });
}

init();

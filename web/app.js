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
  };
}

function fillInput({ reviewTime, roots, targets }) {
  $('review-time').value = reviewTime ?? '';
  for (let i = 0; i < MAX_ROOTS; i++) {
    $(`root-${i}`).value = roots?.[i] ?? '';
  }
  $('targets-input').value = targets ?? '';
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
    card.appendChild(
      el('p', 'note', `最终允许的目标摘要：Targets v${summary.targetsVersion}，共 ${summary.targetCount} 个目标（${summary.targetNames.join('、') || '无'}）`)
    );
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

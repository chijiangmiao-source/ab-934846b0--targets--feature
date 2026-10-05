// 复核 Worker：在后台线程内执行全部验签与规则计算，主线程只收发消息。

import { verifyReview } from './vendor/verifier.js';

self.onmessage = async (event) => {
  try {
    const result = await verifyReview(event.data);
    self.postMessage({ ok: true, result });
  } catch (err) {
    self.postMessage({ ok: false, error: err?.message ?? String(err) });
  }
};

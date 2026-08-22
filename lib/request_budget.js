// lib/request_budget.js
// A monotonic request budget used to prevent sequential provider fallbacks from
// exceeding the response-time budget. It retains no user data.

export function positiveInteger(value, fallback, maximum) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed < 1) return fallback;
  return Math.min(parsed, maximum);
}

export function createRequestBudget({
  // Leave headroom beneath the explicit 10s Vercel function ceiling for response
  // serialization and platform overhead. This is an accuracy-first budget, not a
  // promise that every external provider will answer within the window.
  totalMs = positiveInteger(process.env.VERIFYPULSE_SCAN_BUDGET_MS, 8500, 9000),
  clock = () => Date.now(),
} = {}) {
  const startedAt = clock();
  const deadlineAt = startedAt + totalMs;

  function remainingMs() {
    return Math.max(0, deadlineAt - clock());
  }

  function canStart(minimumMs = 250) {
    return remainingMs() >= minimumMs;
  }

  function timeoutFor({ capMs = 1200, minimumMs = 250 } = {}) {
    const remaining = remainingMs();
    if (remaining < minimumMs) return 0;
    return Math.max(minimumMs, Math.min(capMs, remaining));
  }

  return {
    startedAt,
    deadlineAt,
    totalMs,
    elapsedMs: () => Math.max(0, clock() - startedAt),
    remainingMs,
    canStart,
    timeoutFor,
  };
}

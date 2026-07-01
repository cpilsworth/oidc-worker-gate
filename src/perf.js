/**
 * Lightweight request tracer for the performance harness (off by default).
 *
 * The gate's fetch handler marks phase boundaries with `t.phase(name)`. The
 * elapsed wall time between two marks is attributed to the first phase. I/O wait
 * (KV reads, the origin subrequest) is reported separately via `recordIo(kind)`
 * and attributed to the open phase, so each phase decomposes into:
 *
 *     cpu  = wall − wait        (on-CPU compute: parsing, crypto, regex)
 *     wait = KV + origin time   (off-CPU: blocked on a subrequest)
 *
 * This decomposition matters because Cloudflare bills and limits **CPU time**,
 * not wall time — `await fetch(origin)` can dominate latency while costing the
 * worker almost no CPU. Splitting the two is what tells you whether an
 * optimisation should target compute or I/O.
 *
 * Production passes no tracer, so `index.js` falls back to `NOOP` — a frozen bag
 * of empty methods. The only residual cost on the hot path is a handful of
 * empty method calls (no `performance.now()`, no allocation), which the
 * harness measures as the observer effect (see the report).
 */

export class Tracer {
  constructor() {
    this.total = 0;
    this.phases = [];
    this._cur = null;
    this._t0 = 0;
  }

  /** Mark the start of a traced request. */
  begin() {
    this._t0 = performance.now();
    this._cur = null;
    this.phases = [];
    this.total = 0;
  }

  /** Close the current phase (if any) and open `name`. */
  phase(name) {
    const now = performance.now();
    if (this._cur) this._cur.wall = now - this._cur._start;
    this._cur = { name, _start: now, wall: 0, waitKv: 0, waitOrigin: 0, kvOps: 0, originOps: 0 };
    this.phases.push(this._cur);
  }

  /** Close the final phase and record total wall time. Idempotent. */
  end() {
    const now = performance.now();
    if (this._cur) {
      this._cur.wall = now - this._cur._start;
      this._cur = null;
    }
    this.total = now - this._t0;
  }

  /**
   * Attribute `ms` of off-CPU wait to the currently open phase.
   * @param {"kv"|"origin"} kind
   * @param {number} ms
   */
  recordIo(kind, ms) {
    if (!this._cur) return;
    if (kind === "kv") { this._cur.waitKv += ms; this._cur.kvOps += 1; }
    else { this._cur.waitOrigin += ms; this._cur.originOps += 1; }
  }

  /** Snapshot the decomposed timings for this request. */
  report() {
    const phases = this.phases.map((p) => {
      const wait = p.waitKv + p.waitOrigin;
      return {
        name: p.name,
        wall: p.wall,
        wait,
        waitKv: p.waitKv,
        waitOrigin: p.waitOrigin,
        kvOps: p.kvOps,
        originOps: p.originOps,
        cpu: Math.max(0, p.wall - wait),
      };
    });
    const cpu = phases.reduce((s, p) => s + p.cpu, 0);
    const wait = phases.reduce((s, p) => s + p.wait, 0);
    const kvOps = phases.reduce((s, p) => s + p.kvOps, 0);
    const originOps = phases.reduce((s, p) => s + p.originOps, 0);
    return { total: this.total, cpu, wait, kvOps, originOps, phases };
  }
}

/** No-op tracer used in production: empty methods, no clock reads, no allocation. */
export const NOOP = Object.freeze({
  begin() {},
  phase() {},
  end() {},
  recordIo() {},
  report() {
    return null;
  },
});

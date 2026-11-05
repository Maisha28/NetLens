/* Hand-drawn charts (canvas / SVG) for the light theme. No libraries, nothing fetched at demo time. */
"use strict";

const INK = "#172033", SUB = "#55627a", GRIDC = "#e6ebf3";
const SANS = () => getComputedStyle(document.body).getPropertyValue("--sans") || "sans-serif";
const MONO = () => getComputedStyle(document.body).getPropertyValue("--mono") || "monospace";

function prepCanvas(canvas, height) {
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || canvas.parentElement.clientWidth || 600;
  canvas.style.height = height + "px";
  if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(height * dpr)) {
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(height * dpr);
  }
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, height);
  return { ctx, w, h: height };
}

function niceMax(v) {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  const n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
}

/* ------------------------------------------------------ throughput (one series) */
const Throughput = {
  /** series rows: [t, bytes, packets, tcp, udp, arp, other]; alerts: [{ts, rule}] */
  draw(canvas, series, alerts) {
    const { ctx, w, h } = prepCanvas(canvas, 260);
    const padL = 66, padR = 14, padT = 18, padB = 32;
    const cw = w - padL - padR, ch = h - padT - padB;
    if (!series.length) return;

    const total = series.map((r) => r[1]);
    const sm = total.map((_, i) => (total[Math.max(0, i - 1)] + total[i] * 2 + total[Math.min(total.length - 1, i + 1)]) / 4);
    const max = niceMax(Math.max(...sm, 1) * 1.15);
    const x = (i) => padL + (i / (series.length - 1)) * cw;
    const y = (v) => padT + ch - (v / max) * ch;

    ctx.font = `13.5px ${SANS()}`; ctx.lineWidth = 1;
    for (let g = 0; g <= 3; g++) {
      const v = (max * g) / 3, yy = y(v);
      ctx.strokeStyle = GRIDC; ctx.beginPath(); ctx.moveTo(padL, yy); ctx.lineTo(w - padR, yy); ctx.stroke();
      ctx.fillStyle = SUB; ctx.textAlign = "right"; ctx.fillText(fmt.rate(v), padL - 10, yy + 5);
    }
    ctx.textAlign = "center"; ctx.fillStyle = SUB;
    for (const back of [120, 90, 60, 30, 0]) {
      const i = series.length - 1 - back;
      if (i >= 0) ctx.fillText(back === 0 ? "now" : `${back}s ago`, x(i), h - 8);
    }

    const grad = ctx.createLinearGradient(0, padT, 0, padT + ch);
    grad.addColorStop(0, "rgba(36,86,216,.30)"); grad.addColorStop(1, "rgba(36,86,216,.02)");
    ctx.beginPath(); sm.forEach((v, i) => (i ? ctx.lineTo(x(i), y(v)) : ctx.moveTo(x(i), y(v))));
    ctx.lineTo(x(sm.length - 1), y(0)); ctx.lineTo(x(0), y(0)); ctx.closePath(); ctx.fillStyle = grad; ctx.fill();
    ctx.beginPath(); sm.forEach((v, i) => (i ? ctx.lineTo(x(i), y(v)) : ctx.moveTo(x(i), y(v))));
    ctx.strokeStyle = "#2456d8"; ctx.lineWidth = 2.5; ctx.lineJoin = "round"; ctx.stroke();

    const t0 = series[0][0], t1 = series[series.length - 1][0];
    for (const a of alerts || []) {
      if (a.ts < t0 || a.ts > t1 + 1) continue;
      const xx = padL + ((a.ts - t0) / (t1 - t0)) * cw;
      ctx.strokeStyle = "#d03a3a"; ctx.lineWidth = 2; ctx.setLineDash([5, 5]);
      ctx.beginPath(); ctx.moveTo(xx, padT + 14); ctx.lineTo(xx, padT + ch); ctx.stroke(); ctx.setLineDash([]);
      ctx.fillStyle = "#d03a3a"; ctx.beginPath(); ctx.arc(xx, padT + 8, 7, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = "#fff"; ctx.font = `bold 11px ${SANS()}`; ctx.textAlign = "center"; ctx.fillText("!", xx, padT + 12);
    }
    canvas._meta = { series, padL, cw, alerts };
  },
  hover(canvas, ev) {
    const m = canvas._meta; if (!m) return;
    const r = canvas.getBoundingClientRect();
    const i = Math.round(((ev.clientX - r.left - m.padL) / m.cw) * (m.series.length - 1));
    if (i < 0 || i >= m.series.length) return tip.hide();
    const row = m.series[i];
    const near = (m.alerts || []).find((a) => Math.abs(a.ts - row[0]) < 1.6);
    tip.show(`<b>${fmt.time(row[0])}</b><span>${fmt.rate(row[1])}</span>` + (near ? `<br><b style="color:#ff9aa9">Alert: ${esc((RULES[near.rule] || {}).title || near.rule)}</b>` : ""), ev.clientX, ev.clientY);
  },
};

/* ------------------------------------------------- per-device usage history */
const HostChart = {
  /** history: [{bytes, base_bytes, ready, alert}] - bars = usage, green line = normal, amber dashes = alert level. */
  draw(canvas, history, opts = {}) {
    const { ctx, w, h } = prepCanvas(canvas, opts.height || 150);
    const padL = 64, padR = 8, padT = 10, padB = 8;
    const cw = w - padL - padR, ch = h - padT - padB, mult = opts.mult || 3;
    if (!history.length) {
      ctx.fillStyle = SUB; ctx.font = `15px ${SANS()}`; ctx.textAlign = "center";
      ctx.fillText("Collecting the first few seconds of data…", w / 2, h / 2); return;
    }
    const n = Math.max(history.length, 12), bw = cw / n;
    const peak = Math.max(...history.map((p) => Math.max(p.bytes, (p.base_bytes || 0) * mult)), 1);
    const max = niceMax(peak * 1.1), y = (v) => padT + ch - (v / max) * ch;

    ctx.font = `12.5px ${SANS()}`; ctx.lineWidth = 1;
    for (let g = 0; g <= 2; g++) {
      const v = (max * g) / 2, yy = y(v);
      ctx.strokeStyle = GRIDC; ctx.beginPath(); ctx.moveTo(padL, yy); ctx.lineTo(w - padR, yy); ctx.stroke();
      ctx.fillStyle = SUB; ctx.textAlign = "right"; ctx.fillText(fmt.bytes(v), padL - 8, yy + 4);
    }
    history.forEach((p, i) => {
      const x = padL + (n - history.length + i) * bw, top = y(p.bytes);
      ctx.fillStyle = p.alert ? "#d03a3a" : p.ready ? "#7da2f0" : "#c5cedd";
      ctx.beginPath();
      if (ctx.roundRect) ctx.roundRect(x + 2, top, Math.max(3, bw - 4), padT + ch - top, 4); else ctx.rect(x + 2, top, Math.max(3, bw - 4), padT + ch - top);
      ctx.fill();
    });
    const stepLine = (mul, color, dash, width) => {
      ctx.beginPath(); let started = false;
      history.forEach((p, i) => {
        if (p.base_bytes == null) return;
        const x0 = padL + (n - history.length + i) * bw, yy = y(p.base_bytes * mul);
        if (!started) { ctx.moveTo(x0, yy); started = true; } else ctx.lineTo(x0, yy);
        ctx.lineTo(x0 + bw, yy);
      });
      ctx.setLineDash(dash); ctx.strokeStyle = color; ctx.lineWidth = width; ctx.stroke(); ctx.setLineDash([]);
    };
    stepLine(1, "#138a55", [], 2.5);
    stepLine(mult, "#d98a1c", [6, 5], 2);
  },
};

/* ------------------------------------------------------------------ donut */
function donut(items, { size = 160, thickness = 26, center = "", sub = "" } = {}) {
  const total = items.reduce((a, b) => a + b.value, 0) || 1;
  const r = (size - thickness) / 2, c = 2 * Math.PI * r;
  let offset = 0;
  const arcs = items.map((it) => {
    const len = (it.value / total) * c;
    const seg = `<circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="${it.color}" stroke-width="${thickness}" stroke-dasharray="${Math.max(0, len - 1.5)} ${c - Math.max(0, len - 1.5)}" stroke-dashoffset="${-offset}" transform="rotate(-90 ${size / 2} ${size / 2})"><title>${esc(it.label)}: ${esc(it.text || "")}</title></circle>`;
    offset += len;
    return seg;
  }).join("");
  return `<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}">
    <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="#e9eef6" stroke-width="${thickness}"/>${arcs}
    <text x="50%" y="${sub ? "49%" : "54%"}" text-anchor="middle" fill="${INK}" font-size="${size / 6}" font-weight="750">${esc(center)}</text>
    ${sub ? `<text x="50%" y="65%" text-anchor="middle" fill="${SUB}" font-size="${size / 12}">${esc(sub)}</text>` : ""}
  </svg>`;
}

/* ------------------------------------------------------------ beacon raster */
const Raster = {
  draw(canvas, rows, now, windowSec = 180) {
    const rowH = 38, height = Math.max(110, rows.length * rowH + 44);
    const { ctx, w, h } = prepCanvas(canvas, height);
    const labelW = 250, padR = 16, top = 6, cw = w - labelW - padR;
    const x = (t) => labelW + ((t - (now - windowSec)) / windowSec) * cw;
    ctx.font = `13px ${SANS()}`; ctx.textAlign = "center";
    for (let s = 0; s <= windowSec; s += 30) {
      const xx = x(now - windowSec + s);
      ctx.strokeStyle = GRIDC; ctx.beginPath(); ctx.moveTo(xx, top); ctx.lineTo(xx, h - 26); ctx.stroke();
      ctx.fillStyle = SUB; ctx.fillText(s === windowSec ? "now" : `${windowSec - s}s ago`, xx, h - 8);
    }
    rows.forEach((r, i) => {
      const yy = top + i * rowH + rowH / 2;
      if (r.periodic) { ctx.fillStyle = "#e4f5ec"; ctx.fillRect(0, yy - rowH / 2, w, rowH); }
      ctx.textAlign = "left"; ctx.fillStyle = r.periodic ? INK : SUB; ctx.font = `${r.periodic ? "600 " : ""}15px ${SANS()}`;
      const name = r.site || r.org || r.dst;
      ctx.fillText((name.length > 20 ? name.slice(0, 19) + "…" : name), 10, yy + 5);
      for (const t of r.events) {
        if (t < now - windowSec) continue;
        ctx.beginPath(); ctx.arc(x(t), yy, 7, 0, Math.PI * 2);
        ctx.fillStyle = r.periodic ? "#138a55" : "#9bb4ec"; ctx.fill();
      }
    });
  },
};

/* ------------------------------------------------------------ network map */
class Topology {
  constructor(canvas) {
    this.canvas = canvas;
    this.nodes = new Map(); this.links = []; this.particles = [];
    this.hover = null; this.S = null; this.running = true;
    canvas.addEventListener("mousemove", (e) => this.onMove(e));
    canvas.addEventListener("mouseleave", () => { this.hover = null; tip.hide(); });
    canvas.addEventListener("click", () => { if (this.hover && this.hover.kind === "device") location.hash = "#/devices"; });
    this.loop = this.loop.bind(this);
    requestAnimationFrame(this.loop);
  }
  stop() { this.running = false; }

  update(S) {
    this.S = S;
    const hosts = S.hosts || [];
    const self = hosts.find((h) => Names.isSelf(h.ip, S));
    const devices = hosts.filter((h) => !Names.isSelf(h.ip, S));
    const nodes = new Map();
    const cx = this.canvas.clientWidth / 2, cy = this.canvas.clientHeight / 2;
    const reuse = (key, init) => this.nodes.get(key) || { ...init, x: cx, y: cy };

    const selfNode = reuse("self", {});
    Object.assign(selfNode, { key: "self", kind: "self", label: "This laptop", sub: "sees all traffic", host: self });
    nodes.set("self", selfNode);
    devices.forEach((h, i) => {
      const n = reuse("d:" + h.ip, {});
      Object.assign(n, { key: "d:" + h.ip, kind: "device", label: Names.name(h, S), sub: h.ip, host: h, icon: Names.kind(h, S), alert: h.alerted_recently, idx: i, total: devices.length });
      nodes.set(n.key, n);
    });
    const orgTotals = new Map();
    for (const h of hosts) for (const [org, bytes] of h.top_orgs || []) orgTotals.set(org, (orgTotals.get(org) || 0) + bytes);
    const orgs = [...orgTotals.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
    orgs.forEach(([org, bytes], i) => {
      const n = reuse("o:" + org, {});
      Object.assign(n, { key: "o:" + org, kind: "org", label: org === "Unknown" ? "Other servers" : org, sub: fmt.bytes(bytes), bytes, idx: i, total: orgs.length });
      nodes.set(n.key, n);
    });
    const links = [];
    const devMax = Math.max(1, ...devices.map((d) => d.bytes)), orgMax = Math.max(1, ...orgs.map((o) => o[1]));
    for (const d of devices) links.push({ a: "d:" + d.ip, b: "self", w: Math.max(.25, d.bytes / devMax), kind: "lan" });
    for (const [org, bytes] of orgs) links.push({ a: "self", b: "o:" + org, w: Math.max(.2, bytes / orgMax), kind: "wan" });
    this.nodes = nodes; this.links = links;
  }

  layout() {
    const W = this.canvas.clientWidth, H = this.canvas.clientHeight;
    const spread = (i, n, top, span) => (n === 1 ? H / 2 : top + (i / (n - 1)) * span);
    for (const n of this.nodes.values()) {
      let tx = W * 0.47, ty = H * 0.5;
      if (n.kind === "device") { tx = Math.max(110, W * 0.13); ty = spread(n.idx, n.total, H * 0.2, H * 0.6); }
      else if (n.kind === "org") { tx = W - Math.max(100, W * 0.13); ty = spread(n.idx, n.total, H * 0.14, H * 0.74); }
      n.x += (tx - n.x) * 0.14; n.y += (ty - n.y) * 0.14;
    }
  }

  onMove(e) {
    const r = this.canvas.getBoundingClientRect();
    const mx = e.clientX - r.left, my = e.clientY - r.top;
    let best = null;
    for (const n of this.nodes.values()) if (Math.abs(mx - n.x) < (n.kind === "org" ? 60 : 34) && Math.abs(my - n.y) < 30) best = n;
    this.hover = best;
    if (!best) return tip.hide();
    if (best.kind === "org") tip.show(`<b>${esc(best.label)}</b><span>${esc(best.sub)} exchanged</span>`, e.clientX, e.clientY);
    else tip.show(`<b>${esc(best.label)}</b><span>${esc(best.sub)}</span>` + (best.host ? `<br><span>${fmt.bytes(best.host.bytes)} so far</span>` : "") + (best.kind === "device" ? `<br><span>Click to open Devices</span>` : ""), e.clientX, e.clientY);
  }

  loop(now) {
    if (!this.running || !this.canvas.isConnected) return;
    const { ctx, w, h } = prepCanvas(this.canvas, this.canvas._h || 380);
    this.layout();
    const t = now / 1000;
    ctx.font = `600 12.5px ${SANS()}`; ctx.fillStyle = "#98a3b8"; ctx.textAlign = "center";
    ctx.fillText("YOUR DEVICES", Math.max(110, w * 0.13), 18);
    ctx.fillText("CAPTURE POINT", w * 0.47, 18);
    ctx.fillText("THE INTERNET", w - Math.max(100, w * 0.13), 18);

    for (const l of this.links) {
      const a = this.nodes.get(l.a), b = this.nodes.get(l.b);
      if (!a || !b) continue;
      ctx.strokeStyle = l.kind === "lan" ? "#b7c9f2" : "#c9d3e6"; ctx.lineWidth = 1.5 + l.w * 4;
      ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
      if (Math.random() < 0.03 + l.w * 0.1) this.particles.push({ l, p: 0, v: 0.5 + Math.random() * 0.5, back: Math.random() < 0.35 });
    }
    this.particles = this.particles.filter((q) => (q.p += q.v * 0.012) < 1);
    for (const q of this.particles) {
      const a = this.nodes.get(q.l.a), b = this.nodes.get(q.l.b);
      if (!a || !b) continue;
      const p = q.back ? 1 - q.p : q.p;
      ctx.beginPath(); ctx.arc(a.x + (b.x - a.x) * p, a.y + (b.y - a.y) * p, 4, 0, Math.PI * 2);
      ctx.fillStyle = q.l.kind === "lan" ? "#2456d8" : "#0f8f84"; ctx.fill();
    }
    for (const n of this.nodes.values()) this.drawNode(ctx, n, t);
    requestAnimationFrame(this.loop);
  }

  drawNode(ctx, n, t) {
    const hovered = this.hover === n;
    if (n.kind === "org") {
      const text = n.label.length > 17 ? n.label.slice(0, 16) + "…" : n.label;
      ctx.font = `600 15px ${SANS()}`;
      const w = ctx.measureText(text).width + 30;
      ctx.fillStyle = hovered ? "#e8eefc" : "#fff"; ctx.strokeStyle = hovered ? "#2456d8" : "#cdd6e3"; ctx.lineWidth = 1.6;
      ctx.beginPath(); ctx.roundRect(n.x - w / 2, n.y - 19, w, 38, 19); ctx.fill(); ctx.stroke();
      ctx.fillStyle = INK; ctx.textAlign = "center"; ctx.fillText(text, n.x, n.y + 5);
      return;
    }
    const isSelf = n.kind === "self", rad = isSelf ? 34 : 28;
    const color = isSelf ? "#0f8f84" : n.alert ? "#d03a3a" : "#2456d8";
    if (n.alert) { ctx.strokeStyle = `rgba(208,58,58,${0.3 + 0.3 * Math.sin(t * 6)})`; ctx.lineWidth = 5; ctx.beginPath(); ctx.arc(n.x, n.y, rad + 9, 0, Math.PI * 2); ctx.stroke(); }
    ctx.fillStyle = "#fff"; ctx.beginPath(); ctx.arc(n.x, n.y, rad, 0, Math.PI * 2); ctx.fill();
    ctx.strokeStyle = color; ctx.lineWidth = hovered ? 5 : 3.5; ctx.stroke();
    ctx.save(); ctx.translate(n.x, n.y); ctx.strokeStyle = color; ctx.lineWidth = 2.6; ctx.lineCap = "round"; ctx.lineJoin = "round";
    const icon = isSelf ? "laptop" : n.icon;
    if (icon === "devices") { ctx.beginPath(); ctx.roundRect(-7, -13, 14, 26, 3.5); ctx.stroke(); ctx.beginPath(); ctx.moveTo(-2.5, 8); ctx.lineTo(2.5, 8); ctx.stroke(); }
    else if (icon === "chip") { ctx.strokeRect(-8, -8, 16, 16); ctx.beginPath(); for (const d of [-3.5, 3.5]) { ctx.moveTo(d, -13); ctx.lineTo(d, -8); ctx.moveTo(d, 8); ctx.lineTo(d, 13); ctx.moveTo(-13, d); ctx.lineTo(-8, d); ctx.moveTo(8, d); ctx.lineTo(13, d); } ctx.stroke(); }
    else { ctx.strokeRect(-13, -9, 26, 16); ctx.beginPath(); ctx.moveTo(-16, 12); ctx.lineTo(16, 12); ctx.stroke(); }
    ctx.restore();
    ctx.textAlign = "center"; ctx.fillStyle = INK; ctx.font = `600 15.5px ${SANS()}`;
    ctx.fillText(n.label.length > 22 ? n.label.slice(0, 21) + "…" : n.label, n.x, n.y + rad + 20);
    ctx.fillStyle = "#7a869c"; ctx.font = `13px ${MONO()}`; ctx.fillText(n.sub || "", n.x, n.y + rad + 37);
  }
}

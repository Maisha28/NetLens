/* Shared helpers: DOM, formatting, API, device naming. */
"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/** Tiny hyperscript: h("div", {class:"x", onclick:fn}, child, "text", ...) */
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "html") el.innerHTML = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(kid));
  }
  return el;
}

function icon(name, cls = "") {
  return `<svg class="ic ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><use href="#i-${name}"/></svg>`;
}

/* ---------------------------------------------------------------- formatting */
const fmt = {
  num(n) { return Number(n || 0).toLocaleString("en-US"); },
  bytes(n) {
    n = Number(n || 0);
    if (n < 1024) return `${n} B`;
    const u = ["KB", "MB", "GB", "TB"];
    let i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return `${n >= 100 ? n.toFixed(0) : n >= 10 ? n.toFixed(1) : n.toFixed(2)} ${u[i]}`;
  },
  rate(bps) { return `${fmt.bytes(bps)}/s`; },
  time(ts) {
    if (!ts) return "-";
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString([], { hour12: false });
  },
  timeMs(ts) {
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
  },
  dur(sec) {
    sec = Math.max(0, sec || 0);
    if (sec < 1) return `${(sec * 1000).toFixed(0)} ms`;
    if (sec < 60) return `${sec.toFixed(1)} s`;
    if (sec < 3600) return `${Math.floor(sec / 60)}m ${Math.floor(sec % 60)}s`;
    return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
  },
  ago(ts, now) {
    const d = Math.max(0, (now || Date.now() / 1000) - ts);
    if (d < 2) return "just now";
    if (d < 60) return `${Math.floor(d)}s ago`;
    if (d < 3600) return `${Math.floor(d / 60)}m ago`;
    return `${Math.floor(d / 3600)}h ago`;
  },
  short(hex, n = 8) { return hex ? `${hex.slice(0, n)}…${hex.slice(-4)}` : ""; },
};

/* ---------------------------------------------------------------------- API */
async function api(path, body) {
  const opts = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON */ }
  if (!res.ok) throw new Error((data && data.error) || `${res.status} ${res.statusText}`);
  return data;
}

/* ------------------------------------------------------------------ toasts */
function toast(title, message, level = "") {
  const el = h("div", { class: `toast ${level}` }, h("b", {}, title), message ? h("div", { class: "m" }, message) : null);
  $("#toasts").append(el);
  setTimeout(() => { el.style.transition = "opacity .4s, transform .4s"; el.style.opacity = 0; el.style.transform = "translateX(30px)"; setTimeout(() => el.remove(), 400); }, 6500);
}

/* ----------------------------------------------------------------- tooltip */
const tip = {
  show(html, x, y) {
    const t = $("#tip");
    t.innerHTML = html;
    t.classList.remove("hidden");
    const w = t.offsetWidth;
    t.style.left = Math.min(window.innerWidth - w - 12, x + 14) + "px";
    t.style.top = y + 14 + "px";
  },
  hide() { $("#tip").classList.add("hidden"); },
};

/* ----------------------------------------------------------- persisted UI state */
const store = {
  get(key, fallback) { try { const v = localStorage.getItem("netlens." + key); return v == null ? fallback : JSON.parse(v); } catch { return fallback; } },
  set(key, value) { try { localStorage.setItem("netlens." + key, JSON.stringify(value)); } catch { /* private mode */ } },
};

/* ----------------------------------------------------------- device naming */
const Names = {
  labels: store.get("labels", {}),
  focus: store.get("focus", null),

  isSelf(ip, S) {
    const meta = (S && S.meta) || {};
    return (meta.self_ips || []).includes(ip) || ip.endsWith(".137.1");
  },
  /** Best human name for an IP: user label > self > guessed kind. */
  name(host, S) {
    const ip = typeof host === "string" ? host : host.ip;
    if (this.labels[ip]) return this.labels[ip];
    if (this.isSelf(ip, S)) return "This laptop";
    const hs = typeof host === "string" ? ((S && S.hosts) || []).find((x) => x.ip === ip) : host;
    if (hs) {
      if (/Espressif|Raspberry/.test(hs.vendor || "")) return `IoT device (${hs.vendor.split(" ")[0]})`;
      if (hs.randomized_mac) return "Phone / modern device";
      if (hs.vendor && !/Unknown/.test(hs.vendor)) return `${hs.vendor} device`;
    }
    return "Device";
  },
  kind(host, S) {
    const ip = host.ip;
    if (this.isSelf(ip, S)) return "laptop";
    if (/Espressif|Raspberry/.test(host.vendor || "")) return "chip";
    if (host.randomized_mac || /phone/i.test(this.labels[ip] || "")) return "devices";
    return "laptop";
  },
  set(ip, label) {
    if (label) this.labels[ip] = label; else delete this.labels[ip];
    store.set("labels", this.labels);
  },
  setFocus(ip) { this.focus = ip; store.set("focus", ip); },
  match(ip) { return !this.focus || ip === this.focus; },
};

const POSTURE_COLORS = {
  tls13: "#138a55", tls12: "#2f9e75", tls_unseen: "#2456d8", tls_legacy: "#d03a3a",
  quic: "#6d4fd6", dns: "#d98a1c", cleartext: "#b91c4a", other: "#98a3b8",
};
const PROTO_COLORS = { TCP: "#2456d8", UDP: "#6d4fd6", ARP: "#b45f06", ICMP: "#138a55", OTHER: "#7a869c" };

/** Each detection rule in plain English. */
const RULES = {
  bandwidth_hog: {
    title: "Unusually heavy data use",
    short: "A device is using far more data than it normally does.",
    plain: "A device used much more data than it normally does.",
    how: "NetLens learns each device's normal usage. It raises this when usage is more than 3× that normal.",
    caveat: "A big download or video call looks the same, so NetLens shows the numbers instead of accusing anyone.",
    req: "REQ-25",
  },
  port_scan: {
    title: "Port scan",
    short: "A device is trying lots of doors (ports) on another device.",
    plain: "A device tried many different ports on another device in a few seconds - what a scanner does to look for weak spots.",
    how: "Counts how many different ports a device tries to connect to in one window. It raises this at 15 or more (and at least 3× normal).",
    caveat: "Network tools and some apps probe a few ports legitimately.",
    req: "REQ-26",
  },
  arp_spoof: {
    title: "Impersonation (ARP spoofing)",
    short: "A device is pretending to be another device on the network.",
    plain: "A second device started claiming an address that already belonged to another device.",
    how: "Remembers which hardware address owns each IP address. It raises this when a second hardware address claims the same IP.",
    caveat: "Replacing a network card can look identical, so NetLens reports old and new addresses as evidence.",
    req: "REQ-27",
  },
};

/* ------------------------------------------------------------- activity log */
/** A short, human-readable log of what just happened. Built from state changes in app.js. */
const Events = {
  list: store.get("events", []),
  add(text, kind = "info", ico = "bulb") {
    this.list.unshift({ t: Date.now() / 1000, text, kind, ico });
    this.list = this.list.slice(0, 40);
    store.set("events", this.list.slice(0, 20));
  },
  clear() { this.list = []; store.set("events", []); },
};

/** One answer to "is everything OK?" used by Home and the header. */
function statusOf(S) {
  if (!S || S.mode === "idle") return { level: "idle", title: "Choose where to watch", text: "Pick Live capture (your phone), a Simulation, or a saved Replay to begin." };
  const recent = S.alerts.filter((a) => S.now - a.ts < 300);
  if (recent.length) {
    const first = recent[0], r = RULES[first.rule] || { title: first.rule };
    return { level: "bad", title: recent.length === 1 ? "1 security alert" : `${recent.length} security alerts`, text: `Latest: ${r.title} involving ${Names.name(first.host, S)}.`, cta: "See alerts" };
  }
  const devices = S.hosts.filter((h) => !Names.isSelf(h.ip, S));
  if (!devices.length) return { level: "wait", title: S.mode === "live" ? "Waiting for a device" : "Starting up", text: S.mode === "live" ? "Connect your phone to the hotspot and open any app." : "Traffic will appear in a moment." };
  const learning = S.hosts.filter((h) => !(h.baseline && h.baseline.ready));
  if (learning.length) return { level: "wait", title: "Learning what's normal", text: "NetLens watches each device for a short while first, so it can tell normal from unusual. Alerts start once it has learned." };
  return { level: "good", title: "Everything looks normal", text: "Every device is behaving like itself. NetLens is watching for unusual data use, port scans and impersonation." };
}

/* ------------------------------------------------------------- page registry */
const PAGES = {};

/** The plain-language explainer shown at the top of every page (toggle: "Guide"). */
function guideHTML({ title, text, why }) {
  return `<div class="guide"><div class="ico">${icon("bulb")}</div><div><h3>${esc(title)}</h3><p>${text}</p>${why ? `<div class="why"><b>In one line:</b> ${why}</div>` : ""}</div></div>`;
}

function emptyHTML(title, text, ico = "radar", action = "") {
  return `<div class="empty">${icon(ico)}<b>${esc(title)}</b><div>${text}</div>${action}</div>`;
}

function barRows(items, { color, fmtVal = fmt.bytes, max } = {}) {
  const top = max || Math.max(1, ...items.map((i) => i.value));
  return items.map((i) => `<div class="bar-row"><div class="name" title="${esc(i.label)}">${esc(i.label)}</div><div class="bar"><i style="width:${Math.max(2, (i.value / top) * 100)}%;${i.color || color ? `background:${i.color || color}` : ""}"></i></div><div class="val">${esc(fmtVal(i.value, i))}</div></div>`).join("");
}


/* ---------------------------------------------------------------------- theme */
const PALETTES = {
  light: {
    ink: "#172033", sub: "#55627a", grid: "#e6ebf3", surface: "#ffffff", track: "#e9eef6", accent: "#2456d8",
    barIdle: "#c5cedd", barReady: "#7da2f0", okSoft: "#e4f5ec", dotIdle: "#9bb4ec", cap: "#98a3b8", faint: "#7a869c",
    lan: "#b7c9f2", wan: "#c9d3e6", orgHover: "#e8eefc", orgLine: "#cdd6e3",
  },
  dark: {
    ink: "#e8eefb", sub: "#9db0d2", grid: "rgba(255,255,255,.08)", surface: "#121b2f", track: "#1f2c4a", accent: "#6b97ff",
    barIdle: "#34486f", barReady: "#5b8cff", okSoft: "rgba(62,207,142,.14)", dotIdle: "#5b7bc0", cap: "#6f84ab", faint: "#6f84ab",
    lan: "rgba(107,151,255,.5)", wan: "rgba(125,145,195,.38)", orgHover: "#1f2c4a", orgLine: "#34486f",
  },
};

const Theme = {
  get() { return document.documentElement.dataset.theme === "dark" ? "dark" : "light"; },
  set(t) {
    const root = document.documentElement;
    root.classList.add("theme-anim");           // cross-fade only while switching
    root.dataset.theme = t;
    store.set("theme", t);
    setTimeout(() => root.classList.remove("theme-anim"), 500);
  },
  toggle() { this.set(this.get() === "dark" ? "light" : "dark"); },
};
/** Chart colours for the current theme (read on every draw, so charts follow a switch immediately). */
function P() { return PALETTES[Theme.get()]; }

/** Animate an element's number to a new value; non-numeric values are set directly. */
function tweenNumber(el, value, ms = 700) {
  if (typeof value !== "number") { el.textContent = value; el._v = undefined; return; }
  const from = el._v == null ? 0 : el._v;
  el._v = value;
  if (from === value) { el.textContent = fmt.num(value); return; }
  const t0 = performance.now(); el._tw = t0;
  const tick = (now) => {
    if (el._tw !== t0) return;                  // superseded by a newer target
    const k = Math.min(1, (now - t0) / ms), e = 1 - Math.pow(1 - k, 3);
    el.textContent = fmt.num(Math.round(from + (value - from) * e));
    if (k < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

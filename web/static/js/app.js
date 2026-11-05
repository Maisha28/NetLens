/* App shell: navigation, polling, header, alert toasts, plain-English activity log. */
"use strict";

window.S = null;
const App = {
  current: null,
  ackAlerts: 0,
  lastAlertId: 0,
  lost: 0,
  firstState: true,
  prevMode: null,
  prevUptime: 0,
  known: { hosts: new Set(), sites: new Set(), ready: new Set(), findings: new Set() },
  seeded: false,

  init() {
    const groups = {};
    Object.entries(PAGES).forEach(([id, p]) => { (groups[p.group] = groups[p.group] || []).push([id, p]); });
    $("#nav").innerHTML = ["Main", "Explain", "Technical"].filter((g) => groups[g]).map((g) =>
      `<div class="nav-group">${g}</div>` + groups[g].map(([id, p]) => `<a href="#/${id}" data-id="${id}">${icon(p.icon)}<span>${p.title}</span>${id === "alerts" ? `<span class="count zero" id="navAlerts">0</span>` : ""}</a>`).join("")).join("");

    const guideOn = store.get("guide", true);
    document.body.classList.toggle("no-guide", !guideOn);
    $("#guideSwitch").classList.toggle("on", guideOn);
    $("#guideSwitch").onclick = () => {
      const on = document.body.classList.toggle("no-guide") === false;
      $("#guideSwitch").classList.toggle("on", on); store.set("guide", on);
    };
    $("#btnPause").onclick = async () => {
      if (!S) return;
      try { await api("/api/control", { action: S.paused ? "resume" : "pause" }); this.poll(); } catch (e) { toast("Control", e.message, "med"); }
    };
    $("#btnSource").onclick = () => Setup.open();
    $("#btnReport").onclick = () => { location.href = "/api/report"; toast("Report", "Downloading alerts, the sealed log and encryption findings as a file."); };

    window.addEventListener("hashchange", () => this.route());
    this.route();
    this.poll();
    setInterval(() => this.poll(), 1000);
    window.addEventListener("resize", () => { if (this.current && S) this.render(); });
  },

  parse() {
    const [, id, arg] = (location.hash || "#/overview").split("/");
    return { id: PAGES[id] ? id : "overview", arg };
  },

  route() {
    const { id, arg } = this.parse();
    if (this.current && this.current.id === id && PAGES[id].onArg) { PAGES[id].onArg(arg); return; }
    if (this.current && PAGES[this.current.id].unmount) PAGES[this.current.id].unmount();
    this.current = { id };
    const p = PAGES[id];
    $$("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.id === id));
    $("#pageTitle").textContent = p.title;
    $("#pageSub").textContent = p.sub;
    document.title = `${p.title} · NetLens`;
    const view = $("#view");
    view.innerHTML = ""; view.scrollTop = 0;
    p.mount(view, arg);
    if (S) p.update(S);
    if (id === "alerts" && S) this.ackAlerts = S.totals.alerts;
  },

  render() {
    if (!S || !this.current) return;
    try { PAGES[this.current.id].update(S); } catch (e) { console.error(`page ${this.current.id}:`, e); }
  },

  async poll() {
    let data;
    try { data = await api("/api/state"); this.lost = 0; } catch {
      this.lost++;
      if (this.lost >= 3) $("#bannerSlot").innerHTML = `<div class="banner err" style="margin-top:16px"><div>!</div><div><b>Lost connection to NetLens.</b> Is the NetLens window still open?</div></div>`;
      return;
    }
    window.S = S = data;
    this.header(S);
    this.watch(S);
    this.render();
    if (this.firstState) { this.firstState = false; if (S.mode === "idle") Setup.open(); }
  },

  header(S) {
    const mode = S.mode;
    const label = { live: "Live", sim: "Simulation", pcap: "Replay", idle: "No source" }[mode] || mode;
    const extra = S.meta && S.meta.iface ? "" : "";
    $("#sourceBadge").innerHTML = `<span class="source-badge ${mode === "idle" ? "idle" : mode}"><span class="dot"></span>${label}${extra}</span>`;
    const pb = $("#btnPause");
    pb.disabled = mode === "idle";
    pb.innerHTML = S.paused ? `<svg><use href="#i-play"/></svg><span>Resume</span>` : `<svg><use href="#i-pause"/></svg><span>Pause</span>`;
    const unseen = Math.max(0, S.totals.alerts - this.ackAlerts);
    const nav = $("#navAlerts"); nav.textContent = unseen; nav.classList.toggle("zero", unseen === 0);
    $("#sideFoot").innerHTML = (S.meta && S.meta.record && mode === "live" ? `<div style="margin-bottom:10px"><span class="badge ok">● recording</span><div class="mono" style="word-break:break-all;margin-top:6px;font-size:12.5px">captures/${esc(S.meta.record)}</div></div>` : "") +
      "NetLens never reads message content - only who talks to whom, how much, and when.";

    const slot = $("#bannerSlot");
    if (S.error) {
      const low = S.error.toLowerCase();
      const hint = /permission|administrator/.test(low) ? "Close NetLens and start it again with <b>run_netlens.bat</b> (it asks for Administrator rights)." : /npcap|winpcap|libpcap|pcap/.test(low) ? "Install <b>Npcap</b> from npcap.com with <i>WinPcap API-compatible Mode</i> ticked." : "Check the capture adapter under <b>Source</b>.";
      slot.innerHTML = `<div class="banner err" style="margin:18px 32px 0"><div>!</div><div><b>Capture problem:</b> ${esc(S.error)}<br>${hint} <button class="btn small" style="margin-left:8px" onclick="Setup.open()">Open Source</button></div></div>`;
    } else if (S.paused) {
      slot.innerHTML = `<div class="banner warn" style="margin:18px 32px 0"><div>❚❚</div><div><b>Paused.</b> Nothing new is being analysed. Press Resume to continue.</div></div>`;
    } else slot.innerHTML = "";
  },

  /** Turn state changes into plain sentences for the Home page, and toast new alerts. */
  watch(S) {
    // a source switch / reset starts a fresh story
    if ((this.prevMode !== null && S.mode !== this.prevMode) || S.uptime < this.prevUptime - 1) {
      Events.clear();
      this.known = { hosts: new Set(), sites: new Set(), ready: new Set(), findings: new Set() };
      this.lastAlertId = 0; this.ackAlerts = 0; this.seeded = false;
    }
    this.prevMode = S.mode; this.prevUptime = S.uptime;

    const quiet = !this.seeded;           // first pass after a page load: remember what exists without announcing it again
    const announce = !quiet || Events.list.length === 0;
    for (const hs of S.hosts) {
      if (Names.isSelf(hs.ip, S)) continue;
      const name = Names.name(hs, S);
      if (!this.known.hosts.has(hs.ip)) {
        this.known.hosts.add(hs.ip);
        if (announce) Events.add(`${name} joined the network (${hs.ip})`, "ok", "devices");
        if (!quiet) toast("New device on your network", `${name} · ${hs.ip}`);
      }
      for (const [site] of hs.top_sites || []) {
        const key = hs.ip + "|" + site;
        if (!this.known.sites.has(key)) { this.known.sites.add(key); if (announce) Events.add(`${name} started using ${site}`, "info", "flows"); }
      }
      if (hs.baseline && hs.baseline.ready && !this.known.ready.has(hs.ip)) {
        this.known.ready.add(hs.ip);
        if (announce) Events.add(`NetLens learned what's normal for ${name}`, "ok", "check");
      }
    }
    for (const f of S.findings || []) {
      if (!this.known.findings.has(f.id)) { this.known.findings.add(f.id); if (announce) Events.add(`Weak encryption found: ${f.title}`, "bad", "crypto"); }
    }

    const fresh = S.alerts.filter((a) => a.id > this.lastAlertId).reverse();
    for (const a of fresh) {
      const r = RULES[a.rule] || { title: a.rule };
      if (announce) Events.add(`Alert: ${r.title} - ${Names.name(a.host, S)}`, "bad", "alerts");
      if (!quiet) toast(`Alert: ${r.title}`, `${Names.name(a.host, S)} - open Alerts for details.`, a.severity === "critical" ? "crit" : "high");
      const f = $("#flash"); f.classList.remove("go"); void f.offsetWidth; f.classList.add("go");
    }
    this.lastAlertId = S.alerts.length ? Math.max(...S.alerts.map((a) => a.id)) : 0;
    if (this.current && this.current.id === "alerts") this.ackAlerts = S.totals.alerts;
    if (S.totals.alerts < this.ackAlerts) this.ackAlerts = S.totals.alerts;
    this.seeded = true;
  },
};

document.addEventListener("DOMContentLoaded", () => App.init());

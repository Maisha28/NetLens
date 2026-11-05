/* Security score - a grade per device, every deduction explained. Doubles as the printable report. */
"use strict";

PAGES.security = {
  title: "Security score",
  sub: "A grade for every device, and exactly why",
  icon: "shield",
  group: "Main",
  data: null,
  timer: null,

  mount(root) {
    root.innerHTML = `
      ${guideHTML({
        title: "A report card for your network",
        text: "Each device starts at 100 and loses points for specific problems NetLens actually observed - outdated encryption, unencrypted data, or suspicious behaviour. Every deduction is listed with what to do about it. <b>Print this page</b> to hand it to whoever looks after the network.",
      })}
      <div class="print-only" id="sc-printhead"></div>
      <div id="sc-overall"></div>
      <div class="grid cols-2" id="sc-devices"></div>
      <div class="card" id="sc-method"></div>`;
    this.load();
    this.timer = setInterval(() => this.load(), 2500);
  },

  unmount() { clearInterval(this.timer); },

  async load() {
    try { this.data = await api("/api/security"); } catch { return; }
    this.render();
  },

  update() { if (this.data) this.render(); },

  render() {
    const D = this.data, S = window.S;
    if (!D || !$("#sc-overall")) return;
    const when = new Date(D.generated_at * 1000).toLocaleString();
    const simNote = D.mode === "sim" ? `<div class="banner warn" style="margin-top:10px"><div>!</div><div><b>Simulated data.</b> This report was produced from synthetic traffic and describes no real device.</div></div>` : "";
    $("#sc-printhead").innerHTML = `<div class="rep-head"><div><h1>NetLens security report</h1><div class="muted">Generated ${esc(when)} · ${esc(D.label || D.mode)} · watched for ${fmt.dur(D.uptime)}</div></div><div class="rep-mark">${icon("shield")}</div></div>${simNote}`;

    const o = D.overall, weakest = o.weakest ? D.devices.find((d) => d.ip === o.weakest.ip) : null;
    $("#sc-overall").innerHTML = `<div class="card overall">
      <div class="gradebig ${esc(o.grade)}">${esc(o.grade)}</div>
      <div style="flex:1;min-width:240px"><div class="faint" style="font-weight:600;letter-spacing:.4px;text-transform:uppercase;font-size:13px">Overall network grade</div>
        <div style="font-size:26px;font-weight:700;letter-spacing:-.3px">${o.score == null ? "Not enough data yet" : `${o.score} / 100`}</div>
        <div class="muted" style="font-size:17px">${esc(o.summary)}${weakest ? ` Weakest: <b>${esc(Names.name(weakest.ip, S))}</b> (${esc(weakest.grade)}).` : ""}</div></div>
      <div class="no-print"><button class="btn primary" onclick="window.print()">${icon("download")} Print / save as PDF</button></div></div>`;

    $("#sc-devices").innerHTML = D.devices.length ? D.devices.map((d) => this.card(d, S)).join("") :
      `<div style="grid-column:1/-1">${emptyHTML("No devices yet", "Connect a device and use it for a minute - it will be graded here.", "devices")}</div>`;

    $("#sc-method").innerHTML = `<div class="card-head"><h2>How the grade is calculated</h2><span class="hint">A ≥ 90 · B ≥ 75 · C ≥ 60 · D ≥ 40 · F below</span></div>
      <p class="lead">Every device starts at 100. Points are lost only for the problems below - nothing is hidden or weighted by a model.</p>
      <table class="t"><thead><tr><th>Problem</th><th class="r">Points lost</th></tr></thead><tbody>${D.methodology.map((m) => `<tr><td class="wrap">${esc(m.rule)}</td><td class="r"><b>−${m.points}</b></td></tr>`).join("")}</tbody></table>
      <div style="margin-top:16px"><b>Limits.</b> ${D.limits.map((l) => `<div class="muted" style="margin-top:4px">• ${esc(l)}</div>`).join("")}</div>`;
  },

  card(d, S) {
    const name = esc(Names.name(d.ip, S));
    if (!d.assessed) {
      return `<div class="card device sc-dev na"><div class="device-head"><div class="gradebig sm ${d.grade === "?" ? "Q" : "N"}">${esc(d.grade)}</div><div style="flex:1;min-width:0"><div class="dev-name">${name}</div><div class="mono faint">${esc(d.ip)}</div></div><span class="badge mute">${esc(d.status)}</span></div><div class="muted">${esc(d.note)}</div></div>`;
    }
    const color = { A: "var(--ok)", B: "var(--accent-2)", C: "var(--warn)", D: "#c2410c", F: "var(--critical)" }[d.grade];
    return `<div class="card device sc-dev">
      <div class="device-head"><div class="gradebig sm ${esc(d.grade)}">${esc(d.grade)}</div>
        <div style="flex:1;min-width:0"><div class="dev-name">${name}</div><div class="mono faint">${esc(d.ip)}${d.vendor ? " · " + esc(d.vendor) : ""}</div></div>
        <div class="right"><div style="font-size:24px;font-weight:750;color:${color}">${d.score}<span class="faint" style="font-size:15px;font-weight:500"> /100</span></div><div class="muted" style="font-size:14px">${esc(d.status)}</div></div></div>
      <div class="progress"><i style="width:${d.score}%;background:${color}"></i></div>
      ${d.deductions.length ? `<div class="deducts">${d.deductions.map((x) => `<div class="deduct"><span class="pts">−${x.points}</span><div><b>${esc(x.title)}</b><div class="muted">${esc(x.detail)}</div>${x.advice ? `<div class="advice"><b>What to do:</b> ${esc(x.advice)}</div>` : ""}</div></div>`).join("")}</div>` : `<div class="muted">No problems were observed for this device.</div>`}
      ${d.good.length ? `<div class="goods">${d.good.map((g) => `<div>${icon("check")} ${esc(g)}</div>`).join("")}</div>` : ""}
    </div>`;
  },
};

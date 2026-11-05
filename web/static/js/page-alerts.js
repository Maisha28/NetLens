/* Alerts - a sentence and three numbers; the evidence is one click away. */
"use strict";

PAGES.alerts = {
  title: "Alerts",
  sub: "Anything unusual, explained in plain English",
  icon: "alerts",
  group: "Main",
  seen: new Set(),
  first: true,
  open: {},

  mount(root) {
    this.seen = new Set(); this.first = true;
    root.innerHTML = `
      ${guideHTML({
        title: "NetLens raises three kinds of alert",
        text: "Each alert says <b>what happened</b>, to <b>which device</b>, and shows the <b>numbers</b> behind it. It never claims to know the attacker's intent - it shows evidence and lets you judge.",
      })}
      <div class="grid cols-3" id="al-rules"></div>
      <div id="al-list" style="display:grid;gap:24px"></div>`;
    $("#al-list").addEventListener("toggle", (e) => { const d = e.target; if (d.dataset && d.dataset.key) this.open[d.dataset.key] = d.open; }, true);
  },

  update(S) {
    if (!S) return;
    const counts = {};
    S.alerts.forEach((a) => { counts[a.rule] = (counts[a.rule] || 0) + 1; });
    $("#al-rules").innerHTML = Object.entries(RULES).map(([id, r]) => `
      <div class="card rule-card"><div class="row between" style="margin-bottom:8px"><h3>${r.title}</h3><span class="badge ${counts[id] ? "bad" : "mute"}">${counts[id] || 0} so far</span></div><p>${r.short}</p></div>`).join("");

    const list = $("#al-list");
    if (!S.alerts.length) {
      const armed = S.totals.hosts > 0 && S.totals.ready_hosts === S.totals.hosts;
      list.innerHTML = emptyHTML("No alerts - all quiet", armed ? "NetLens is watching. An alert appears here the moment a device does something unusual." : "NetLens is still learning what's normal for each device. Alerts switch on once it has.", "shield", `<a class="btn" href="#/demo">Open the demo guide</a>`);
      return;
    }
    list.innerHTML = S.alerts.map((a) => this.card(a, S)).join("");
    S.alerts.forEach((a) => this.seen.add(a.id));
  },

  card(a, S) {
    const r = RULES[a.rule] || { title: a.rule, plain: "", caveat: "", how: "" };
    const ev = a.evidence || {};
    const who = esc(Names.name(a.host, S));
    const win = a.window_seconds || S.window_seconds;
    let sentence = "", nums = "", rows = "";
    const dd = (k, v, hot) => `<dt>${k}</dt><dd class="${hot ? "hot" : ""}">${v}</dd>`;
    const num = (label, value, hot) => `<div class="${hot ? "hot" : ""}"><small>${label}</small><b>${value}</b></div>`;

    if (a.rule === "port_scan") {
      sentence = `<b>${who}</b> tried <b>${ev.distinct_ports} different ports</b> in ${win} seconds. Its normal is about ${Math.max(1, Math.round(ev.baseline_ports))}.`;
      nums = num("Ports tried", ev.distinct_ports, true) + num("Normal", Math.max(1, Math.round(ev.baseline_ports))) + num("Alert level", Math.round(ev.threshold));
      rows = dd("device", `${esc(a.host)}`) + dd("observed", `${ev.distinct_ports} distinct ports on ${ev.distinct_hosts} host(s) in ${win}s`, true) + dd("baseline", `${ev.baseline_ports} ports (learned average)`) + dd("threshold", `${ev.threshold} ports`) + (ev.sample_ports ? dd("ports", ev.sample_ports.join(", ") + (ev.distinct_ports > ev.sample_ports.length ? ", …" : "")) : "");
    } else if (a.rule === "bandwidth_hog") {
      sentence = `<b>${who}</b> used <b>${fmt.bytes(ev.bytes)}</b> in ${win} seconds - about <b>${ev.multiplier_observed}× its normal</b> (${fmt.bytes(ev.baseline_bytes)}).`;
      nums = num("Used", fmt.bytes(ev.bytes), true) + num("Normal", fmt.bytes(ev.baseline_bytes)) + num("Times normal", ev.multiplier_observed + "×", true);
      rows = dd("device", esc(a.host)) + dd("observed", `${fmt.num(ev.bytes)} bytes in ${win}s`, true) + dd("baseline", `${fmt.num(Math.round(ev.baseline_bytes))} bytes (learned average)`) + dd("ratio", `${ev.multiplier_observed}× (alert at ${ev.multiplier_threshold}×)`, true) + dd("share", `${ev.share_of_window_total_pct}% of all traffic in the window`);
    } else if (a.rule === "arp_spoof") {
      sentence = `Another device (<span class="mono">${esc(ev.new_mac)}</span>) started claiming the address of <b>${esc(Names.name(ev.ip, S))}</b> (${esc(ev.ip)}), which belonged to <span class="mono">${esc(ev.old_mac)}</span>.`;
      nums = num("Address claimed", esc(ev.ip), true) + num("Originally owned by", `<span class="mono" style="font-size:17px">${esc(ev.old_mac)}</span>`) + num("Now also claimed by", `<span class="mono" style="font-size:17px">${esc(ev.new_mac)}</span>`, true);
      rows = dd("ip claimed", esc(ev.ip)) + dd("old MAC", esc(ev.old_mac)) + dd("new MAC", esc(ev.new_mac), true) + dd("time", fmt.time(a.ts));
    } else { sentence = esc(a.message); rows = dd("device", esc(a.host)); }

    const isNew = !this.seen.has(a.id) && !this.first;
    this.first = false;
    const key = `al:${a.id}`;
    return `<div class="card alert-card ${esc(a.severity)} ${isNew ? "new" : ""}">
      <div class="alert-head"><h3>${esc(r.title)}</h3><span class="badge ${a.severity === "critical" ? "crit" : a.severity === "high" ? "bad" : "warn"}">${esc(a.severity)}</span><span style="flex:1"></span><span class="faint">${fmt.time(a.ts)} · ${fmt.ago(a.ts, S.now)}</span></div>
      <div class="alert-sentence">${sentence}</div>
      <div class="keynums">${nums}</div>
      <div class="muted" style="font-size:15.5px"><b style="color:var(--text)">What it could mean:</b> ${esc(r.plain)} ${esc(r.caveat)}</div>
      <details class="more" data-key="${key}" ${this.open[key] ? "open" : ""} style="margin-top:0"><summary>Show the evidence</summary><div>
        <dl class="evidence">${rows}</dl>
        <div class="seal" style="margin-top:12px">${icon("shield")} Sealed in the tamper-proof log as entry #${a.seal.idx} · fingerprint ${fmt.short(a.seal.hash, 10)} ${a.repeats ? `<span class="badge mute">+${a.repeats} repeats suppressed</span>` : ""}<a href="#/crypto" style="margin-left:auto">Check it hasn't been changed →</a></div>
      </div></details></div>`;
  },
};

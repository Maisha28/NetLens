/* Home - one question: is everything OK? */
"use strict";

PAGES.overview = {
  title: "Home",
  sub: "Is everything OK on your network?",
  icon: "overview",
  group: "Main",
  topo: null,

  mount(root) {
    root.innerHTML = `
      <div id="hm-hero"></div>
      <div class="tiles" id="hm-tiles"></div>
      <div class="grid split">
        <div class="card"><div class="card-head"><h2>Your network, live</h2><span class="hint">devices → this laptop → the internet</span></div><canvas id="hm-topo"></canvas></div>
        <div class="card"><div class="card-head"><h2>What just happened</h2></div><div class="activity" id="hm-activity"></div></div>
      </div>
      <div class="grid split">
        <div class="card"><div class="card-head"><h2>Network activity</h2><span class="hint">last 2 minutes · red marks = alerts</span></div><canvas id="hm-thru"></canvas></div>
        <div class="card"><div class="card-head"><h2>Where the data goes</h2></div><div id="hm-where"></div></div>
      </div>`;
    const topo = $("#hm-topo");
    topo._h = 380; topo.style.height = "380px";
    this.topo = new Topology(topo);
    const thru = $("#hm-thru");
    thru.addEventListener("mousemove", (e) => Throughput.hover(thru, e));
    thru.addEventListener("mouseleave", () => tip.hide());
  },

  unmount() { if (this.topo) this.topo.stop(); },

  update(S) {
    const st = statusOf(S);
    const iconFor = { good: "shield", bad: "alerts", wait: "radar", idle: "plug" }[st.level];
    const cta = st.level === "idle" ? `<button class="btn primary" onclick="Setup.open()">Choose source</button>` : st.cta ? `<a class="btn" href="#/alerts">${st.cta}</a>` : "";
    $("#hm-hero").innerHTML = `<div class="hero ${st.level}"><div class="big">${icon(iconFor)}</div><div><h2>${esc(st.title)}</h2><p>${esc(st.text)}</p></div>${cta}</div>`;

    const devices = S.hosts.filter((h) => !Names.isSelf(h.ip, S));
    const sites = new Map();
    for (const h of S.hosts) for (const [k, v] of h.top_sites || []) sites.set(k, (sites.get(k) || 0) + v);
    const tile = (num, lbl, sub) => `<div class="tile"><div class="num">${num}</div><div class="lbl">${lbl}</div><div class="sub">${sub}</div></div>`;
    $("#hm-tiles").innerHTML =
      tile(devices.length, "Devices connected", devices.length ? devices.map((d) => Names.name(d, S)).slice(0, 2).join(", ") : "none yet") +
      tile(sites.size, "Websites &amp; apps seen", sites.size ? [...sites.keys()].slice(0, 3).join(", ") : "none yet") +
      tile(fmt.bytes(S.totals.bytes), "Data observed", `${fmt.rate(S.totals.bps)} right now`) +
      tile(S.totals.alerts, "Security alerts", S.totals.alerts ? "see the Alerts page" : "none so far");

    // activity log (built in app.js from state changes)
    const ev = Events.list.slice(0, 5);
    $("#hm-activity").innerHTML = ev.length
      ? ev.map((e) => `<div class="ev"><div class="dot ${e.kind === "bad" ? "bad" : e.kind === "ok" ? "ok" : ""}">${icon(e.ico)}</div><div>${esc(e.text)}</div><div class="when">${fmt.ago(e.t)}</div></div>`).join("")
      : `<div class="faint" style="padding:12px 0;font-size:16.5px">Nothing yet. New devices, websites and alerts will be listed here as they happen.</div>`;

    Throughput.draw($("#hm-thru"), S.timeline, S.alerts.map((a) => ({ ts: a.ts, rule: a.rule })));
    this.topo.update(S);

    const where = sites.size ? [...sites.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) => ({ label: k, value: v }))
      : S.orgs.filter(([o]) => o !== "Unknown").slice(0, 5).map(([o, b]) => ({ label: o, value: b }));
    $("#hm-where").innerHTML = where.length ? barRows(where) : `<div class="faint" style="font-size:16.5px">No internet traffic yet.</div>`;
  },
};

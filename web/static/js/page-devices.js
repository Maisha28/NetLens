/* Devices - one clear card each: what it's doing, and normal vs right now. */
"use strict";

function osHint(ttl) {
  if (!ttl) return "";
  if (ttl <= 64) return "Android / iPhone / Mac / Linux";
  if (ttl <= 128) return "Windows";
  return "Network equipment";
}

PAGES.devices = {
  title: "Devices",
  sub: "What each device is doing, compared with its own normal",
  icon: "devices",
  group: "Main",
  open: {},

  mount(root) {
    root.innerHTML = `
      ${guideHTML({
        title: "Each device is compared with itself",
        text: "NetLens learns how much data a device <b>normally</b> uses. The <span style='color:#0f8f84;font-weight:600'>green bar</span> is normal, the <span style='color:#2456d8;font-weight:600'>blue bar</span> is right now, and the <span style='color:#b45f06;font-weight:600'>orange mark</span> is the level that would raise an alert.",
      })}
      <div id="dv-empty"></div>
      <div class="grid cols-2" id="dv-grid"></div>
      <div class="card">
        <div class="card-head"><h2>More tools</h2></div>
        <details class="more" id="dv-idle" style="border-top:0;margin-top:0;padding-top:0">
          <summary>Idle test - which apps contact the internet on a timer?</summary>
          <div><p class="lead">Put a phone face-down for a few minutes. Dots show each time it opened a connection; <b style="color:#138a55">green rows</b> repeat at an almost fixed interval, so an app is "phoning home" even though nobody is using the phone.</p>
            <canvas id="dv-raster"></canvas><div id="dv-beacons" style="margin-top:12px"></div></div>
        </details>
        <details class="more" id="dv-arp-d">
          <summary>Who owns which address? (ARP table)</summary>
          <div><p class="lead">Every device on the network announces which hardware address owns which IP. NetLens remembers the first owner of each IP and raises an alert if someone else claims it.</p><div id="dv-arp"></div></div>
        </details>
      </div>`;
    $("#dv-grid").addEventListener("toggle", (e) => { const d = e.target; if (d.dataset && d.dataset.key) this.open[d.dataset.key] = d.open; }, true);
  },

  update(S) {
    if (!S) return;
    $("#dv-empty").innerHTML = S.hosts.length ? "" : emptyHTML("No devices yet", S.mode === "idle" ? "Choose a data source first." : "Connect your phone to the hotspot and open any app - it appears here within seconds.", "devices", S.mode === "idle" ? `<button class="btn primary" onclick="Setup.open()">Choose source</button>` : "");
    const grid = $("#dv-grid"), keep = new Set();
    S.hosts.forEach((hs) => {
      keep.add(hs.ip);
      let card = grid.querySelector(`[data-ip="${hs.ip}"]`);
      if (!card) { card = h("div", { class: "card device" }); card.dataset.ip = hs.ip; grid.append(card); }
      this.fill(card, hs, S);
    });
    $$(".device", grid).forEach((c) => { if (!keep.has(c.dataset.ip)) c.remove(); });

    const rows = S.beacons.raster;
    const raster = $("#dv-raster");
    if (rows.length) { raster.style.display = ""; if ($("#dv-idle").open) Raster.draw(raster, rows, S.now, 180); } else raster.style.display = "none";
    $("#dv-beacons").innerHTML = S.beacons.periodic.length
      ? S.beacons.periodic.map((b) => `<div class="row between" style="padding:10px 0;border-top:1px solid var(--border);font-size:16px"><span><b>${esc(Names.name(b.host, S))}</b> contacts <b>${esc(b.site || b.org)}</b></span><span class="badge ok">every ${b.period} seconds</span></div>`).join("")
      : `<div class="faint">${rows.length ? "No regular pattern yet - a few more minutes of idle time will reveal one." : "Waiting for outbound connections…"}</div>`;
    const arp = Object.entries(S.arp_table);
    $("#dv-arp").innerHTML = arp.length
      ? `<table class="t"><thead><tr><th>Address (IP)</th><th>Device</th><th>Hardware address (MAC)</th></tr></thead><tbody>${arp.map(([ip, mac]) => `<tr><td class="mono">${ip}</td><td>${esc(Names.name(ip, S))}</td><td class="mono">${mac}</td></tr>`).join("")}</tbody></table>`
      : `<div class="faint">No ARP traffic seen yet.</div>`;
  },

  fill(card, hs, S) {
    const self = Names.isSelf(hs.ip, S);
    const b = hs.baseline, ready = b && b.ready, learn = b ? Math.min(3, b.samples) : 0;
    card.classList.toggle("alerting", !!hs.alerted_recently);
    card.classList.toggle("focus", Names.focus === hs.ip);
    const name = Names.name(hs, S);
    const used = (hs.top_sites.length ? hs.top_sites : hs.top_orgs.filter(([o]) => o !== "Unknown")).slice(0, 3).map(([k]) => k);
    const sentence = self ? "This laptop relays everyone's traffic - that is how NetLens can see it." : used.length ? `Mostly using <b>${used.map(esc).join(", ")}</b>.` : "No internet activity yet.";
    const status = hs.alerted_recently ? `<span class="badge crit">Alert</span>` : ready ? `<span class="badge ok">Normal</span>` : `<span class="badge warn">Learning ${learn}/3</span>`;

    let meter;
    if (ready) {
      const normal = b.bytes, now = hs.window_bytes, limit = normal * 3;
      const max = Math.max(now, limit * 1.15, 1);
      meter = `<div class="meter">
        <div class="line"><span class="muted">Normal</span><div class="track"><div class="fill normal" style="width:${(normal / max) * 100}%"></div><div class="limit" style="left:${(limit / max) * 100}%" title="Alert level"></div></div><span class="val">${fmt.bytes(normal)}</span></div>
        <div class="line"><span class="muted">Right now</span><div class="track"><div class="fill ${now > limit ? "hot" : "now"}" style="width:${Math.min(100, (now / max) * 100)}%"></div></div><span class="val" style="${now > limit ? "color:var(--danger)" : ""}">${fmt.bytes(now)}</span></div>
        <div class="faint" style="font-size:14px">per ${S.window_seconds}-second window · the orange mark is the alert level (3× normal)</div></div>`;
    } else {
      meter = `<div><div class="progress"><i style="width:${(learn / 3) * 100}%"></i></div><div class="muted" style="margin-top:8px;font-size:15.5px">NetLens is learning what's normal for this device. Alerts are switched on after 3 short windows.</div></div>`;
    }

    const k = (n) => `data-key="${hs.ip}:${n}" ${this.open[`${hs.ip}:${n}`] ? "open" : ""}`;
    card.innerHTML = `
      <div class="device-head">
        <div class="dev-ico">${icon(Names.kind(hs, S))}</div>
        <div style="flex:1;min-width:0"><div class="dev-name">${esc(name)} ${self ? "" : `<button title="Rename" data-act="rename">${icon("edit")}</button>`}</div><div class="mono faint">${hs.ip}</div></div>
        ${status}
      </div>
      <div class="dev-sentence">${sentence}</div>
      ${meter}
      <details class="more" ${k("hist")}><summary>Show usage over time</summary><div><canvas></canvas><div class="legend" style="margin-top:8px"><span><i style="background:#7da2f0"></i>Usage</span><span><i style="background:#138a55"></i>Normal</span><span><i style="background:#d98a1c"></i>Alert level</span><span><i style="background:#d03a3a"></i>Alert</span></div></div></details>
      <details class="more" ${k("tech")}><summary>Show technical details</summary><div>
        <div class="facts">
          <div><small>Total data</small><b>${fmt.bytes(hs.bytes)}</b></div><div><small>Packets</small><b>${fmt.num(hs.packets)}</b></div><div><small>Last seen</small><b>${fmt.ago(hs.last_seen, S.now)}</b></div>
          <div><small>Ports tried now</small><b>${hs.window_ports}${b ? ` <span class="faint" style="font-weight:400">/ ${b.ports.toFixed(1)} normal</span>` : ""}</b></div>
          <div style="grid-column:span 2"><small>Hardware address</small><b class="mono" style="font-size:14.5px">${hs.mac || "unknown"}</b></div>
        </div>
        <div class="row wrap" style="margin-top:12px;gap:8px">${hs.vendor ? `<span class="badge ${hs.randomized_mac ? "violet" : "mute"}" title="${hs.randomized_mac ? "The phone uses a randomised private address, so the maker can't be read from it." : ""}">${esc(hs.vendor)}</span>` : ""}${hs.ttl ? `<span class="badge mute">Looks like: ${esc(osHint(hs.ttl))}</span>` : ""}</div>
        <div style="margin-top:14px"><button class="btn small ${Names.focus === hs.ip ? "primary" : ""}" data-act="focus">${Names.focus === hs.ip ? "Focused - click to clear" : "Show only this device in Live packets &amp; Conversations"}</button></div>
      </div></details>`;
    const det = card.querySelector('details[data-key$=":hist"]');
    if (det && det.open) HostChart.draw($("canvas", card), hs.history, { height: 150, mult: 3 });
    card.querySelector('[data-act="focus"]').onclick = () => { Names.setFocus(Names.focus === hs.ip ? null : hs.ip); this.update(S); };
    const rn = card.querySelector('[data-act="rename"]');
    if (rn) rn.onclick = () => { const v = prompt(`Name for ${hs.ip} (for example "My phone"):`, Names.labels[hs.ip] || ""); if (v !== null) { Names.set(hs.ip, v.trim()); this.update(S); } };
  },
};

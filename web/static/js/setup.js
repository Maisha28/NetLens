/* Source chooser / live-capture setup wizard. */
"use strict";

const Setup = {
  info: null,
  timer: null,
  selected: null,
  showAll: false,
  pick: false,
  error: "",
  busy: false,

  async open() {
    this.error = "";
    $("#overlayRoot").innerHTML = `<div class="overlay" id="su-overlay"><div class="wizard" id="su-wizard"><div class="faint">Checking this machine…</div></div></div>`;
    $("#su-overlay").addEventListener("mousedown", (e) => { if (e.target.id === "su-overlay" && window.S && window.S.mode !== "idle") this.close(); });
    await this.refresh();
    this.timer = setInterval(() => this.refresh(), 2500);
  },

  close() { clearInterval(this.timer); $("#overlayRoot").innerHTML = ""; },

  async refresh() {
    if (this.busy) return;
    try { this.info = await api("/api/system"); } catch { return; }
    const rec = this.info.interfaces.find((i) => i.recommended) || this.info.interfaces.find((i) => i.hotspot && !i.noise);
    if (!this.selected || !this.info.interfaces.some((i) => i.name === this.selected)) this.selected = rec ? rec.name : null;
    // auto-follow the recommended adapter the moment the hotspot comes up
    if (this.info.recommended && !this._userPicked) this.selected = this.info.recommended;
    this.render();
  },

  render() {
    const w = $("#su-wizard"); if (!w || !this.info) return;
    const I = this.info, S = window.S || {};
    const win = I.platform === "win32";
    const rec = I.interfaces.find((i) => i.recommended);
    const ifaces = I.interfaces.filter((i) => this.showAll || !i.noise);
    const canLive = I.admin && I.npcap && this.selected;
    const chk = (cls, title, detail) => `<div class="check"><span class="st ${cls}">${cls === "ok" ? "✓" : cls === "no" ? "✗" : "…"}</span><div><b>${title}</b><small>${detail}</small></div></div>`;

    w.innerHTML = `
      <div class="row between"><div><h2>Choose your data source</h2><div class="lead">Nothing is captured or simulated until you pick one. Real traffic and simulated traffic are never mixed.</div></div>
        ${S.mode && S.mode !== "idle" ? `<button class="btn small ghost" onclick="Setup.close()">✕ Close</button>` : ""}</div>
      <div class="choices">
        <div class="choice primary">
          <h3>${icon("radar")} Live capture · your own phone <span class="badge ok">REAL DATA</span></h3>
          <p>Capture your phone's real traffic through this laptop's Windows hotspot.</p>
          <div>
            ${chk(I.admin ? "ok" : "no", "Administrator rights", I.admin ? "Running elevated." : "Packet capture needs it. Close this, open <b>PowerShell as Administrator</b>, run <span class='code'>python app.py</span> again.")}
            ${chk(I.npcap ? "ok" : "no", "Npcap packet driver", I.npcap ? "Installed." : "Install from <b>npcap.com</b> and tick <i>WinPcap API-compatible Mode</i>.")}
            ${chk(I.hotspot_on ? "ok" : "wait", "Mobile Hotspot on", I.hotspot_on ? `Hotspot adapter found: <b>${esc(rec.name)}</b> (${esc(rec.ips.join(", "))}).` : "Not detected yet. <b>Settings → Network &amp; Internet → Mobile hotspot → On</b>, then connect your phone. This page updates by itself.")}
          </div>
          <div class="muted" style="font-size:15px;margin-top:6px">Capture adapter ${I.hotspot_on ? "" : `<span class="faint">(choose the hotspot's "Wi-Fi Direct Virtual Adapter" once it is on)</span>`}</div>
          ${this.pick ? "" : (() => { const cur = I.interfaces.find((i) => i.name === this.selected); return cur ? `<div class="iface sel" style="cursor:default"><span class="dotr"></span><div style="min-width:0"><b>${esc(cur.name)}</b><small>${esc(cur.description)}${cur.ips.length ? " · " + esc(cur.ips.join(", ")) : ""}</small></div>${cur.recommended ? `<span class="badge ok">hotspot</span>` : ""}</div>` : `<div class="faint">No adapter selected yet.</div>`; })()}
          <button class="btn small ghost" id="su-pick" style="align-self:flex-start">${this.pick ? "Done" : "Change adapter"}</button>
          <div class="iface-list ${this.pick ? "" : "hidden"}" id="su-ifaces">${ifaces.map((i) => `<div class="iface ${i.name === this.selected ? "sel" : ""}" data-n="${esc(i.name)}"><span class="dotr"></span><div style="min-width:0"><b style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(i.name)}</b><small>${esc(i.description)} ${i.ips.length ? "· " + esc(i.ips.join(", ")) : ""}</small></div>${i.recommended ? `<span class="badge ok">hotspot ✓</span>` : i.hotspot ? `<span class="badge mute">virtual wifi</span>` : ""}</div>`).join("") || `<div class="faint">No adapters found - is Npcap installed?</div>`}</div>
          <label class="switch ${this.showAll ? "on" : ""} ${this.pick ? "" : "hidden"}" id="su-all"><i></i>Show all adapters</label>
          ${this.error ? `<div class="banner err">${esc(this.error)}</div>` : ""}
          <button class="btn primary" id="su-live" ${canLive && !this.busy ? "" : "disabled"}>${icon("play")} Start live capture</button>
          <div class="faint" style="font-size:12px">Each live session is saved to <span class="code">captures/</span> automatically for offline replay.</div>
        </div>

        <div class="choice">
          <h3>${icon("chip")} Simulation <span class="badge warn">SYNTHETIC</span></h3>
          <p>No hardware, admin rights or phone needed. Generates a believable hotspot network and lets you <b>stage a port scan, ARP spoof and bandwidth spike</b> on demand.</p>
          <p class="faint" style="font-size:12.5px">The traffic is made-up, but it is raw bytes sent through the <b>real</b> decoder, baseline, rules and ledger. The header says <b>SIMULATION</b> the whole time.</p>
          <div style="flex:1"></div>
          <button class="btn" id="su-sim">${icon("play")} Start simulation</button>
        </div>

        <div class="choice">
          <h3>${icon("refresh")} Replay a recording <span class="badge info">SAVED</span></h3>
          <p>Replay a previous live session from <span class="code">captures/</span> - the safety net if the projector room's network fails.</p>
          <div style="display:grid;gap:6px;max-height:190px;overflow:auto">${(I.recordings || []).map((r) => `<div class="row between" style="padding:7px 10px;border:1px solid var(--border);border-radius:10px;background:var(--bg-2)"><div style="min-width:0"><b style="font-size:12.5px;display:block;overflow:hidden;text-overflow:ellipsis">${esc(r.name)}</b><small class="faint">${fmt.bytes(r.size)}</small></div><button class="btn small" data-f="${esc(r.name)}">Replay</button></div>`).join("") || `<div class="faint" style="font-size:12.5px">No recordings yet - they appear after your first live session.</div>`}</div>
        </div>
      </div>
      <div class="row between" style="margin-top:18px">
        <ol class="steps" style="grid-template-columns:repeat(4,1fr);display:grid;gap:14px"><li>Turn on Windows Mobile Hotspot</li><li>Connect your phone to it</li><li>Select the hotspot adapter &amp; start</li><li>Open apps on the phone and watch</li></ol>
      </div>
      <div class="row" style="margin-top:14px"><button class="btn small ghost" id="su-clear">Clear collected data</button><span class="faint" style="font-size:12px">Switching source always starts from a clean slate.</span></div>`;

    $$("#su-ifaces .iface", w).forEach((el) => el.addEventListener("click", () => { this._userPicked = true; this.selected = el.dataset.n; this.pick = false; this.render(); }));
    $("#su-pick", w).onclick = () => { this.pick = !this.pick; this.render(); };
    $("#su-all", w).onclick = () => { this.showAll = !this.showAll; this.render(); };
    $("#su-live", w).onclick = () => this.start({ mode: "live", iface: this.selected });
    $("#su-sim", w).onclick = () => this.start({ mode: "sim" });
    $$("[data-f]", w).forEach((b) => (b.onclick = () => this.start({ mode: "pcap", file: b.dataset.f })));
    $("#su-clear", w).onclick = async () => { await api("/api/control", { action: "reset" }); toast("Cleared", "All collected data was reset."); };
  },

  async start(body) {
    this.busy = true; this.error = ""; this.render();
    try {
      await api("/api/source", body);
      this.busy = false; this.close();
      toast(body.mode === "live" ? "Live capture started" : body.mode === "sim" ? "Simulation started" : "Replay started", body.mode === "live" ? "Open apps on your phone - devices appear within seconds." : body.mode === "sim" ? "Baselines take ~15 s to learn before alerts can fire." : "");
      location.hash = "#/overview";
    } catch (e) {
      this.busy = false; this.error = e.message; this.render();
    }
  },
};

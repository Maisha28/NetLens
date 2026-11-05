/* Conversations - packets grouped into flows (5-tuple), both directions merged. */
"use strict";

const SERVICES = { 53: "DNS", 80: "HTTP", 443: "HTTPS", 22: "SSH", 123: "NTP", 67: "DHCP", 68: "DHCP", 5353: "mDNS", 1900: "SSDP", 445: "SMB", 135: "RPC", 21: "FTP", 25: "SMTP", 3389: "RDP", 8080: "HTTP-alt" };
const POSTURE_BADGE = {
  tls13: ["ok", "TLS 1.3"], tls12: ["ok", "TLS 1.2"], tls_unseen: ["info", "HTTPS"], tls_legacy: ["bad", "Legacy TLS"],
  quic: ["violet", "QUIC"], dns: ["warn", "DNS (plain)"], cleartext: ["crit", "Cleartext"], other: ["mute", "-"],
};

PAGES.flows = {
  title: "Conversations",
  sub: "Who is talking to whom",
  icon: "flows",
  group: "Technical",
  sort: "recent",
  text: "",
  posture: "all",

  mount(root) {
    root.innerHTML = `
      ${guideHTML({
        title: 'A conversation is two devices talking',
        text: 'NetLens groups packets into conversations and names who is on the other end - a website, an app, or a company.',
      })}
      <div class="row wrap between">
        <div class="row wrap">
          <input class="input" id="fl-text" placeholder="Search site, organisation, IP…" style="width:260px" value="${esc(this.text)}">
          <div class="seg" id="fl-sort"><button data-s="recent" class="${this.sort === "recent" ? "on" : ""}">Most recent</button><button data-s="bytes" class="${this.sort === "bytes" ? "on" : ""}">Most data</button></div>
          <div class="seg" id="fl-post"><button data-p="all" class="on">All</button><button data-p="cleartext">Cleartext</button><button data-p="legacy">Weak crypto</button><button data-p="enc">Encrypted</button></div>
          <span id="fl-focus"></span>
        </div>
        <span class="muted mono" id="fl-count"></span>
      </div>
      <div class="card" style="padding:0"><div class="table-wrap" style="max-height:calc(100vh - 330px)">
        <table class="t"><thead><tr><th>Device</th><th>Destination</th><th>Proto</th><th>Service</th><th>Security</th><th class="r">Sent ↑</th><th class="r">Received ↓</th><th class="r">Packets</th><th class="r">Duration</th><th>State</th><th>Last seen</th></tr></thead><tbody id="fl-body"></tbody></table>
      </div></div>`;
    $("#fl-text").addEventListener("input", (e) => { this.text = e.target.value.toLowerCase(); this.update(window.S); });
    $("#fl-sort").addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; this.sort = b.dataset.s; $$("#fl-sort button").forEach((x) => x.classList.toggle("on", x === b)); this.update(window.S); });
    $("#fl-post").addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; this.posture = b.dataset.p; $$("#fl-post button").forEach((x) => x.classList.toggle("on", x === b)); this.update(window.S); });
  },

  update(S) {
    if (!S) return;
    let rows = S.conversations.slice();
    if (Names.focus) rows = rows.filter((r) => r.client.startsWith(Names.focus + ":") || r.server.startsWith(Names.focus + ":"));
    if (this.text) rows = rows.filter((r) => `${r.client} ${r.server} ${r.site} ${r.org} ${r.sni}`.toLowerCase().includes(this.text));
    if (this.posture === "cleartext") rows = rows.filter((r) => r.posture === "cleartext" || r.posture === "dns");
    if (this.posture === "legacy") rows = rows.filter((r) => r.posture === "tls_legacy" || r.posture === "cleartext");
    if (this.posture === "enc") rows = rows.filter((r) => ["tls13", "tls12", "tls_unseen", "quic"].includes(r.posture));
    rows.sort((a, b) => (this.sort === "bytes" ? b.bytes - a.bytes : b.last - a.last));

    $("#fl-body").innerHTML = rows.slice(0, 90).map((r) => {
      const [cip, cport] = splitEp(r.client), [sip, sport] = splitEp(r.server);
      const clientIsLocal = isPrivate(cip);
      const local = clientIsLocal ? cip : sip, remote = clientIsLocal ? r.server : r.client;
      const remotePort = clientIsLocal ? sport : cport;
      const service = SERVICES[sport] || SERVICES[cport] || (remotePort ? String(remotePort) : "-");
      const [bcls, btxt] = POSTURE_BADGE[r.posture] || POSTURE_BADGE.other;
      const remoteIp = splitEp(remote)[0];
      const remoteLocal = isPrivate(remoteIp);
      const dest = remoteLocal ? Names.name(remoteIp, S) : (r.site || r.sni);
      const org = remoteLocal || r.org === "Unknown" || r.org.toLowerCase() === (dest || "").toLowerCase() ? "" : r.org;
      return `<tr>
        <td><b>${esc(Names.name(local, S))}</b> <span class="faint mono">${esc(local)}</span></td>
        <td class="wrap">${dest ? `<b>${esc(dest)}</b> ` : ""}<span class="muted">${esc(org)}</span> <span class="faint mono">${esc(remote)}</span></td>
        <td><span class="proto ${r.proto}">${r.proto}</span></td><td>${esc(service)}</td>
        <td><span class="badge ${bcls}">${btxt}</span></td>
        <td class="r">${fmt.bytes(clientIsLocal ? r.up : r.down)}</td><td class="r">${fmt.bytes(clientIsLocal ? r.down : r.up)}</td>
        <td class="r">${fmt.num(r.packets)}</td><td class="r">${fmt.dur(r.last - r.first)}</td>
        <td>${r.state === "reset" ? `<span class="badge bad">reset</span>` : r.state === "closed" ? `<span class="badge mute">closed</span>` : `<span class="badge ok">open</span>`}</td>
        <td class="faint">${fmt.ago(r.last, S.now)}</td></tr>`;
    }).join("") || `<tr><td colspan="11" class="faint" style="padding:24px;text-align:center">No conversations match yet.</td></tr>`;
    $("#fl-count").textContent = `${Math.min(rows.length, 90)} of ${S.totals.conversations} conversations`;
    $("#fl-focus").innerHTML = Names.focus ? `<span class="badge violet">Focused: ${esc(Names.name(Names.focus, S))} <a href="#" onclick="Names.setFocus(null);PAGES.flows.update(window.S);return false" style="color:inherit">✕</a></span>` : "";
  },
};

function splitEp(ep) { const i = ep.lastIndexOf(":"); return [ep.slice(0, i), Number(ep.slice(i + 1))]; }
function isPrivate(ip) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(ip);
}

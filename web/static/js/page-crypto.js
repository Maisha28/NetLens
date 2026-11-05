/* Encryption & proof - is traffic encrypted, and were the alerts tampered with? */
"use strict";

const ENCRYPTED = ["tls13", "tls12", "tls_unseen", "quic"];

PAGES.crypto = {
  title: "Encryption & Proof",
  sub: "Is your traffic protected, and can the alerts be trusted?",
  icon: "crypto",
  group: "Main",
  ledger: null,
  timer: null,

  mount(root) {
    root.innerHTML = `
      ${guideHTML({
        title: "Two things this page shows",
        text: "<b>1.</b> Whether the traffic NetLens sees is encrypted - judged from the cleartext start of each secure connection, <b>without decrypting anything</b>. <b>2.</b> Proof that saved alerts haven't been edited, using a cryptographic seal.",
      })}
      <div class="grid split">
        <div class="card"><div class="card-head"><h2>How much is encrypted?</h2></div><div id="cr-post"></div></div>
        <div class="card"><div class="card-head"><h2>What others on the Wi-Fi can still see</h2></div><div id="cr-see"></div></div>
      </div>
      <div class="card"><div class="card-head"><h2>Problems found</h2></div><div id="cr-find"></div></div>

      <div class="card">
        <div class="card-head"><h2>Proof the alerts weren't changed</h2></div>
        <div class="steps3" style="margin-bottom:22px">
          <div><span class="n">1</span><span><b>Chain.</b> Every alert is linked to the one before it, like pages numbered in a book. Remove or change one and the chain breaks.</span></div>
          <div><span class="n">2</span><span><b>Seal.</b> Each link is signed with a secret key stored separately, so nobody can quietly rebuild the chain.</span></div>
          <div><span class="n">3</span><span><b>Check.</b> Press the buttons below to verify, then try to tamper with an alert and watch it get caught.</span></div>
        </div>
        <div class="row wrap" style="margin-bottom:16px"><button class="btn primary" id="cr-verify">${icon("shield")} Check integrity</button><button class="btn danger" id="cr-tamper">Try to tamper with an alert</button><button class="btn" id="cr-restore">Undo tampering</button></div>
        <div id="cr-banner"></div><div class="chain" id="cr-chain"></div>
      </div>

      <div class="card">
        <details class="more" style="border-top:0;margin-top:0;padding-top:0">
          <summary>Technical details - TLS handshakes and fingerprints</summary>
          <div>
            <p class="lead">Grade: <b>A</b> = TLS 1.3 · <b>B</b> = TLS 1.2 · <b>C</b> = offers broken ciphers · <b>F</b> = TLS 1.1 or older.</p>
            <div class="table-wrap" style="max-height:380px"><table class="t"><thead><tr><th>Device</th><th>Site</th><th>Version</th><th>Cipher chosen</th><th>Grade</th></tr></thead><tbody id="cr-tls"></tbody></table></div>
            <h3 style="margin:24px 0 8px;font-size:18px">Client fingerprints (JA3)</h3>
            <p class="lead">The same fingerprint means the same TLS software. It identifies the app or operating system, not the person.</p>
            <div id="cr-ja3"></div>
          </div>
        </details>
      </div>`;
    $("#cr-verify").onclick = () => this.act("/api/ledger/verify");
    $("#cr-tamper").onclick = () => this.act("/api/ledger/tamper");
    $("#cr-restore").onclick = () => this.act("/api/ledger/restore");
    this.timer = setInterval(() => this.loadLedger(), 2000);
    this.loadLedger();
  },

  unmount() { clearInterval(this.timer); },

  async act(path) {
    try {
      const res = await api(path, {});
      const v = res.verification || res;
      toast(v.ok ? "Integrity check passed" : "Tampering detected", v.ok ? `${v.count} sealed alert(s) - none have been changed.` : `Entry #${v.broken_at} no longer matches its seal.`, v.ok ? "" : "crit");
    } catch (e) { toast("Integrity check", e.message, "med"); }
    this.loadLedger();
  },

  async loadLedger() {
    try { this.ledger = await api("/api/ledger"); } catch { return; }
    this.renderLedger();
  },

  renderLedger() {
    const L = this.ledger; if (!L || !$("#cr-chain")) return;
    const v = L.verification;
    const byIdx = Object.fromEntries((v.checks || []).map((c) => [c.idx, c]));
    $("#cr-banner").innerHTML = !L.count ? "" : v.ok
      ? `<div class="banner good" style="margin-bottom:12px">${icon("shield")}<div><b>All good.</b> ${v.count} sealed alert(s) - every one still matches its seal.</div></div>`
      : `<div class="banner err" style="margin-bottom:12px">${icon("alerts")}<div><b>Tampering detected at entry #${v.broken_at}.</b> The saved alert was changed after it was sealed, so it can no longer be trusted. Everything after it is in doubt too.</div></div>`;
    if (!L.count) { $("#cr-chain").innerHTML = emptyHTML("No sealed alerts yet", "Alerts are sealed the moment they fire. Trigger one from the Demo guide, then come back here to check and tamper with it.", "shield"); return; }
    $("#cr-chain").innerHTML = L.entries.map((e) => {
      const c = byIdx[e.idx] || { hash: true, link: true, signature: true };
      const bad = !(c.hash && c.link && c.signature);
      const p = e.payload || {};
      return `<div class="block ${bad ? "bad" : ""}"><div class="bi">ALERT ${e.idx + 1} · ${fmt.time(e.ts)}</div><div class="bt">${esc((RULES[p.rule] || {}).title || p.rule || "")}</div>
        <div style="margin-bottom:8px;color:${bad ? "var(--critical)" : "var(--muted)"}">${esc(p.host || "")}</div>
        <code title="${e.entry_hash}">fingerprint ${fmt.short(e.entry_hash, 8)}</code>
        <div class="chk"><i class="${c.hash ? "p" : "f"}">content ${c.hash ? "✓" : "✗"}</i><i class="${c.link ? "p" : "f"}">chain ${c.link ? "✓" : "✗"}</i><i class="${c.signature ? "p" : "f"}">seal ${c.signature ? "✓" : "✗"}</i></div></div>`;
    }).join("");
  },

  update(S) {
    if (!S) return;
    const total = S.posture.reduce((a, p) => a + p.bytes, 0);
    const sum = (keys) => S.posture.filter((p) => keys.includes(p.key)).reduce((a, p) => a + p.bytes, 0);
    const enc = sum(ENCRYPTED), weak = sum(["tls_legacy"]), plain = sum(["cleartext", "dns"]), other = total - enc - weak - plain;
    const pct = (v) => (total ? Math.round((v / total) * 100) : 0);
    $("#cr-post").innerHTML = total
      ? `<div class="meterbig"><div class="pct">${pct(enc)}<small>%</small></div><div style="flex:1;min-width:220px;font-size:17px">of the data NetLens has seen is <b>encrypted</b>.</div>
        ${donut([{ value: enc, color: "#138a55", label: "Encrypted", text: pct(enc) + "%" }, { value: weak, color: "#d03a3a", label: "Weak", text: pct(weak) + "%" }, { value: plain, color: "#d98a1c", label: "Not encrypted", text: pct(plain) + "%" }, { value: Math.max(0, other), color: "#cfd7e4", label: "Other", text: pct(other) + "%" }], { size: 150, thickness: 24 })}</div>
        <div style="margin-top:18px">${barRows([{ label: "Encrypted", value: pct(enc), color: "#138a55" }, { label: "Weak encryption", value: pct(weak), color: "#d03a3a" }, { label: "Not encrypted", value: pct(plain), color: "#d98a1c" }], { fmtVal: (v) => v + "%", max: 100 })}</div>
        <div class="faint" style="font-size:14.5px">"Not encrypted" includes DNS lookups, which are sent as plain text.</div>`
      : `<div class="faint" style="font-size:16.5px">Waiting for traffic…</div>`;

    $("#cr-see").innerHTML = `
      <div class="row between" style="padding:11px 0"><span style="font-size:16.5px"><b>Which websites</b> you visit</span><span class="badge warn">visible</span></div>
      <div class="row between" style="padding:11px 0;border-top:1px solid var(--border)"><span style="font-size:16.5px"><b>When</b> and <b>how much</b></span><span class="badge warn">visible</span></div>
      <div class="row between" style="padding:11px 0;border-top:1px solid var(--border)"><span style="font-size:16.5px"><b>What type</b> of device it is</span><span class="badge warn">visible</span></div>
      <div class="row between" style="padding:11px 0;border-top:1px solid var(--border)"><span style="font-size:16.5px">The <b>content</b> of secure connections</span><span class="badge ok">protected</span></div>
      <div class="faint" style="font-size:14.5px;margin-top:8px">This is the information NetLens works from - enough to spot unusual behaviour without reading anything private.</div>`;

    $("#cr-find").innerHTML = S.findings.length
      ? S.findings.map((f) => `<div class="finding"><span class="badge ${f.severity === "critical" ? "crit" : f.severity === "high" ? "bad" : "warn"}">${esc(f.severity)}</span><div><b>${esc(f.title)}</b><div class="d">${esc(f.detail)}</div></div></div>`).join("")
      : `<div class="banner good">${icon("shield")}<div><b>No problems found.</b> Everything seen so far uses modern encryption. To see a finding, connect an old smart-home device, or open <span class="code">http://neverssl.com</span> on your phone.</div></div>`;

    $("#cr-tls").innerHTML = S.tls.map((t) => `<tr><td><b>${esc(Names.name(t.client, S))}</b></td><td>${esc(t.site || t.sni || t.server)}</td><td>${esc(t.negotiated || t.offered_version)}</td><td class="mono" style="font-size:13px">${t.cipher ? esc(t.cipher) : "-"}${t.cipher_weakness ? ` <span class="badge bad">weak</span>` : ""}</td><td><span class="grade ${esc(t.grade)}">${esc(t.grade)}</span></td></tr>`).join("")
      || `<tr><td colspan="5" class="faint" style="padding:20px;text-align:center">No secure connections captured yet.</td></tr>`;
    $("#cr-ja3").innerHTML = S.ja3.length
      ? S.ja3.map((g) => `<div class="row between" style="padding:10px 0;border-top:1px solid var(--border);font-size:15px"><span><span class="mono">${g.ja3.slice(0, 16)}…</span> &nbsp; ${g.clients.map((c) => esc(Names.name(c, S))).join(", ")} · ${g.count} connections</span><span class="grade ${esc(g.grade)}">${esc(g.grade)}</span></div>`).join("")
      : `<div class="faint">None yet.</div>`;
  },
};

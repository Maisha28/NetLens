/* Demo Playbook - a self-checking walkthrough for presenting to judges (live phone or simulation). */
"use strict";

const PLAYBOOK = [
  { id: "connect", title: "Connect your phone",
    do: `Turn on Windows <b>Mobile Hotspot</b>, join it from your phone, then open <b>Source → Live capture</b> and start.`,
    see: "A new device appears on the left of the network map within seconds, with its MAC address and a guess at what it is.",
    say: "“The laptop is the gateway, so every packet from the phone passes through it - that's our capture point.”",
    check: (S) => S.hosts.some((h) => !Names.isSelf(h.ip, S)), go: "overview" },
  { id: "names", title: "Turn bytes into names",
    do: "On the phone, open YouTube, Instagram and a news site.",
    see: "Conversations fill with site names (YouTube, Instagram…) and organisations (Google, Meta…) - resolved offline from DNS answers, TLS handshakes and an IP-range table.",
    say: "“Raw IPs mean nothing. We recover the website name from the DNS answer and the cleartext SNI in the TLS handshake, and the company from an offline range table.”",
    check: (S) => new Set(S.hosts.flatMap((h) => h.top_sites.map((s) => s[0]))).size >= 2, go: "flows" },
  { id: "baseline", title: "Watch it learn 'normal'",
    do: "Keep using the phone normally for about a minute (3 detection windows).",
    see: "On Devices, the progress bar fills and the status changes to <b>Normal</b>. Home then says <b>Everything looks normal</b>.",
    say: "“Each device is compared with its own history (an EWMA), not a fixed number. Until it has 3 windows we deliberately raise nothing - that's how we avoid false alarms.”",
    check: (S) => S.hosts.some((h) => !Names.isSelf(h.ip, S) && h.baseline && h.baseline.ready), go: "devices" },
  { id: "idle", title: "The idle test",
    do: "Put the phone face-down, untouched, for 2-3 minutes.",
    see: "On Devices, open <b>Idle test</b> under More tools: apps still connect on a near-fixed timer (green rows) while nobody is using the phone.",
    say: "“An idle phone is not silent: apps phone home on a timer. NetLens flags that regularity - a coefficient of variation under 0.25 - as a beacon.”",
    check: (S) => S.beacons.periodic.length > 0, go: "devices" },
  { id: "hog", title: "Bandwidth spike",
    do: "Start a large download or a long HD video on the phone.",
    see: "An <b>Unusually heavy data use</b> alert appears with the amount used, what is normal, and how many times more. The device on the Home map pulses red.",
    say: "“Observed is more than 3× this device's own baseline - and the alert shows the numbers, not an accusation.”",
    check: (S) => S.alerts.some((a) => a.rule === "bandwidth_hog"), go: "alerts" },
  { id: "scan", title: "Port scan",
    do: `From a <b>second device you own</b>, scan this laptop's hotspot address, e.g. <span class="code">nmap -p 1-1000 192.168.137.1</span>. Only ever scan your own machines.`,
    see: "A <b>Port scan</b> alert within seconds, showing how many different ports were tried compared with normal.",
    say: "“Hundreds of distinct destination ports in one window against a baseline of a handful - that is what a scan is.”",
    check: (S) => S.alerts.some((a) => a.rule === "port_scan"), go: "alerts" },
  { id: "crypto", title: "Weak or missing encryption",
    do: `On the phone, open <span class="code">http://neverssl.com</span> (a site made for testing plain HTTP).`,
    see: "On Encryption &amp; Proof, an <b>Unencrypted HTTP traffic</b> problem appears. Secure connections are graded A to F from their opening handshake.",
    say: "“We can't read HTTPS - and we don't try - but the handshake advertises versions and ciphers, so we can audit crypto hygiene without decrypting anything.”",
    check: (S) => S.findings.length > 0, go: "crypto" },
  { id: "seal", title: "Prove the evidence is untouched",
    do: `On Encryption &amp; Proof press <b>Check integrity</b>, then <b>Try to tamper with an alert</b>, then Check integrity again.`,
    see: "The chain is green. After tampering, the edited alert turns red and is pinpointed. <b>Undo tampering</b> puts it back.",
    say: "“Each alert is hash-chained with SHA-256 and signed with HMAC. Edit one and the chain breaks; recompute the hashes and the signature breaks - the key isn't in the database.”",
    check: (S) => S.ledger.count > 0, go: "crypto" },
];

PAGES.demo = {
  title: "Demo guide",
  sub: "A script for presenting NetLens - it ticks itself off",
  icon: "demo",
  group: "Explain",

  mount(root) {
    root.innerHTML = `
      ${guideHTML({
        title: 'Follow the steps',
        text: 'Each step says what to do, what you will see, and what to say. A step turns green by itself when NetLens detects the result.',
      })}
      <div id="dm-mode"></div>
      <div class="grid split"><div class="play" id="dm-steps"></div><div style="display:grid;gap:16px;align-content:start" id="dm-side"></div></div>`;
  },

  update(S) {
    if (!S) return;
    const live = S.mode === "live", sim = S.mode === "sim";
    $("#dm-mode").innerHTML = S.mode === "idle"
      ? `<div class="banner info"><div>${icon("plug")}</div><div><b>Pick a source to begin.</b> <button class="btn small primary" style="margin-left:8px" onclick="Setup.open()">Choose source</button></div></div>`
      : live ? `<div class="banner info"><div>${icon("radar")}</div><div><b>Live mode.</b> Follow the steps below with your own phone. Every number on screen is real traffic from your hotspot.</div></div>`
        : sim ? `<div class="banner warn"><div>${icon("chip")}</div><div><b>Simulation mode.</b> Traffic is synthetic (clearly labelled), but it runs through the real decoder, rules and ledger. Use the <b>Scenario Lab</b> on the right to stage each event.</div></div>` : "";

    const done = PLAYBOOK.map((p) => { try { return !!p.check(S); } catch { return false; } });
    const doneN = done.filter(Boolean).length;
    $("#dm-steps").innerHTML = PLAYBOOK.map((p, i) => `<div class="play-step ${done[i] ? "done" : ""}"><div class="num">${done[i] ? icon("check") : i + 1}</div>
      <div><h4>${p.title}</h4><div class="do"><span class="lbl">Do</span>${p.do}</div><div class="see"><span class="lbl">You'll see</span>${p.see}</div><div class="say"><span class="lbl">Say</span>${p.say}</div></div>
      <a class="btn small" href="#/${p.go}">Open ${PAGES[p.go].title} →</a></div>`).join("");

    let side = `<div class="card"><div class="card-head"><h2>Progress</h2><span class="badge ${doneN === PLAYBOOK.length ? "ok" : "info"}">${doneN}/${PLAYBOOK.length}</span></div><div class="progress"><i style="width:${(doneN / PLAYBOOK.length) * 100}%"></i></div></div>`;
    if (sim && S.sim) {
      const scn = S.scenarios, act = S.sim.active || {};
      const armed = S.totals.hosts > 0 && S.totals.ready_hosts >= 3;
      side += `<div class="card"><div class="card-head"><h2>Scenario Lab</h2><span class="badge ${armed ? "ok" : "warn"}">${armed ? "armed" : "learning baselines…"}</span></div>
        <div class="muted" style="font-size:12.5px;margin-bottom:10px">Stages traffic <b>inside the simulation only</b>, against simulated devices - never real ones. Wait for the badge to say <b>armed</b> before attacks.</div>
        <div style="display:grid;gap:8px">
        <div class="scn" style="border-color:rgba(62,230,196,.4)"><div><b>Run the scripted demo</b><small>bulb joins → bandwidth spike → port scan → ARP spoof, ~50 s</small>${S.sim.guided.length ? `<div style="margin-top:6px">${S.sim.guided.map((g) => `<div class="faint" style="font-size:12px">${g.done ? "✓" : "○"} +${g.at}s ${esc(g.text)}</div>`).join("")}</div>` : ""}</div><button class="btn primary small" data-s="guided" ${armed ? "" : "disabled"}>Run</button></div>
        ${Object.entries(scn).filter(([k]) => k !== "guided").map(([k, t]) => `<div class="scn"><div><b>${esc(t)}</b><small>${act[k] ? `running · ${act[k]}s left` : k.replace("_", " ")}</small></div><button class="btn small" data-s="${k}" ${["smart_bulb", "idle_phone", "resume_browsing"].includes(k) || armed ? "" : "disabled"}>Stage</button></div>`).join("")}
        </div></div>`;
    } else if (live) {
      side += `<div class="card"><div class="card-head"><h2>Live mode tips</h2></div><div class="muted" style="font-size:13px;display:grid;gap:8px">
        <div>• Start capture <b>before</b> opening apps - TLS handshakes are only seen when a connection <i>begins</i> after capture starts.</div>
        <div>• Turn off <b>Private DNS</b> on the phone (Android) to see DNS names; encrypted DNS hides them - itself a finding.</div>
        <div>• Every live session is saved to <span class="code">captures/</span> so you can <b>replay it offline</b> if the room's network misbehaves.</div>
        <div>• ARP spoofing can't be staged safely live - switch to <b>Simulation</b> to demonstrate that rule.</div></div>
        <div style="margin-top:12px"><button class="btn small" onclick="Setup.open()">Switch source…</button></div></div>`;
    }
    $("#dm-side").innerHTML = side;
    $$("#dm-side [data-s]").forEach((b) => b.addEventListener("click", async () => {
      try { const r = await api("/api/scenario", { name: b.dataset.s }); toast("Staged", r.title); } catch (e) { toast("Scenario", e.message, "med"); }
    }));
  },
};

/* Pipeline - the data path every group member must be able to narrate, with the real last packet at each stage. */
"use strict";

const STAGES = [
  { id: "capture", name: "Capture", file: "capture/capture.py", req: "REQ-1…5",
    what: "Npcap hands raw frames to scapy's sniff(); NetLens takes the untouched bytes plus a timestamp and does <b>no parsing</b> here. If one frame fails later, capture carries on.",
    inout: "network interface → (raw bytes, timestamp)",
    say: "“Capture does one job: hand over the untouched bytes with a timestamp. We deliberately don't parse here, so a bad frame can never stop the capture.”" },
  { id: "decode", name: "Decode", file: "decoder/decoder.py", req: "REQ-6…12",
    what: "Hand-written parsers read Ethernet → IPv4 → TCP/UDP → DNS/ARP/TLS with <span class='code'>struct.unpack</span> at the RFC byte offsets - <b>no scapy dissection</b>. Truncated or odd frames become 'OTHER' instead of crashing.",
    inout: "raw bytes → PacketRecord (the shared contract)",
    say: "“This is the syllabus part: Ethernet, IP, TCP, UDP, DNS parsed by hand with struct.unpack at their RFC offsets. Open the Packet Lab and I can point at any field in the raw bytes.”" },
  { id: "flow", name: "Flow tracker", file: "storage/flow_tracker.py", req: "REQ-13…16",
    what: "Packets are grouped by 5-tuple (src IP, src port, dst IP, dst port, protocol) with running packet/byte counts and first/last-seen times. NetLens also merges both directions into one <b>conversation</b> for display.",
    inout: "PacketRecord → flow / conversation counters",
    say: "“A connection is identified by its 5-tuple. We count packets and bytes per flow, and merge both directions into one conversation for the display.”" },
  { id: "store", name: "Store", file: "storage/db.py", req: "REQ-24, §5.3",
    what: "Every packet, flow, baseline and alert is written to local SQLite with <b>parameterised queries</b>, so data taken from the network can never alter a query. Nothing leaves this laptop.",
    inout: "records → netlens_demo.db (packets, flows, baselines, alerts)",
    say: "“Everything lands in SQLite with parameterised queries. Nothing leaves this laptop - no cloud, no API.”" },
  { id: "enrich", name: "Enrich", file: "enrichment/", req: "REQ-17…20",
    what: "Offline names: IP → organisation by longest-prefix match, DNS answers and TLS SNI → website, MAC → vendor. No network request is ever made, so a demo can't fail on a missing API.",
    inout: "IP / MAC / DNS → 'YouTube · Google'",
    say: "“Numbers become names. All offline, so there is nothing that can fail on demo day.”" },
  { id: "baseline", name: "Baseline", file: "baseline/baseline.py", req: "REQ-21…24",
    what: "Every detection window, each device's bytes, packets and distinct ports are blended into an <b>EWMA</b> (α = 0.2). A baseline only counts as <i>ready</i> after 3 windows.",
    inout: "window stats → per-device 'normal'",
    say: "“Each device's own history is its baseline - an exponentially weighted moving average. Until there are three windows of data, we raise nothing.”" },
  { id: "detect", name: "Detect", file: "detection/rules.py", req: "REQ-25…30",
    what: "Three explicit rules compare the window against the <b>prior</b> baseline: bandwidth hog, port scan, ARP spoof. A window that raised an alert is <b>not</b> learned from, so an attack can't teach NetLens it is normal. No machine learning.",
    inout: "stats + baseline → Alert(rule, host, observed, baseline, threshold)",
    say: "“Three explicit rules, each a threshold you can read and defend. No machine learning - every alert comes from a stated number.”" },
  { id: "seal", name: "Seal & show", file: "crypto/ledger.py · web/", req: "§5.3, REQ-31…35",
    what: "Each alert is appended to a SHA-256 hash chain, signed with HMAC, then pushed to this dashboard. Anything that changes a stored alert later is detected.",
    inout: "Alert → sealed ledger entry → UI",
    say: "“The alert is hash-chained and signed before it reaches the screen, so the evidence can be checked later. That is the integrity half of our cryptography.”" },
];

PAGES.pipeline = {
  title: "How it works",
  sub: "The path every packet takes",
  icon: "pipeline",
  group: "Explain",
  sel: "capture",

  mount(root) {
    root.innerHTML = `
      ${guideHTML({
        title: 'Eight steps from packet to alert',
        text: 'Click a step to see what it does. The numbers are live, and the panel on the right shows the real latest packet at that step.',
      })}
      <div class="pipe" id="pp-row"></div>
      <div class="card" style="padding:16px 22px"><div class="row between"><span class="muted" style="font-size:15px">Latest packet in flight</span><span class="mono" id="pp-sum" style="font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:75%"></span></div><div style="position:relative;height:10px;margin-top:8px;border-radius:99px;background:var(--bg-2);overflow:hidden"><div id="pp-dot" style="position:absolute;top:1px;left:0;width:60px;height:8px;border-radius:99px;background:linear-gradient(90deg,transparent,var(--accent),var(--accent-2));animation:fly 2.4s linear infinite"></div></div></div>
      <style>@keyframes fly{from{left:-60px}to{left:100%}}</style>
      <div class="grid split"><div class="card" id="pp-detail"></div><div class="trace" id="pp-trace"></div></div>`;
    $("#pp-row").innerHTML = STAGES.map((s, i) => `<div class="stage" data-id="${s.id}"><span class="pulse-dot"></span><div class="n">STAGE ${i + 1}</div><div class="nm">${s.name}</div><div class="ct">0</div><div class="cl"></div></div>`).join("");
    $("#pp-row").addEventListener("click", (e) => { const st = e.target.closest(".stage"); if (st) { this.sel = st.dataset.id; this.update(window.S); } });
  },

  update(S) {
    if (!S) return;
    const g = S.stages, tr = S.trace || {};
    const counts = {
      capture: [fmt.num(g.captured), "frames"], decode: [fmt.num(g.decoded), g.decode_errors ? `${g.decode_errors} errors` : "0 errors"],
      flow: [fmt.num(g.flows), `${fmt.num(S.totals.conversations)} conversations`], store: [fmt.num(g.stored), "rows in SQLite"],
      enrich: [fmt.num(S.totals.dns_queries), "names resolved"], baseline: [`${g.baselines}/${S.totals.hosts}`, "devices learned"],
      detect: [fmt.num(g.windows), `windows · ${g.alerts} alerts`], seal: [fmt.num(g.sealed), "alerts sealed"],
    };
    $$("#pp-row .stage").forEach((el) => { const c = counts[el.dataset.id]; $(".ct", el).textContent = c[0]; $(".cl", el).textContent = c[1]; el.classList.toggle("sel", el.dataset.id === this.sel); });
    $("#pp-sum").textContent = tr.summary || "waiting for the first packet…";

    const st = STAGES.find((s) => s.id === this.sel) || STAGES[0];
    $("#pp-detail").innerHTML = `<div class="card-head"><h2>Stage: ${st.name}</h2><span class="tag">${st.file}</span></div>
      <div style="font-size:14px;line-height:1.6">${st.what}</div>
      <div class="row" style="margin-top:12px;gap:8px"><span class="badge info">${st.inout}</span><span class="tag">SRS ${st.req}</span></div>
      <div style="margin-top:14px;padding:12px 14px;border-left:3px solid var(--accent);background:var(--accent-soft);border-radius:0 12px 12px 0;font-style:italic;color:#33425f;font-size:16px">${st.say}</div>`;

    const dst = S.hosts.length ? S.hosts.find((h) => h.ip === tr.host) : null;
    const base = tr.baseline;
    const steps = {
      capture: [["Raw bytes", tr.raw_hex ? `${tr.raw_hex} …  (${tr.raw_len} bytes total)` : "-"], ["Reads", "nothing - parsing starts at the next stage"]],
      decode: [["Layers found", (tr.layers || []).join(" → ") || "-"], ["Decoded to", tr.summary || "-"]],
      flow: [["Flow (5-tuple)", tr.flow ? tr.flow.key : "-"], ["Running totals", tr.flow ? `${tr.flow.packets} packets · ${fmt.bytes(tr.flow.bytes)}` : "-"]],
      store: [["Action", "INSERT INTO packets … (parameterised)"], ["Rows so far", fmt.num(g.stored)]],
      enrich: [["Names", dst ? `${esc(Names.name(dst, S))} (${tr.host})` : (tr.host || "-")], ["Method", "offline IP-range table · DNS answers · TLS SNI · MAC OUI"]],
      baseline: [["Device", tr.host || "-"], ["This window", fmt.bytes(tr.window_bytes || 0)], ["Learned normal", base ? `${fmt.bytes(base.bytes)} per window (${base.samples} windows)` : "not learned yet"]],
      detect: [["Rules checked", "bandwidth_hog · port_scan · arp_spoof"], ["Compared against", "the prior baseline - never one the spike itself inflated"], ["Last window", S.windows.length ? `${fmt.bytes(S.windows[S.windows.length - 1].bytes)} · ${S.windows[S.windows.length - 1].alerts} alert(s)` : "-"]],
      seal: [["Ledger head", S.ledger.head.slice(0, 32) + "…"], ["Entries", String(S.ledger.count)], ["Delivery", "polled by this dashboard every second"]],
    }[st.id];
    $("#pp-trace").innerHTML = `<div class="step"><div class="k">At this stage</div><div class="v" style="color:var(--muted);font-family:var(--sans)">the most recent packet looked like…</div></div>` +
      steps.map(([k, v]) => `<div class="step"><div class="k">${k}</div><div class="v">${esc(v)}</div></div>`).join("");
  },
};

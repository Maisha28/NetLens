/* Packet Lab - pick a packet, see exactly which bytes each field came from. */
"use strict";

const LAYER_SWATCH = { eth: "#8b9bb9", arp: "#ffb454", ip: "#46d68c", tcp: "#5b8cff", udp: "#a78bfa", icmp: "#3ee6c4", dns: "#ff77c8", tls: "#ff5d73", data: "#6f7f9e" };

PAGES.lab = {
  title: "Packet lab",
  sub: "Raw bytes next to their meaning",
  icon: "lab",
  group: "Technical",
  list: [],
  listSeq: 0,
  sel: null,
  timer: null,
  detail: null,

  mount(root, arg) {
    this.list = []; this.listSeq = 0; this.detail = null;
    root.innerHTML = `
      ${guideHTML({
        title: 'See what is inside a packet',
        text: 'Pick a packet on the left. The coloured block is the raw data; click a field below to see which bytes it came from.',
      })}
      <div class="lab">
        <div><div class="row between" style="margin-bottom:8px"><span class="muted" style="font-size:12.5px">Recent packets</span><input class="input" id="lb-filter" placeholder="filter…" style="width:130px;padding:4px 9px"></div><div class="pkt-list" id="lb-list"></div></div>
        <div id="lb-detail"><div class="empty">${icon("lab")}<b>Select a packet</b><div>Choose one from the list, or click any row in the Live Feed.</div></div></div>
      </div>`;
    $("#lb-filter").addEventListener("input", () => this.renderList());
    this.timer = setInterval(() => this.poll(), 900);
    this.poll().then(() => { if (!arg && !this.sel && this.list.length) { /* leave unselected so the presenter chooses */ } });
    if (arg) this.open(Number(arg));
  },

  onArg(arg) { if (arg) this.open(Number(arg)); },
  unmount() { clearInterval(this.timer); },
  update() {},

  async poll() {
    let d;
    try { d = await api(`/api/feed?since=${this.listSeq}`); } catch { return; }
    this.listSeq = d.seq;
    this.list = this.list.concat(d.packets).slice(-160);
    this.renderList();
  },

  renderList() {
    const box = $("#lb-list"); if (!box) return;
    const q = ($("#lb-filter").value || "").toLowerCase();
    const items = this.list.filter((p) => !q || `${p.src} ${p.dst} ${p.info} ${p.proto}`.toLowerCase().includes(q)).slice(-90).reverse();
    box.innerHTML = items.map((p) => `<div class="pkt-item ${p.seq === this.sel ? "sel" : ""}" data-seq="${p.seq}">
      <span><span class="proto ${p.proto}">${p.proto}</span> <span class="faint">#${p.seq} · ${p.len} B</span></span>
      <span style="overflow:hidden;text-overflow:ellipsis">${esc(p.src)} → ${esc(p.dst)}</span>
      <span class="faint" style="overflow:hidden;text-overflow:ellipsis">${esc(p.info.replace(/^(TCP|UDP|ARP|ICMP) /, ""))}</span></div>`).join("") || `<div class="faint" style="padding:16px">No packets yet.</div>`;
    $$(".pkt-item", box).forEach((el) => el.addEventListener("click", () => { history.replaceState(null, "", `#/lab/${el.dataset.seq}`); this.open(Number(el.dataset.seq)); }));
  },

  async open(seq) {
    this.sel = seq;
    this.renderList();
    const box = $("#lb-detail");
    let d;
    try { d = await api(`/api/packet/${seq}`); } catch (e) {
      box.innerHTML = emptyHTML("That packet is too old", "NetLens remembers the most recent 5,000 packets. Pick a newer one from the list, or press Freeze on Live packets first.", "lab");
      return;
    }
    this.detail = d;
    const bytes = d.hex.match(/../g) || [];
    const kindAt = new Array(bytes.length).fill("data");
    const layerAt = new Array(bytes.length).fill(-1);
    d.layers.forEach((l, li) => { for (let i = l.start; i < l.end && i < bytes.length; i++) { kindAt[i] = l.kind; layerAt[i] = li; } });

    let hex = "";
    for (let off = 0; off < bytes.length; off += 16) {
      const row = bytes.slice(off, off + 16);
      hex += `<div class="hex-line"><span class="hex-off">${off.toString(16).padStart(4, "0")}</span><span class="hex-bytes">${row.map((b, i) => `<span data-i="${off + i}" class="L-${kindAt[off + i]}${i === 7 ? " sep" : ""}">${b}</span>`).join("")}</span><span class="hex-ascii">${row.map((b, i) => { const c = parseInt(b, 16); return `<span data-i="${off + i}" class="L-${kindAt[off + i]}">${c >= 32 && c < 127 ? esc(String.fromCharCode(c)) : "·"}</span>`; }).join("")}</span></div>`;
    }

    const tree = d.layers.map((l, li) => `<div class="layer"><div class="layer-head"><i class="sw" style="background:${LAYER_SWATCH[l.kind] || "#888"}"></i>${esc(l.name)}<span class="faint mono" style="margin-left:auto;font-size:11.5px;font-weight:400">bytes ${l.start}–${l.end - 1} (${l.end - l.start})</span></div>
      ${l.fields.map((f, fi) => `<div class="field" data-o="${f.offset}" data-l="${f.length}" data-layer="${li}"><span class="fn">${esc(f.name)}</span><span class="fo">${f.length ? `@${f.offset} +${f.length}` : "derived"}</span><span class="fv"><b>${esc(f.value)}</b>${f.hex && f.length ? ` <span class="faint mono">(0x${esc(f.hex.length > 24 ? f.hex.slice(0, 24) + "…" : f.hex)})</span>` : ""}${f.note ? `<small>${esc(f.note)}</small>` : ""}</span></div>`).join("")}</div>`).join("");

    box.innerHTML = `<div style="display:grid;gap:14px">
      <div class="card"><div class="row between wrap"><div><span class="proto ${d.summary ? d.summary.proto : "OTHER"}">${d.summary ? d.summary.proto : "?"}</span> <b>Packet #${seq}</b> <span class="muted">· ${d.length} bytes on the wire</span></div><span class="faint mono">${d.summary ? fmt.timeMs(d.summary.t) : ""}</span></div>
        ${d.summary ? `<div class="mono muted" style="margin-top:6px;font-size:12.5px">${esc(d.summary.info)}</div>` : ""}</div>
      <div class="legend">${d.layers.map((l) => `<span><i style="background:${LAYER_SWATCH[l.kind]}"></i>${esc(l.name)}</span>`).join("")}</div>
      <div class="hexdump" id="lb-hex">${hex}</div>
      ${d.notes.map((n) => `<div class="banner info"><div>${icon("bulb")}</div><div>${esc(n)}</div></div>`).join("")}
      <div style="display:grid;gap:10px">${tree}</div></div>`;

    const clear = () => $$("#lb-hex .hl").forEach((s) => s.classList.remove("hl"));
    const mark = (o, l) => { clear(); for (let i = o; i < o + l; i++) $$(`#lb-hex [data-i="${i}"]`).forEach((s) => s.classList.add("hl")); };
    $$("#lb-detail .field").forEach((el) => el.addEventListener("click", () => {
      $$("#lb-detail .field").forEach((x) => x.classList.remove("sel")); el.classList.add("sel");
      const l = Number(el.dataset.l);
      if (l) { mark(Number(el.dataset.o), l); const first = $(`#lb-hex [data-i="${el.dataset.o}"]`); if (first) first.scrollIntoView({ block: "nearest", behavior: "smooth" }); }
      else clear();
    }));
    $$("#lb-hex .hex-bytes span, #lb-hex .hex-ascii span").forEach((s) => s.addEventListener("click", () => {
      const i = Number(s.dataset.i);
      const f = $$("#lb-detail .field").find((x) => Number(x.dataset.l) && i >= Number(x.dataset.o) && i < Number(x.dataset.o) + Number(x.dataset.l));
      if (f) f.click(); else clear();
    }));
  },
};

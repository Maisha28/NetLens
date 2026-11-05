/* Live Feed - one line per decoded packet, as it arrives. */
"use strict";

PAGES.feed = {
  title: "Live packets",
  sub: "Every packet, the moment it arrives",
  icon: "feed",
  group: "Technical",
  seq: 0,
  timer: null,
  filter: "ALL",
  text: "",
  auto: true,
  paused: false,
  count: 0,

  mount(root) {
    this.seq = 0; this.count = 0;
    root.innerHTML = `
      ${guideHTML({
        title: 'One line per packet',
        text: 'Each row is one packet, read from its raw bytes. Click any row to see exactly which bytes mean what.',
      })}
      <div class="row wrap between">
        <div class="row wrap">
          <div class="seg" id="fd-chips">${["ALL", "TCP", "UDP", "ARP", "DNS", "TLS", "CLEAR"].map((c) => `<button data-c="${c}" class="${c === this.filter ? "on" : ""}">${c === "CLEAR" ? "Cleartext" : c}</button>`).join("")}</div>
          <input class="input" id="fd-text" placeholder="Filter: IP, site, organisation…" style="width:240px" value="${esc(this.text)}">
          <span id="fd-focus"></span>
        </div>
        <div class="row">
          <span class="muted mono" id="fd-count"></span>
          <label class="switch on" id="fd-auto"><i></i>Auto-scroll</label>
          <button class="btn small" id="fd-pause"><svg><use href="#i-pause"/></svg><span>Freeze</span></button>
        </div>
      </div>
      <div class="feed" id="fd-feed"><div class="feed-row head"><span>Time</span><span>Proto</span><span>Source → Destination</span><span>Bytes</span><span>Details</span><span>Site / organisation</span></div></div>`;
    $("#fd-chips").addEventListener("click", (e) => {
      const b = e.target.closest("button"); if (!b) return;
      this.filter = b.dataset.c;
      $$("#fd-chips button").forEach((x) => x.classList.toggle("on", x === b));
      this.refilter();
    });
    $("#fd-text").addEventListener("input", (e) => { this.text = e.target.value.toLowerCase(); this.refilter(); });
    $("#fd-auto").addEventListener("click", () => { this.auto = !this.auto; $("#fd-auto").classList.toggle("on", this.auto); });
    $("#fd-pause").addEventListener("click", () => {
      this.paused = !this.paused;
      $("#fd-pause span").textContent = this.paused ? "Resume" : "Freeze";
    });
    this.timer = setInterval(() => this.poll(), 500);
    this.poll();
  },

  unmount() { clearInterval(this.timer); },

  match(p) {
    if (Names.focus && !(p.src.startsWith(Names.focus) || p.dst.startsWith(Names.focus))) return false;
    if (this.filter === "DNS" && p.tag !== "dns") return false;
    if (this.filter === "TLS" && p.tag !== "tls") return false;
    if (this.filter === "CLEAR" && p.tag !== "clear") return false;
    if (["TCP", "UDP", "ARP"].includes(this.filter) && p.proto !== this.filter) return false;
    if (this.text && !`${p.src} ${p.dst} ${p.info} ${p.site} ${p.org}`.toLowerCase().includes(this.text)) return false;
    return true;
  },

  row(p, isNew) {
    const tagBadge = p.tag === "tls" ? `<span class="badge info">TLS</span>` : p.tag === "dns" ? `<span class="badge warn">DNS</span>` : p.tag === "clear" ? `<span class="badge crit">CLEARTEXT</span>` : "";
    const el = h("div", { class: "feed-row" + (isNew ? " new" : ""), onclick: () => { location.hash = `#/lab/${p.seq}`; } });
    el.dataset.seq = p.seq;
    el._p = p;
    el.innerHTML = `<span class="faint">${fmt.timeMs(p.t)}</span><span class="proto ${esc(p.proto)}">${esc(p.proto)}</span><span>${esc(p.src)} <span class="faint">→</span> ${esc(p.dst)}</span><span class="right">${p.len}</span><span class="info" title="${esc(p.info)}">${p.flags ? `<span class="tag">${esc(p.flags)}</span> ` : ""}${tagBadge} ${esc(shortInfo(p))}</span><span class="faint" style="overflow:hidden;text-overflow:ellipsis">${esc(p.site || p.org)}</span>`;
    return el;
  },

  refilter() {
    $$("#fd-feed .feed-row:not(.head)").forEach((r) => { r.style.display = this.match(r._p) ? "" : "none"; });
  },

  async poll() {
    if (this.paused) return;
    let data;
    try { data = await api(`/api/feed?since=${this.seq}`); } catch { return; }
    this.seq = data.seq;
    const feed = $("#fd-feed");
    if (!feed) return;
    const nearBottom = feed.scrollHeight - feed.scrollTop - feed.clientHeight < 80;
    for (const p of data.packets) {
      const el = this.row(p, this.count > 0);
      if (!this.match(p)) el.style.display = "none";
      feed.append(el);
      this.count++;
    }
    const rows = $$(".feed-row:not(.head)", feed);
    for (let i = 0; i < rows.length - 450; i++) rows[i].remove();
    if (this.auto && (nearBottom || data.packets.length)) feed.scrollTop = feed.scrollHeight;
    $("#fd-count").textContent = `${fmt.num(this.count)} shown`;
    $("#fd-focus").innerHTML = Names.focus ? `<span class="badge violet">Focused: ${esc(Names.name(Names.focus, window.S))} <a href="#" onclick="Names.setFocus(null);PAGES.feed.refilter();this.parentElement.remove();return false" style="color:inherit">✕</a></span>` : "";
  },

  update() { /* feed polls itself */ },
};

/** Drop the "TCP a:b -> c:d [FLAGS]" prefix that the columns already show; keep what is new (DNS name, TLS version...). */
function shortInfo(p) {
  const rest = p.info.replace(/^(TCP|UDP|ICMP) \S+ -> \S+( \[[^\]]*\])?\s*/, "");
  return rest || (p.proto === "TCP" ? "" : p.info);
}

/* Landing page: the scroll-driven "raw bytes to verdict" story and the animated result counters. */
(function () {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const NS = "http://www.w3.org/2000/svg";
  const svg = (tag, attrs, parent) => { const el = document.createElementNS(NS, tag); for (const k in attrs) el.setAttribute(k, attrs[k]); if (parent) parent.append(el); return el; };

  /* ------------------------------------------------------- a real frame's bytes */
  const FRAME = [
    ..."da 4e 91 3c 70 b2 00 0c f1 5a 22 10 08 00".split(" "),                                                   // Ethernet (14)
    ..."45 00 00 28 2d 17 40 00 40 06 cd 86 c0 a8 89 2d 8e fa 4d 0e".split(" "),                                  // IPv4 (20)
    ..."c9 21 01 bb 3e 6a 83 ac 00 00 00 00 50 02 ff ff 8a 5d 00 00".split(" "),                                  // TCP (20)
  ];
  const layerOf = (i) => (i < 14 ? "eth" : i < 34 ? "ip" : "tcp");

  function buildHex(el) {
    for (let r = 0; r < FRAME.length; r += 16) {
      const row = document.createElement("div"); row.className = "row";
      row.innerHTML = `<span class="off">${r.toString(16).padStart(4, "0")}</span>` +
        FRAME.slice(r, r + 16).map((b, k) => `<span class="b ${layerOf(r + k)}" style="--i:${r + k}">${b}</span>`).join("");
      el.append(row);
    }
  }
  buildHex($("#hex0")); buildHex($("#hex1"));

  const FIELDS = [
    ["Destination MAC", "da:4e:91:3c:70:b2"], ["Source MAC", "00:0c:f1:5a:22:10"], ["TTL", "64 · Android / iOS family"],
    ["Protocol", "6 = TCP"], ["From", "192.168.137.45"], ["To", "142.250.77.14 · Google"], ["Port", "443 = HTTPS"], ["Flags", "SYN"],
  ];
  $("#fields1").innerHTML = FIELDS.map(([k, v], i) => `<span style="--i:${i}">${k} <b>${v}</b></span>`).join("");

  /* ----------------------------------------------------- scene 3: conversations */
  const flow = $("#flowsvg");
  const N = {
    phone: [74, 112, "Phone", "#5b8cff"], lap: [74, 268, "Laptop", "#5b8cff"], hub: [262, 190, "This laptop", "#35e0c0"],
    g: [452, 60, "YouTube", "#a78bfa"], m: [474, 160, "Instagram", "#a78bfa"], a: [468, 262, "Apple", "#a78bfa"], c: [420, 338, "Cloudflare", "#a78bfa"],
  };
  const L = [["phone", "hub"], ["lap", "hub"], ["hub", "g"], ["hub", "m"], ["hub", "a"], ["hub", "c"]];
  L.forEach(([a, b], i) => {
    const A = N[a], B = N[b], d = `M${A[0]},${A[1]} Q${(A[0] + B[0]) / 2},${(A[1] + B[1]) / 2 - 26} ${B[0]},${B[1]}`;
    svg("path", { d, class: "link", style: `--i:${i}` }, flow);
    for (let k = 0; k < 2; k++) {
      const c = svg("circle", { r: 5, fill: b === "hub" ? "#7fa6ff" : "#35e0c0", class: "pk" }, flow);
      const m = svg("animateMotion", { dur: `${2.4 + (i % 3) * 0.5}s`, repeatCount: "indefinite", begin: `${k * 1.2 + i * 0.2}s`, path: d }, c);
    }
  });
  Object.values(N).forEach(([x, y, label, col], i) => {
    const g = svg("g", { class: "nd", style: `--i:${i}` }, flow);
    svg("circle", { cx: x, cy: y, r: i === 2 ? 30 : 24, class: "node", stroke: col }, g);
    svg("circle", { cx: x, cy: y, r: i === 2 ? 11 : 7, fill: col }, g);
    svg("text", { x, y: y + (i === 2 ? 52 : 46) }, g).textContent = label;
  });

  /* ------------------------------------------------- scene 4: learns "normal" */
  const bars = $("#barsvg");
  const H = [58, 70, 52, 66, 74, 60, 68, 55, 72, 63, 70, 59, 66, 71, 218];
  const base = 66, thr = base * 3, y0 = 244;
  svg("line", { x1: 18, y1: y0, x2: 504, y2: y0, stroke: "#2a3a5e", "stroke-width": 1 }, bars);
  H.forEach((h, i) => svg("rect", { x: 24 + i * 32, y: y0 - h, width: 24, height: h, rx: 5, class: "bar" + (i === H.length - 1 ? " spike" : ""), style: `--i:${i}` }, bars));
  svg("path", { d: `M18,${y0 - base} H504`, class: "base" }, bars);
  svg("path", { d: `M18,${y0 - thr} H504`, class: "thr" }, bars);
  svg("text", { x: 22, y: y0 - base - 8 }, bars).textContent = "this device's normal";
  svg("text", { x: 22, y: y0 - thr - 8 }, bars).textContent = "alert level (3× normal)";

  /* ---------------------------------------------------- scene 5: the chain */
  const chain = $("#chain");
  [["Port scan", "a41f…9c2e"], ["Heavy use", "5d8b…03f7"], ["Impersonation", "c77a…e1b4"], ["Port scan", "09ee…7a30"]].forEach(([t, h], i) => {
    const b = document.createElement("div"); b.className = "blk" + (i === 2 ? " bad" : ""); b.style.setProperty("--i", i * 2);
    b.innerHTML = `<b>${t}</b>${h}<em>sealed ✓</em>`;
    chain.append(b);
    if (i < 3) { const l = document.createElement("div"); l.className = "lnk"; l.style.setProperty("--i", i * 2); chain.append(l); }
  });

  /* ------------------------------------------------------ scroll-driven steps */
  const story = $("#story"), steps = $$(".step"), scenes = $$(".scene"), dots = $$("#storyDots i");
  let cur = -1, tamperTimer = 0;
  function setStep(i) {
    if (i === cur) return;
    steps.forEach((s, k) => { s.classList.toggle("on", k === i); s.classList.toggle("past", k < i); });
    scenes.forEach((s, k) => s.classList.toggle("on", k === i));
    dots.forEach((d, k) => d.classList.toggle("on", k === i));
    // the tampered block flips from "sealed" to "edited" a moment after the chain appears
    clearTimeout(tamperTimer);
    const bad = $(".blk.bad em");
    if (bad) { bad.textContent = "sealed ✓"; if (i === 4) tamperTimer = setTimeout(() => { bad.textContent = "edited ✗"; }, 2800); }
    cur = i;
  }
  function storyScroll() {
    const r = story.getBoundingClientRect(), total = r.height - innerHeight;
    if (r.bottom < 0 || r.top > innerHeight) return;
    const p = Math.min(0.9999, Math.max(0, -r.top / total));
    setStep(Math.floor(p * steps.length));
  }
  addEventListener("scroll", storyScroll, { passive: true });
  addEventListener("resize", storyScroll);
  storyScroll(); setStep(Math.max(0, cur));
  dots.forEach((d, i) => d.addEventListener("click", () => {
    const top = story.offsetTop, total = story.offsetHeight - innerHeight;
    scrollTo({ top: top + ((i + 0.5) / steps.length) * total, behavior: "smooth" });
  }));

  // deep link: landing.html#story-3 opens straight on the fourth scene (handy when presenting)
  const deep = /^#story-(\d)$/.exec(location.hash);
  if (deep) addEventListener("load", () => scrollTo({ top: story.offsetTop + ((Number(deep[1]) + 0.5) / steps.length) * (story.offsetHeight - innerHeight), behavior: "instant" }));

  /* -------------------------------------------------------- counting numbers */
  const cio = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue;
      cio.unobserve(e.target);
      $$("[data-count]", e.target).forEach(count);
      if (e.target.matches("[data-count]")) count(e.target);
    }
  }, { threshold: 0.35 });
  $$(".counters, .beforeafter").forEach((el) => cio.observe(el));
  function count(el) {
    const to = Number(el.dataset.count), of = el.dataset.of, t0 = performance.now(), dur = 1500;
    const tick = (now) => {
      const k = Math.min(1, (now - t0) / dur), v = Math.round(to * (1 - Math.pow(1 - k, 3)));
      el.textContent = of ? `${v}/${of}` : String(v);
      if (k < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }
})();

/* Landing page: theme, nav, reveal-on-scroll, card glow, decode ticker and the hero network canvas. */
(function () {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const root = document.documentElement;
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ------------------------------------------------------------------ theme */
  $("#themeBtn").addEventListener("click", () => {
    const next = root.dataset.theme === "dark" ? "light" : "dark";
    root.dataset.theme = next;
    try { localStorage.setItem("netlens.theme", JSON.stringify(next)); } catch (e) { /* private mode */ }
  });

  /* ------------------------------------------------- scroll progress + nav */
  const bar = $("#scrollbar"), nav = $("#nav");
  function onScroll() {
    const max = document.documentElement.scrollHeight - innerHeight;
    bar.style.width = (max > 0 ? (scrollY / max) * 100 : 0) + "%";
    nav.classList.toggle("stuck", scrollY > 24);
  }
  addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  /* ----------------------------------------------------------- reveal on scroll */
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
  }, { threshold: 0.14, rootMargin: "0px 0px -6% 0px" });
  $$(".reveal").forEach((el) => io.observe(el));

  /* --------------------------------------------- cards: cursor glow + gentle tilt */
  $$(".tilt").forEach((card) => {
    card.addEventListener("mousemove", (e) => {
      const r = card.getBoundingClientRect(), x = (e.clientX - r.left) / r.width, y = (e.clientY - r.top) / r.height;
      card.style.setProperty("--mx", x * 100 + "%"); card.style.setProperty("--my", y * 100 + "%");
      if (!reduce) card.style.transform = `perspective(900px) rotateX(${(0.5 - y) * 7}deg) rotateY(${(x - 0.5) * 9}deg) translateY(-4px)`;
    });
    card.addEventListener("mouseleave", () => { card.style.transform = ""; });
  });

  /* ---------------------------------------------------------- decode ticker */
  const LINES = [
    ["TCP", "192.168.137.45:51022 → 142.250.77.14:443", "YouTube · Google"],
    ["UDP", "192.168.137.45:49821 → 192.168.137.1:53", "DNS lookup"],
    ["TCP", "192.168.137.45:51044 → 157.240.1.174:443", "Instagram · Meta"],
    ["ARP", "who has 192.168.137.1? tell 192.168.137.60", "ARP request"],
    ["TCP", "192.168.137.60:40001 → 192.168.137.1:445", "port probe"],
    ["TCP", "192.168.137.45:51067 → 17.253.144.10:443", "Apple"],
    ["UDP", "192.168.137.45:50112 → 142.250.77.14:443", "QUIC · encrypted"],
  ];
  const tk = $("#ticker");
  let li = 0;
  function pushLine() {
    const [p, flow, name] = LINES[li++ % LINES.length];
    const row = document.createElement("div");
    row.className = "t-row";
    row.innerHTML = `<span class="pr ${p}">${p}</span><span>${flow}</span><span class="nm">${name}</span>`;
    tk.append(row);
    while (tk.children.length > 6) tk.firstChild.remove();
  }
  for (let i = 0; i < 4; i++) pushLine();
  if (!reduce) setInterval(pushLine, 1400);

  /* ------------------------------------------------------------ hero canvas */
  const cv = $("#heroNet"), ctx = cv.getContext("2d");
  let W = 0, H = 0, dpr = 1, running = true, mouse = { x: 0.5, y: 0.5, tx: 0.5, ty: 0.5 };
  const stars = Array.from({ length: 70 }, () => ({ x: Math.random(), y: Math.random(), s: 0.4 + Math.random() * 1.3, v: 0.00004 + Math.random() * 0.00012 }));
  const NODES = [
    { id: "hub", x: 0.70, y: 0.44, r: 30, label: "This laptop", kind: "hub", depth: 8 },
    { id: "phone", x: 0.55, y: 0.24, r: 22, label: "Phone", kind: "dev", depth: 16 },
    { id: "lap", x: 0.50, y: 0.44, r: 20, label: "Laptop", kind: "dev", depth: 12 },
    { id: "bulb", x: 0.58, y: 0.62, r: 18, label: "Smart bulb", kind: "dev", depth: 18 },
    { id: "g", x: 0.92, y: 0.13, r: 16, label: "Google", kind: "org", depth: 22 },
    { id: "m", x: 0.97, y: 0.29, r: 14, label: "Meta", kind: "org", depth: 26 },
    { id: "a", x: 0.96, y: 0.45, r: 15, label: "Apple", kind: "org", depth: 20 },
    { id: "c", x: 0.93, y: 0.61, r: 14, label: "Cloudflare", kind: "org", depth: 24 },
    { id: "w", x: 0.85, y: 0.74, r: 14, label: "AWS", kind: "org", depth: 18 },
  ];
  const byId = Object.fromEntries(NODES.map((n) => [n.id, n]));
  const LINKS = [["phone", "hub"], ["lap", "hub"], ["bulb", "hub"], ["hub", "g"], ["hub", "m"], ["hub", "a"], ["hub", "c"], ["hub", "w"]];
  const packets = [];
  let alarm = null, nextAlarm = 4200;

  function size() {
    dpr = Math.min(2, devicePixelRatio || 1);
    W = cv.clientWidth; H = cv.clientHeight;
    cv.width = W * dpr; cv.height = H * dpr;
  }
  addEventListener("resize", size);
  size();
  addEventListener("mousemove", (e) => { mouse.tx = e.clientX / innerWidth; mouse.ty = e.clientY / innerHeight; }, { passive: true });
  new IntersectionObserver((es) => { running = es[0].isIntersecting; if (running) requestAnimationFrame(frame); }).observe(cv);

  function pos(n, t) {
    const px = (mouse.x - 0.5) * n.depth * 2, py = (mouse.y - 0.5) * n.depth * 2;
    const wob = Math.sin(t / 1800 + n.x * 9) * 5, wob2 = Math.cos(t / 2100 + n.y * 7) * 5;
    const narrow = W < 960 ? 0.5 : 0;   // on small screens the graph spreads across the full width
    return { x: (n.x * (1 - narrow) + narrow * (0.1 + n.x * 0.8)) * W + px + wob, y: n.y * H + py + wob2 };
  }

  function spawn() {
    const [a, b] = LINKS[(Math.random() * LINKS.length) | 0];
    const fwd = byId[a].kind === "dev" || Math.random() < 0.55;
    packets.push({ a: fwd ? a : b, b: fwd ? b : a, p: 0, v: 0.004 + Math.random() * 0.006 });
  }

  let last = performance.now(), acc = 0;
  function frame(now) {
    if (!running) return;
    const dt = Math.min(48, now - last); last = now;
    mouse.x += (mouse.tx - mouse.x) * 0.06; mouse.y += (mouse.ty - mouse.y) * 0.06;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    const dark = root.dataset.theme !== "light";
    const ink = dark ? "234,240,255" : "15,25,48";

    // drifting star field with faint constellation lines
    for (const s of stars) { s.x = (s.x + s.v * dt) % 1; s.y = (s.y + s.v * 0.4 * dt) % 1; }
    ctx.fillStyle = `rgba(${ink},.5)`;
    for (const s of stars) { ctx.beginPath(); ctx.arc(s.x * W, s.y * H, s.s, 0, 6.283); ctx.fill(); }
    ctx.lineWidth = 1;
    for (let i = 0; i < stars.length; i++) for (let j = i + 1; j < stars.length; j++) {
      const dx = (stars[i].x - stars[j].x) * W, dy = (stars[i].y - stars[j].y) * H, d = dx * dx + dy * dy;
      if (d < 9000) { ctx.strokeStyle = `rgba(${ink},${0.10 * (1 - d / 9000)})`; ctx.beginPath(); ctx.moveTo(stars[i].x * W, stars[i].y * H); ctx.lineTo(stars[j].x * W, stars[j].y * H); ctx.stroke(); }
    }

    // links
    const P = {}; for (const n of NODES) P[n.id] = pos(n, now);
    for (const [a, b] of LINKS) {
      const A = P[a], B = P[b], g = ctx.createLinearGradient(A.x, A.y, B.x, B.y);
      g.addColorStop(0, "rgba(91,140,255,.55)"); g.addColorStop(1, "rgba(53,224,192,.45)");
      ctx.strokeStyle = g; ctx.lineWidth = 1.6;
      ctx.beginPath(); ctx.moveTo(A.x, A.y);
      ctx.quadraticCurveTo((A.x + B.x) / 2, (A.y + B.y) / 2 - 24, B.x, B.y); ctx.stroke();
    }

    // packets
    acc += dt; if (acc > 150) { acc = 0; if (packets.length < 46) spawn(); }
    for (let i = packets.length - 1; i >= 0; i--) {
      const k = packets[i]; k.p += k.v * dt / 8;
      if (k.p >= 1) { packets.splice(i, 1); continue; }
      const A = P[k.a], B = P[k.b], cx = (A.x + B.x) / 2, cy = (A.y + B.y) / 2 - 24, t = k.p;
      const x = (1 - t) * (1 - t) * A.x + 2 * (1 - t) * t * cx + t * t * B.x, y = (1 - t) * (1 - t) * A.y + 2 * (1 - t) * t * cy + t * t * B.y;
      const hot = alarm && (k.a === alarm.id || k.b === alarm.id);
      ctx.beginPath(); ctx.arc(x, y, hot ? 3.6 : 2.8, 0, 6.283);
      ctx.fillStyle = hot ? "#ff6b7d" : byId[k.a].kind === "org" || byId[k.b].kind === "org" ? "#35e0c0" : "#7fa6ff";
      ctx.shadowColor = ctx.fillStyle; ctx.shadowBlur = 12; ctx.fill(); ctx.shadowBlur = 0;
    }

    // alarm pulse on a random device
    nextAlarm -= dt;
    if (nextAlarm <= 0) { const devs = NODES.filter((n) => n.kind === "dev"); alarm = { id: devs[(Math.random() * devs.length) | 0].id, t: 0 }; nextAlarm = 7000; }
    if (alarm) {
      alarm.t += dt;
      const A = P[alarm.id], k = alarm.t / 2400;
      if (k >= 1) alarm = null;
      else for (let ring = 0; ring < 2; ring++) {
        const kk = (k + ring * 0.25) % 1;
        ctx.strokeStyle = `rgba(255,107,125,${0.7 * (1 - kk)})`; ctx.lineWidth = 3;
        ctx.beginPath(); ctx.arc(A.x, A.y, byId[alarm.id].r + 6 + kk * 54, 0, 6.283); ctx.stroke();
      }
    }

    // nodes
    ctx.textAlign = "center";
    for (const n of NODES) {
      const { x, y } = P[n.id], hot = alarm && alarm.id === n.id;
      const col = hot ? "255,107,125" : n.kind === "hub" ? "53,224,192" : n.kind === "dev" ? "91,140,255" : "167,139,250";
      const halo = ctx.createRadialGradient(x, y, 0, x, y, n.r * 2.6);
      halo.addColorStop(0, `rgba(${col},.30)`); halo.addColorStop(1, `rgba(${col},0)`);
      ctx.fillStyle = halo; ctx.beginPath(); ctx.arc(x, y, n.r * 2.6, 0, 6.283); ctx.fill();
      ctx.fillStyle = dark ? "#0b1324" : "#ffffff"; ctx.beginPath(); ctx.arc(x, y, n.r, 0, 6.283); ctx.fill();
      ctx.strokeStyle = `rgb(${col})`; ctx.lineWidth = n.kind === "hub" ? 3.5 : 2.5; ctx.stroke();
      ctx.fillStyle = `rgb(${col})`;
      if (n.kind === "hub") { ctx.fillRect(x - 11, y - 8, 22, 14); ctx.fillRect(x - 15, y + 9, 30, 3); }
      else if (n.kind === "dev") { ctx.beginPath(); ctx.roundRect(x - 5, y - 9, 10, 18, 3); ctx.fill(); }
      else { ctx.beginPath(); ctx.arc(x, y, 4, 0, 6.283); ctx.fill(); }
      ctx.font = `600 ${n.kind === "org" ? 12.5 : 13.5}px "Segoe UI", sans-serif`;
      ctx.fillStyle = `rgba(${ink},.82)`; ctx.fillText(n.label, x, y + n.r + 19);
    }
    if (!reduce) requestAnimationFrame(frame); else running = false;
  }
  requestAnimationFrame(frame);
  if (reduce) requestAnimationFrame(frame);
})();


/* ---------------------------------------------------------------- ambient polish */
(function () {
  "use strict";
  const $ = (q, r = document) => r.querySelector(q);
  const $$ = (q, r = document) => [...r.querySelectorAll(q)];
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // headline: split into words so they can blur in one after another
  const h1 = $(".hero h1");
  if (h1) {
    let i = 0;
    const wrap = (node) => [...node.childNodes].forEach((n) => {
      if (n.nodeType === 3) {
        const frag = document.createDocumentFragment();
        n.textContent.split(/(\s+)/).forEach((t) => {
          if (!t.trim()) { frag.append(t); return; }
          const s = document.createElement("span"); s.className = "w"; s.style.setProperty("--i", i++); s.textContent = t; frag.append(s);
        });
        n.replaceWith(frag);
      } else if (n.nodeType === 1 && n.tagName !== "BR") wrap(n);
    });
    wrap(h1);
  }

  // cursor spotlight + gentle parallax on the hero
  const hero = $(".hero");
  if (hero && !reduce) {
    hero.addEventListener("mousemove", (e) => {
      const r = hero.getBoundingClientRect();
      hero.style.setProperty("--sx", e.clientX - r.left + "px"); hero.style.setProperty("--sy", e.clientY - r.top + "px");
    });
    const aur = $(".hero .aurora");
    addEventListener("scroll", () => { if (aur && scrollY < innerHeight * 1.2) aur.style.transform = `translateY(${scrollY * 0.22}px)`; }, { passive: true });
  }

  // magnetic buttons
  if (!reduce) $$(".btn.primary").forEach((b) => {
    b.classList.add("magnet");
    b.addEventListener("mousemove", (e) => {
      const r = b.getBoundingClientRect();
      b.style.transform = `translate(${(e.clientX - r.left - r.width / 2) * 0.18}px, ${(e.clientY - r.top - r.height / 2) * 0.28}px)`;
    });
    b.addEventListener("mouseleave", () => { b.style.transform = ""; });
  });

  // comparison rows reveal one by one
  const rows = $$(".crow:not(.head)");
  const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } }), { threshold: 0.2 });
  rows.forEach((r, i) => { r.classList.add("reveal"); r.style.transitionDelay = i * 70 + "ms"; io.observe(r); });
})();

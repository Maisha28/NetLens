/* Tuning lab - replay one recording under different settings and measure every alert. */
"use strict";

PAGES.tuning = {
  title: "Tuning lab",
  sub: "Measured proof that the detector was tuned, not guessed",
  icon: "chip",
  group: "Explain",
  R: { capture: null, study: null, sweep: {}, holdout: null, sweepParam: "hog_multiplier" },
  info: null,
  timer: null,
  running: null,

  mount(root, arg) {
    root.innerHTML = `
      ${guideHTML({
        title: "How do we know the thresholds are right?",
        text: "A detector is only useful if it catches real problems <b>without crying wolf</b>. Here one recording - where the right answer for every event is known - is replayed under different settings, and every alert is marked right or wrong. The same data goes in each time, so the only thing that changes is the setting.",
      })}
      <div class="card" id="tn-pick"></div>
      <div class="card" id="tn-study"></div>
      <div class="card" id="tn-sweep"></div>
      <div class="card" id="tn-holdout"></div>
      <div class="card" id="tn-events"></div>`;
    this.loadInfo().then(() => { if (arg === "auto") this.runAll(); });
    if (this.running) { clearInterval(this.timer); this.timer = setInterval(() => this.pollJob(), 350); }  // resume a study started before switching tabs
  },

  unmount() { clearInterval(this.timer); this.timer = null; },
  update() {},

  async loadInfo() {
    try { this.info = await api("/api/tuning/info"); } catch (e) { toast("Tuning lab", e.message, "med"); return; }
    const bench = this.info.captures.find((c) => c.benchmark);
    if (!this.R.capture || !this.info.captures.some((c) => c.name === this.R.capture)) this.R.capture = bench ? bench.name : (this.info.captures[0] || {}).name || null;
    this.renderAll();
  },

  renderAll() { this.renderPick(); this.renderStudy(); this.renderSweep(); this.renderHoldout(); this.renderEvents(); },

  header(n, title, hint) { return `<div class="card-head"><h2><span class="stepnum">${n}</span>${title}</h2>${hint ? `<span class="hint">${hint}</span>` : ""}</div>`; },
  busy(kind) { return this.running && this.running.kind === kind; },
  runBar(kind) {
    if (!this.busy(kind)) return "";
    const j = this.job || { done: 0, total: 1 };
    return `<div class="runbar"><div class="progress"><i style="width:${Math.max(4, (j.done / j.total) * 100)}%"></i></div><span class="muted">Replaying… ${j.done} of ${j.total}</span></div>`;
  },

  /* ---------------------------------------------------------------- step 1 */
  renderPick() {
    const I = this.info; if (!I) return;
    const cap = I.captures.find((c) => c.name === this.R.capture);
    const hasBench = I.captures.some((c) => c.benchmark);
    $("#tn-pick").innerHTML = `${this.header(1, "Choose a recording")}
      <p class="lead">${hasBench ? "The built-in <b>benchmark</b> is a 5-minute synthetic hotspot capture. Every attack and every <i>harmless-but-unusual</i> event in it is labelled, so each alert can be judged right or wrong." : "No recording has known answers yet. Create the built-in benchmark - a 5-minute synthetic capture where every attack and every harmless-but-unusual event is labelled."}</p>
      <div class="row wrap">
        ${I.captures.length ? `<select class="input" id="tn-cap">${I.captures.map((c) => `<option value="${esc(c.name)}" ${c.name === this.R.capture ? "selected" : ""}>${esc(c.name)} ${c.labelled ? "· has known answers" : "· no labels"}</option>`).join("")}</select>` : ""}
        <button class="btn ${hasBench ? "" : "primary"}" id="tn-gen">${hasBench ? "Regenerate benchmark" : "Create the benchmark"}</button>
        <button class="btn primary" id="tn-all" ${this.running || !cap ? "disabled" : ""}>Run everything (steps 2-4)</button>
        ${cap ? (cap.labelled ? `<span class="badge ok">Known answers ✓</span>` : `<span class="badge warn">No labels - alerts can be counted but not judged</span>`) : ""}
      </div>
      <details class="more"><summary>How alerts are judged</summary><div class="muted" style="font-size:16px;line-height:1.7">
        <div><b>Caught</b> - the first alert for a real attack (right kind, right device, right time).</div>
        <div><b>False alarm</b> - an alert for a harmless event, or for nothing at all.</div>
        <div><b>Repeat</b> - another alert for an attack already caught (noise).</div>
        <div><b>Missed</b> - an attack with no alert. <b>Quiet</b> - a harmless event that correctly raised nothing.</div>
        <div style="margin-top:8px" class="faint">The benchmark is synthetic and says so. It measures the detector's trade-offs reproducibly; it does not claim accuracy on every real network. To score a real recording, put a <span class="code">name.labels.json</span> file next to it.</div></div></details>`;
    const sel = $("#tn-cap"); if (sel) sel.onchange = () => { this.R.capture = sel.value; this.R.study = null; this.R.sweep = {}; this.renderAll(); };
    $("#tn-all").onclick = () => this.runAll();
    $("#tn-gen").onclick = async () => {
      $("#tn-gen").disabled = true; $("#tn-gen").textContent = "Creating…";
      try { await api("/api/tuning/benchmark", {}); this.R.capture = "benchmark.pcap"; this.R.study = null; this.R.sweep = {}; toast("Benchmark ready", "A fresh labelled recording was created."); } catch (e) { toast("Tuning lab", e.message, "med"); }
      this.loadInfo();
    };
  },

  /* ---------------------------------------------------------------- step 2 */
  renderStudy() {
    const st = this.R.study, el = $("#tn-study"); if (!el) return;
    let body = `<p class="lead">Start from a naive first-attempt detector and make one change at a time until you reach the shipped settings. The same recording is replayed after each change.</p>
      <div class="row"><button class="btn primary" id="tn-run-study" ${this.running || !this.R.capture ? "disabled" : ""}>${st ? "Run it again" : "Run the before / after test"}</button></div>${this.runBar("study")}`;
    if (st) {
      const first = st.steps[0], last = st.steps[st.steps.length - 1];
      body += st.labelled
        ? `<div class="hero ${last.false_alarms === 0 ? "good" : "wait"}" style="margin:18px 0"><div class="big">${icon("shield")}</div><div><h2>${first.false_alarms} false alarms → ${last.false_alarms}</h2><p>The untuned detector raised <b>${first.alerts} alerts</b>, <b>${first.false_alarms}</b> of them wrong. After ${st.steps.length - 1} measured changes it raises <b>${last.alerts}</b> and still catches <b>${last.caught} of ${last.attacks}</b> attacks.</p></div></div>
          <canvas id="tn-bars"></canvas><div class="legend" style="margin:8px 0 18px"><span><i style="background:#d03a3a"></i>False alarms (lower is better)</span><span><i style="background:#e8a33d"></i>Attacks missed (lower is better)</span></div>
          <table class="t"><thead><tr><th>Step</th><th>What changed</th><th class="r">Alerts</th><th class="r">Attacks caught</th><th class="r">False alarms</th><th class="r">Attack windows flagged</th></tr></thead><tbody>${st.steps.map((s, i) => `<tr ${i === st.steps.length - 1 ? 'style="background:var(--ok-soft)"' : ""}><td><b>${i === 0 ? "Start" : i}</b></td><td class="wrap"><b>${esc(s.title)}</b><div class="muted" style="font-size:14.5px;max-width:560px">${esc(s.why)}</div></td><td class="r">${s.alerts}</td><td class="r">${s.caught}/${s.attacks}</td><td class="r"><b style="color:${s.false_alarms ? "var(--danger)" : "var(--ok)"}">${s.false_alarms}</b></td><td class="r">${s.coverage == null ? "-" : Math.round(s.coverage * 100) + "%"}</td></tr>`).join("")}</tbody></table>
          <div class="muted" style="margin-top:12px;font-size:15px"><b>Reading it:</b> step 5 ("don't learn from alerts") deliberately trades a few extra repeat alerts for resistance to <i>baseline poisoning</i> - see "attack windows flagged" rise from ${Math.round(st.steps[4].coverage * 100)}% to ${Math.round(st.steps[5].coverage * 100)}%; step 6 then removes the repeats.</div>`
        : `<div class="banner warn" style="margin-top:16px"><div>!</div><div>This recording has no labels, so alerts are counted but cannot be judged: <b>${last.alerts}</b> alert(s) with the shipped settings versus <b>${first.alerts}</b> with the untuned ones.</div></div>`;
    }
    el.innerHTML = this.header(2, "Before and after tuning") + body;
    const btn = $("#tn-run-study"); if (btn) btn.onclick = () => this.run("study");
    if (st && st.labelled) TuneChart.bars($("#tn-bars"), st.steps.map((s) => ({ false_alarms: s.false_alarms, missed: s.missed })));
  },

  /* ---------------------------------------------------------------- step 3 */
  renderSweep() {
    const I = this.info, el = $("#tn-sweep"); if (!I || !el) return;
    const p = this.R.sweepParam, sw = this.R.sweep[p];
    const opts = Object.entries(I.sweeps).map(([k, v]) => `<option value="${k}" ${k === p ? "selected" : ""}>${esc(v.title)}</option>`).join("");
    let body = `<p class="lead">Pick one setting, try a range of values, and see what each does. Everything else stays at the shipped values.</p>
      <div class="row wrap"><select class="input" id="tn-param">${opts}</select><button class="btn primary" id="tn-run-sweep" ${this.running || !this.R.capture ? "disabled" : ""}>${sw ? "Run again" : "Try different values"}</button></div>
      <div class="faint" style="margin:8px 0 0">${esc(I.sweeps[p].why)}</div>${this.runBar("sweep")}`;
    if (sw && sw.labelled) {
      const fmtX = p === "hog_multiplier" ? (v) => `${v}×` : p === "hog_min_observed_per_s" ? (v) => (v >= 1000 ? `${v / 1000}k` : String(v)) : (v) => String(v);
      const full = sw.points.filter((q) => q.missed === 0);
      const minFalse = full.length ? Math.min(...full.map((q) => q.false_alarms)) : null;
      const best = full.filter((q) => q.false_alarms === minFalse);
      let verdict = "No value catches every attack on this recording.";
      if (best.length) {
        const lo = best[0].value, hi = best[best.length - 1].value, def = sw.default;
        verdict = `Values from <b>${fmtX(lo)}</b> to <b>${fmtX(hi)}</b> catch every attack with the fewest false alarms (${minFalse}). The shipped setting, <b>${fmtX(def)}</b>, ${def >= lo && def <= hi ? "sits inside that range" : "is outside it"}.`;
      }
      body += `<div class="banner info" style="margin:16px 0"><div>${icon("bulb")}</div><div>${verdict}</div></div><canvas id="tn-lines"></canvas>
        <div class="legend" style="margin-top:8px"><span><i style="background:#d03a3a"></i>False alarms</span><span><i style="background:#e8a33d"></i>Attacks missed</span><span><i style="background:rgba(19,138,85,.35)"></i>Shipped value</span></div>
        <div class="muted" style="margin-top:10px;font-size:15px"><b>The trade-off:</b> set it too low and harmless events trip it (red rises); too high and real attacks slip through (amber rises). The shipped value is chosen from the flat middle, not an edge.</div>`;
    } else if (sw) body += `<div class="banner warn" style="margin-top:16px"><div>!</div><div>Choose a recording with known answers to chart this.</div></div>`;
    el.innerHTML = this.header(3, "Find the best setting") + body;
    $("#tn-param").onchange = (e) => { this.R.sweepParam = e.target.value; this.renderSweep(); };
    $("#tn-run-sweep").onclick = () => this.run("sweep", this.R.sweepParam);
    if (sw && sw.labelled) {
      const fmtX = p === "hog_multiplier" ? (v) => `${v}×` : p === "hog_min_observed_per_s" ? (v) => (v >= 1000 ? `${v / 1000}k` : String(v)) : (v) => String(v);
      TuneChart.lines($("#tn-lines"), sw.points, sw.default, fmtX);
    }
  },

  /* ---------------------------------------------------------------- step 4 */
  renderHoldout() {
    const h = this.R.holdout, el = $("#tn-holdout"); if (!el) return;
    let body = `<p class="lead">The shipped settings were chosen on one recording, so they might just be memorising it. Here they are scored on <b>5 brand-new variations</b> of the same kinds of events (different random traffic) that were never used for tuning.</p>
      <div class="row"><button class="btn primary" id="tn-run-hold" ${this.running ? "disabled" : ""}>${h ? "Run again" : "Run the held-out check"}</button></div>${this.runBar("holdout")}`;
    if (h) {
      const t = h.totals;
      body += `<div class="hero ${t.tuned.false_alarms <= 2 ? "good" : "wait"}" style="margin:18px 0"><div class="big">${icon("check")}</div><div><h2>${t.tuned.caught} of ${t.attacks} attacks caught</h2><p>On unseen traffic the tuned detector raised <b>${t.tuned.false_alarms}</b> false alarm${t.tuned.false_alarms === 1 ? "" : "s"} in total; the untuned one raised <b>${t.naive.false_alarms}</b>. The settings are not just memorising one recording.</p></div></div>
        <table class="t"><thead><tr><th>Variation</th><th class="r">Attacks</th><th class="r">Tuned: caught</th><th class="r">Tuned: false alarms</th><th class="r">Untuned: false alarms</th></tr></thead><tbody>${h.seeds.map((r) => `<tr><td>Variation ${r.seed}</td><td class="r">${r.tuned.attacks}</td><td class="r">${r.tuned.caught}/${r.tuned.attacks}</td><td class="r"><b style="color:${r.tuned.false_alarms ? "var(--danger)" : "var(--ok)"}">${r.tuned.false_alarms}</b></td><td class="r">${r.naive.false_alarms}</td></tr>`).join("")}</tbody></table>
        <div class="muted" style="margin-top:10px;font-size:15px">Not perfect, and that is honest: an occasional miss or false alarm remains. What matters is that the result holds up on data the tuning never saw.</div>`;
    }
    el.innerHTML = this.header(4, "Check it isn't over-fitted") + body;
    $("#tn-run-hold").onclick = () => this.run("holdout");
  },

  /* ---------------------------------------------------------------- step 5 */
  renderEvents() {
    const st = this.R.study, el = $("#tn-events"); if (!el) return;
    if (!st || !st.labelled) { el.innerHTML = this.header(5, "Look at each event") + `<div class="faint" style="font-size:16.5px">Run the before / after test (step 2) to see how the shipped settings handled every individual event.</div>`; return; }
    const ev = st.detail.events, badge = (e) => {
      if (e.kind === "attack") return e.outcome === "caught" ? `<span class="badge ok">Caught ✓${e.delay != null ? ` in ${e.delay}s` : ""}</span>` : `<span class="badge bad">Missed ✗</span>`;
      return e.outcome === "quiet" ? `<span class="badge ok">Correctly quiet ✓</span>` : `<span class="badge bad">False alarm ✗</span>`;
    };
    el.innerHTML = this.header(5, "Look at each event", "with the shipped settings") + `<p class="lead">Every labelled event in the recording and what the tuned detector did about it.</p>
      <table class="t"><thead><tr><th>Event</th><th>Should it alert?</th><th>What happened</th><th class="r">Windows flagged</th></tr></thead><tbody>${ev.map((e) => `<tr><td class="wrap"><b>${esc(e.title)}</b><div class="muted" style="font-size:14.5px;max-width:520px">${esc(e.why)}</div></td><td>${e.kind === "attack" ? `<span class="badge bad">Yes - attack</span>` : `<span class="badge mute">No - harmless</span>`}</td><td>${badge(e)}</td><td class="r">${e.kind === "attack" ? `${e.flagged}/${e.windows}` : "-"}</td></tr>`).join("")}</tbody></table>`;
  },

  /* ----------------------------------------------------------------- jobs */
  /** Start a study; the returned promise resolves when it has finished (or failed). */
  run(kind, param) {
    return new Promise(async (resolve) => {
      if (this.running) return resolve();
      try { await api("/api/tuning/run", { kind, capture: this.R.capture, param }); } catch (e) { toast("Tuning lab", e.message, "med"); return resolve(); }
      this._done = resolve;
      this.running = { kind, param }; this.job = { done: 0, total: 1 };
      this.renderAll();
      clearInterval(this.timer);
      this.timer = setInterval(() => this.pollJob(), 350);
    });
  },

  async runAll() {
    await this.run("study");
    await this.run("sweep", this.R.sweepParam);
    await this.run("holdout");
  },

  async pollJob() {
    let j; try { j = await api("/api/tuning/job"); } catch { return; }
    if (j.status === "running") { this.job = j; const bar = $(".runbar .progress i"); if (bar) { bar.style.width = Math.max(4, (j.done / j.total) * 100) + "%"; bar.parentElement.nextElementSibling.textContent = `Replaying… ${j.done} of ${j.total}`; } return; }
    clearInterval(this.timer); this.timer = null;
    this.running = null;
    const finish = this._done; this._done = null;
    if (j.status === "error") { toast("Tuning lab", j.error, "med"); this.renderAll(); if (finish) finish(); return; }
    const r = j.result;
    if (r.kind === "study") this.R.study = r; else if (r.kind === "sweep") this.R.sweep[r.param] = r; else if (r.kind === "holdout") this.R.holdout = r;
    this.renderAll();
    if (finish) finish();
  },
};

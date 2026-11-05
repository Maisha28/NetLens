/* Landing page: the "How to use NetLens" walkthrough - five animated scenes that advance by themselves. */
(function () {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const root = $("#use");
  if (!root) return;

  const STEP_SECONDS = 8.5;
  const STEPS = [
    { title: "Turn on the Mobile Hotspot",
      text: "In Windows open Settings → Network & internet → Mobile hotspot and switch it on. Your laptop becomes the gateway for your phone, which is what lets NetLens see its traffic.",
      see: "A virtual adapter with the address 192.168.137.1." },
    { title: "Connect your phone",
      text: "Join the hotspot from your phone's Wi-Fi settings and use the phone as usual. Every packet it sends now passes through the laptop.",
      see: "The phone receives an address such as 192.168.137.45." },
    { title: "Start NetLens as Administrator",
      text: "Double-click the launcher and approve the Windows prompt. Packet capture needs elevated rights, so the launcher requests them for you.",
      cmd: "run_netlens.bat", see: "The dashboard opens in your browser." },
    { title: "Choose Live capture",
      text: "The setup wizard checks Administrator rights, the Npcap driver and the hotspot adapter, then starts capturing. Every session is also recorded for offline replay.",
      see: "Three green checks, then \"capturing\"." },
    { title: "Watch, understand, report",
      text: "NetLens learns what is normal for each device, raises plain-English alerts when something is not, grades every device A to F and prints a one-page report.",
      see: "Status turns green; alerts appear with the numbers behind them." },
  ];

  const wifi = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M2 9a15 15 0 0120 0M5 13a10 10 0 0114 0M8.5 16.5a5 5 0 017 0"/><circle cx="12" cy="20" r="1" fill="currentColor"/></svg>`;
  const laptopSvg = `<svg viewBox="0 0 120 100"><rect x="14" y="8" width="92" height="60" rx="7" fill="var(--bg-2)" stroke="var(--text)" stroke-width="3"/><rect x="22" y="16" width="76" height="44" rx="3" fill="var(--card)"/><path d="M4 78h112l-8 12H12z" fill="var(--text)" opacity=".85"/><path d="M45 36a22 22 0 0130 0M51 43a14 14 0 0118 0" fill="none" stroke="#35e0c0" stroke-width="3" stroke-linecap="round"/><circle cx="60" cy="50" r="2.6" fill="#35e0c0"/></svg>`;
  const cursor = `<svg viewBox="0 0 24 24"><path d="M4 2l16 9-7 2-3 7z"/></svg>`;

  const SCENES = [
    `<div class="u-card" style="--d:.1s;width:230px"><div class="u-row"><b>Mobile hotspot</b><span class="u-switch"><i></i></span></div><small>Share my internet connection</small>
       <div class="u-kv"><span>Network name</span><b class="u-reveal" style="--d:1.5s">NetLens-Hotspot</b></div>
       <div class="u-kv"><span>Laptop address</span><b class="u-reveal mono" style="--d:1.9s">192.168.137.1</b></div></div>
     <div class="u-laptop" style="--d:.3s"><div class="u-waves"><i style="--k:0"></i><i style="--k:1"></i><i style="--k:2"></i></div>${laptopSvg}</div>`,

    `<div class="u-laptop" style="--d:.1s;width:120px"><div class="u-waves"><i style="--k:0"></i><i style="--k:1"></i></div>${laptopSvg}</div>
     <div class="u-link" style="--d:.2s"><i></i></div>
     <div class="u-phone" style="--d:.4s"><div class="wifi"><i></i>NetLens-Hotspot</div><div class="ip">192.168.137.45</div><div class="ln"></div><div class="ln" style="width:70%"></div></div>
     <div class="u-badge" style="--d:2.7s"><i></i>1 device connected</div>`,

    `<div class="u-term" style="--d:.1s"><div class="bar"><i></i><i></i><i></i><span>PowerShell</span></div><div class="body">
       <div><span class="ps">PS C:\\NetLens&gt;</span> <span class="u-type" style="--n:16;--d:.6s;--dur:1.6s">.\\run_netlens.bat</span></div>
       <div class="u-line" style="--d:2.4s">Requesting Administrator rights for packet capture...</div>
       <div class="u-line ok" style="--d:6.2s">NetLens is running at <span class="u-url">http://localhost:8765</span></div>
       <div class="u-line" style="--d:6.6s">Opening your browser...</div></div>
       <div class="u-uac"><b>User Account Control</b>Do you want to allow this app to make changes to your device?<div class="btns"><span class="yes">Yes</span><span>No</span></div></div></div>
     <div class="u-cursor">${cursor}</div>`,

    `<div class="u-card u-wiz" style="--d:.1s"><h4>Choose your data source</h4><small>Live capture · your own phone</small><div style="height:8px"></div>
       <div class="u-check" style="--d:.5s"><span class="st"><i class="sp"></i><i class="okc">✓</i></span>Administrator rights<small>elevated</small></div>
       <div class="u-check" style="--d:1.2s"><span class="st"><i class="sp"></i><i class="okc">✓</i></span>Npcap packet driver<small>installed</small></div>
       <div class="u-check" style="--d:1.9s"><span class="st"><i class="sp"></i><i class="okc">✓</i></span>Hotspot adapter found<small class="mono">192.168.137.1</small></div>
       <div class="u-go">▶ Start live capture</div><div class="u-capt"><i></i>Capturing - recording to captures/live-….pcap</div></div>`,

    `<div class="u-dash" style="--d:.1s">
       <div class="u-ban"><div class="wait"><span style="font-size:22px">◌</span><span><b>Learning what's normal</b><small>Watching each device for a few windows first</small></span></div>
         <div class="good"><span style="font-size:22px">✓</span><span><b>Everything looks normal</b><small>Every device is behaving like itself</small></span></div>
         <div class="bad"><span style="font-size:22px">!</span><span><b>1 security alert</b><small>Latest: Port scan involving Intel device</small></span></div></div>
       <div class="u-tiles"><div class="u-tile"><b>3</b><small>Devices</small></div><div class="u-tile"><b>9</b><small>Sites seen</small></div><div class="u-tile"><b>6.2 MB</b><small>Observed</small></div></div>
       <div class="u-alert" style="opacity:0"><b>Port scan</b>tried 121 ports in 3 s - normal is 2<span>121</span></div>
       <div class="u-grades"><i class="a">A</i>Phone<i class="f">F</i>IoT bulb<span class="u-print">Print report</span></div></div>`,
  ];

  /* ------------------------------------------------------------- build DOM */
  const list = $("#useSteps"), stage = $("#useStage");
  STEPS.forEach((s, i) => {
    const b = document.createElement("button");
    b.className = "u-step"; b.type = "button"; b.setAttribute("aria-label", `Step ${i + 1}: ${s.title}`);
    b.innerHTML = `<span class="num">${i + 1}</span><div><h3>${s.title}</h3><div class="more"><div><p>${s.text}</p>${s.cmd ? `<span class="cmd">${s.cmd}</span>` : ""}<div class="see"><b>You'll see</b><span>${s.see}</span></div></div></div></div><span class="bar"><i></i></span>`;
    b.addEventListener("click", () => go(i, true));
    list.append(b);
  });
  const cap = document.createElement("div");
  cap.className = "u-cap";
  cap.innerHTML = `<span id="useCap"></span><span class="dotsrow">${STEPS.map(() => "<i></i>").join("")}</span>`;
  SCENES.forEach((html) => { const d = document.createElement("div"); d.className = "u-scene"; d.innerHTML = html; stage.append(d); });
  stage.append(cap);

  const items = [...list.children], scenes = [...stage.querySelectorAll(".u-scene")], dots = [...cap.querySelectorAll(".dotsrow i")];
  root.style.setProperty("--dur", STEP_SECONDS + "s");
  let cur = -1, playing = true, visible = false;

  function go(i, manual) {
    i = (i + STEPS.length) % STEPS.length;
    items.forEach((el, k) => { el.classList.toggle("on", k === i); el.classList.toggle("done", k < i); el.setAttribute("aria-current", k === i ? "step" : "false"); });
    scenes.forEach((el, k) => { el.classList.remove("on"); if (k === i) { void el.offsetWidth; el.classList.add("on"); } });
    dots.forEach((d, k) => d.classList.toggle("on", k === i));
    $("#useCap").innerHTML = `<b>Step ${i + 1} of ${STEPS.length}</b> · ${STEPS[i].title}`;
    // restart this step's progress bar
    const fill = items[i].querySelector(".bar i");
    fill.style.animation = "none"; void fill.offsetWidth; fill.style.animation = "";
    cur = i;
    if (manual && !playing) fill.style.animationPlayState = "paused";
  }
  items.forEach((el, i) => el.querySelector(".bar i").addEventListener("animationend", () => { if (i === cur && playing) go(cur + 1); }));

  function setPlaying(p) {
    playing = p;
    root.classList.toggle("paused", !p || !visible);
    $("#useToggle").textContent = p ? "❚❚ Pause" : "▶ Play";
  }
  $("#useToggle").addEventListener("click", () => setPlaying(!playing));
  [list, stage].forEach((el) => {
    el.addEventListener("mouseenter", () => root.classList.add("paused"));
    el.addEventListener("mouseleave", () => root.classList.toggle("paused", !playing || !visible));
  });
  new IntersectionObserver((es) => {
    visible = es[0].isIntersecting;
    root.classList.toggle("paused", !playing || !visible);
    if (visible && cur < 0) go(0);
  }, { threshold: 0.25 }).observe(root);
  go(0);
})();

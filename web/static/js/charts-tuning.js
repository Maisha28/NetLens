/* Charts for the Tuning Lab: before/after bars and one-setting sweeps. */
"use strict";

const TuneChart = {
  /** Grouped bars per tuning step: false alarms (red) and attacks missed (amber). */
  bars(canvas, steps) {
    const { ctx, w, h } = prepCanvas(canvas, 300);
    const padL = 54, padR = 16, padT = 30, padB = 44;
    const cw = w - padL - padR, ch = h - padT - padB;
    const maxV = countMax(Math.max(1, ...steps.map((s) => Math.max(s.false_alarms, s.missed))) * 1.12);
    const y = (v) => padT + ch - (v / maxV) * ch;
    ctx.font = `13.5px ${SANS()}`; ctx.lineWidth = 1;
    for (let g = 0; g <= 4; g++) {
      const v = (maxV * g) / 4, yy = y(v);
      ctx.strokeStyle = P().grid; ctx.beginPath(); ctx.moveTo(padL, yy); ctx.lineTo(w - padR, yy); ctx.stroke();
      ctx.fillStyle = P().sub; ctx.textAlign = "right"; ctx.fillText(String(Math.round(v)), padL - 10, yy + 5);
    }
    const gw = cw / steps.length, bw = Math.min(34, gw / 3);
    steps.forEach((s, i) => {
      const cx = padL + gw * i + gw / 2;
      const last = i === steps.length - 1;
      if (last) { ctx.fillStyle = "rgba(19,138,85,.08)"; ctx.fillRect(padL + gw * i + 4, padT - 8, gw - 8, ch + 8); }
      [[s.false_alarms, "#d03a3a", -bw - 2], [s.missed, "#e8a33d", 2]].forEach(([v, color, dx]) => {
        const top = y(v);
        ctx.fillStyle = color; ctx.beginPath();
        if (ctx.roundRect) ctx.roundRect(cx + dx, top, bw, Math.max(2, padT + ch - top), 5); else ctx.rect(cx + dx, top, bw, padT + ch - top);
        ctx.fill();
        ctx.fillStyle = P().ink; ctx.font = `bold 14px ${SANS()}`; ctx.textAlign = "center"; ctx.fillText(String(v), cx + dx + bw / 2, top - 7);
      });
      ctx.fillStyle = last ? "#138a55" : P().sub; ctx.font = `${last ? "bold " : ""}15px ${SANS()}`; ctx.textAlign = "center";
      ctx.fillText(i === 0 ? "Untuned" : last ? "Shipped" : `Step ${i}`, cx, h - 14);
    });
  },

  /** Sweep one setting: false alarms (red) and missed attacks (amber) at each value; the default is shaded. */
  lines(canvas, points, defaultValue, fmtX = (v) => String(v)) {
    const { ctx, w, h } = prepCanvas(canvas, 300);
    const padL = 54, padR = 24, padT = 30, padB = 44;
    const cw = w - padL - padR, ch = h - padT - padB;
    const maxV = countMax(Math.max(1, ...points.map((p) => Math.max(p.false_alarms, p.missed))) * 1.15);
    const x = (i) => padL + (points.length === 1 ? cw / 2 : (i / (points.length - 1)) * cw);
    const y = (v) => padT + ch - (v / maxV) * ch;
    ctx.font = `13.5px ${SANS()}`; ctx.lineWidth = 1;
    for (let g = 0; g <= 4; g++) {
      const v = (maxV * g) / 4, yy = y(v);
      ctx.strokeStyle = P().grid; ctx.beginPath(); ctx.moveTo(padL, yy); ctx.lineTo(w - padR, yy); ctx.stroke();
      ctx.fillStyle = P().sub; ctx.textAlign = "right"; ctx.fillText(String(Math.round(v)), padL - 10, yy + 5);
    }
    const di = points.findIndex((p) => Number(p.value) === Number(defaultValue));
    if (di >= 0) {
      const half = cw / Math.max(1, points.length - 1) / 2;
      ctx.fillStyle = "rgba(19,138,85,.10)"; ctx.fillRect(x(di) - half, padT - 8, half * 2, ch + 8);
      ctx.fillStyle = "#138a55"; ctx.font = `bold 13px ${SANS()}`; ctx.textAlign = "center"; ctx.fillText("shipped", x(di), padT - 12);
    }
    [["false_alarms", "#d03a3a"], ["missed", "#e8a33d"]].forEach(([key, color]) => {
      ctx.strokeStyle = color; ctx.lineWidth = 3; ctx.lineJoin = "round"; ctx.beginPath();
      points.forEach((p, i) => (i ? ctx.lineTo(x(i), y(p[key])) : ctx.moveTo(x(i), y(p[key]))));
      ctx.stroke();
      points.forEach((p, i) => {
        ctx.fillStyle = P().surface; ctx.strokeStyle = color; ctx.lineWidth = 3;
        ctx.beginPath(); ctx.arc(x(i), y(p[key]), 6, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
      });
    });
    ctx.fillStyle = P().sub; ctx.font = `14.5px ${SANS()}`; ctx.textAlign = "center";
    points.forEach((p, i) => ctx.fillText(fmtX(p.value), x(i), h - 14));
  },
};

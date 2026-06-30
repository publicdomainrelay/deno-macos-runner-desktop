#!/usr/bin/env -S deno run --allow-read --allow-write
// Generate DFFML-style logomark: 6 filled sinusoidal ribbons, evenly spaced
// around circle, each tracing NUM_PEAKS wave cycles within its ~120° sector.
// Overlapping sectors create interlocking color pattern. Wave crests = arc peaks.
//
// Usage: deno run --allow-read --allow-write scripts/generate-logomark.ts [peaks]

const NUM_PEAKS = parseInt(Deno.args[0] ?? "7", 10);
const OUT = new URL("../logomark.svg", import.meta.url).pathname;

const CX = 151, CY = 151, PATHS = 6;
const MID = 87, AMP = 50, HW = 14;
const SECTOR = (2*Math.PI)/PATHS * 1.3; // sector half-width
const PTS = Math.max(6, Math.round(NUM_PEAKS * 8 / PATHS)); // pts per ribbon

const GRAD = [
  ["#A844FF","#1ED1FF"],["#1ED1FF","#65F400"],["#65F400","#FFE102"],
  ["#F47E00","#FFE100"],["#FF4FB2","#F47E00"],["#A844FF","#FF4FB2"],
];

interface P { x: number; y: number }
function pt(th: number, r: number): P { return {x:CX+r*Math.cos(th), y:CY+r*Math.sin(th)}; }
function wr(th: number, ph: number, e: number): number {
  return MID + e*HW + AMP*Math.sin(NUM_PEAKS*th + ph);
}

// Phase offset per ribbon: shifts wave alignment for interleaving
function ribbon(center: number): string {
  const ph = center; // phase = sector center
  const t0 = center - SECTOR, t1 = center + SECTOR;
  const up: P[] = [], lo: P[] = [];
  for (let i = 0; i <= PTS; i++) {
    const th = t0 + (i/PTS)*(t1-t0);
    up.push(pt(th, wr(th, ph, +1)));
    lo.push(pt(th, wr(th, ph, -1)));
  }

  const parts = [`M${up[0].x.toFixed(1)} ${up[0].y.toFixed(1)}`];
  const dt = (t1-t0)/PTS;

  for (let i = 1; i < up.length; i++) {
    const p0=up[i-1], p3=up[i], th0=t0+(i-1)*dt, th3=t0+i*dt;
    const c1=pt(th0+dt*.33, wr(th0+dt*.33,ph,+1)+2);
    const c2=pt(th3-dt*.33, wr(th3-dt*.33,ph,+1)+2);
    parts.push(`C${c1.x.toFixed(1)} ${c1.y.toFixed(1)} ${c2.x.toFixed(1)} ${c2.y.toFixed(1)} ${p3.x.toFixed(1)} ${p3.y.toFixed(1)}`);
  }

  parts.push(`L${lo[lo.length-1].x.toFixed(1)} ${lo[lo.length-1].y.toFixed(1)}`);

  for (let i = lo.length-2; i >= 0; i--) {
    const p3=lo[i], p0=lo[i+1], th3=t0+i*dt, th0=t0+(i+1)*dt;
    const c1=pt(th0-dt*.33, wr(th0-dt*.33,ph,-1)-2);
    const c2=pt(th3+dt*.33, wr(th3+dt*.33,ph,-1)-2);
    parts.push(`C${c1.x.toFixed(1)} ${c1.y.toFixed(1)} ${c2.x.toFixed(1)} ${c2.y.toFixed(1)} ${p3.x.toFixed(1)} ${p3.y.toFixed(1)}`);
  }
  parts.push("Z");
  return parts.join("");
}

const defs = GRAD.map((g,i) =>
  `<linearGradient id="g${i}" x1="151" y1="10" x2="151" y2="292" gradientUnits="userSpaceOnUse"><stop stop-color="${g[0]}"/><stop offset="1" stop-color="${g[1]}"/></linearGradient>`
).join('\n');

// BW mode for non-19 peak counts
const bw = NUM_PEAKS !== 19;
const defsOut = bw
  ? [0,1,2,3,4,5].map(i => `<linearGradient id="g${i}" x1="0" y1="0" x2="1" y2="1" gradientUnits="userSpaceOnUse"><stop stop-color="#000"/><stop offset="1" stop-color="#000"/></linearGradient>`).join('\n')
  : defs;

const paths = [];
for (let p = 0; p < PATHS; p++) {
  const center = (p/PATHS)*2*Math.PI - Math.PI/2;
  paths.push(ribbon(center));
}

const pathEls = paths.map((d,i) =>
  `  <path fill-rule="evenodd" clip-rule="evenodd" d="${d}" fill="url(#g${i})"/>`
).join('\n');

const svg = [`<svg width="302" height="302" viewBox="0 0 302 302" fill="none" xmlns="http://www.w3.org/2000/svg">`,
  `<defs>`, defsOut, `</defs>`, pathEls, `</svg>`, ``].join('\n');

await Deno.writeTextFile(OUT, svg);
console.log(`Generated ${OUT}: ${NUM_PEAKS} peaks, ${PATHS} ribbons, BW=${bw}, ${svg.length}B`);

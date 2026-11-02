import { chromium } from 'playwright-core'; import { readFileSync } from 'node:fs';
const [a, b] = process.argv.slice(2);
const br = await chromium.launch(); const pg = await br.newPage();
const r = await pg.evaluate(async ([x, y]) => {
  const load = (u) => new Promise((res) => { const i = new Image(); i.onload = () => res(i); i.src = u; });
  const [ia, ib] = await Promise.all([load(x), load(y)]);
  const w = Math.min(ia.width, ib.width), h = Math.min(ia.height, ib.height);
  const dat = (i) => { const c = document.createElement('canvas'); c.width = i.width; c.height = i.height; const g = c.getContext('2d'); g.drawImage(i, 0, 0); return g.getImageData(0, 0, w, h).data; };
  const da = dat(ia), db = dat(ib); let n = 0, minx = w, miny = h, maxx = 0, maxy = 0, maxd = 0;
  for (let p = 0; p < w * h; p++) { const d = Math.abs(da[p*4]-db[p*4]) + Math.abs(da[p*4+1]-db[p*4+1]) + Math.abs(da[p*4+2]-db[p*4+2]); if (d) { n++; maxd = Math.max(maxd, d); const px = p % w, py = (p / w) | 0; minx = Math.min(minx, px); maxx = Math.max(maxx, px); miny = Math.min(miny, py); maxy = Math.max(maxy, py); } }
  return { sizeA: [ia.width, ia.height], sizeB: [ib.width, ib.height], diffPixels: n, maxChannelSum: maxd, box: [minx, miny, maxx, maxy] };
}, ['data:image/png;base64,' + readFileSync(a).toString('base64'), 'data:image/png;base64,' + readFileSync(b).toString('base64')]);
console.log(JSON.stringify(r)); await br.close();

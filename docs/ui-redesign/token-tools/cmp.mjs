import { readdirSync, readFileSync } from 'node:fs';
const [a, b] = process.argv.slice(2);
let same = 0; const diff = [];
for (const f of readdirSync(a).filter((x) => x.endsWith('.png'))) { try { if (readFileSync(a + '/' + f).equals(readFileSync(b + '/' + f))) same++; else diff.push(f); } catch { diff.push(f + '(missing)'); } }
console.log('identical', same, 'different', diff.length, diff.join(' '));

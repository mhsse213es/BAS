// Page-side capture for the G1e harness. Computed styles are keyed by a
// structural path (tag + child index from body); G1e changes attributes only,
// so paths match one-to-one between the builds.
import { SEP } from './compare.mjs';

export async function settle(page) {
  await page.waitForLoadState('networkidle', { timeout: 10_000 }).catch(() => {});
  await page.evaluate(async () => {
    await document.fonts.ready;
    // Loaders render after their fetch resolves, sometimes through further
    // promises or short timers that network idle does not cover: wait until
    // the DOM has been quiet for 300 ms (at most 5 s).
    await new Promise((resolve) => {
      let timer = setTimeout(done, 300);
      const cap = setTimeout(done, 5000);
      const mo = new MutationObserver(() => { clearTimeout(timer); timer = setTimeout(done, 300); });
      mo.observe(document.documentElement, { subtree: true, childList: true, attributes: true, characterData: true });
      function done() { mo.disconnect(); clearTimeout(timer); clearTimeout(cap); resolve(); }
    });
    for (const a of document.getAnimations()) {
      const t = a.effect && a.effect.getComputedTiming();
      if (t && t.iterations === Infinity) { a.pause(); a.currentTime = 0; } else { a.finish(); }
    }
  });
}

export async function snapshotStyles(page, props) {
  return page.evaluate(({ props, sep }) => {
    // Expand shorthands to the longhands the browser actually computes.
    const longhands = new Set();
    for (const p of props) {
      const s = document.createElement('div').style;
      s.setProperty(p, 'initial');
      if (s.length) for (let i = 0; i < s.length; i++) longhands.add(s[i]); else longhands.add(p);
    }
    const list = [...longhands].sort();
    const out = { '#props': list.join(sep) };
    (function walk(el, path) {
      const cs = getComputedStyle(el);
      out[path] = list.map((p) => cs.getPropertyValue(p)).join(sep);
      let i = 0;
      for (const c of el.children) walk(c, `${path}>${c.tagName.toLowerCase()}:${i++}`);
    })(document.body, 'body');
    return out;
  }, { props, sep: SEP });
}

export async function elementPath(page, selector) {
  return page.evaluate((sel) => {
    let el = document.querySelector(sel);
    const parts = [];
    while (el && el !== document.body) {
      parts.unshift(`${el.tagName.toLowerCase()}:${[...el.parentElement.children].indexOf(el)}`);
      el = el.parentElement;
    }
    return ['body', ...parts].join('>');
  }, selector);
}

export async function screenshot(page, masks = []) {
  return page.screenshot({ fullPage: true, animations: 'disabled', caret: 'hide', mask: masks.map((m) => page.locator(m)) });
}

export async function runSteps(page, steps) {
  for (const s of steps) {
    if (s.click) await page.click(s.click);
    else if (s.fill) await page.fill(s.fill[0], s.fill[1]);
    else if (s.select) await page.selectOption(s.select[0], s.select[1]);
    else throw new Error(`unknown checkpoint step ${JSON.stringify(s)}`);
    await settle(page);
  }
}

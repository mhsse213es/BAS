// Generic dialog behaviour for every .overlay (modal) and .drawer-overlay (drawer).
//
// The console has ~24 modals and ~23 drawers that each open by toggling `.open` on their overlay and
// close through their own handler. They disagree on role/aria-modal, focus handling and Escape. Rather
// than edit each one, this module watches the overlays and, while one is open, gives it the shared
// behaviour: dialog semantics, focus moved in and restored on close, Tab kept inside, Escape closes.
//
// It never closes anything by itself state-wise: Escape triggers the overlay's OWN close control so the
// feature's cleanup (poll timers, selected ids, ...) still runs. Existing Escape handlers keep working;
// this only acts if the overlay is still open after they ran.
const OVERLAY_SEL = '.overlay, .drawer-overlay';
const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
const CLOSE_SEL = '.drawer-close, [data-on-click^="close"], [data-on-click*="Close"]';

export function installOverlayA11y(doc) {
  doc = doc || document;
  var win = doc.defaultView;
  var stack = []; // open overlays, oldest first: { overlay, opener }

  function isOpen(o) {
    return o.classList.contains('open') || (!!o.style.display && o.style.display !== 'none');
  }
  function dialogOf(o) { return o.querySelector('.modal, .drawer') || o; }
  function visible(el) { return !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length); }
  function focusables(dlg) { return Array.prototype.filter.call(dlg.querySelectorAll(FOCUSABLE), visible); }
  function indexOf(o) { for (var i = 0; i < stack.length; i++) if (stack[i].overlay === o) return i; return -1; }

  function label(dlg) {
    var h = dlg.querySelector('h1, h2, h3, .drawer-title');
    var t = h && h.textContent.trim();
    if (!t) {
      // Drawers put their title in a header next to the close button.
      var hd = dlg.querySelector('.drawer-header');
      t = hd ? hd.textContent.replace(/✕/g, '').replace(/\s+/g, ' ').trim() : '';
    }
    return t || 'Dialog';
  }

  function opened(o) {
    var dlg = dialogOf(o);
    if (!dlg.getAttribute('role')) dlg.setAttribute('role', 'dialog');
    dlg.setAttribute('aria-modal', 'true');
    if (!dlg.getAttribute('aria-label') && !dlg.getAttribute('aria-labelledby')) {
      dlg.setAttribute('aria-label', label(dlg));
      dlg.setAttribute('data-a11y-label', 'auto');
    }
    if (!dlg.hasAttribute('tabindex')) dlg.setAttribute('tabindex', '-1');
    var active = doc.activeElement;
    stack.push({ overlay: o, opener: active && active !== doc.body ? active : null });
    // Content is often filled in just after open, so move focus on the next tick.
    win.setTimeout(function() {
      if (indexOf(o) < 0) return;
      // The title is frequently rendered after open; refresh a label we generated ourselves.
      if (dlg.getAttribute('data-a11y-label') === 'auto') dlg.setAttribute('aria-label', label(dlg));
      if (dlg.contains(doc.activeElement)) return;
      dlg.focus({ preventScroll: true });
    }, 0);
  }

  function closed(o) {
    var i = indexOf(o);
    if (i < 0) return;
    var opener = stack[i].opener;
    stack.splice(i, 1);
    var a = doc.activeElement;
    var lost = !a || a === doc.body || o.contains(a);
    if (lost && opener && doc.contains(opener) && typeof opener.focus === 'function') opener.focus({ preventScroll: true });
  }

  function sync(o) {
    var open = isOpen(o);
    var tracked = indexOf(o) >= 0;
    if (open && !tracked) opened(o);
    else if (!open && tracked) closed(o);
  }

  function requestClose(o) {
    var dlg = dialogOf(o);
    var btn = Array.prototype.filter.call(dlg.querySelectorAll(CLOSE_SEL), visible)[0];
    if (!btn) {
      btn = Array.prototype.filter.call(dlg.querySelectorAll('button'), function(b) {
        return visible(b) && /^(cancel|close)$/i.test(b.textContent.trim());
      })[0];
    }
    if (btn) { btn.click(); return; }
    // No close control: fall back to the overlay's own backdrop handler, else just hide it.
    if (o.getAttribute('data-on-click')) o.dispatchEvent(new win.MouseEvent('click', { bubbles: true }));
    if (isOpen(o)) o.classList.remove('open');
  }

  doc.addEventListener('keydown', function(e) {
    if (!stack.length) return;
    var top = stack[stack.length - 1].overlay;
    if (e.key === 'Escape') {
      if (e.defaultPrevented) return;
      win.setTimeout(function() {
        if (indexOf(top) >= 0 && isOpen(top) && stack[stack.length - 1].overlay === top) requestClose(top);
      }, 0);
      return;
    }
    if (e.key !== 'Tab') return;
    var dlg = dialogOf(top);
    var items = focusables(dlg);
    if (!items.length) { e.preventDefault(); dlg.focus({ preventScroll: true }); return; }
    var first = items[0];
    var last = items[items.length - 1];
    var a = doc.activeElement;
    if (!dlg.contains(a) || a === dlg) { e.preventDefault(); (e.shiftKey ? last : first).focus(); return; }
    if (e.shiftKey && a === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && a === last) { e.preventDefault(); first.focus(); }
  });

  var mo = new win.MutationObserver(function(records) {
    records.forEach(function(r) { sync(r.target); });
  });
  function watch(o) {
    mo.observe(o, { attributes: true, attributeFilter: ['class', 'style'] });
    sync(o);
  }
  Array.prototype.forEach.call(doc.querySelectorAll(OVERLAY_SEL), watch);
  // Overlays created later (appended to body) get the same treatment.
  new win.MutationObserver(function(records) {
    records.forEach(function(r) {
      Array.prototype.forEach.call(r.addedNodes, function(n) {
        if (n.nodeType !== 1) return;
        if (n.matches(OVERLAY_SEL)) watch(n);
        Array.prototype.forEach.call(n.querySelectorAll(OVERLAY_SEL), watch);
      });
    });
  }).observe(doc.body, { childList: true });
  return { stack: stack };
}

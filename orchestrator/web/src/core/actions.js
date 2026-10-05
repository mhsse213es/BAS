// Delegated event actions (G1d spec section 4). Markup names an action with
// data-on-<event>="name" and optional data-args="<JSON array>"; one listener
// per event type on the document dispatches to the registry passed to
// installActions(). No inline handlers, no window lookups, and arguments are
// data -- they are parsed as JSON, never evaluated.
import { x } from './escape.js';

export const EVENT_TYPES = ['click', 'change', 'input', 'keydown', 'blur', 'mouseover', 'mouseout', 'mouseenter', 'mouseleave', 'mousedown'];

// Events that do not bubble: listened for in the capture phase and acted on
// only at the target, exactly like the inline attribute they replace.
const NON_BUBBLING = new Set(['blur', 'mouseenter', 'mouseleave']);

// The only way templates attach behaviour. Returns attribute text with a
// leading space: '<button' + on('click', 'openRun', id) + '>'.
export function on(eventType, name, ...args) {
  if (!EVENT_TYPES.includes(eventType)) throw new Error(`on(): unsupported event "${eventType}"`);
  let attr = ` data-on-${eventType}="${x(name)}"`;
  if (args.length) attr += ` data-args="${x(JSON.stringify(args))}"`;
  return attr;
}

// Common action: replaces onclick="event.stopPropagation()".
export function stopEvent(el, event) { event.stopPropagation(); }

export function dispatch(registry, type, event) {
  const attr = `data-on-${type}`;
  const walk = !NON_BUBBLING.has(type);
  for (let el = event.target; el && el.nodeType === 1; el = walk ? el.parentElement : null) {
    const name = el.getAttribute(attr);
    if (name === null) continue;
    // An inline handler never fired on a disabled control; neither do we.
    if (el.disabled === true) return;
    const fn = Object.prototype.hasOwnProperty.call(registry, name) ? registry[name] : undefined;
    if (typeof fn !== 'function') { console.error(`action "${name}" is not registered`); return; }
    let args = [];
    const raw = el.getAttribute('data-args');
    if (raw !== null) {
      try { args = JSON.parse(raw); } catch { args = null; }
      if (!Array.isArray(args)) { console.error(`action "${name}": data-args is not a JSON array`); return; }
    }
    if (type === 'click' && el.tagName === 'A' && el.getAttribute('href') === '#') event.preventDefault();
    fn.apply(el, [...args, el, event]);
    if (event.cancelBubble) return;
  }
}

export function installActions(registry, root = document) {
  for (const type of EVENT_TYPES) {
    root.addEventListener(type, (event) => dispatch(registry, type, event), NON_BUBBLING.has(type));
  }
}

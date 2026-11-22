// Motion for the whole site. Loaded by components.js, so every page that has the header gets it.
// Nothing here is needed to use the site: with scripts off, or with "reduce motion" switched on in the
// system settings, every element is simply there. Only transform and opacity are animated, apart from
// the open/close of <details>, which uses block-size in browsers that support it (see the CSS).

const query = matchMedia('(prefers-reduced-motion: reduce)');

/** True when the person asked their system for less motion. Checked each time, so a change applies at once. */
export const reduced = () => query.matches;

const root = document.documentElement;
const $$ = (selector, scope = document) => [...scope.querySelectorAll(selector)];

function sessionGet(key) {
  try {
    return sessionStorage.getItem(key);
  } catch {
    return null;
  }
}
function sessionSet(key, value) {
  try {
    sessionStorage.setItem(key, value);
  } catch {
    /* the clouds just start over on the next page */
  }
}

/** Counts a number up inside an element: setText(n) is called with whole numbers. Returns a cancel function. */
export function countUp(setText, to, ms = 700) {
  if (reduced() || to <= 0) {
    setText(to);
    return () => {};
  }
  const start = performance.now();
  let frame = 0;
  const tick = (now) => {
    const t = Math.min(1, (now - start) / ms);
    const eased = 1 - (1 - t) ** 3; // decelerate: fast at first, then settles
    setText(Math.round(to * eased));
    if (t < 1) frame = requestAnimationFrame(tick);
  };
  setText(0);
  frame = requestAnimationFrame(tick);
  return () => cancelAnimationFrame(frame);
}

/** Stagger: gives each element its place in line (--i), which the CSS turns into a delay. */
export function stagger(elements, cap = 10) {
  elements.forEach((el, i) => el.style.setProperty('--i', String(Math.min(i, cap))));
}

/** Runs the change in the middle of a quick fade, so a list does not snap. */
export function crossfade(element, change, ms = 140) {
  if (reduced()) return change();
  element.classList.add('swap');
  setTimeout(() => {
    change();
    requestAnimationFrame(() => element.classList.remove('swap'));
  }, ms);
}

// ---------------------------------------------------------------- page load and scroll reveal

function reveal() {
  // What counts as a block: the direct children of <main> and of its sections. Results that arrive
  // later (findings, source results) have their own motion.
  const blocks = $$(':scope > main > *, :scope > main > section > *', document.body).filter(
    (el) => !el.hidden && !el.closest('#findings, #result, #progress, #problem') && el.offsetParent !== null,
  );
  const fold = innerHeight * 0.96;
  const above = [];
  const below = [];
  for (const el of blocks) (el.getBoundingClientRect().top < fold ? above : below).push(el);

  // Above the fold: a slow, ordered arrival.
  above.forEach((el, i) => {
    el.style.setProperty('--i', String(Math.min(i, 7)));
    el.classList.add('arrive');
  });

  // Below the fold: each block rises once, when it is about to be seen.
  if (!below.length || !('IntersectionObserver' in window)) return;
  const watcher = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        entry.target.classList.add('in');
        watcher.unobserve(entry.target);
      }
    },
    { rootMargin: '0px 0px -6% 0px', threshold: 0.01 },
  );
  for (const el of below) {
    el.classList.add('pre');
    watcher.observe(el);
  }
}

// ---------------------------------------------------------------- the clouds keep their place between pages

function keepClouds() {
  // Each page load would restart the drifting clouds. Remember when the visit began and start the
  // animation that far in, so they carry on from where they were.
  let began = Number(sessionGet('flawradar-clouds'));
  if (!began) {
    began = Date.now();
    sessionSet('flawradar-clouds', String(began));
  }
  const seconds = (Date.now() - began) / 1000;
  root.style.setProperty('--cloud-far-delay', `-${(seconds % 260).toFixed(1)}s`);
  root.style.setProperty('--cloud-near-delay', `-${(seconds % 150).toFixed(1)}s`);
}

function start() {
  if (reduced()) return;
  root.classList.add('motion');
  keepClouds();
  reveal();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
else start();

// If the person turns "reduce motion" on while the page is open, drop everything straight away.
query.addEventListener?.('change', () => root.classList.toggle('motion', !query.matches));

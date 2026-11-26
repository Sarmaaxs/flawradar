// Build elements without ever parsing HTML from a string.
export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === false || value == null) continue;
    if (key === 'class') el.className = value;
    else if (key.startsWith('on') && typeof value === 'function') el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    el.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return el;
}

export async function api(path, options = {}) {
  const headers = {
    Accept: 'application/json',
    ...(options.body ? { 'Content-Type': 'application/json' } : {}),
    ...options.headers,
  };
  const res = await fetch(path, { ...options, headers });
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* not JSON */
  }
  if (!res.ok) {
    const err = new Error(data?.error?.message || `Request failed (${res.status})`);
    err.status = res.status;
    err.code = data?.error?.code;
    err.detail = data?.error;
    throw err;
  }
  return data;
}

let infoPromise = null;
/** Scanner details from the server, including the version of the terms. Fetched once. */
export function scannerInfo() {
  if (!infoPromise) infoPromise = api('/api/scanner');
  return infoPromise;
}

const TERMS_KEY = 'flawradar-terms-accepted';

/** The terms version this browser has accepted before, or null. Storage may be blocked, so every access is guarded. */
export function rememberedTerms() {
  try {
    return localStorage.getItem(TERMS_KEY);
  } catch {
    return null;
  }
}

export function rememberTerms(version) {
  try {
    localStorage.setItem(TERMS_KEY, version);
  } catch {
    /* the box is simply shown again next time */
  }
}

export function forgetTerms() {
  try {
    localStorage.removeItem(TERMS_KEY);
  } catch {
    /* nothing to do */
  }
}

const DELETE_PREFIX = 'flawradar-delete-';

/** The secret that lets this browser delete a report it started. Kept only in this browser. */
export function rememberDeleteToken(id, token) {
  if (!id || !token) return;
  try {
    localStorage.setItem(DELETE_PREFIX + id, token);
  } catch {
    /* without it, the delete button is simply not shown */
  }
}

export function deleteTokenFor(id) {
  try {
    return localStorage.getItem(DELETE_PREFIX + id);
  } catch {
    return null;
  }
}

export function forgetDeleteToken(id) {
  try {
    localStorage.removeItem(DELETE_PREFIX + id);
  } catch {
    /* nothing to do */
  }
}

export function formatDate(ms) {
  return `${new Date(ms).toISOString().replace('T', ' ').slice(0, 16)} UTC`;
}

export function safeHttpsUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === 'https:' ? u.href : null;
  } catch {
    return null;
  }
}
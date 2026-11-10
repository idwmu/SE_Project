/* PPS core: API client, auth flow, tab registry, live WebSocket, helpers. */
"use strict";

const PPS = (() => {
  const API = "/api/v1";
  const ROLE_RANK = { trainee: 0, analyst: 1, admin: 2 };

  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
    del(k) { try { localStorage.removeItem(k); } catch { /* ignore */ } },
  };

  const state = {
    clientToken: store.get("pps.client"),
    token: store.get("pps.token"),
    user: null,
    tabs: [],
    current: null,
    listeners: {},
    status: null,
  };

  // ---------------------------------------------------------------- helpers
  const $ = (sel, root = document) => root.querySelector(sel);
  function h(tag, attrs = {}, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "html") el.innerHTML = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids.flat()) {
      if (kid === null || kid === undefined || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmtBytes = (n) => { n = Number(n || 0); const u = ["B", "KB", "MB", "GB"]; let i = 0; while (n >= 1024 && i < 3) { n /= 1024; i++; } return `${n.toFixed(i ? 1 : 0)} ${u[i]}`; };
  const fmtBits = (n) => { n = Number(n || 0); const u = ["bps", "kbps", "Mbps", "Gbps"]; let i = 0; while (n >= 1000 && i < 3) { n /= 1000; i++; } return `${n.toFixed(i ? 1 : 0)} ${u[i]}`; };
  const fmtTime = (ts) => ts ? new Date(ts * 1000).toLocaleTimeString([], { hour12: false }) + "." + String(Math.floor((ts % 1) * 1000)).padStart(3, "0") : "";
  const fmtDate = (ts) => ts ? new Date(ts * 1000).toLocaleString([], { hour12: false }) : "";
  const fmtDur = (s) => { s = Math.round(s || 0); const m = Math.floor(s / 60); return m ? `${m}m ${s % 60}s` : `${s}s`; };

  function toast(msg, kind = "info", ms = 4000) {
    const el = h("div", { class: `toast ${kind}`, role: kind === "error" ? "alert" : "status" }, msg);
    $("#toasts").append(el);
    setTimeout(() => el.remove(), ms);
  }

  function on(evt, fn) { (state.listeners[evt] ||= []).push(fn); }
  function emit(evt, data) { (state.listeners[evt] || []).forEach((fn) => { try { fn(data); } catch (e) { console.error(e); } }); }

  const can = (minRole) => state.user && ROLE_RANK[state.user.role] >= ROLE_RANK[minRole];

  // ---------------------------------------------------------------- API client
  async function api(path, { method = "GET", body, raw = false, form = null } = {}) {
    const headers = {};
    if (state.token) headers.Authorization = `Bearer ${state.token}`;
    if (state.clientToken) headers["X-PPS-Client"] = state.clientToken;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetch(API + path, { method, headers, body: form || (body !== undefined ? JSON.stringify(body) : undefined) });
    if (raw && res.ok) return res;
    let data = null;
    try { data = await res.json(); } catch { /* empty */ }
    if (!res.ok) {
      const err = (data && data.error) || { code: `HTTP_${res.status}`, message: (data && data.detail && JSON.stringify(data.detail)) || res.statusText };
      if (res.status === 401 && ["UNAUTHENTICATED", "TOKEN_EXPIRED"].includes(err.code) && state.token) {
        logout(err.message);
      }
      const e = new Error(err.message); e.code = err.code; e.status = res.status; throw e;
    }
    return data;
  }

  // ---------------------------------------------------------------- tabs
  function registerTab(def) { state.tabs.push(def); }

  function buildShell() {
    const nav = $("#tabs"); const panels = $("#panels");
    nav.innerHTML = ""; panels.innerHTML = "";
    state.listeners = {};  // modules re-register their listeners in init()
    for (const t of state.tabs) {
      if (t.minRole && !can(t.minRole)) continue;
      const btn = h("button", { id: `tab-${t.id}`, onclick: () => show(t.id) }, t.title, t.badge ? h("span", { class: "badge HIGH hidden", id: `badge-${t.id}` }) : null);
      nav.append(btn);
      const panel = h("section", { class: "tab-panel", id: `panel-${t.id}` });
      panels.append(panel);
      t.el = panel;
      t.init(panel);
    }
    $("#whoami").textContent = `${state.user.username} \u00b7 ${state.user.role}`;
    show(store.get("pps.tab") && state.tabs.find((t) => t.id === store.get("pps.tab") && t.el) ? store.get("pps.tab") : state.tabs[0].id);
  }

  function show(id) {
    state.current = id;
    store.set("pps.tab", id);
    for (const t of state.tabs) {
      if (!t.el) continue;
      const on_ = t.id === id;
      t.el.classList.toggle("on", on_);
      $(`#tab-${t.id}`).classList.toggle("on", on_);
      if (on_ && t.onShow) t.onShow();
    }
  }

  function setBadge(tabId, n) {
    const b = document.getElementById(`badge-${tabId}`);
    if (!b) return;
    b.textContent = n; b.classList.toggle("hidden", !n);
  }

  // ---------------------------------------------------------------- live WebSocket (reconnect with backoff)
  const live = { ws: null, filter: "", backoff: 1000, timer: null, wanted: false };
  function connectLive() {
    live.wanted = true;
    if (live.ws && live.ws.readyState <= 1) return;
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const url = `${proto}://${location.host}${API}/ws/live?token=${encodeURIComponent(state.token)}&filter=${encodeURIComponent(live.filter)}`;
    const ws = new WebSocket(url);
    live.ws = ws;
    ws.onopen = () => { live.backoff = 1000; emit("ws", "open"); };
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.type === "batch") {
        state.status = msg.status;
        $("#brand-dot").classList.toggle("active", msg.status.state === "ACTIVE");
        emit("status", msg.status);
        if (msg.packets.length) emit("packets", msg.packets);
        for (const e of msg.events) emit(e.topic, e.data);
      } else if (msg.type === "error") {
        emit("ws-error", msg);
      } else if (msg.type === "filter_ok") {
        emit("filter-ok", msg.filter);
      }
    };
    ws.onclose = (ev) => {
      emit("ws", "closed");
      if (ev.code === 4401) return logout("Session expired, please sign in again.");
      if (!live.wanted) return;
      clearTimeout(live.timer);
      live.timer = setTimeout(connectLive, live.backoff);
      live.backoff = Math.min(live.backoff * 2, 30000);  // 1 s .. 30 s (SRS 3.4)
    };
  }
  function setLiveFilter(f) {
    live.filter = f;
    if (live.ws && live.ws.readyState === 1) live.ws.send(JSON.stringify({ filter: f }));
  }
  function disconnectLive() { live.wanted = false; clearTimeout(live.timer); if (live.ws) live.ws.close(); }

  // ---------------------------------------------------------------- auth screens
  function screen(which) {
    for (const id of ["pair-screen", "login-screen", "app"]) $(`#${id}`).classList.toggle("hidden", id !== which);
  }

  function logout(msg) {
    state.token = null; state.user = null; store.del("pps.token");
    disconnectLive();
    screen("login-screen");
    if (msg) $("#login-err").textContent = msg;
  }

  async function enterApp() {
    try {
      state.user = await api("/auth/me");
    } catch { return logout(); }
    screen("app");
    buildShell();
    connectLive();
    emit("login", state.user);
  }

  function wireAuth() {
    $("#pair-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      $("#pair-err").textContent = "";
      try {
        const r = await api("/pair", { method: "POST", body: { pin: $("#pair-pin").value.trim(), client_name: $("#pair-name").value.trim() || navigator.platform || "browser" } });
        state.clientToken = r.client_token; store.set("pps.client", r.client_token);
        screen("login-screen"); $("#login-user").focus();
      } catch (err) { $("#pair-err").textContent = err.message; }
    });
    $("#login-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      $("#login-err").textContent = "";
      try {
        const r = await api("/auth/login", { method: "POST", body: { username: $("#login-user").value.trim(), password: $("#login-pass").value } });
        state.token = r.access_token; store.set("pps.token", r.access_token);
        $("#login-pass").value = "";
        enterApp();
      } catch (err) {
        if (err.code === "NOT_PAIRED") { store.del("pps.client"); state.clientToken = null; screen("pair-screen"); $("#pair-err").textContent = err.message; return; }
        $("#login-err").textContent = err.message;
      }
    });
    $("#unpair").addEventListener("click", () => { store.del("pps.client"); state.clientToken = null; screen("pair-screen"); });
    $("#logout").addEventListener("click", () => logout());
    $("#theme").addEventListener("click", () => {
      const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
      document.documentElement.dataset.theme = next; store.set("pps.theme", next);
    });
  }

  function boot() {
    if (store.get("pps.theme")) document.documentElement.dataset.theme = store.get("pps.theme");
    wireAuth();
    if (!state.clientToken) return screen("pair-screen");
    if (!state.token) return screen("login-screen");
    enterApp();
  }

  return { api, h, esc, $, toast, on, emit, can, registerTab, show, setBadge, connectLive, setLiveFilter, boot, state,
    fmtBytes, fmtBits, fmtTime, fmtDate, fmtDur, store };
})();

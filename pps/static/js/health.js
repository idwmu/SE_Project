/* Device health view (F-062) with storage warning (F-034). */
"use strict";

(() => {
  const { h, $, api, fmtBytes, fmtDur } = PPS;
  let timer = null;

  function init(panel) {
    panel.append(h("div", { class: "grid hcards", id: "health-cards" }));
  }

  function card(title, ...body) { return h("div", { class: "card stack" }, h("h3", {}, title), ...body); }

  async function load() {
    const box = $("#health-cards"); if (!box) return;
    const hl = await api("/device/health");
    const st = hl.storage;
    const usedPct = st.quota_bytes ? Math.min(100, (100 * st.used_bytes) / st.quota_bytes) : 0;
    box.innerHTML = "";
    box.append(
      card("Battery", hl.battery
        ? h("div", {}, h("div", { class: "stat" }, h("div", { class: "v" }, `${hl.battery.percent}%`)), h("div", { class: "meter" + (hl.battery.percent < 20 ? " warn" : "") }, h("div", { style: `width:${hl.battery.percent}%` })),
          h("div", { class: "small muted" }, hl.battery.plugged_in ? "Charging / plugged in" : (hl.battery.secs_left ? `${fmtDur(hl.battery.secs_left)} left` : "On battery")))
        : h("div", { class: "muted" }, "No battery reported by this host")),
      card("Capture storage", h("div", { class: "stat" }, h("div", { class: "v" }, fmtBytes(st.used_bytes))),
        h("div", { class: "meter" + (st.warning ? " warn" : "") }, h("div", { style: `width:${usedPct.toFixed(1)}%` })),
        h("div", { class: "small muted" }, `of ${fmtBytes(st.quota_bytes)} quota · disk ${st.disk_free_pct}% free`),
        st.warning ? h("div", { class: "badge MEDIUM" }, "LOW STORAGE WARNING") : h("div", { class: "badge ok" }, "OK")),
      card("Uptime", h("dl", { class: "kv" }, h("dt", {}, "PPS service"), h("dd", {}, fmtDur(hl.uptime_s)), h("dt", {}, "System"), h("dd", {}, fmtDur(hl.system_uptime_s)))),
      card("System", h("dl", { class: "kv" }, h("dt", {}, "CPU"), h("dd", {}, `${hl.cpu_percent}%`), h("dt", {}, "Memory"), h("dd", {}, `${hl.memory_percent}%`),
        h("dt", {}, "Host"), h("dd", {}, hl.host), h("dt", {}, "Platform"), h("dd", {}, hl.platform))),
      card("Pipeline", h("dl", { class: "kv" }, h("dt", {}, "Capture"), h("dd", {}, hl.capture_state), h("dt", {}, "Live clients"), h("dd", {}, hl.ws_clients),
        h("dt", {}, "Dropped in live view"), h("dd", {}, hl.ws_dropped_packets))));
  }

  PPS.registerTab({ id: "health", title: "Device health", init,
    onShow: () => { load(); clearInterval(timer); timer = setInterval(() => { if (PPS.state.current === "health") load(); }, 5000); } });
})();

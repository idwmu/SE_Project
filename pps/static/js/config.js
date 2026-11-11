/* Settings tab: interface defaults, limits, alert thresholds, storage quota (F-060). */
"use strict";

(() => {
  const { h, $, api, toast, can } = PPS;

  const FIELDS = [
    ["default_interface", "Default interface", "text"],
    ["max_duration_s", "Default duration limit (s, 0 = none)", "number"],
    ["max_packets", "Default packet limit (0 = none)", "number"],
    ["portscan_threshold", "Port-scan threshold (distinct ports)", "number"],
    ["portscan_window_s", "Port-scan window (s)", "number"],
    ["max_storage_mb", "Capture storage quota (MB)", "number"],
    ["low_space_warn_pct", "Low-storage warning (% left)", "number"],
  ];

  function init(panel) {
    const admin = can("admin");
    panel.append(h("form", { class: "card stack", id: "cfg-form", onsubmit: saveConfig, style: "max-width:640px" },
      h("h3", {}, "Configuration"),
      admin ? null : h("div", { class: "small muted" }, "Read-only: only an admin can change settings."),
      ...FIELDS.map(([k, label, type]) => h("label", { class: "fld" }, label, h("input", { type, id: `cfg-${k}`, name: k, disabled: !admin }))),
      h("label", { class: "fld" }, "ARP whitelist (one ip=mac per line)", h("textarea", { id: "cfg-arp_whitelist", rows: 3, class: "mono", disabled: !admin })),
      admin ? h("div", { class: "row" }, h("button", { class: "btn primary", type: "submit" }, "Save configuration")) : null,
      h("div", { class: "ferr", id: "cfg-err" })));
  }

  async function load() {
    const cfg = await api("/config");
    for (const [k] of FIELDS) $(`#cfg-${k}`).value = cfg[k];
    $("#cfg-arp_whitelist").value = (cfg.arp_whitelist || []).join("\n");
  }

  async function saveConfig(e) {
    e.preventDefault(); $("#cfg-err").textContent = "";
    const body = {};
    for (const [k, , type] of FIELDS) body[k] = type === "number" ? Number($(`#cfg-${k}`).value) : $(`#cfg-${k}`).value.trim();
    body.arp_whitelist = $("#cfg-arp_whitelist").value.split("\n").map((s) => s.trim()).filter(Boolean);
    try { await api("/config", { method: "PUT", body }); toast("Configuration saved"); PPS.emit("config-saved", body); }
    catch (err) { $("#cfg-err").textContent = err.message; }
  }

  PPS.registerTab({ id: "settings", title: "Settings", init, onShow: load });
})();
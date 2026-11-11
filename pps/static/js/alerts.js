/* Alerts tab: ARP spoofing / port scan alerts (F-040, F-041), push + history + ack (F-043). */
"use strict";

(() => {
  const { h, $, api, toast, on, can, fmtDate } = PPS;
  let unseen = 0;

  function init(panel) {
    panel.append(h("div", { class: "card" },
      h("div", { class: "row", style: "justify-content:space-between" }, h("h3", { style: "margin:0" }, "Alerts"),
        h("div", { class: "row" },
          h("select", { id: "alert-type", onchange: load }, h("option", { value: "" }, "All types"), h("option", { value: "ARP_SPOOF" }, "ARP spoofing"), h("option", { value: "PORT_SCAN" }, "Port scan")),
          h("button", { class: "btn sm", onclick: load }, "Refresh"))),
      h("div", { id: "alert-list" })));
    on("alert", (a) => {
      toast(`${a.severity}: ${a.message}`, "alert", 8000);
      if (PPS.state.current !== "alerts") { unseen++; PPS.setBadge("alerts", unseen); }
      else load();
      if ("Notification" in window && Notification.permission === "granted" && document.hidden) {
        new Notification("PPS alert", { body: a.message });
      }
    });
    if ("Notification" in window && Notification.permission === "default") {
      document.addEventListener("click", () => Notification.requestPermission(), { once: true });
    }
  }

  async function load() {
    unseen = 0; PPS.setBadge("alerts", 0);
    const box = $("#alert-list"); if (!box) return;
    const t = $("#alert-type").value;
    const list = await api(`/alerts${t ? "?type=" + t : ""}`);
    box.innerHTML = "";
    if (!list.length) { box.append(h("p", { class: "muted" }, "No alerts. Replay arp_spoof.pcap or port_scan.pcap to see the detectors fire.")); return; }
    for (const a of list) {
      const d = a.details || {};
      const extra = a.type === "ARP_SPOOF" ? `IP ${d.ip}: ${d.old_mac} \u2192 ${d.new_mac}` :
        a.type === "PORT_SCAN" ? `${d.src_ip} \u2192 ${d.dst_ip}, ${d.port_count} ports (e.g. ${(d.sample_ports || []).join(", ")})` : JSON.stringify(d);
      box.append(h("div", { class: `alert-item ${a.acked ? "acked" : ""}` },
        h("span", { class: `badge ${a.severity}` }, a.severity),
        h("div", {}, h("div", {}, a.message), h("div", { class: "small muted mono" }, extra),
          h("div", { class: "t" }, `${fmtDate(a.ts)} \u00b7 ${a.type} \u00b7 session ${a.session_id || "-"}`)),
        a.acked ? h("span", { class: "small muted" }, "acknowledged") :
          can("analyst") ? h("button", { class: "btn sm", onclick: async () => { await api(`/alerts/${a.id}/ack`, { method: "POST" }); load(); } }, "Acknowledge") : h("span")));
    }
  }

  PPS.registerTab({ id: "alerts", title: "Alerts", badge: true, init, onShow: load });
})();

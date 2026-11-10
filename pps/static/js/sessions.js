/* Sessions tab: stored captures, PCAP export (F-030/031), search with display filters (F-021/022). */
"use strict";

(() => {
  const { h, $, api, toast, on, can, fmtBytes, fmtDate, fmtDur, fmtTime } = PPS;
  let el, openId = null, offset = 0;
  const PAGE = 200;

  function init(panel) {
    el = panel;
    panel.append(
      h("div", { class: "card" },
        h("div", { class: "row", style: "justify-content:space-between" }, h("h3", { style: "margin:0" }, "Capture sessions"),
          h("button", { class: "btn sm", onclick: load }, "Refresh")),
        h("div", { style: "overflow:auto" }, h("table", { class: "list" },
          h("thead", {}, h("tr", {}, ...["Session", "Source", "Started", "Duration", "Packets", "Size", "Status", ""].map((t) => h("th", {}, t)))),
          h("tbody", { id: "sess-body" })))),
      h("div", { class: "card stack hidden", id: "sess-view", style: "margin-top:12px" },
        h("div", { class: "row", style: "justify-content:space-between" }, h("h3", { style: "margin:0", id: "sess-title" }, ""),
          h("button", { class: "btn sm", onclick: () => $("#sess-view").classList.add("hidden") }, "Close")),
        h("div", { class: "filterbar", style: "grid-template-columns:1fr auto" },
          h("input", { type: "text", id: "sess-filter", class: "mono", placeholder: "Display filter, e.g. dns or tcp.port == 80",
            onkeydown: (e) => { if (e.key === "Enter") { offset = 0; search(); } } }),
          h("button", { class: "btn", onclick: () => { offset = 0; search(); } }, "Search")),
        h("div", { class: "ferr", id: "sess-err" }),
        h("div", { class: "small muted", id: "sess-count" }),
        h("div", { class: "pkt-wrap", style: "height:360px" }, h("table", { class: "pkts" },
          h("thead", {}, h("tr", {}, ...["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"].map((t) => h("th", {}, t)))),
          h("tbody", { id: "sess-pkts" }))),
        h("div", { class: "row" }, h("button", { class: "btn sm", id: "sess-prev", onclick: () => { offset = Math.max(0, offset - PAGE); search(); } }, "Previous"),
          h("button", { class: "btn sm", id: "sess-next", onclick: () => { offset += PAGE; search(); } }, "Next"))));
    on("state", (s) => { if (s.state === "IDLE" || s.state === "ERROR") load(); });
    on("warning", (w) => { toast(w.message, "warn", 7000); load(); });
  }

  async function load() {
    const body = $("#sess-body"); if (!body) return;
    const list = await api("/captures");
    body.innerHTML = "";
    if (!list.length) body.append(h("tr", {}, h("td", { colspan: 8, class: "muted" }, "No sessions yet. Start a capture on the Live capture tab.")));
    for (const s of list) {
      const dur = s.ended ? s.ended - s.started : null;
      body.append(h("tr", {},
        h("td", { class: "mono" }, s.id), h("td", {}, s.source), h("td", {}, fmtDate(s.started)), h("td", {}, dur !== null ? fmtDur(dur) : "running"),
        h("td", {}, (s.packets || 0).toLocaleString()), h("td", {}, fmtBytes(s.file_size)),
        h("td", {}, h("span", { class: `badge ${s.status === "DONE" ? "ok" : s.status === "ERROR" ? "HIGH" : "MEDIUM"}`, title: s.error || "" }, s.status)),
        h("td", { class: "row" },
          h("button", { class: "btn sm", disabled: s.status === "ACTIVE", onclick: () => openSession(s) }, "Open"),
          h("button", { class: "btn sm", disabled: s.status === "ACTIVE", onclick: () => download(s.id) }, "Download PCAP"),
          can("admin") ? h("button", { class: "btn sm", disabled: s.status === "ACTIVE", onclick: () => del(s.id) }, "Delete") : null)));
    }
  }

  async function download(id) {
    try {
      const res = await api(`/captures/${id}/pcap`, { raw: true });
      const blob = await res.blob();
      const a = h("a", { href: URL.createObjectURL(blob), download: `${id}.pcap` });
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 5000);
      toast(`Downloaded ${id}.pcap (opens in Wireshark)`);
    } catch (e) { toast(e.message, "error"); }
  }

  async function del(id) {
    if (!confirm(`Delete session ${id} and its PCAP?`)) return;
    try {
      await api(`/captures/${id}`, { method: "DELETE" });
      toast(`Deleted ${id}`);
      if (openId === id) { openId = null; $("#sess-view").classList.add("hidden"); }
      load();
    } catch (e) { toast(e.message, "error"); }
  }

  function openSession(s) {
    openId = s.id; offset = 0;
    $("#sess-title").textContent = `Session ${s.id}`;
    $("#sess-view").classList.remove("hidden");
    search();
    $("#sess-view").scrollIntoView({ behavior: "smooth" });
  }

  async function search() {
    $("#sess-err").textContent = "";
    try {
      const r = await api(`/captures/${openId}/packets?filter=${encodeURIComponent($("#sess-filter").value.trim())}&offset=${offset}&limit=${PAGE}`);
      const body = $("#sess-pkts"); body.innerHTML = "";
      for (const p of r.packets) body.append(h("tr", { class: `p-${p.protocol}` },
        h("td", {}, p.seq), h("td", {}, fmtTime(p.ts)), h("td", {}, p.src_ip || p.src_mac || ""), h("td", {}, p.dst_ip || p.dst_mac || ""),
        h("td", {}, p.protocol), h("td", {}, p.length), h("td", { class: "info", title: p.info }, p.info)));
      $("#sess-count").textContent = `${r.matched.toLocaleString()} of ${r.total.toLocaleString()} packets match \u00b7 showing ${r.matched ? offset + 1 : 0}-${offset + r.packets.length}`;
      $("#sess-prev").disabled = offset === 0;
      $("#sess-next").disabled = offset + r.packets.length >= r.matched;
    } catch (e) { $("#sess-err").textContent = e.message; }
  }

  PPS.registerTab({ id: "sessions", title: "Sessions", init, onShow: load });
})();

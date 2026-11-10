/* Live capture tab: controls (F-001/002/052), status (F-003), stats + live table (F-051),
   display filters + presets (F-021..023), packet detail (F-010/011). */
"use strict";

(() => {
  const { h, $, api, toast, on, can, fmtBits, fmtTime, fmtDur, store } = PPS;
  const MAX_ROWS = 1000;
  let rows = [];          // packets currently in the table
  let selected = null;
  let autoscroll = true;
  let el;

  function init(panel) {
    el = panel;
    panel.append(
      h("div", { class: "grid dash" },
        controls(),
        h("div", { class: "grid" },
          h("div", { class: "grid stats" },
            stat("st-packets", "Packets"), stat("st-pps", "Packets / s"), stat("st-bw", "Bandwidth"), stat("st-elapsed", "Elapsed")),
          h("div", { class: "grid tops" },
            h("div", { class: "card" }, h("h3", {}, "Top talkers"), h("div", { class: "bars", id: "top-talkers" }, h("span", { class: "muted small" }, "No traffic yet"))),
            h("div", { class: "card" }, h("h3", {}, "Top protocols"), h("div", { class: "bars", id: "top-protos" }, h("span", { class: "muted small" }, "No traffic yet")))),
          filterBar(),
          h("div", { class: "pkt-wrap", id: "pkt-wrap" },
            h("table", { class: "pkts" },
              h("thead", {}, h("tr", {}, ...["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"].map((t) => h("th", {}, t)))),
              h("tbody", { id: "pkt-body" }))),
          h("div", { class: "row small muted" },
            h("label", {}, h("input", { type: "checkbox", id: "autoscroll", checked: true, onchange: (e) => { autoscroll = e.target.checked; } }), " Auto-scroll"),
            h("span", { id: "row-count" }, "0 packets shown"),
            h("button", { class: "btn sm", onclick: clearTable }, "Clear view")),
          h("div", { class: "card detail", id: "pkt-detail" }, h("h3", {}, "Packet detail"), h("div", { class: "muted small" }, "Select a packet to see its decoded layers."))
        )
      )
    );
    $("#pkt-body").addEventListener("click", (e) => {
      const tr = e.target.closest("tr"); if (!tr) return;
      const p = rows.find((r) => r.seq === Number(tr.dataset.seq)); if (!p) return;
      el.querySelectorAll("tr.sel").forEach((x) => x.classList.remove("sel"));
      tr.classList.add("sel"); selected = p.seq; showDetail(p);
    });
    on("packets", addPackets);
    on("status", renderStatus);
    on("ws-error", (m) => { if (m.code === "FILTER_INVALID") $("#df-err").textContent = m.message; });
    on("filter-ok", () => { $("#df-err").textContent = ""; });
    on("login", loadSources);
    PPS.setLiveFilter(store.get("pps.dfilter") || "");
  }

  function stat(id, label) { return h("div", { class: "card stat" }, h("div", { class: "v", id }, "0"), h("div", { class: "k" }, label)); }

  // ---------------------------------------------------------------- controls
  function controls() {
    const analyst = can("analyst");
    return h("div", { class: "card stack" },
      h("div", { class: "row", style: "justify-content:space-between" }, h("h3", { style: "margin:0" }, "Capture"), h("span", { class: "pill IDLE", id: "cap-state" }, "IDLE")),
      h("div", { class: "row" },
        h("label", {}, h("input", { type: "radio", name: "srctype", value: "replay", checked: true, onchange: srcChanged }), " Replay PCAP"),
        h("label", {}, h("input", { type: "radio", name: "srctype", value: "live", onchange: srcChanged, disabled: !analyst }), " Live interface")),
      h("label", { class: "fld", id: "fld-replay" }, "Replay file", h("select", { id: "replay-file" }),
        h("label", { class: "fld" }, "Speed", h("select", { id: "replay-speed" },
          h("option", { value: "1" }, "1x (real time)"), h("option", { value: "4" }, "4x"), h("option", { value: "0" }, "As fast as possible")))),
      h("div", { id: "fld-live", class: "stack hidden" },
        h("label", { class: "fld" }, "Interface", h("select", { id: "iface" })),
        h("label", { class: "fld" }, "Capture filter (BPF)", h("input", { type: "text", id: "bpf", placeholder: "e.g. tcp port 80 or udp port 53", class: "mono", onchange: checkBpf })),
        h("div", { class: "ferr", id: "bpf-err" }),
        h("label", { class: "small" }, h("input", { type: "checkbox", id: "authorised" }), " I am authorised to capture on this network")),
      h("div", { class: "row" },
        h("label", { class: "fld", style: "flex:1" }, "Duration (s, 0 = none)", h("input", { type: "number", id: "duration", min: 0, placeholder: "default" })),
        h("label", { class: "fld", style: "flex:1" }, "Packet limit (0 = none)", h("input", { type: "number", id: "maxpk", min: 0, placeholder: "default" }))),
      h("div", { class: "row" },
        h("button", { class: "btn primary", id: "btn-start", onclick: start, disabled: !analyst }, "Start"),
        h("button", { class: "btn danger", id: "btn-stop", onclick: stop, disabled: true }, "Stop"),
        analyst ? h("label", { class: "btn sm", title: "Upload a .pcap to replay" }, "Upload PCAP",
          h("input", { type: "file", accept: ".pcap,.pcapng", class: "hidden", onchange: upload })) : null),
      h("div", { class: "small muted", id: "cap-info" }, analyst ? "" : "Trainee view: you can watch live traffic; an analyst starts captures."),
      h("div", { class: "ferr", id: "cap-err" }));
  }

  function srcType() { return el.querySelector("input[name=srctype]:checked").value; }
  function srcChanged() {
    const live = srcType() === "live";
    $("#fld-live").classList.toggle("hidden", !live);
    $("#fld-replay").classList.toggle("hidden", live);
  }

  async function loadSources() {
    try {
      const files = await api("/replay-files");
      const sel = $("#replay-file"); sel.innerHTML = "";
      files.forEach((f) => sel.append(h("option", { value: f.name }, `${f.name} (${PPS.fmtBytes(f.size)})`)));
      if (!files.length) sel.append(h("option", { value: "" }, "No PCAPs in data/replay"));
    } catch (e) { toast(e.message, "error"); }
    if (!can("analyst")) return;
    try {
      const ifs = await api("/interfaces");
      const sel = $("#iface"); sel.innerHTML = "";
      ifs.forEach((i) => sel.append(h("option", { value: i.name }, `${i.description}${i.ips.length ? " - " + i.ips[0] : ""}`)));
      if (!ifs.length) sel.append(h("option", { value: "" }, "No capture interfaces (install Npcap/libpcap)"));
    } catch (e) { toast(e.message, "error"); }
    try {
      const cfg = await api("/config");
      if (cfg.default_interface) $("#iface").value = cfg.default_interface;
      $("#duration").placeholder = `default ${cfg.max_duration_s}`;
      $("#maxpk").placeholder = `default ${cfg.max_packets || "none"}`;
    } catch { /* settings API not available: keep server defaults */ }
  }

  async function checkBpf() {
    const v = $("#bpf").value.trim(); const box = $("#bpf"); $("#bpf-err").textContent = "";
    box.classList.remove("bad", "good");
    if (!v) return;
    let r;
    try { r = await api("/filters/validate", { method: "POST", body: { expression: v, kind: "bpf" } }); } catch { return; }
    box.classList.add(r.valid ? "good" : "bad");
    $("#bpf-err").textContent = r.valid ? (r.note || "") : r.error;
  }

  async function start() {
    $("#cap-err").textContent = "";
    const live = srcType() === "live";
    const num = (id) => ($(id).value === "" ? null : Number($(id).value));
    const body = {
      source_type: live ? "live" : "replay",
      source: live ? $("#iface").value : $("#replay-file").value,
      bpf: live ? $("#bpf").value.trim() : "",
      duration_s: num("#duration"), max_packets: num("#maxpk"),
      replay_speed: Number($("#replay-speed").value), authorised: live ? $("#authorised").checked : false,
    };
    $("#btn-start").disabled = true;
    const t0 = performance.now();
    try {
      clearTable();
      const st = await api("/captures", { method: "POST", body });
      renderStatus(st);
      toast(`Capture started in ${Math.round(performance.now() - t0)} ms (${st.session.id})`);
    } catch (e) {
      $("#cap-err").textContent = e.message; $("#btn-start").disabled = false;
    }
  }

  async function stop() {
    const s = PPS.state.status; if (!s || !s.session) return;
    $("#btn-stop").disabled = true;
    try { renderStatus(await api(`/captures/${s.session.id}/stop`, { method: "POST" })); } catch (e) { toast(e.message, "error"); }
  }

  async function upload(e) {
    const f = e.target.files[0]; if (!f) return;
    const form = new FormData(); form.append("file", f);
    try { await api("/replay-files", { method: "POST", form }); toast(`Uploaded ${f.name}`); await loadSources(); $("#replay-file").value = f.name; }
    catch (err) { toast(err.message, "error"); }
    e.target.value = "";
  }

  let lastState = null;
  function renderStatus(st) {
    const pill = $("#cap-state"); if (!pill) return;
    pill.className = `pill ${st.state}`; pill.textContent = st.state;
    const active = ["STARTING", "ACTIVE"].includes(st.state);
    $("#btn-start").disabled = active || !can("analyst");
    $("#btn-stop").disabled = !active || !can("analyst");
    const s = st.stats || {};
    $("#st-packets").textContent = (s.packets || 0).toLocaleString();
    $("#st-pps").textContent = s.pps ?? 0;
    $("#st-bw").textContent = fmtBits(s.bandwidth_bps);
    $("#st-elapsed").textContent = active ? fmtDur(st.elapsed_s) : (st.session && st.session.ended ? fmtDur(st.session.ended - st.session.started) : "0s");
    bars("#top-talkers", s.top_talkers || []);
    bars("#top-protos", s.top_protocols || []);
    const info = $("#cap-info");
    if (st.session) {
      const lim = st.limits || {};
      info.textContent = `${st.session.id} \u00b7 ${st.session.source}${st.session.bpf ? " \u00b7 BPF: " + st.session.bpf : ""}` +
        (active ? ` \u00b7 limits: ${lim.duration_s ? lim.duration_s + "s" : "no time limit"}, ${lim.max_packets ? lim.max_packets + " pkts" : "no packet limit"}` : ` \u00b7 ${st.session.status}${st.session.stop_reason ? " (" + st.session.stop_reason + ")" : ""}`);
    }
    if (st.state === "ERROR" && st.error) $("#cap-err").textContent = st.error;
    if (lastState && lastState !== st.state && st.state === "IDLE" && st.session) toast(`Capture finished: ${st.session.packets} packets saved`);
    lastState = st.state;
  }

  function bars(sel, items) {
    const box = $(sel); box.innerHTML = "";
    if (!items.length) { box.append(h("span", { class: "muted small" }, "No traffic yet")); return; }
    const max = items[0][1] || 1;
    items.forEach(([k, v]) => box.append(h("div", { class: "b", style: `--w:${(100 * v / max).toFixed(0)}%` }, h("span", {}, k), h("span", {}, v.toLocaleString()))));
  }

  // ---------------------------------------------------------------- display filter + presets
  function filterBar() {
    return h("div", { class: "card stack" },
      h("div", { class: "filterbar" },
        h("input", { type: "text", id: "dfilter", placeholder: 'Display filter, e.g.  ip.addr == 192.168.50.10 and (dns or http)', value: store.get("pps.dfilter") || "",
          onkeydown: (e) => { if (e.key === "Enter") applyFilter(); } }),
        h("button", { class: "btn", onclick: applyFilter }, "Apply"),
        h("select", { id: "presets", onchange: pickPreset }, h("option", { value: "" }, "Presets\u2026")),
        h("button", { class: "btn", onclick: savePreset, disabled: !can("analyst") }, "Save preset")),
      h("div", { class: "ferr", id: "df-err" }),
      h("div", { class: "small muted" }, "Fields: ip.src ip.dst ip.addr eth.src eth.dst mac port src.port dst.port tcp.port udp.port proto len info tcp.flags \u00b7 Protocols: tcp udp icmp arp dns http ipv4 ipv6 \u00b7 Operators: == != > < >= <= contains \u00b7 and/or/not, && || !"));
  }

  async function loadPresets() {
    const sel = $("#presets"); if (!sel) return;
    let list = [];
    try { list = await api("/filters/presets"); } catch { sel.disabled = true; return; }
    sel.innerHTML = ""; sel.append(h("option", { value: "" }, list.length ? "Presets\u2026" : "No presets yet"));
    list.forEach((p) => sel.append(h("option", { value: p.expression, title: p.expression }, p.name)));
  }
  function pickPreset(e) { if (e.target.value) { $("#dfilter").value = e.target.value; applyFilter(); } }

  async function applyFilter() {
    const f = $("#dfilter").value.trim();
    let r;
    try { r = await api("/filters/validate", { method: "POST", body: { expression: f, kind: "display" } }); }
    catch (e) { $("#df-err").textContent = e.message; return; }
    $("#dfilter").classList.toggle("bad", !r.valid);
    $("#df-err").textContent = r.valid ? "" : r.error;
    if (!r.valid) return;
    store.set("pps.dfilter", f);
    PPS.setLiveFilter(f);
    clearTable();
    toast(f ? `Live view filtered: ${f}` : "Live filter cleared");
  }

  async function savePreset() {
    const f = $("#dfilter").value.trim(); if (!f) return toast("Type a filter first", "warn");
    const name = prompt("Preset name:"); if (!name) return;
    try { await api(`/filters/presets/${encodeURIComponent(name)}`, { method: "PUT", body: { expression: f } }); toast(`Preset "${name}" saved`); loadPresets(); }
    catch (e) { toast(e.message, "error"); }
  }

  // ---------------------------------------------------------------- packet table
  function addPackets(pkts) {
    const body = $("#pkt-body"); if (!body) return;
    const frag = document.createDocumentFragment();
    for (const p of pkts) {
      rows.push(p);
      frag.append(h("tr", { class: `p-${p.protocol}`, "data-seq": p.seq },
        h("td", {}, p.seq), h("td", {}, fmtTime(p.ts)), h("td", {}, p.src_ip || p.src_mac || ""), h("td", {}, p.dst_ip || p.dst_mac || ""),
        h("td", {}, p.protocol), h("td", {}, p.length), h("td", { class: "info", title: p.info }, p.info)));
    }
    body.append(frag);
    const extra = rows.length - MAX_ROWS;
    if (extra > 0) { rows.splice(0, extra); for (let i = 0; i < extra; i++) body.firstChild && body.firstChild.remove(); }
    $("#row-count").textContent = `${rows.length} packets shown (newest ${MAX_ROWS} kept)`;
    if (autoscroll) { const w = $("#pkt-wrap"); w.scrollTop = w.scrollHeight; }
  }

  function clearTable() { rows = []; selected = null; const b = $("#pkt-body"); if (b) b.innerHTML = ""; $("#row-count").textContent = "0 packets shown"; }

  function showDetail(p) {
    const box = $("#pkt-detail"); box.innerHTML = "";
    box.append(h("h3", {}, `Packet ${p.seq} \u00b7 ${p.length} bytes \u00b7 ${fmtTime(p.ts)}`));
    for (const layer of p.layers || []) {
      const dl = h("dl");
      for (const [k, v] of Object.entries(layer.fields || {})) dl.append(h("dt", {}, k), h("dd", {}, Array.isArray(v) ? v.join(", ") : String(v)));
      box.append(h("details", { open: true }, h("summary", {}, layer.proto), dl));
    }
  }

  PPS.registerTab({ id: "live", title: "Live capture", init, onShow: () => { loadPresets(); } });
  PPS.live = { loadPresets };
})();

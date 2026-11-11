/* Admin tab: user accounts and roles (F-061, SR-004), audit log (SR-005). */
"use strict";

(() => {
  const { h, $, api, toast, on, fmtDate } = PPS;
  const ROLES = ["trainee", "analyst", "admin"];

  function init(panel) {
    panel.append(
      h("div", { class: "card stack", style: "max-width:760px" },
        h("h3", {}, "Users and roles"),
        h("table", { class: "list" }, h("thead", {}, h("tr", {}, h("th", {}, "User"), h("th", {}, "Role"), h("th", {}, "Active"), h("th", {}, ""))), h("tbody", { id: "user-body" })),
        h("form", { class: "row", onsubmit: addUser },
          h("input", { type: "text", id: "nu-name", placeholder: "username", required: true, minlength: 3, maxlength: 32, pattern: "[a-z0-9][a-z0-9._-]{2,31}", title: "3-32 characters: lower-case letters, digits, . _ -", autocomplete: "off", style: "flex:1" }),
          h("input", { type: "password", id: "nu-pass", placeholder: "password (8+)", required: true, minlength: 8, maxlength: 128, autocomplete: "new-password", style: "flex:1" }),
          h("select", { id: "nu-role" }, ROLES.map((r) => h("option", { value: r, selected: r === "analyst" }, r))),
          h("button", { class: "btn", type: "submit" }, "Add user")),
        h("div", { class: "small muted" }, "Trainee: view only · Analyst: run captures, filters, acknowledge alerts · Admin: settings, users, audit log. The last active admin cannot be demoted or disabled.")),
      h("div", { class: "card stack", style: "margin-top:12px" },
        h("div", { class: "row", style: "justify-content:space-between" }, h("h3", { style: "margin:0" }, "Audit log"), h("span", { id: "audit-verify" })),
        h("div", { class: "small muted" }, "Each entry is chained to the one before it, so edits and deletions inside the log are detected. Removing only the newest entries is not."),
        h("div", { class: "pkt-wrap", style: "height:340px" }, h("table", { class: "list" },
          h("thead", {}, h("tr", {}, ...["#", "Time", "Actor", "Action", "Details"].map((t) => h("th", {}, t)))), h("tbody", { id: "audit-body" })))));
    on("config-saved", () => { if (PPS.state.current === "admin") loadAudit(); });
  }

  function load() { loadUsers(); loadAudit(); }

  const isSelf = (username) => PPS.state.user && PPS.state.user.username === username;

  async function loadUsers() {
    let users;
    try { users = await api("/users"); } catch (e) { toast(e.message, "error"); return; }
    const body = $("#user-body"); body.innerHTML = "";
    for (const u of users) {
      const roleSel = h("select", { onchange: (e) => changeRole(u, e.target) },
        ROLES.map((r) => h("option", { value: r, selected: r === u.role }, r)));
      body.append(h("tr", {}, h("td", {}, u.username, isSelf(u.username) ? " (you)" : ""), h("td", {}, roleSel),
        h("td", {}, u.active ? "yes" : "no"),
        h("td", {}, h("button", { class: "btn sm", onclick: () => toggleActive(u) }, u.active ? "Disable" : "Enable"))));
    }
  }

  function changeRole(u, select) {
    const role = select.value;
    if (isSelf(u.username) && role !== "admin" && !confirm("Change your own role? You may lose access to this tab.")) {
      select.value = u.role; return;
    }
    patch(u.username, { role });
  }

  function toggleActive(u) {
    if (u.active && isSelf(u.username) && !confirm("Disable your own account? You will be signed out.")) return;
    patch(u.username, { active: !u.active });
  }

  async function patch(username, body) {
    try { await api(`/users/${encodeURIComponent(username)}`, { method: "PATCH", body }); toast(`Updated ${username}`); }
    catch (e) { toast(e.message, "error"); }
    loadUsers(); loadAudit();
  }

  async function addUser(e) {
    e.preventDefault();
    const name = $("#nu-name").value.trim();
    try {
      await api("/users", { method: "POST", body: { username: name, password: $("#nu-pass").value, role: $("#nu-role").value } });
      toast(`Created ${name}`); $("#nu-name").value = ""; $("#nu-pass").value = "";
      loadUsers(); loadAudit();
    } catch (err) { toast(err.message, "error"); }
  }

  async function loadAudit() {
    let r;
    try { r = await api("/audit"); } catch (e) { toast(e.message, "error"); return; }
    const v = r.verification;
    $("#audit-verify").innerHTML = "";
    $("#audit-verify").append(v.ok ? h("span", { class: "badge ok" }, `Hash chain verified · ${v.entries} entries`)
      : h("span", { class: "badge HIGH" }, `TAMPERING DETECTED at entry #${v.broken_at}`));
    const body = $("#audit-body"); body.innerHTML = "";
    for (const a of r.entries) body.append(h("tr", {}, h("td", {}, a.id), h("td", {}, fmtDate(a.ts)), h("td", {}, a.actor), h("td", {}, a.action),
      h("td", { class: "mono", style: "white-space:normal" }, JSON.stringify(a.details))));
  }

  PPS.registerTab({ id: "admin", title: "Admin", minRole: "admin", init, onShow: load });
})();

"use strict";
const el = (id) => document.getElementById(id);
const state = {models: [], jobs: [], selected: null, providers: []};
function notice(text, error = false) { el("notice").textContent = text; el("notice").classList.toggle("error", error); }
async function api(path, data) {
  const options = {credentials: "same-origin", headers: {}};
  if (data !== undefined) {
    options.method = "POST"; options.headers["Content-Type"] = "application/json";
    const token = document.cookie.split("; ").find((s) => s.startsWith("_xsrf="));
    options.headers["X-XSRFToken"] = token ? decodeURIComponent(token.slice(6)) : "";
    options.body = JSON.stringify(data);
  }
  const response = await fetch("/api/" + path, options);
  if (response.status === 401) { window.location.assign("/login"); throw new Error("Signed out"); }
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || "Request failed");
  return body;
}
function lines(id) { return el(id).value.split("\n").map((s) => s.trim()).filter(Boolean); }
function option(select, value, label) { const o = document.createElement("option"); o.value = value; o.textContent = label; select.append(o); }
function card(parent, title, text) { const div = document.createElement("div"); div.className = "card"; const strong = document.createElement("strong"); strong.textContent = title; const p = document.createElement("p"); p.textContent = text; div.append(strong, p); parent.append(div); return div; }
function handle(id, event, action) { el(id).addEventListener(event, async (e) => { e.preventDefault(); try { await action(e); } catch (error) { notice(error.message, true); } }); }
async function models() {
  state.models = (await api("models")).models; el("shared-model").replaceChildren();
  state.models.forEach((m, i) => option(el("shared-model"), String(i), m.name + " / " + m.model));
  if (!state.models.length) option(el("shared-model"), "", "No shared models granted");
}
async function refreshJobs() {
  state.jobs = (await api("jobs")).jobs; el("jobs").replaceChildren();
  const parent = el("parent-job").value; el("parent-job").replaceChildren(); option(el("parent-job"), "", "New conversation");
  for (const job of state.jobs) {
    const item = card(el("jobs"), job.job_id.slice(0, 12) + " · " + job.status + " · " + job.server, job.spec.prompt.slice(0, 180));
    const button = document.createElement("button"); button.textContent = "View task"; button.onclick = () => showJob(job.job_id).catch((e) => notice(e.message, true)); item.append(button);
    if (job.status === "succeeded") option(el("parent-job"), job.job_id, job.job_id.slice(0, 12) + " · " + job.spec.prompt.slice(0, 60));
  }
  el("parent-job").value = parent;
  if (state.selected) await showJob(state.selected);
}
async function showJob(id) {
  state.selected = id; const job = await api("jobs/" + id); el("job-detail").hidden = false;
  el("job-title").textContent = id + " · " + job.status;
  const events = (await api("jobs/" + id + "/events")).events;
  el("events").textContent = events.map((e) => e.type + "\n" + JSON.stringify(e.data, null, 2)).join("\n\n");
  el("cancel-job").disabled = ["succeeded", "failed", "cancelled"].includes(job.status);
  el("artifacts").replaceChildren();
  for (const file of (await api("jobs/" + id + "/artifacts")).artifacts) {
    const link = document.createElement("a"); link.href = "/download/" + id + "/" + file.relative_path.split("/").map(encodeURIComponent).join("/");
    link.textContent = file.relative_path + " (" + file.size_bytes + " bytes)"; const p = document.createElement("p"); p.append(link); el("artifacts").append(p);
  }
}
async function admin() {
  el("users").textContent = JSON.stringify((await api("admin/users")).users, null, 2);
  el("grants").textContent = JSON.stringify((await api("admin/grants")).grants, null, 2);
  el("leases").textContent = JSON.stringify((await api("admin/leases")).leases, null, 2);
  state.providers = (await api("admin/providers")).providers; el("providers").replaceChildren();
  for (const p of state.providers) {
    const item = card(el("providers"), p.id + " · " + p.name, p.url + " · " + p.protocol + " · " + p.discovery + " · " + (p.enabled ? "enabled" : "disabled") + "\n" + p.models.join(", "));
    const edit = document.createElement("button"); edit.textContent = "Edit"; edit.onclick = () => {
      for (const k of ["id", "name", "url", "protocol"]) el("provider-" + k).value = p[k];
      el("provider-enabled").checked = Boolean(p.enabled); el("provider-models").value = p.models.join("\n"); el("provider-key").value = "";
    }; item.append(edit);
  }
}
handle("connection", "change", async () => { const personal = el("connection").value === "personal"; el("personal-choice").hidden = !personal; el("shared-choice").hidden = personal; });
handle("personal", "submit", async () => { await api("personal", personalSettings()); el("personal-key").value = ""; notice("Personal connection saved for this session."); });
function personalSettings() { const settings = {url: el("personal-url").value, protocol: el("personal-protocol").value}; if (el("personal-key").value) settings.api_key = el("personal-key").value; return settings; }
handle("personal-discover", "click", async () => {
  const data = await api("personal/discover", personalSettings()); el("personal-models").replaceChildren();
  data.models.forEach((m) => option(el("personal-models"), m, m)); el("personal-key").value = "";
  notice("Found " + data.models.length + " models. Select or enter a model ID.");
});
handle("personal-clear", "click", async () => { await api("personal/clear", {}); el("personal-key").value = ""; el("personal-model").value = ""; el("personal-url").value = ""; el("personal-models").replaceChildren(); notice("Personal settings cleared; personal task credentials revoked."); });
handle("analysis", "submit", async () => {
  const personal = el("connection").value === "personal";
  const selection = state.models[Number(el("shared-model").value)];
  if (!personal && (!selection || el("shared-model").value === "")) throw new Error("Choose a granted shared model or a personal connection.");
  if (personal && !el("personal-model").value.trim()) throw new Error("Enter a personal model ID.");
  const job = await api("jobs", {server: el("server").value, provider: personal ? "personal" : selection.provider,
    model: personal ? el("personal-model").value.trim() : selection.model, prompt: el("prompt").value,
    cpu_threads: Number(el("cpus").value), memory_gb: Number(el("memory").value), gpu: el("gpu").checked,
    input_paths: lines("inputs"), parent_job: el("parent-job").value || null});
  notice("Task queued on " + job.server + "."); state.selected = job.job_id; await refreshJobs();
});
handle("cancel-job", "click", async () => { await api("jobs/" + state.selected + "/cancel", {}); await refreshJobs(); });
handle("refresh", "click", refreshJobs);
handle("catalog-search", "submit", async () => {
  const found = await api("catalog?q=" + encodeURIComponent(el("catalog-query").value)); el("catalog").replaceChildren();
  for (const c of found.capabilities) card(el("catalog"), c.name + " · " + c.readiness_status, c.id + "\n" + (c.description || "") + "\n" + (c.executable || c.environment || "") + "\n" + (c.restrictions || []).join("; "));
});
handle("user-access", "submit", async () => { await api("admin/users", {username: el("access-user").value, enabled: el("access-enabled").value === "true"}); await admin(); notice("Application access updated."); });
handle("provider", "submit", async () => {
  const data = {id: el("provider-id").value, name: el("provider-name").value, url: el("provider-url").value,
    protocol: el("provider-protocol").value, enabled: el("provider-enabled").checked, models: lines("provider-models")};
  const existing = state.providers.some((p) => p.id === data.id);
  if (el("provider-key").value || !existing) data.api_key = el("provider-key").value;
  await api("admin/providers", data); el("provider-key").value = ""; await admin(); await models(); notice("Provider saved. New models require explicit user grants.");
});
handle("provider-refresh", "click", async () => { await api("admin/refresh", {provider: el("provider-id").value}); await admin(); await models(); notice("Model catalog refreshed. Grant newly discovered models explicitly."); });
handle("grant", "submit", async () => { await api("admin/grants", {username: el("grant-user").value, provider: el("grant-provider").value, model: el("grant-model").value, enabled: el("grant-enabled").value === "true"}); await admin(); await models(); notice("Model permission updated."); });
handle("logout", "click", async () => { await api("logout", {}); window.location.assign("/login"); });
handle("lease-release", "submit", async () => { if (!window.confirm("Release only after confirming the worker has stopped. Continue?")) return; await api("admin/leases/release", {job_id: el("lease-job").value.trim()}); await admin(); notice("Reservation released."); });
async function initialize() {
  const me = await api("me"); el("identity").textContent = me.username + (me.admin ? " · administrator" : "");
  const servers = (await api("servers")).servers;
  Object.entries(servers).forEach(([alias, s]) => option(el("server"), alias, alias + " · " + s.cpu_threads + " threads / " + s.memory_gb + " GB"));
  await models(); await refreshJobs();
  if (me.admin) { el("admin").hidden = false; await admin(); }
  window.setInterval(() => refreshJobs().catch((e) => notice(e.message, true)), 5000);
}
initialize().catch((error) => notice(error.message, true));

/* js-recon — interfaz web. Sin dependencias.
   Regla de oro: todo lo que viene del objetivo (valores, URLs, snippets, análisis)
   se pinta con textContent / nodos de texto, nunca con innerHTML sin escapar. */
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "text") el.textContent = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) el.append(k instanceof Node ? k : String(k));
  return el;
}

const store = {
  get(k, d) { try { const v = localStorage.getItem("jsrecon:" + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem("jsrecon:" + k, JSON.stringify(v)); } catch { /* sin almacenamiento */ } },
};

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: opts.body ? { "Content-Type": "application/json" } : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* vacío */ }
  if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
  return data;
}

let toastTimer;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg; t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 1800);
}
async function copy(text, what = "Copiado") {
  try { await navigator.clipboard.writeText(text); toast(what); }
  catch { toast("No se pudo copiar"); }
}

/* ======================================================================
   Estado
   ====================================================================== */
const S = {
  meta: null,
  hosts: [],
  job: null, logNext: 0, pollTimer: null, clockTimer: null, startedAt: 0,
  report: null, runId: null,
  tab: "secret", q: "", env: "all", reveal: false,
  history: [],
  limit: {},
};

const CATS = {
  secret: {
    label: "Secretos", short: "secretos",
    intro: "Claves, tokens y credenciales. LIVE = producción (trátalo como incidente); test = sandbox, normalmente ruido.",
  },
  logic: {
    label: "Lógica", short: "lógica",
    intro: "Pagos, flags de debug y comprobaciones hechas en el cliente. Aquí un entorno TEST en la web real es una alerta, no una rebaja.",
  },
  dom: {
    label: "DOM", short: "sinks/fuentes",
    intro: "Sinks y fuentes del DOM: candidatos a XSS basado en DOM u open redirect. Confirma si llega dato controlable al sink.",
  },
  version: {
    label: "Versiones", short: "versiones",
    intro: "Librerías y versiones detectadas. Crúzalas con avisos de seguridad conocidos.",
  },
  endpoint: {
    label: "Endpoints", short: "endpoints",
    intro: "Rutas y URLs que aparecen en el código. Únicas, con los ficheros donde salen.",
  },
};
const CAT_ORDER = ["secret", "logic", "dom", "version", "endpoint"];
const LOGIC_ORDER = ["payment_method", "test_mode", "debug_flag", "client_check", "role_check"];
const HOT_EP = /(admin|internal|debug|graphql|token|auth|login|upload|export|backup|config|private|secret|swagger|actuator|\.env)/i;

/* ======================================================================
   Formulario
   ====================================================================== */
const form = $("#scan-form");

function formData() {
  const fd = new FormData(form);
  return {
    url: (fd.get("url") || "").trim(),
    scope_confirmed: fd.get("scope_confirmed") === "on",
    browser: fd.get("capture") === "browser",
    fresh_profile: fd.get("fresh_profile") === "on",
    scope_subdomains: fd.get("scope_subdomains") === "on",
    include_third_party: fd.get("include_third_party") === "on",
    allow_hosts: [...S.hosts],
    max_js: fd.get("max_js") || "",
    insecure: fd.get("insecure") === "on",
    mode: fd.get("mode"),
    model: fd.get("model") || (S.meta && S.meta.default_model) || "haiku",
    dry_run: fd.get("dry_run") === "on",
    accept_cost: fd.get("accept_cost") === "on",
  };
}

function shellQuote(s) {
  return /^[\w@%+=:,./-]+$/.test(s) ? s : "'" + s.replace(/'/g, "'\\''") + "'";
}

function renderCli() {
  const d = formData();
  const parts = [];
  const flag = (f) => parts.push(h("b", null, f));
  const code = $("#cli");
  code.replaceChildren();
  code.append("python -m uv run python main.py ", d.url ? shellQuote(d.url) : "<url>");
  if (d.mode === "noai") flag("--no-ai");
  if (d.mode === "deep") flag("--deep");
  if (d.mode !== "noai" && S.meta && d.model !== S.meta.default_model) parts.push(h("b", null, "--model " + d.model));
  if (d.mode !== "noai" && d.dry_run) flag("--dry-run");
  if (d.browser) flag("--browser");
  if (d.browser && d.fresh_profile) flag("--fresh-profile");
  if (d.scope_subdomains) flag("--scope-subdomains");
  if (d.include_third_party) flag("--include-third-party");
  for (const host of d.allow_hosts) parts.push(h("b", null, "--allow-host " + shellQuote(host)));
  if (d.insecure) flag("--insecure");
  if (d.max_js) parts.push(h("b", null, "--max-js " + d.max_js));
  for (const p of parts) code.append(" ", p);
}

function syncForm() {
  const d = formData();
  $("#ai-opts").hidden = d.mode === "noai";
  $("#row-cost").hidden = d.mode !== "deep";
  $("#row-fresh").hidden = !d.browser;
  $("#third-warn").hidden = !d.include_third_party;
  $("#nokey").hidden = !S.meta || S.meta.api_key;
  if (S.meta) $("#f-maxjs").placeholder = String(d.browser ? S.meta.browser_max_js : S.meta.max_js);
  renderCli();
  store.set("form", { ...d, url: d.url, scope_confirmed: false });
}

function renderHosts() {
  const box = $("#hosts"), input = $("#f-host");
  $$(".chip", box).forEach((c) => c.remove());
  S.hosts.forEach((host, i) => {
    box.insertBefore(h("span", { class: "chip" }, host,
      h("button", { type: "button", "aria-label": "Quitar " + host, onclick: () => { S.hosts.splice(i, 1); renderHosts(); syncForm(); } }, "×")), input);
  });
}
$("#f-host").addEventListener("keydown", (e) => {
  const input = e.currentTarget;
  if ((e.key === "Enter" || e.key === "," || e.key === " ") && input.value.trim()) {
    e.preventDefault();
    for (const v of input.value.split(/[\s,]+/)) {
      const host = v.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      if (host && !S.hosts.includes(host)) S.hosts.push(host);
    }
    input.value = "";
    renderHosts(); syncForm();
  } else if (e.key === "Backspace" && !input.value && S.hosts.length) {
    S.hosts.pop(); renderHosts(); syncForm();
  }
});

function restoreForm() {
  const saved = store.get("form", null);
  if (!saved) return;
  form.url.value = saved.url || "";
  const set = (name, on) => { if (form[name]) form[name].checked = !!on; };
  ["fresh_profile", "scope_subdomains", "include_third_party", "insecure", "dry_run"].forEach((n) => set(n, saved[n]));
  if (saved.max_js) form.max_js.value = saved.max_js;
  const radio = (name, val) => { const r = form.querySelector(`input[name="${name}"][value="${val}"]`); if (r && !r.disabled) r.checked = true; };
  radio("mode", saved.mode);
  radio("capture", saved.browser ? "browser" : "direct");
  radio("model", saved.model);
  S.hosts = Array.isArray(saved.allow_hosts) ? saved.allow_hosts.filter((x) => typeof x === "string") : [];
  renderHosts();
}

form.addEventListener("input", syncForm);
form.addEventListener("change", syncForm);
$("#f-scope").addEventListener("change", () => $(".check-scope").classList.remove("need"));
$("#copy-cli").addEventListener("click", () => copy($("#cli").textContent, "Comando copiado"));

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#form-error");
  err.hidden = true;
  const d = formData();
  const fail = (msg) => { err.textContent = msg; err.hidden = false; };
  if (!/^https?:\/\/[^\s/]+/i.test(d.url)) { form.url.focus(); return fail("Escribe una URL http:// o https:// válida."); }
  if (!d.scope_confirmed) { $(".check-scope").classList.add("need"); return fail("Confirma el scope antes de lanzar tráfico."); }
  $("#launch").disabled = true;
  try {
    const { id } = await api("/api/scan", { method: "POST", body: JSON.stringify(d) });
    form.scope_confirmed.checked = false;
    startJob(id, d.url, d.browser);
  } catch (ex) {
    fail(ex.message);
    $("#launch").disabled = false;
  }
});

/* ======================================================================
   Vistas
   ====================================================================== */
function show(view) {
  for (const v of ["empty", "running", "report", "history"]) $("#view-" + v).hidden = v !== view;
  const navReport = view !== "history";
  $("#nav-report").classList.toggle("on", navReport);
  $("#nav-history").classList.toggle("on", !navReport);
  if (view === "history") loadHistory();
}
function showReportSide() {
  if (S.job) show("running");
  else if (S.report) show("report");
  else show("empty");
}
$$("[data-view]").forEach((b) => b.addEventListener("click", () => (b.dataset.view === "history" ? show("history") : showReportSide())));

/* ======================================================================
   Escaneo en curso
   ====================================================================== */
function startJob(id, target, browser) {
  S.job = id; S.logNext = 0; S.startedAt = Date.now();
  $("#run-target").textContent = target || "";
  $("#run-browser").hidden = !browser;
  $("#console").replaceChildren(h("div", { class: "ln info" }, h("span", { class: "t" }, "--:--:--"), h("span", { class: "lv" }, "info"), h("span", { class: "m cursor" }, "En cola…")));
  $("#launch").disabled = true;
  show("running");
  clearInterval(S.clockTimer);
  S.clockTimer = setInterval(() => {
    const s = Math.floor((Date.now() - S.startedAt) / 1000);
    $("#run-clock").textContent = `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
  }, 500);
  poll();
}

async function poll() {
  clearTimeout(S.pollTimer);
  if (!S.job) return;
  let st;
  try { st = await api(`/api/scan/${S.job}?since=${S.logNext}`); }
  catch (e) { S.pollTimer = setTimeout(poll, 2000); return; }
  if (S.logNext === 0) {
    $("#console").replaceChildren();
    $("#run-target").textContent = st.target;
    $("#run-browser").hidden = !st.browser;
  }
  const con = $("#console");
  const stick = con.scrollTop + con.clientHeight >= con.scrollHeight - 30;
  $$(".cursor", con).forEach((c) => c.classList.remove("cursor"));
  for (const l of st.logs) {
    con.append(h("div", { class: "ln " + l.level }, h("span", { class: "t" }, l.t), h("span", { class: "lv" }, l.level === "warning" ? "aviso" : l.level), h("span", { class: "m" }, l.msg)));
  }
  S.logNext = st.next;
  if (st.status === "running") {
    const last = con.lastElementChild && $(".m", con.lastElementChild);
    if (last) last.classList.add("cursor");
    if (stick) con.scrollTop = con.scrollHeight;
    S.pollTimer = setTimeout(poll, 700);
    return;
  }
  if (stick) con.scrollTop = con.scrollHeight;
  clearInterval(S.clockTimer);
  S.job = null;
  $("#launch").disabled = false;
  if (st.status === "done") {
    await openReport(st.run_id);
    toast("Escaneo terminado");
  } else {
    con.append(h("div", { class: "ln error" }, h("span", { class: "t" }), h("span", { class: "lv" }, "fin"), h("span", { class: "m" }, "El escaneo terminó con error: " + st.error)));
  }
  loadHistory(true);
}

/* ======================================================================
   Informe
   ====================================================================== */
async function openReport(runId) {
  try {
    const rep = await api(`/api/reports/${encodeURIComponent(runId)}`);
    S.report = rep; S.runId = runId; S.limit = {};
    try { history.replaceState(null, "", "#r=" + encodeURIComponent(runId)); } catch { /* sandbox */ }
    const live = rep.findings.filter((f) => f.category === "secret" && f.env === "live").length;
    const first = live ? "secret" : CAT_ORDER.find((c) => rep.findings.some((f) => f.category === c)) || (rep.analysis ? "ai" : "files");
    S.tab = first;
    renderReport();
    show("report");
  } catch (e) {
    toast("No se pudo abrir el informe: " + e.message);
  }
}

function fmtDate(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString("es-ES", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

function renderReport() {
  const r = S.report;
  $("#rep-date").textContent = "Informe · " + fmtDate(r.generated_at);
  $("#rep-target").textContent = r.target;
  const inl = r.js_files.filter((j) => j.inline).length;
  const meta = $("#rep-meta");
  meta.replaceChildren(
    h("b", null, r.js_files.length), ` ficheros JS (${inl} inline)`,
    " · ", h("b", null, r.out_of_scope.length), " fuera de scope",
    " · ", h("b", null, r.errors.length), " errores",
    r.analysis ? [" · IA: ", h("b", null, r.analysis.model)] : " · sin IA",
  );
  $("#dl-json").href = `/api/reports/${encodeURIComponent(S.runId)}/download/json`;
  $("#dl-md").href = `/api/reports/${encodeURIComponent(S.runId)}/download/md`;

  // Recuento principal (no depende de la búsqueda: es el resumen del informe)
  const tally = $("#tally");
  tally.replaceChildren();
  for (const c of CAT_ORDER) {
    const items = r.findings.filter((f) => f.category === c);
    const uniq = new Set(items.map((f) => f.value)).size;
    const n = c === "version" || c === "endpoint" ? uniq : items.length;
    let x = "", hot = false;
    if (c === "secret") {
      const live = items.filter((f) => f.env === "live").length;
      const test = items.filter((f) => f.env === "test").length;
      x = live ? `${live} LIVE` : test ? `${test} test` : "";
      hot = live > 0;
    } else if (c === "logic") {
      const t = items.filter((f) => f.env === "test").length;
      x = t ? `${t} en modo TEST` : ""; hot = t > 0;
    } else if (c === "endpoint") {
      const hotN = [...new Set(items.map((f) => f.value))].filter((v) => HOT_EP.test(v)).length;
      x = hotN ? `${hotN} sensibles` : "";
    } else if (c === "dom") {
      const sinks = items.filter((f) => f.kind === "dom_sink").length;
      x = sinks ? `${sinks} sinks` : "";
    }
    tally.append(h("button", { type: "button", class: n ? "" : "zero", onclick: () => { S.tab = c; renderTabs(); renderPanel(); } },
      h("span", { class: "n" }, n), h("span", { class: "k" }, CATS[c].label), h("span", { class: "x" + (hot ? " hot" : "") }, x)));
  }
  $$(".filters button").forEach((b) => b.classList.toggle("on", b.dataset.env === S.env));
  renderTabs();
  renderPanel();
}

/* ---------- búsqueda ---------- */
function terms() { return S.q.toLowerCase().split(/\s+/).filter(Boolean); }
function matches(hay, ts) { const s = hay.toLowerCase(); return ts.every((t) => s.includes(t)); }
function findingHay(f) { return [f.kind, S.reveal ? f.value : f.masked, f.source, f.env, snippetText(f), f.category].join(" "); }
function envOk(f) {
  if (S.env === "all" || !(f.category === "secret" || f.category === "logic")) return true;
  return S.env === "none" ? !f.env : f.env === S.env;
}
function filtered(cat) {
  const ts = terms();
  return S.report.findings.filter((f) => f.category === cat && envOk(f) && (!ts.length || matches(findingHay(f), ts)));
}

/* Resalta los términos de búsqueda en un texto -> DocumentFragment */
function hl(text, ts = terms()) {
  const frag = document.createDocumentFragment();
  text = String(text ?? "");
  if (!ts.length || !text) { frag.append(text); return frag; }
  const lower = text.toLowerCase();
  const ranges = [];
  for (const t of ts) {
    let i = 0;
    while ((i = lower.indexOf(t, i)) !== -1) { ranges.push([i, i + t.length]); i += t.length; }
  }
  if (!ranges.length) { frag.append(text); return frag; }
  ranges.sort((a, b) => a[0] - b[0]);
  const merged = [ranges[0]];
  for (const [a, b] of ranges.slice(1)) {
    const last = merged[merged.length - 1];
    if (a <= last[1]) last[1] = Math.max(last[1], b); else merged.push([a, b]);
  }
  let pos = 0;
  for (const [a, b] of merged) {
    if (a > pos) frag.append(text.slice(pos, a));
    frag.append(h("mark", null, text.slice(a, b)));
    pos = b;
  }
  if (pos < text.length) frag.append(text.slice(pos));
  return frag;
}

/* ---------- pestañas ---------- */
function tabDefs() {
  const r = S.report;
  const defs = CAT_ORDER.map((c) => {
    const items = filtered(c);
    const n = c === "version" || c === "endpoint" ? new Set(items.map((f) => f.value)).size : items.length;
    const hot = (c === "secret" && items.some((f) => f.env === "live")) || (c === "logic" && items.some((f) => f.env === "test"));
    return { id: c, label: CATS[c].label, n, hot };
  });
  if (r.analysis) defs.push({ id: "ai", label: "Análisis IA", n: r.analysis.dry_run ? "estimación" : null });
  const ts = terms();
  const files = ts.length ? filesRows().filter((x) => matches(x.hay, ts)).length : r.js_files.length;
  defs.push({ id: "files", label: "Ficheros", n: files });
  if (r.errors.length || r.out_of_scope.length) defs.push({ id: "issues", label: "Errores y fuera de scope", n: r.errors.length + r.out_of_scope.length });
  return defs;
}

function renderTabs() {
  const tabs = $("#tabs");
  tabs.replaceChildren();
  const defs = tabDefs();
  if (!defs.some((d) => d.id === S.tab)) S.tab = defs[0].id;
  for (const d of defs) {
    tabs.append(h("button", {
      type: "button", role: "tab", "aria-selected": String(d.id === S.tab), class: d.id === S.tab ? "on" : "",
      onclick: () => { S.tab = d.id; renderTabs(); renderPanel(); },
    }, d.label, d.n != null ? h("span", { class: "c" + (d.hot ? " hot" : "") }, d.n) : null));
  }
  const showEnv = S.tab === "secret" || S.tab === "logic";
  $(".filters").style.visibility = showEnv ? "visible" : "hidden";
}

/* ---------- panel ---------- */
const PAGE = 200;
function renderPanel() {
  const p = $("#panel");
  p.replaceChildren();
  const t = S.tab;
  if (CATS[t]) {
    p.append(h("p", { class: "tab-intro" }, CATS[t].intro));
    if (t === "version" || t === "endpoint") p.append(renderGrouped(t));
    else p.append(renderFindings(t));
  } else if (t === "ai") p.append(renderAI());
  else if (t === "files") p.append(renderFiles());
  else if (t === "issues") p.append(renderIssues());
}

/* Con los secretos ocultos, se enmascaran TODOS los secretos del informe que
   aparezcan en el contexto (no solo el de la fila): un snippet puede contener
   varias claves. Los más largos primero para no romper solapamientos. */
function secretPairs() {
  if (!S.report._pairs) {
    const m = new Map();
    for (const f of S.report.findings) if (f.category === "secret" && f.value && f.value !== f.masked) m.set(f.value, f.masked);
    S.report._pairs = [...m].sort((a, b) => b[0].length - a[0].length);
  }
  return S.report._pairs;
}
function snippetText(f) {
  let s = f.snippet || "";
  if (S.reveal) return s;
  for (const [v, masked] of secretPairs()) if (s.includes(v)) s = s.split(v).join(masked);
  return s;
}

function envBadge(f) {
  if (f.category === "secret") {
    if (f.env === "live") return h("span", { class: "env env-live", title: "Producción" }, "live");
    if (f.env === "test") return h("span", { class: "env env-test", title: "Sandbox / pruebas" }, "test");
    return h("span", { class: "env env-none", title: "Entorno desconocido" }, "¿?");
  }
  if (f.category === "logic") {
    if (f.env === "test") return h("span", { class: "env env-testalert", title: "Entorno de pruebas expuesto en la web" }, "test");
    if (f.env === "live") return h("span", { class: "env env-none" }, "live");
  }
  if (f.category === "dom") return h("span", { class: "env env-none" }, f.kind === "dom_sink" ? "sink" : "fuente");
  return h("span", { class: "env env-none" }, "—");
}

function shortSrc(src) {
  try {
    const u = new URL(src);
    const file = u.pathname.split("/").filter(Boolean).pop() || u.host;
    return file + (u.hash ? u.hash : "");
  } catch { return src; }
}

function sortFindings(cat, items) {
  const envRank = (f) => (cat === "secret" ? { live: 0, "": 1, test: 2 }[f.env] ?? 1 : cat === "logic" ? (f.env === "test" ? 0 : 1) : 0);
  const kindRank = (f) => (cat === "logic" ? (LOGIC_ORDER.indexOf(f.kind) + 1 || 99) : cat === "dom" ? (f.kind === "dom_sink" ? 0 : 1) : 0);
  return items.slice().sort((a, b) => envRank(a) - envRank(b) || kindRank(a) - kindRank(b) || a.kind.localeCompare(b.kind) || a.source.localeCompare(b.source) || a.line - b.line);
}

function renderFindings(cat) {
  const items = sortFindings(cat, filtered(cat));
  const frag = document.createDocumentFragment();
  if (!items.length) return nothing(cat);
  const lim = S.limit[cat] || PAGE;
  const ts = terms();
  const list = h("div", { class: "rows" });
  for (const f of items.slice(0, lim)) {
    const shown = cat === "secret" && !S.reveal ? f.masked : f.value;
    const row = h("details", { class: "row" },
      h("summary", null,
        h("span", null, envBadge(f)),
        h("span", { class: "kind" }, hl(f.kind, ts)),
        h("code", { class: "val" }, hl(shown, ts)),
        h("span", { class: "src", title: f.source }, hl(shortSrc(f.source), ts), h("span", { class: "ln" }, ":" + f.line)),
        h("span", { class: "chev", "aria-hidden": "true" }, "›")),
    );
    row.addEventListener("toggle", () => {
      if (row.open && !row.querySelector(".detail")) row.append(findingDetail(f, shown, ts));
    }, { once: false });
    list.append(row);
  }
  frag.append(list);
  if (items.length > lim) frag.append(h("button", { type: "button", class: "more", onclick: () => { S.limit[cat] = lim + PAGE * 2; renderPanel(); } }, `Mostrar más (${items.length - lim} restantes)`));
  return frag;
}

function findingDetail(f, shown, ts) {
  const snip = snippetText(f);
  const pre = h("pre", { class: "snippet" });
  if (shown && snip.includes(shown)) {
    const [a, ...rest] = snip.split(shown);
    pre.append(hl(a, ts), h("span", { class: "hit" }, hl(shown, ts)), hl(rest.join(shown), ts));
  } else pre.append(hl(snip, ts));
  return h("div", { class: "detail" },
    h("dl", null,
      h("dt", null, "tipo"), h("dd", null, f.kind),
      h("dt", null, "entorno"), h("dd", null, f.env || "desconocido"),
      h("dt", null, "fichero"), h("dd", null, f.source),
      h("dt", null, "línea"), h("dd", null, f.line)),
    pre,
    h("div", { class: "acts" },
      h("button", { type: "button", class: "btn", onclick: () => copy(f.value, f.category === "secret" ? "Valor completo copiado" : "Copiado") }, f.category === "secret" ? "Copiar valor completo" : "Copiar valor"),
      h("button", { type: "button", class: "btn", onclick: () => copy(f.source) }, "Copiar URL")));
}

function renderGrouped(cat) {
  const items = filtered(cat);
  if (!items.length) return nothing(cat);
  const groups = new Map();
  for (const f of items) {
    if (!groups.has(f.value)) groups.set(f.value, { value: f.value, kind: f.kind, srcs: new Map() });
    const g = groups.get(f.value);
    g.srcs.set(f.source, (g.srcs.get(f.source) || 0) + 1);
  }
  const ts = terms();
  const frag = document.createDocumentFragment();
  const all = [...groups.values()];
  frag.append(h("div", { class: "tab-tools" },
    h("span", null, `${all.length} valores únicos en ${new Set(items.map((f) => f.source)).size} ficheros`),
    h("button", { type: "button", class: "btn", onclick: () => copy(all.map((g) => g.value).sort().join("\n"), `${all.length} líneas copiadas`) }, "Copiar lista")));

  let sections;
  if (cat === "endpoint") {
    const sorted = (arr) => arr.sort((a, b) => (HOT_EP.test(b.value) - HOT_EP.test(a.value)) || a.value.localeCompare(b.value));
    sections = [
      ["Rutas", sorted(all.filter((g) => g.kind !== "endpoint_url"))],
      ["URLs absolutas", sorted(all.filter((g) => g.kind === "endpoint_url"))],
    ].filter(([, a]) => a.length);
  } else {
    sections = [[null, all.sort((a, b) => a.value.localeCompare(b.value))]];
  }
  const lim = S.limit[cat] || PAGE;
  let shown = 0;
  const wrap = h("div", { class: "glist" });
  for (const [title, arr] of sections) {
    if (shown >= lim) break;
    if (title) wrap.append(h("div", { class: "seg-head" }, `${title} · ${arr.length}`));
    for (const g of arr) {
      if (shown++ >= lim) break;
      const hot = cat === "endpoint" && HOT_EP.exec(g.value);
      const total = [...g.srcs.values()].reduce((a, b) => a + b, 0);
      wrap.append(h("details", { class: "grow" },
        h("summary", null,
          h("code", { class: "val" }, hot ? h("b", null, hl(g.value, ts)) : hl(g.value, ts)),
          h("span", { class: "meta" }, hot ? h("span", { class: "env env-testalert", style: null }, hot[1].toLowerCase()) : null, " ", `${total}× · ${g.srcs.size} fich.`),
          h("span", { class: "chev", "aria-hidden": "true" }, "›")),
        h("ul", null, [...g.srcs].map(([s, n]) => h("li", null, hl(s, ts), n > 1 ? h("span", { class: "count" }, `  ×${n}`) : null)))));
    }
  }
  frag.append(wrap);
  if (all.length > lim) frag.append(h("button", { type: "button", class: "more", onclick: () => { S.limit[cat] = lim + PAGE * 2; renderPanel(); } }, `Mostrar más (${all.length - lim} restantes)`));
  return frag;
}

function nothing(cat) {
  const any = S.report.findings.some((f) => f.category === cat);
  return h("p", { class: "nothing" }, any ? "Ningún resultado coincide con la búsqueda o el filtro." : `El pre-filtro no detectó ${CATS[cat].short}.`);
}

/* ---------- Análisis IA: markdown mínimo y seguro ---------- */
function esc(s) { return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function inline(s) {
  // s ya está escapado: solo añadimos etiquetas nuestras.
  return s
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[\s(])\*([^*\s][^*]*)\*(?=[\s).,;:]|$)/g, "$1<em>$2</em>")
    .replace(/(^|[\s(])_([^_\s][^_]*)_(?=[\s).,;:]|$)/g, "$1<em>$2</em>");
}
function markdown(src) {
  const lines = String(src || "").replace(/\r\n?/g, "\n").split("\n");
  const out = [];
  let i = 0;
  const para = [];
  const flush = () => { if (para.length) { out.push("<p>" + inline(esc(para.join(" "))) + "</p>"); para.length = 0; } };
  while (i < lines.length) {
    const l = lines[i];
    if (/^```/.test(l)) {
      flush();
      const buf = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) buf.push(lines[i++]);
      i++;
      out.push("<pre><code>" + esc(buf.join("\n")) + "</code></pre>");
      continue;
    }
    let m;
    if ((m = /^(#{1,4})\s+(.*)$/.exec(l))) { flush(); out.push(`<h${m[1].length}>${inline(esc(m[2]))}</h${m[1].length}>`); i++; continue; }
    if (/^\s*([-*_])\s*\1\s*\1[\s\1]*$/.test(l)) { flush(); out.push("<hr>"); i++; continue; }
    if (/^\s*\|.*\|\s*$/.test(l) && i + 1 < lines.length && /^\s*\|?\s*:?-{2,}/.test(lines[i + 1])) {
      flush();
      const cells = (r) => r.trim().replace(/^\||\|$/g, "").split("|").map((c) => inline(esc(c.trim())));
      let t = "<table><thead><tr>" + cells(l).map((c) => `<th>${c}</th>`).join("") + "</tr></thead><tbody>";
      i += 2;
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) t += "<tr>" + cells(lines[i++]).map((c) => `<td>${c}</td>`).join("") + "</tr>";
      out.push(t + "</tbody></table>");
      continue;
    }
    if (/^\s*([-*+]|\d+[.)])\s+/.test(l)) {
      flush();
      const ordered = /^\s*\d/.test(l);
      const items = [];
      while (i < lines.length && /^\s*([-*+]|\d+[.)])\s+/.test(lines[i])) {
        let item = lines[i].replace(/^\s*([-*+]|\d+[.)])\s+/, "");
        i++;
        while (i < lines.length && /^\s{2,}\S/.test(lines[i]) && !/^\s*([-*+]|\d+[.)])\s+/.test(lines[i])) item += " " + lines[i++].trim();
        items.push("<li>" + inline(esc(item)) + "</li>");
      }
      out.push(`<${ordered ? "ol" : "ul"}>${items.join("")}</${ordered ? "ol" : "ul"}>`);
      continue;
    }
    if (/^>\s?/.test(l)) { flush(); out.push("<blockquote>" + inline(esc(l.replace(/^>\s?/, ""))) + "</blockquote>"); i++; continue; }
    if (!l.trim()) { flush(); i++; continue; }
    para.push(l.trim());
    i++;
  }
  flush();
  return out.join("\n");
}

function renderAI() {
  const a = S.report.analysis;
  const frag = document.createDocumentFragment();
  frag.append(h("div", { class: "ai-meta" },
    h("span", null, "modelo ", h("b", null, a.model)),
    h("span", null, "entrada ", h("b", null, (a.input_tokens || 0).toLocaleString("es-ES")), " tok"),
    h("span", null, "salida ", h("b", null, (a.output_tokens || 0).toLocaleString("es-ES")), " tok"),
    h("span", null, a.dry_run ? "coste máx. estimado " : "coste ", h("b", null, "$" + Number(a.cost_usd || 0).toFixed(4))),
    a.omitted_findings ? h("span", null, h("b", null, a.omitted_findings), " hallazgos omitidos por presupuesto") : null));
  const prose = h("div", { class: "prose" });
  prose.innerHTML = markdown(a.text); // seguro: markdown() escapa todo el texto antes de añadir etiquetas
  frag.append(prose);
  return frag;
}

/* ---------- Ficheros / errores ---------- */
function filesRows() {
  return S.report.js_files.map((j) => {
    const n = S.report.findings.filter((f) => f.source === j.url);
    return { ...j, n: n.length, secrets: n.filter((f) => f.category === "secret").length, hay: j.url };
  });
}
function renderFiles() {
  const ts = terms();
  const rows = filesRows().filter((x) => !ts.length || matches(x.hay, ts)).sort((a, b) => b.secrets - a.secrets || b.n - a.n);
  if (!rows.length) return h("p", { class: "nothing" }, "Ningún fichero coincide.");
  return h("div", { class: "ledger-wrap" }, h("table", { class: "ledger" },
    h("thead", null, h("tr", null, h("th", null, "Fichero"), h("th", null, "Tipo"), h("th", { class: "num" }, "Tamaño"), h("th", { class: "num" }, "Hallazgos"), h("th", { class: "num" }, "Secretos"))),
    h("tbody", null, rows.map((j) => h("tr", { class: "click", title: "Buscar hallazgos de este fichero", onclick: () => { setQuery(j.url); } },
      h("td", { class: "url" }, hl(j.url, ts)),
      h("td", { class: "dim" }, j.inline ? "inline" : "externo"),
      h("td", { class: "num dim" }, fmtSize(j.chars)),
      h("td", { class: "num" }, j.n),
      h("td", { class: "num" + (j.secrets ? " hot" : " dim") }, j.secrets))))));
}
function fmtSize(c) { return c > 1048576 ? (c / 1048576).toFixed(1) + " M" : c > 1024 ? Math.round(c / 1024) + " K" : c + " B"; }
function renderIssues() {
  const r = S.report, ts = terms();
  const frag = document.createDocumentFragment();
  const block = (title, arr, intro) => {
    if (!arr.length) return;
    frag.append(h("div", { class: "seg-head" }, `${title} · ${arr.length}`));
    if (intro) frag.append(h("p", { class: "tab-intro" }, intro));
    frag.append(h("ul", { class: "plain" }, arr.filter((x) => !ts.length || matches(x, ts)).map((x) => h("li", null, h("code", null, hl(x, ts))))));
  };
  block("Errores", r.errors);
  block("Fuera de scope (no descargados)", r.out_of_scope, "Si alguno de estos hosts está autorizado, añádelo en «Hosts adicionales» o usa «Subdominios».");
  return frag;
}

/* ---------- controles del informe ---------- */
let qTimer;
function setQuery(v) { $("#q").value = v; S.q = v; S.limit = {}; renderTabs(); renderPanel(); if (S.tab === "files") { S.tab = CAT_ORDER.find((c) => filtered(c).length) || "files"; renderTabs(); renderPanel(); } }
$("#q").addEventListener("input", (e) => {
  clearTimeout(qTimer);
  qTimer = setTimeout(() => { S.q = e.target.value; S.limit = {}; renderTabs(); renderPanel(); }, 120);
});
$$(".filters button").forEach((b) => b.addEventListener("click", () => {
  S.env = b.dataset.env;
  $$(".filters button").forEach((x) => x.classList.toggle("on", x === b));
  renderTabs(); renderPanel();
}));
$("#reveal").addEventListener("change", (e) => { S.reveal = e.target.checked; renderTabs(); renderPanel(); });
document.addEventListener("keydown", (e) => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
  if (e.key === "/" && !typing) {
    if (!$("#view-report").hidden) { e.preventDefault(); $("#q").focus(); $("#q").select(); }
    else if (!$("#view-history").hidden) { e.preventDefault(); $("#hq").focus(); }
  } else if (e.key === "Escape" && document.activeElement === $("#q")) {
    setQuery(""); $("#q").blur();
  }
});

/* ======================================================================
   Archivo
   ====================================================================== */
async function loadHistory(silent) {
  try { S.history = await api("/api/reports"); }
  catch (e) { if (!silent) toast("No se pudo leer el archivo"); return; }
  $("#hist-count").textContent = S.history.length || "";
  renderHistory();
}
function renderHistory() {
  const box = $("#history");
  const q = $("#hq").value.trim().toLowerCase();
  const rows = S.history.filter((r) => !q || r.target.toLowerCase().includes(q) || r.id.toLowerCase().includes(q));
  if (!S.history.length) { box.replaceChildren(h("p", { class: "nothing" }, "Todavía no hay informes en output/.")); return; }
  if (!rows.length) { box.replaceChildren(h("p", { class: "nothing" }, "Ningún informe coincide.")); return; }
  const c = (r, k) => r.counts[k] || 0;
  box.replaceChildren(h("div", { class: "ledger-wrap" }, h("table", { class: "ledger" },
    h("thead", null, h("tr", null,
      h("th", null, "Fecha"), h("th", null, "Objetivo"), h("th", { class: "num" }, "JS"),
      h("th", { class: "num" }, "Secr."), h("th", { class: "num" }, "Live"), h("th", { class: "num" }, "Lóg."),
      h("th", { class: "num" }, "DOM"), h("th", { class: "num" }, "Endp."), h("th", null, "IA"))),
    h("tbody", null, rows.map((r) => h("tr", { class: "click" + (r.id === S.runId ? " cur" : ""), tabindex: "0", onclick: () => openReport(r.id), onkeydown: (e) => { if (e.key === "Enter") openReport(r.id); } },
      h("td", { class: "dim" }, fmtDate(r.generated_at)),
      h("td", { class: "url" }, hl(r.target, q ? [q] : [])),
      h("td", { class: "num" }, r.js_files),
      h("td", { class: "num" }, c(r, "secret")),
      h("td", { class: "num" + (r.live ? " hot" : " dim") }, r.live),
      h("td", { class: "num" }, c(r, "logic")),
      h("td", { class: "num" }, c(r, "dom")),
      h("td", { class: "num" }, c(r, "endpoint")),
      h("td", { class: "dim" }, r.ai ? "sí" : "—"))))))
  );
}
$("#hq").addEventListener("input", renderHistory);

/* ======================================================================
   Estado del entorno + arranque
   ====================================================================== */
function renderStatus() {
  const m = S.meta;
  const ul = $("#status");
  const theme = store.get("theme", "auto");
  ul.replaceChildren(
    h("li", { class: m.api_key ? "ok" : "bad", title: m.api_key ? "ANTHROPIC_API_KEY configurada" : "Sin ANTHROPIC_API_KEY: solo modo regex" }, h("i"), m.api_key ? "API key" : "sin API key"),
    h("li", { class: m.browser ? "ok" : "", title: m.browser_reason || "Playwright disponible" }, h("i"), m.browser ? "navegador" : "sin navegador"),
    h("li", null, h("i"), m.docker ? "docker" : "local"),
    h("li", null, h("button", { type: "button", onclick: cycleTheme, title: "Cambiar tema" }, "tema: " + { auto: "auto", light: "claro", dark: "oscuro" }[theme])),
  );
}
function applyTheme() {
  const t = store.get("theme", "auto");
  if (t === "auto") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", t);
}
function cycleTheme() {
  const order = ["auto", "light", "dark"];
  store.set("theme", order[(order.indexOf(store.get("theme", "auto")) + 1) % 3]);
  applyTheme(); renderStatus();
}

function renderModels() {
  const box = $("#models");
  box.replaceChildren();
  for (const m of S.meta.models) {
    const usd = (n) => "$" + (n < 1 ? n.toFixed(2) : String(n));
    const price = m.price ? `${usd(m.price[0])} / ${usd(m.price[1])} por Mtok` : m.id;
    box.append(h("label", null,
      h("input", { type: "radio", name: "model", value: m.key, checked: m.key === S.meta.default_model }),
      h("span", null, h("b", null, m.key[0].toUpperCase() + m.key.slice(1)), h("small", null, price))));
  }
}

async function init() {
  applyTheme();
  try { S.meta = await api("/api/meta"); }
  catch (e) {
    $("#form-error").textContent = "No se pudo contactar con el servidor: " + e.message;
    $("#form-error").hidden = false;
    return;
  }
  renderStatus();
  renderModels();
  if (!S.meta.browser) {
    const r = form.querySelector('input[name="capture"][value="browser"]');
    r.disabled = true;
    $("#browser-note").textContent = S.meta.browser_reason;
    $("#browser-note").hidden = false;
  }
  restoreForm();
  syncForm();
  loadHistory(true);

  if (S.meta.job) { startJob(S.meta.job, "", false); return; }
  const m = /^#r=(.+)$/.exec(location.hash);
  if (m) await openReport(decodeURIComponent(m[1]));
  else show("empty");
}
init();

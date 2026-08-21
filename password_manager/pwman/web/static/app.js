/* pwman web interface.
 *
 * Two rules mirror the CLI: a password is only fetched from the server when the
 * user asks for it (never as part of the list), and nothing is written into DOM
 * markup as HTML -- every value goes through textContent, so a password or note
 * can never be interpreted as markup.
 */
"use strict";

(() => {
  const CLIPBOARD_SECONDS = 20;
  const TOTP_AUTO_REFRESHES = 5;

  const state = {
    csrf: null,
    entries: [],
    tags: [],
    selectedId: null,
    query: "",
    tag: "",
    lastActivity: 0,
    idleTimeout: 300,
    timers: { totp: null, clipboard: null, idle: null, poll: null },
  };

  const byId = (id) => document.getElementById(id);

  /** Build an element; children are appended as text or nodes, never as HTML. */
  function h(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (value === null || value === undefined) continue;
      // ARIA states are literal "true"/"false" strings, not boolean attributes:
      // setAttribute("aria-selected", "") would never match [aria-selected="true"].
      if (key.startsWith("aria-")) { node.setAttribute(key, String(value)); continue; }
      if (value === false) continue;
      if (key === "class") node.className = value;
      else if (key === "dataset") Object.assign(node.dataset, value);
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else if (key === "value") node.value = value;
      else node.setAttribute(key, value === true ? "" : String(value));
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
    return node;
  }

  function toast(message, kind) {
    const node = h("div", { class: `toast ${kind ? "toast--" + kind : ""}` }, message);
    byId("toasts").append(node);
    setTimeout(() => node.remove(), 4200);
  }

  // ---------------------------------------------------------------- API ----

  async function api(method, path, body) {
    const headers = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (state.csrf) headers["X-CSRF-Token"] = state.csrf;
    const response = await fetch(path, {
      method,
      headers,
      credentials: "same-origin",
      cache: "no-store",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let data = {};
    try { data = await response.json(); } catch (error) { /* empty body */ }
    if (response.status === 401 && state.csrf) {
      showLock(lockMessage(data.reason));
      throw new Error(data.error || "locked");
    }
    if (!response.ok) throw new Error(data.error || `request failed (${response.status})`);
    state.lastActivity = Date.now();
    return data;
  }

  // ------------------------------------------------------------- locking ---

  function lockMessage(reason) {
    if (reason === "idle") return "Locked after being idle.";
    if (reason === "replaced") return "Another window took over this session.";
    return "The vault was locked.";
  }

  function showLock(message) {
    state.csrf = null;
    state.entries = [];
    state.selectedId = null;
    stopTimers();
    byId("main").hidden = true;
    byId("lock-screen").hidden = false;
    byId("lock-error").textContent = message || "";
    const input = byId("master-password");
    input.value = "";
    input.focus();
  }

  function stopTimers() {
    for (const key of Object.keys(state.timers)) {
      if (state.timers[key]) clearInterval(state.timers[key]);
      state.timers[key] = null;
    }
  }

  async function unlock(event) {
    event.preventDefault();
    const button = byId("unlock-button");
    const input = byId("master-password");
    button.disabled = true;
    byId("lock-error").textContent = "";
    try {
      const result = await api("POST", "/api/unlock", { password: input.value });
      state.csrf = result.csrf;
      state.idleTimeout = result.idle_timeout;
      state.lastActivity = Date.now();
      input.value = "";
      (result.warnings || []).forEach((warning) => toast(warning, "error"));
      byId("lock-screen").hidden = true;
      byId("main").hidden = false;
      await refreshEntries();
      startTimers();
    } catch (error) {
      byId("lock-error").textContent = error.message;
      input.select();
    } finally {
      button.disabled = false;
    }
  }

  function startTimers() {
    state.timers.idle = setInterval(updateIdleIndicator, 1000);
    // Polls the lock state without counting as activity, so a forgotten tab
    // still locks on schedule.
    state.timers.poll = setInterval(async () => {
      try {
        const status = await fetch("/api/state", { credentials: "same-origin", cache: "no-store" });
        const data = await status.json();
        if (data.locked) showLock(lockMessage(data.reason));
        else if (!data.authenticated) showLock(lockMessage("replaced"));
      } catch (error) { /* server gone; the next action will report it */ }
    }, 5000);
  }

  function updateIdleIndicator() {
    if (!state.idleTimeout) return;
    const remaining = Math.max(0, state.idleTimeout - Math.round((Date.now() - state.lastActivity) / 1000));
    const minutes = Math.floor(remaining / 60);
    const seconds = String(remaining % 60).padStart(2, "0");
    byId("idle-indicator").textContent = `locks in ${minutes}:${seconds}`;
  }

  // ------------------------------------------------------------ clipboard --

  async function copyValue(value, label) {
    try {
      await navigator.clipboard.writeText(value);
    } catch (error) {
      toast("the browser refused clipboard access - use Reveal instead", "error");
      return;
    }
    toast(`${label} copied - clearing in ${CLIPBOARD_SECONDS}s`, "ok");
    if (state.timers.clipboard) clearTimeout(state.timers.clipboard);
    state.timers.clipboard = setTimeout(async () => {
      try {
        const current = await navigator.clipboard.readText();
        if (current && current !== value) return; // the user copied something else
      } catch (error) { /* no read permission: clear anyway, better than leaving it */ }
      try {
        await navigator.clipboard.writeText("");
        toast("clipboard cleared");
      } catch (error) { /* needs focus; nothing else we can do */ }
    }, CLIPBOARD_SECONDS * 1000);
  }

  // ----------------------------------------------------------------- list --

  async function refreshEntries() {
    const data = await api("GET", "/api/entries");
    state.entries = data.entries;
    state.tags = data.tags;
    renderTags();
    renderList();
    if (state.selectedId && state.entries.some((entry) => entry.id === state.selectedId)) {
      await showEntry(state.selectedId);
    }
  }

  function visibleEntries() {
    const query = state.query.trim().toLowerCase();
    return state.entries.filter((entry) => {
      if (state.tag && !entry.tags.some((tag) => tag.toLowerCase() === state.tag.toLowerCase())) return false;
      if (!query) return true;
      return [entry.name, entry.username, entry.url, entry.tags.join(" ")]
        .join(" ").toLowerCase().includes(query);
    });
  }

  function renderTags() {
    const container = clear(byId("tag-filter"));
    state.tags.forEach((tag) => {
      container.append(h("button", {
        type: "button",
        class: "tag",
        "aria-pressed": state.tag === tag,
        onclick: () => { state.tag = state.tag === tag ? "" : tag; renderTags(); renderList(); },
      }, tag));
    });
  }

  function renderList() {
    const list = clear(byId("entry-list"));
    const entries = visibleEntries();
    entries.forEach((entry) => {
      list.append(h("li", {
        class: "entry-list__item",
        role: "option",
        "aria-selected": entry.id === state.selectedId,
        onclick: () => showEntry(entry.id),
      },
        h("span", { class: "entry-list__name" }, entry.name),
        h("span", { class: "entry-list__sub" }, entry.username || "—"),
        h("span", {
          class: `entry-list__badge strength--${entry.label.replace(" ", "-")}`,
          title: `${entry.bits} bits · ${entry.label}`,
        }, entry.has_totp ? "⏱ " : "", "●")));
    });
    byId("entry-count").textContent =
      `${entries.length} of ${state.entries.length} entr${state.entries.length === 1 ? "y" : "ies"}`;
  }

  // --------------------------------------------------------------- detail --

  async function showEntry(id) {
    state.selectedId = id;
    renderList();
    const entry = await api("GET", `/api/entries/${encodeURIComponent(id)}`);
    const detail = clear(byId("detail"));
    if (state.timers.totp) { clearInterval(state.timers.totp); state.timers.totp = null; }

    detail.append(
      h("h2", { class: "detail__title" }, entry.name),
      h("p", { class: "detail__meta" },
        `updated ${entry.updated_at} · password set ${entry.password_changed_at}` +
        (entry.history.length ? ` · ${entry.history.length} previous password(s)` : "")));

    if (entry.username) detail.append(valueRow("Username", entry.username, [
      copyButton(entry.username, "Username")]));
    if (entry.url) {
      const link = h("a", { href: entry.url, target: "_blank", rel: "noopener noreferrer" }, entry.url);
      detail.append(valueRow("URL", link, [copyButton(entry.url, "URL")]));
    }

    const secretValue = h("span", { class: "value-row__value" }, entry.has_password ? "••••••••••••" : "—");
    const buttons = [];
    if (entry.has_password) {
      buttons.push(h("button", {
        type: "button", class: "button button--small",
        onclick: async (event) => {
          const button = event.currentTarget;
          const data = await api("POST", `/api/entries/${encodeURIComponent(id)}/reveal`);
          const shown = secretValue.textContent === data.password;
          secretValue.textContent = shown ? "••••••••••••" : data.password;
          button.textContent = shown ? "Reveal" : "Hide";
        },
      }, "Reveal"));
      buttons.push(h("button", {
        type: "button", class: "button button--small button--primary",
        onclick: async () => {
          const data = await api("POST", `/api/entries/${encodeURIComponent(id)}/reveal`);
          await copyValue(data.password, "Password");
        },
      }, "Copy"));
    }
    detail.append(valueRow("Password", secretValue, buttons));
    detail.append(strengthRow(entry.bits, entry.label));

    if (entry.has_totp) detail.append(totpRow(id));
    if (entry.tags.length) {
      detail.append(valueRow("Tags", entry.tags.join(", "), []));
    }
    if (entry.notes) {
      const notes = h("span", { class: "value-row__value value-row__value--notes" }, entry.notes);
      detail.append(valueRow("Notes", notes, [copyButton(entry.notes, "Notes")]));
    }

    detail.append(h("div", { class: "detail__actions" },
      h("button", { type: "button", class: "button", onclick: () => renderForm(entry) }, "Edit"),
      h("button", {
        type: "button", class: "button button--danger",
        onclick: async () => {
          if (!confirm(`Delete "${entry.name}"? This cannot be undone.`)) return;
          await api("DELETE", `/api/entries/${encodeURIComponent(id)}`);
          state.selectedId = null;
          clear(byId("detail")).append(h("p", { class: "detail__empty" }, "Entry deleted."));
          toast("entry deleted", "ok");
          await refreshEntries();
        },
      }, "Delete")));
  }

  function valueRow(label, value, buttons) {
    return h("div", { class: "value-row" },
      h("span", { class: "value-row__label" }, label),
      value instanceof Node ? value : h("span", { class: "value-row__value" }, value),
      h("span", { class: "value-row__buttons" }, buttons || []));
  }

  function copyButton(value, label) {
    return h("button", {
      type: "button", class: "button button--small",
      onclick: () => copyValue(value, label),
    }, "Copy");
  }

  function strengthRow(bits, label) {
    const meter = h("div", { class: `meter strength--${(label || "").replace(" ", "-")}` });
    meter.style.setProperty("--meter-fill", `${Math.min(100, Math.round((bits / 128) * 100))}%`);
    return valueRow("Strength",
      h("span", {}, meter, h("span", { class: "meter-label" }, `${bits} bits · ${label}`)), []);
  }

  function totpRow(id) {
    const code = h("span", { class: "value-row__value" }, "······");
    const note = h("span", { class: "meter-label" }, "");
    let refreshes = 0;

    const load = async () => {
      const data = await api("POST", `/api/entries/${encodeURIComponent(id)}/totp`);
      code.textContent = data.code.replace(/(\d{3})(?=\d)/, "$1 ");
      note.textContent = `valid for ${data.remaining}s`;
      if (state.timers.totp) clearTimeout(state.timers.totp);
      if (refreshes++ < TOTP_AUTO_REFRESHES) {
        state.timers.totp = setTimeout(load, (data.remaining + 1) * 1000);
      } else {
        note.textContent = "expired - refresh to get a new code";
      }
    };
    load();

    return valueRow("2FA code", h("span", {}, code, note), [
      h("button", { type: "button", class: "button button--small", onclick: () => { refreshes = 0; load(); } }, "Refresh"),
      h("button", {
        type: "button", class: "button button--small",
        onclick: async () => {
          const data = await api("POST", `/api/entries/${encodeURIComponent(id)}/totp`);
          await copyValue(data.code, "2FA code");
        },
      }, "Copy"),
    ]);
  }

  // ----------------------------------------------------------------- form --

  function renderForm(entry) {
    const isNew = !entry;
    if (isNew && state.selectedId) { state.selectedId = null; renderList(); }
    const detail = clear(byId("detail"));
    const fields = {
      name: input("Name", entry ? entry.name : "", { required: true }),
      username: input("Username", entry ? entry.username : ""),
      url: input("URL", entry ? entry.url : ""),
      tags: input("Tags (comma separated)", entry ? entry.tags.join(", ") : ""),
      totp: input("TOTP secret or otpauth:// URI", "", { placeholder: entry && entry.has_totp ? "(unchanged)" : "" }),
    };
    const password = input("Password", "", { type: "password", autocomplete: "new-password",
      placeholder: isNew ? "" : "(unchanged)" });
    const meter = h("div", { class: "meter" });
    const meterLabel = h("div", { class: "meter-label" }, isNew ? "" : "leave empty to keep the current password");

    let estimateTimer = null;
    password.querySelector("input").addEventListener("input", (event) => {
      const value = event.target.value;
      clearTimeout(estimateTimer);
      if (!value) { meter.style.setProperty("--meter-fill", "0%"); meterLabel.textContent = ""; return; }
      estimateTimer = setTimeout(async () => {
        const result = await api("POST", "/api/estimate", { password: value });
        meter.className = `meter strength--${result.label.replace(" ", "-")}`;
        meter.style.setProperty("--meter-fill", `${Math.min(100, Math.round((result.bits / 128) * 100))}%`);
        meterLabel.textContent = `${result.bits} bits · ${result.label}` +
          (result.warnings.length ? ` · ${result.warnings[0]}` : "");
      }, 250);
    });

    const length = h("input", { type: "range", min: "8", max: "64", value: "20" });
    const lengthLabel = h("span", { class: "meter-label" }, "20 characters");
    length.addEventListener("input", () => { lengthLabel.textContent = `${length.value} characters`; });
    const mode = h("select", {},
      h("option", { value: "password" }, "Random password"),
      h("option", { value: "passphrase" }, "Passphrase"));

    const generate = h("button", {
      type: "button", class: "button",
      onclick: async () => {
        const body = mode.value === "passphrase"
          ? { mode: "passphrase", words: Math.max(3, Math.round(Number(length.value) / 4)) }
          : { mode: "password", length: Number(length.value) };
        const result = await api("POST", "/api/generate", body);
        const field = password.querySelector("input");
        field.value = result.value;
        field.type = "text";
        field.dispatchEvent(new Event("input"));
        toast(`generated · ${result.bits} bits of entropy`, "ok");
      },
    }, "Generate");

    const form = h("form", { class: "entry-form", onsubmit: (event) => submit(event) },
      h("h2", { class: "detail__title" }, isNew ? "New entry" : `Edit ${entry.name}`),
      h("div", { class: "row" }, fields.name),
      h("div", { class: "row" }, fields.username),
      h("div", { class: "row" }, fields.url),
      h("div", { class: "row" }, password, meter, meterLabel),
      h("div", { class: "row row--pair" },
        h("label", { class: "field" }, h("span", { class: "field__label" }, "Generator"), mode),
        h("span", { class: "generator" }, length, lengthLabel, generate)),
      h("div", { class: "row" }, fields.tags),
      h("div", { class: "row" }, fields.totp),
      h("label", { class: "field" }, h("span", { class: "field__label" }, "Notes"),
        h("textarea", { id: "entry-notes" }, entry ? entry.notes : "")),
      h("div", { class: "detail__actions" },
        h("button", { type: "submit", class: "button button--primary" }, isNew ? "Create" : "Save"),
        h("button", {
          type: "button", class: "button",
          onclick: () => (entry ? showEntry(entry.id) : clear(byId("detail"))
            .append(h("p", { class: "detail__empty" }, "Select an entry."))),
        }, "Cancel")));

    detail.append(form);
    fields.name.querySelector("input").focus();

    async function submit(event) {
      event.preventDefault();
      const body = {
        name: fields.name.querySelector("input").value.trim(),
        username: fields.username.querySelector("input").value,
        url: fields.url.querySelector("input").value,
        tags: fields.tags.querySelector("input").value,
        notes: byId("entry-notes").value,
      };
      const secret = password.querySelector("input").value;
      const totpValue = fields.totp.querySelector("input").value.trim();
      if (isNew || secret) body.password = secret;
      if (totpValue) body.totp_secret = totpValue;
      try {
        const saved = isNew
          ? await api("POST", "/api/entries", body)
          : await api("PUT", `/api/entries/${encodeURIComponent(entry.id)}`, body);
        toast(isNew ? "entry created" : "entry saved", "ok");
        state.selectedId = saved.id;
        await refreshEntries();
        await showEntry(saved.id);
      } catch (error) {
        toast(error.message, "error");
      }
    }
  }

  function input(label, value, attrs) {
    return h("label", { class: "field" },
      h("span", { class: "field__label" }, label),
      h("input", Object.assign({ type: "text", value: value || "", spellcheck: "false" }, attrs || {})));
  }

  // ---------------------------------------------------------------- audit --

  async function showAudit() {
    const data = await api("GET", "/api/audit");
    const detail = clear(byId("detail"));
    detail.append(h("h2", { class: "detail__title" }, "Audit"));
    if (!data.findings.length) {
      detail.append(h("p", { class: "detail__meta" }, `No issues found in ${data.entries} entries.`));
      return;
    }
    const summary = Object.entries(data.summary).map(([kind, count]) => `${count} ${kind}`).join(", ");
    detail.append(h("p", { class: "detail__meta" }, summary));
    const rows = data.findings.map((finding) => h("tr", {},
      h("td", { class: `severity--${finding.severity}` }, finding.severity),
      h("td", {}, h("a", { href: "#", onclick: (event) => {
        event.preventDefault();
        const match = state.entries.find((candidate) => candidate.name === finding.entry);
        if (match) showEntry(match.id);
      } }, finding.entry)),
      h("td", {}, finding.kind),
      h("td", {}, finding.detail)));
    detail.append(h("table", { class: "audit" },
      h("thead", {}, h("tr", {}, ["Severity", "Entry", "Kind", "Detail"].map((title) => h("th", {}, title)))),
      h("tbody", {}, rows)));
  }

  // ------------------------------------------------------------------ go ---

  function init() {
    byId("unlock-form").addEventListener("submit", unlock);
    byId("lock-button").addEventListener("click", async () => {
      try { await api("POST", "/api/lock"); } catch (error) { /* already locked */ }
      showLock("Locked.");
    });
    byId("new-button").addEventListener("click", () => renderForm(null));
    byId("audit-button").addEventListener("click", () => showAudit().catch((e) => toast(e.message, "error")));
    byId("search").addEventListener("input", (event) => { state.query = event.target.value; renderList(); });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && !byId("main").hidden) byId("search").focus();
    });

    fetch("/api/state", { credentials: "same-origin", cache: "no-store" })
      .then((response) => response.json())
      .then((data) => {
        state.idleTimeout = data.idle_timeout;
        byId("lock-path").textContent = data.vault;
        byId("vault-path").textContent = data.vault;
      })
      .catch(() => byId("lock-error").textContent = "cannot reach the pwman server");
  }

  document.addEventListener("DOMContentLoaded", init);
})();

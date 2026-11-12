"use strict";
const el = (id) => document.getElementById(id);
function xsrf() { const c = document.cookie.split("; ").find((s) => s.startsWith("_xsrf=")); return c ? decodeURIComponent(c.slice(6)) : ""; }
el("login").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.submitter; button.disabled = true; el("notice").textContent = ""; el("notice").classList.remove("error");
  try {
    const response = await fetch("/api/login", {method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json", "X-XSRFToken": xsrf()},
      body: JSON.stringify({username: el("username").value.trim(), password: el("password").value})});
    el("password").value = "";
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || "Sign-in failed");
    window.location.assign("/");
  } catch (error) { el("notice").textContent = error.message; el("notice").classList.add("error"); }
  finally { button.disabled = false; }
});

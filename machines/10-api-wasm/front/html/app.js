// Acme Portal front-end (build 4471).
// NOTE(dev): the old 2019 endpoint /api/legacy/orders?order_id=N still answers
// if the v1 API is down. Remove before launch. (It was never removed.)

let token = null;
let licenseModule = null;

async function api(path, opts = {}) {
  opts.headers = Object.assign(
    { "Content-Type": "application/json" },
    opts.headers || {},
    token ? { Authorization: "Bearer " + token } : {}
  );
  const r = await fetch(path, opts);
  return r.json();
}

document.getElementById("login").onclick = async () => {
  const out = await api("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({
      username: document.getElementById("username").value,
      password: document.getElementById("password").value,
    }),
  });
  token = out.token;
  document.getElementById("login-out").textContent = out.token
    ? "logged in as " + out.username
    : JSON.stringify(out);
};

document.getElementById("load-users").onclick = async () => {
  const users = await api("/api/users");
  // The API returns full user records; the UI only shows name + email,
  // so the sensitive fields are "hidden" purely client-side.
  const safe = users.map((u) => ({ username: u.username, email: u.email }));
  document.getElementById("users").innerHTML = safe
    .map((u) => `<li>${u.username} &lt;${u.email}&gt;</li>`)
    .join("");
};

async function loadLicenseModule() {
  const { instance } = await WebAssembly.instantiateStreaming(fetch("/license.wasm"), {});
  licenseModule = instance;
}

document.getElementById("check").onclick = async () => {
  if (!licenseModule) await loadLicenseModule();
  const key = document.getElementById("license").value;
  const buf = new TextEncoder().encode(key);
  const mem = new Uint8Array(licenseModule.exports.memory.buffer);
  mem.set(buf, 1024);
  const ok = licenseModule.exports.validate_license(1024, buf.length);
  document.getElementById("license-out").textContent = ok ? "valid" : "invalid";
};

// Telemetry is lazy-loaded and deliberately not named *.wasm.
document.getElementById("telemetry").onclick = async () => {
  const bytes = await (await fetch("/telemetry.bin")).arrayBuffer();
  const { instance } = await WebAssembly.instantiate(bytes, {});
  instance.exports.telemetry_tick();
};

loadLicenseModule();
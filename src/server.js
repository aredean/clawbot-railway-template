import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import express from "express";
import httpProxy from "http-proxy";
import * as tar from "tar";

// Migrate deprecated CLAWDBOT_* env vars → OPENCLAW_* so existing Railway deployments
// keep working. Users should update their Railway Variables to use the new names.
for (const suffix of ["PUBLIC_PORT", "STATE_DIR", "WORKSPACE_DIR", "GATEWAY_TOKEN", "CONFIG_PATH"]) {
  const oldKey = `CLAWDBOT_${suffix}`;
  const newKey = `OPENCLAW_${suffix}`;
  if (process.env[oldKey] && !process.env[newKey]) {
    process.env[newKey] = process.env[oldKey];
  }
  delete process.env[oldKey];
}

const PORT = Number.parseInt(process.env.PORT ?? process.env.OPENCLAW_PUBLIC_PORT ?? "3000", 10);

const STATE_DIR =
  process.env.OPENCLAW_STATE_DIR?.trim() ||
  path.join(os.homedir(), ".openclaw");

const WORKSPACE_DIR =
  process.env.OPENCLAW_WORKSPACE_DIR?.trim() ||
  path.join(STATE_DIR, "workspace");

const SETUP_PASSWORD = process.env.SETUP_PASSWORD?.trim();

function resolveGatewayToken() {
  const envTok = process.env.OPENCLAW_GATEWAY_TOKEN?.trim();
  if (envTok) return envTok;

  const tokenPath = path.join(STATE_DIR, "gateway.token");
  try {
    const existing = fs.readFileSync(tokenPath, "utf8").trim();
    if (existing) return existing;
  } catch {
    // ignore
  }

  const generated = crypto.randomBytes(32).toString("hex");
  try {
    fs.mkdirSync(STATE_DIR, { recursive: true });
    fs.writeFileSync(tokenPath, generated, { encoding: "utf8", mode: 0o600 });
  } catch {
    // best-effort
  }
  return generated;
}

const OPENCLAW_GATEWAY_TOKEN = resolveGatewayToken();
process.env.OPENCLAW_GATEWAY_TOKEN = OPENCLAW_GATEWAY_TOKEN;

const INTERNAL_GATEWAY_PORT = Number.parseInt(process.env.INTERNAL_GATEWAY_PORT ?? "18789", 10);
const INTERNAL_GATEWAY_HOST = process.env.INTERNAL_GATEWAY_HOST ?? "127.0.0.1";
const GATEWAY_TARGET = `http://${INTERNAL_GATEWAY_HOST}:${INTERNAL_GATEWAY_PORT}`;

const OPENCLAW_ENTRY = process.env.OPENCLAW_ENTRY?.trim() || "/openclaw/dist/entry.js";
const OPENCLAW_NODE = process.env.OPENCLAW_NODE?.trim() || "node";

function clawArgs(args) {
  return [OPENCLAW_ENTRY, ...args];
}

function resolveConfigCandidates() {
  const explicit = process.env.OPENCLAW_CONFIG_PATH?.trim();
  if (explicit) return [explicit];
  return [path.join(STATE_DIR, "openclaw.json")];
}

function configPath() {
  const candidates = resolveConfigCandidates();
  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate)) return candidate;
    } catch {
      // ignore
    }
  }
  return candidates[0] || path.join(STATE_DIR, "openclaw.json");
}

function isConfigured() {
  try {
    return resolveConfigCandidates().some((candidate) => fs.existsSync(candidate));
  } catch {
    return false;
  }
}

(function migrateLegacyConfigFile() {
  if (process.env.OPENCLAW_CONFIG_PATH?.trim()) return;
  const canonical = path.join(STATE_DIR, "openclaw.json");
  if (fs.existsSync(canonical)) return;
  for (const legacy of ["clawdbot.json", "moltbot.json"]) {
    const legacyPath = path.join(STATE_DIR, legacy);
    try {
      if (fs.existsSync(legacyPath)) {
        fs.renameSync(legacyPath, canonical);
        console.log(`[migration] Renamed ${legacy} → openclaw.json`);
        return;
      }
    } catch (err) {
      console.warn(`[migration] Failed to rename ${legacy}: ${err}`);
    }
  }
})();

let gatewayProc = null;
let gatewayStarting = null;
let lastGatewayError = null;
let lastGatewayExit = null;
let lastDoctorOutput = null;
let lastDoctorAt = null;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForGatewayReady(opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 20_000;
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const paths = ["/openclaw", "/"];
      for (const p of paths) {
        try {
          const res = await fetch(`${GATEWAY_TARGET}${p}`, { method: "GET" });
          if (res) return true;
        } catch { }
      }
    } catch { }
    await sleep(250);
  }
  return false;
}

async function startGateway() {
  if (gatewayProc) return;
  if (!isConfigured()) throw new Error("Gateway cannot start: not configured");

  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.mkdirSync(WORKSPACE_DIR, { recursive: true });

  const args = [
    "gateway",
    "run",
    "--bind",
    "loopback",
    "--port",
    String(INTERNAL_GATEWAY_PORT),
    "--auth",
    "token",
    "--token",
    OPENCLAW_GATEWAY_TOKEN,
  ];

  gatewayProc = childProcess.spawn(OPENCLAW_NODE, clawArgs(args), {
    stdio: "inherit",
    env: {
      ...process.env,
      OPENCLAW_STATE_DIR: STATE_DIR,
      OPENCLAW_WORKSPACE_DIR: WORKSPACE_DIR,
    },
  });

  gatewayProc.on("error", (err) => {
    const msg = `[gateway] spawn error: ${String(err)}`;
    console.error(msg);
    lastGatewayError = msg;
    gatewayProc = null;
  });

  gatewayProc.on("exit", (code, signal) => {
    const msg = `[gateway] exited code=${code} signal=${signal}`;
    console.error(msg);
    lastGatewayExit = { code, signal, at: new Date().toISOString() };
    gatewayProc = null;
  });
}

async function runDoctorBestEffort() {
  const now = Date.now();
  if (lastDoctorAt && now - lastDoctorAt < 5 * 60 * 1000) return;
  lastDoctorAt = now;
  try {
    const r = await runCmd(OPENCLAW_NODE, clawArgs(["doctor"]));
    const out = redactSecrets(r.output || "");
    lastDoctorOutput = out.length > 50_000 ? out.slice(0, 50_000) + "\n... (truncated)\n" : out;
  } catch (err) {
    lastDoctorOutput = `doctor failed: ${String(err)}`;
  }
}

async function ensureGatewayRunning() {
  if (!isConfigured()) return { ok: false, reason: "not configured" };
  if (gatewayProc) return { ok: true };
  if (!gatewayStarting) {
    gatewayStarting = (async () => {
      try {
        lastGatewayError = null;
        await startGateway();
        const ready = await waitForGatewayReady({ timeoutMs: 20_000 });
        if (!ready) throw new Error("Gateway did not become ready in time");
      } catch (err) {
        lastGatewayError = `[gateway] start failure: ${String(err)}`;
        await runDoctorBestEffort();
        throw err;
      }
    })().finally(() => {
      gatewayStarting = null;
    });
  }
  await gatewayStarting;
  return { ok: true };
}

async function restartGateway() {
  if (gatewayProc) {
    try { gatewayProc.kill("SIGTERM"); } catch { }
    await sleep(750);
    gatewayProc = null;
  }
  return ensureGatewayRunning();
}

function requireSetupAuth(req, res, next) {
  if (!SETUP_PASSWORD) {
    return res.status(500).type("text/plain").send("SETUP_PASSWORD is not set. Set it in Railway Variables before using /setup.");
  }
  const header = req.headers.authorization || "";
  const [scheme, encoded] = header.split(" ");
  if (scheme !== "Basic" || !encoded) {
    res.set("WWW-Authenticate", 'Basic realm="OpenClaw Setup"');
    return res.status(401).send("Auth required");
  }
  const decoded = Buffer.from(encoded, "base64").toString("utf8");
  const idx = decoded.indexOf(":");
  const password = idx >= 0 ? decoded.slice(idx + 1) : "";
  if (password !== SETUP_PASSWORD) {
    res.set("WWW-Authenticate", 'Basic realm="OpenClaw Setup"');
    return res.status(401).send("Invalid password");
  }
  return next();
}

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

app.get("/setup/healthz", (_req, res) => res.json({ ok: true }));

async function probeGateway() {
  const net = await import("node:net");
  return await new Promise((resolve) => {
    const sock = net.createConnection({
      host: INTERNAL_GATEWAY_HOST,
      port: INTERNAL_GATEWAY_PORT,
      timeout: 750,
    });
    const done = (ok) => {
      try { sock.destroy(); } catch { }
      resolve(ok);
    };
    sock.on("connect", () => done(true));
    sock.on("timeout", () => done(false));
    sock.on("error", () => done(false));
  });
}

app.get("/healthz", async (_req, res) => {
  let gatewayReachable = false;
  if (isConfigured()) {
    try { gatewayReachable = await probeGateway(); } catch { }
  }
  res.json({
    ok: true,
    wrapper: { configured: isConfigured(), stateDir: STATE_DIR, workspaceDir: WORKSPACE_DIR },
    gateway: { target: GATEWAY_TARGET, reachable: gatewayReachable, lastError: lastGatewayError, lastExit: lastGatewayExit, lastDoctorAt },
  });
});

app.get("/setup/app.js", requireSetupAuth, (_req, res) => {
  res.type("application/javascript");
  res.send(fs.readFileSync(path.join(process.cwd(), "src", "setup-app.js"), "utf8"));
});

app.get("/setup", requireSetupAuth, (_req, res) => {
  res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OpenClaw Setup</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; margin: 2rem; max-width: 900px; }
    .card { border: 1px solid #ddd; border-radius: 12px; padding: 1.25rem; margin: 1rem 0; }
    label { display:block; margin-top: 0.75rem; font-weight: 600; }
    input, select { width: 100%; padding: 0.6rem; margin-top: 0.25rem; }
    button { padding: 0.8rem 1.2rem; border-radius: 10px; border: 0; background: #111; color: #fff; font-weight: 700; cursor: pointer; }
    code { background: #f6f6f6; padding: 0.1rem 0.3rem; border-radius: 6px; }
    .muted { color: #555; }
    textarea { width:100%; height: 260px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
  </style>
</head>
<body>
  <h1>OpenClaw Setup</h1>
  <div class="card">
    <h2>Status</h2>
    <div id="status">Loading...</div>
    <div id="statusDetails" class="muted" style="margin-top:0.5rem"></div>
    <div style="margin-top: 0.75rem">
      <a href="/openclaw" target="_blank">Open UI</a> | <a href="/setup/export" target="_blank">Download backup</a>
    </div>
    <div style="margin-top: 0.75rem">
      <input id="importFile" type="file" accept=".tar.gz" />
      <button id="importRun">Import</button>
      <pre id="importOut"></pre>
    </div>
  </div>
  <div class="card">
    <h2>Console</h2>
    <div style="display:flex; gap:0.5rem">
      <select id="consoleCmd">
        <option value="gateway.restart">Restart</option>
        <option value="gateway.stop">Stop</option>
        <option value="gateway.start">Start</option>
        <option value="openclaw.status">Status</option>
        <option value="openclaw.logs.tail">Logs</option>
      </select>
      <input id="consoleArg" placeholder="Arg" />
      <button id="consoleRun">Run</button>
    </div>
    <pre id="consoleOut"></pre>
  </div>
  <div class="card">
    <h2>Config</h2>
    <div id="configPath" class="muted"></div>
    <textarea id="configText"></textarea>
    <button id="configReload">Reload</button>
    <button id="configSave">Save</button>
    <pre id="configOut"></pre>
  </div>
  <div class="card">
    <h2>Onboarding</h2>
    <label>Group</label><select id="authGroup"></select>
    <label>Choice</label><select id="authChoice"></select>
    <label>Secret</label><input id="authSecret" type="password" />
    <label>Flow</label><select id="flow"><option value="quickstart">quickstart</option></select>
    <h3>Channels</h3>
    <label>Telegram</label><input id="telegramToken" type="password" />
    <label>Discord</label><input id="discordToken" type="password" />
    <label>Slack Bot</label><input id="slackBotToken" type="password" />
    <label>Slack App</label><input id="slackAppToken" type="password" />
    <h3>Custom Provider</h3>
    <input id="customProviderId" placeholder="id" />
    <input id="customProviderBaseUrl" placeholder="url" />
    <select id="customProviderApi"><option value="openai-completions">openai-completions</option></select>
    <input id="customProviderApiKeyEnv" placeholder="env" />
    <input id="customProviderModelId" placeholder="model" />
    <div style="margin-top:1rem">
      <button id="run">Run Setup</button>
      <button id="pairingApprove">Approve Pairing</button>
      <button id="reset">Reset</button>
    </div>
    <pre id="log"></pre>
    <div id="devicesList"></div>
    <button id="devicesRefresh">Refresh Devices</button>
  </div>
  <script src="/setup/app.js"></script>
</body>
</html>`);
});

const AUTH_GROUPS = [
  { value: "openai", label: "OpenAI", options: [{ value: "openai-api-key", label: "API Key" }] },
  { value: "anthropic", label: "Anthropic", options: [{ value: "apiKey", label: "API Key" }, { value: "token", label: "Token" }] },
  { value: "google", label: "Google", options: [{ value: "gemini-api-key", label: "Gemini API Key" }] },
  { value: "openrouter", label: "OpenRouter", options: [{ value: "openrouter-api-key", label: "API Key" }] },
  { value: "opencode-zen", label: "OpenCode Zen", options: [{ value: "opencode-zen", label: "API Key" }] }
];

app.get("/setup/api/status", requireSetupAuth, async (_req, res) => {
  const v = await runCmd(OPENCLAW_NODE, clawArgs(["--version"]));
  const h = await runCmd(OPENCLAW_NODE, clawArgs(["channels", "add", "--help"]));
  res.json({ configured: isConfigured(), gatewayTarget: GATEWAY_TARGET, openclawVersion: v.output.trim(), channelsAddHelp: h.output, authGroups: AUTH_GROUPS });
});

app.get("/setup/api/auth-groups", requireSetupAuth, (_req, res) => res.json({ ok: true, authGroups: AUTH_GROUPS }));

function buildOnboardArgs(payload) {
  const args = ["onboard", "--non-interactive", "--accept-risk", "--json", "--no-install-daemon", "--skip-health", "--workspace", WORKSPACE_DIR, "--gateway-bind", "loopback", "--gateway-port", String(INTERNAL_GATEWAY_PORT), "--gateway-auth", "token", "--gateway-token", OPENCLAW_GATEWAY_TOKEN, "--flow", payload.flow || "quickstart"];
  if (payload.authChoice) {
    args.push("--auth-choice", payload.authChoice);
    const secret = (payload.authSecret || "").trim();
    const map = { "openai-api-key": "--openai-api-key", "apiKey": "--anthropic-api-key", "openrouter-api-key": "--openrouter-api-key", "ai-gateway-api-key": "--ai-gateway-api-key", "moonshot-api-key": "--moonshot-api-key", "kimi-code-api-key": "--kimi-code-api-key", "gemini-api-key": "--gemini-api-key", "zai-api-key": "--zai-api-key", "minimax-api": "--minimax-api-key", "minimax-api-lightning": "--minimax-api-key", "synthetic-api-key": "--synthetic-api-key", "opencode-zen": "--opencode-zen-api-key" };
    const flag = map[payload.authChoice];
    if (flag && !secret) throw new Error(`Missing secret for ${payload.authChoice}`);
    if (flag) args.push(flag, secret);
    if (payload.authChoice === "token") {
      if (!secret) throw new Error("Missing token");
      args.push("--token-provider", "anthropic", "--token", secret);
    }
  }
  return args;
}

function runCmd(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const timeoutMs = opts.timeoutMs ?? 120_000;
    const proc = childProcess.spawn(cmd, args, { ...opts, env: { ...process.env, OPENCLAW_STATE_DIR: STATE_DIR, OPENCLAW_WORKSPACE_DIR: WORKSPACE_DIR } });
    let out = "";
    proc.stdout?.on("data", (d) => out += d);
    proc.stderr?.on("data", (d) => out += d);
    const timer = setTimeout(() => { try { proc.kill(); } catch { } resolve({ code: 124, output: out + "\n[timeout]" }); }, timeoutMs);
    proc.on("error", (err) => { clearTimeout(timer); resolve({ code: 127, output: out + `\n[error] ${err}` }); });
    proc.on("close", (code) => { clearTimeout(timer); resolve({ code: code ?? 0, output: out }); });
  });
}

app.post("/setup/api/run", requireSetupAuth, async (req, res) => {
  try {
    if (isConfigured()) return res.json({ ok: true, output: "Already configured." });
    const payload = req.body || {};
    const onboardArgs = buildOnboardArgs(payload);
    const onboard = await runCmd(OPENCLAW_NODE, clawArgs(onboardArgs));
    let extra = "";
    const ok = onboard.code === 0 && isConfigured();
    if (ok) {
      await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "gateway.auth.mode", "token"]));
      await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "gateway.auth.token", OPENCLAW_GATEWAY_TOKEN]));
      await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "gateway.remote.token", OPENCLAW_GATEWAY_TOKEN]));
      await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "gateway.bind", "loopback"]));
      await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "gateway.port", String(INTERNAL_GATEWAY_PORT)]));
      await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "--json", "gateway.trustedProxies", '["127.0.0.1"]']));
      if (payload.telegramToken?.trim()) {
        await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "--json", "channels.telegram", JSON.stringify({ enabled: true, botToken: payload.telegramToken.trim() })]));
        await runCmd(OPENCLAW_NODE, clawArgs(["plugins", "enable", "telegram"]));
      }
      if (payload.discordToken?.trim()) {
        await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "--json", "channels.discord", JSON.stringify({ enabled: true, token: payload.discordToken.trim(), dm: { policy: "pairing" } })]));
      }
      await restartGateway();
      await runCmd(OPENCLAW_NODE, clawArgs(["doctor", "--fix"]));
      await restartGateway();
    }
    res.json({ ok, output: onboard.output + extra });
  } catch (err) { res.status(500).json({ ok: false, output: String(err) }); }
});

function redactSecrets(t) { return String(t || "").replace(/(sk-[A-Za-z0-9-]{20,})/g, "[REDACTED]").replace(/(\d{5,}:[A-Za-z0-9_-]{10,})/g, "[REDACTED]"); }

const ALLOWED_CONSOLE_COMMANDS = new Set(["gateway.restart", "gateway.stop", "gateway.start", "openclaw.status", "openclaw.logs.tail"]);

app.post("/setup/api/console/run", requireSetupAuth, async (req, res) => {
  const { cmd, arg } = req.body || {};
  if (!ALLOWED_CONSOLE_COMMANDS.has(cmd)) return res.status(400).json({ error: "Forbidden" });
  if (cmd === "gateway.restart") { await restartGateway(); return res.json({ ok: true, output: "Restarted" }); }
  if (cmd === "openclaw.status") { const r = await runCmd(OPENCLAW_NODE, clawArgs(["status"])); return res.json({ ok: r.code === 0, output: redactSecrets(r.output) }); }
  if (cmd === "openclaw.logs.tail") { const r = await runCmd(OPENCLAW_NODE, clawArgs(["logs", "--tail", "100"])); return res.json({ ok: r.code === 0, output: redactSecrets(r.output) }); }
  res.status(400).json({ error: "Unhandled" });
});

app.get("/setup/api/config/raw", requireSetupAuth, (req, res) => {
  const p = configPath();
  const exists = fs.existsSync(p);
  res.json({ ok: true, path: p, exists, content: exists ? fs.readFileSync(p, "utf8") : "" });
});

app.post("/setup/api/config/raw", requireSetupAuth, async (req, res) => {
  const { content } = req.body || {};
  const p = configPath();
  if (fs.existsSync(p)) fs.copyFileSync(p, `${p}.bak-${Date.now()}`);
  fs.writeFileSync(p, content || "", { mode: 0o600 });
  if (isConfigured()) await restartGateway();
  res.json({ ok: true });
});

app.post("/setup/api/reset", requireSetupAuth, async (req, res) => {
  if (gatewayProc) { try { gatewayProc.kill(); } catch { } gatewayProc = null; }
  resolveConfigCandidates().forEach(p => { try { fs.rmSync(p, { force: true }); } catch { } });
  res.send("Reset complete");
});

app.get("/setup/export", requireSetupAuth, (req, res) => {
  res.setHeader("content-type", "application/gzip");
  res.setHeader("content-disposition", `attachment; filename="backup.tar.gz"`);
  tar.c({ gzip: true, cwd: "/data" }, ["."]).pipe(res);
});

app.post("/setup/import", requireSetupAuth, async (req, res) => {
  if (gatewayProc) { try { gatewayProc.kill(); } catch { } gatewayProc = null; }
  const chunks = [];
  req.on("data", c => chunks.push(c));
  req.on("end", async () => {
    const buf = Buffer.concat(chunks);
    const tmp = path.join(os.tmpdir(), "import.tar.gz");
    fs.writeFileSync(tmp, buf);
    await tar.x({ file: tmp, cwd: "/data" });
    if (isConfigured()) await restartGateway();
    res.send("Import complete");
  });
});

const proxy = httpProxy.createProxyServer({ target: GATEWAY_TARGET, ws: true, xfwd: true });
app.use(async (req, res) => {
  if (!isConfigured() && !req.path.startsWith("/setup")) return res.redirect("/setup");
  if (isConfigured()) await ensureGatewayRunning();
  proxy.web(req, res);
});

const server = app.listen(PORT, "0.0.0.0", async () => {
  console.log(`Wrapper on ${PORT}`);
  if (isConfigured()) await ensureGatewayRunning();
});

server.on("upgrade", async (req, socket, head) => {
  if (isConfigured()) { await ensureGatewayRunning(); proxy.ws(req, socket, head); } else socket.destroy();
});

/* Cockpit Firewall Manager v3
 * Engines: ufw · firewalld · built-in nftables firewall (table inet cockpit_fw)
 * Commands run through cockpit.spawn with argv arrays (no shell interpolation of user input).
 */
"use strict";

const DIR = "/etc/cockpit-firewall";
const CFG = DIR + "/rules.json", NFT_FILE = DIR + "/ruleset.nft", META = DIR + "/meta.json";
const SETTINGS = DIR + "/settings.json", OWN_WL = DIR + "/whitelist.txt", LOG = DIR + "/activity.log";
const UNIT = "/etc/systemd/system/cockpit-firewall.service";
const TABLE = "cockpit_fw";
const GUARD_PORTS = ["22", "9090"];
const CACHE_KEY = "fwm-cache-v3";
const DEFAULT_OPEN = [["SSH", "22"], ["HTTP", "80"], ["HTTPS", "443"], ["Cockpit", "9090"]];
const PRESETS = [
    ["SSH", "22", "tcp"], ["HTTP", "80", "tcp"], ["HTTPS", "443", "tcp"], ["Cockpit", "9090", "tcp"],
    ["DNS", "53", "both"], ["SMTP", "25", "tcp"], ["IMAPS", "993", "tcp"], ["MySQL", "3306", "tcp"],
    ["PostgreSQL", "5432", "tcp"], ["WireGuard", "51820", "udp"], ["Minecraft", "25565", "tcp"],
];
const PORT_NAMES = {
    20: "FTP data", 21: "FTP file transfer", 22: "SSH remote login", 25: "SMTP email", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP websites", 110: "POP3 email", 123: "NTP time sync", 143: "IMAP email", 443: "HTTPS secure websites",
    465: "SMTPS email", 587: "email submission", 853: "DNS-over-TLS", 993: "IMAPS email", 995: "POP3S email",
    1194: "OpenVPN", 1433: "SQL Server", 2049: "NFS", 3000: "web app / Grafana", 3306: "MySQL database",
    3389: "Remote Desktop", 5432: "PostgreSQL database", 5353: "mDNS", 5900: "VNC remote screen", 6379: "Redis",
    8080: "alternate web port", 8443: "alternate HTTPS", 9090: "Cockpit", 9100: "Prometheus node exporter",
    25565: "Minecraft", 27017: "MongoDB", 51820: "WireGuard VPN",
};
let CF4 = ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"];
let CF6 = ["2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"];

const PROVIDERS = [
    { id: "contabo", name: "Contabo", fw: "Contabo Firewall", test: d => /contabo/i.test(d.vendor) || /^vmi\d+/i.test(d.host), url: "https://new.contabo.com", where: "new.contabo.com → Network Services → Firewall", api: "Contabo hasn't published an API for its firewall, so it can only be managed from their panel." },
    { id: "netcup", name: "netcup", fw: "netcup Firewall", test: d => /netcup/i.test(d.vendor + d.product), url: "https://www.servercontrolpanel.de/SCP/Login", where: "Server Control Panel → your server → Firewall", api: "netcup's SCP REST API can manage firewall policies — a direct connection could be added with an API token." },
    { id: "hetzner", name: "Hetzner", fw: "Hetzner Cloud Firewall", test: d => /hetzner/i.test(d.vendor + d.product), url: "https://console.hetzner.cloud", where: "Cloud Console → Firewalls", api: "" },
    { id: "do", name: "DigitalOcean", fw: "Cloud Firewall", test: d => /digitalocean/i.test(d.vendor + d.product), url: "https://cloud.digitalocean.com/login", where: "Networking → Firewalls", api: "" },
    { id: "vultr", name: "Vultr", fw: "Vultr Firewall", test: d => /vultr/i.test(d.vendor + d.product), url: "https://my.vultr.com/", where: "Network → Firewall", api: "" },
    { id: "linode", name: "Akamai / Linode", fw: "Cloud Firewall", test: d => /linode|akamai/i.test(d.vendor + d.product), url: "https://login.linode.com/login", where: "Firewalls", api: "" },
    { id: "ovh", name: "OVHcloud", fw: "Edge Network Firewall", test: d => /ovh/i.test(d.vendor + d.product), url: "https://www.ovh.com/auth/", where: "IP → Edge Network Firewall", api: "" },
    { id: "ionos", name: "IONOS", fw: "Firewall Policies", test: d => /ionos|1&1/i.test(d.vendor + d.product), url: "https://login.ionos.com", where: "Server & Cloud → Network → Firewall Policies", api: "" },
    { id: "aws", name: "AWS", fw: "Security Groups", test: d => /amazon/i.test(d.vendor + d.product), url: "https://console.aws.amazon.com/", where: "EC2 → Security Groups", api: "" },
    { id: "gcp", name: "Google Cloud", fw: "VPC firewall rules", test: d => /google/i.test(d.vendor + d.product), url: "https://console.cloud.google.com/", where: "VPC network → Firewall", api: "" },
    { id: "azure", name: "Azure", fw: "Network Security Groups", test: d => /microsoft/i.test(d.vendor) && d.virt === "microsoft", url: "https://portal.azure.com", where: "Network security groups", api: "" },
    { id: "oracle", name: "Oracle Cloud", fw: "Security Lists", test: d => /oracle/i.test(d.vendor + d.product), url: "https://cloud.oracle.com", where: "Networking → VCN → Security Lists", api: "" },
];

const S = {
    engine: null, info: {}, rules: [], policy: "", ufwLogging: "", ufwIpv6: "",
    cfg: { policy: "accept", guard: true, trustAll: false, trusted: [], icmp: true, sshLimit: false, logDrops: false, cloudflare: false, rules: [] },
    settings: { setupDone: false, customFiles: [], disabledFiles: [] },
    meta: {}, metaDirty: false, pending: null,
    wlSources: [], whitelist: [], myips: [],
    net: null, provider: null, zone: "public",
    nft: { rows: [], tables: [], chains: [], text: "", raw: "", rawMode: false },
    log: [], blocked: [], blockedLoaded: false,
    sort: { key: "n", dir: "asc" },
    m: { action: "allow", proto: "tcp", src: "anyone", edit: null },
    nm: { pos: "insert", edit: null },
    user: "", setupShown: false, bannerTimer: null, busy: null, loaded: false,
};
const PG = { rules: { size: 25, page: 1 }, nft: { size: 25, page: 1 }, log: { size: 25, page: 1 } };

/* ---------------- helpers ---------------- */
const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));
const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const run = argv => cockpit.spawn(argv, { superuser: "require", err: "message" });
const sh = (script, args) => run(["bash", "-c", script, "--"].concat(args || []));
const errMsg = e => (e && (e.message || e.problem)) || String(e);
const uniq = a => [...new Set(a)];
const DAY = 86400000;

async function readFile(path) { try { return await cockpit.file(path, { superuser: "try" }).read(); } catch (e) { return null; } }
async function readJSON(path, dflt) {
    const t = await readFile(path); if (!t) return Object.assign({}, dflt);
    try { return Object.assign({}, dflt, JSON.parse(t)); } catch (e) { return Object.assign({}, dflt); }
}
async function writeFile(path, text) { await run(["mkdir", "-p", DIR]); await cockpit.file(path, { superuser: "require" }).replace(text); }
const saveSettings = () => writeFile(SETTINGS, JSON.stringify(S.settings, null, 2) + "\n");

function logEvent(type, msg, detail) {
    const e = { ts: Date.now(), user: S.user || "unknown", type, msg, detail: detail || "", src: "module" };
    S.log.push(e);
    return sh('mkdir -p "$1" && printf "%s\\n" "$2" >> "$3"', [DIR, JSON.stringify(e), LOG]).catch(() => {});
}

function toast(msg, err) {
    const t = document.createElement("div");
    t.className = "toast" + (err ? " err" : "");
    t.textContent = msg;
    $("#toasts").appendChild(t);
    setTimeout(() => t.remove(), err ? 9000 : 3500);
}
function confirmBox(title, msg, yesLabel, safe) {
    return new Promise(res => {
        $("#cf-title").textContent = title;
        $("#cf-msg").textContent = msg;
        $("#cf-yes").textContent = yesLabel || "Confirm";
        $("#cf-yes").className = "btn " + (safe ? "primary" : "danger");
        $("#confirm").classList.remove("hidden");
        const done = v => { $("#confirm").classList.add("hidden"); $("#cf-yes").onclick = $("#cf-no").onclick = null; res(v); };
        $("#cf-yes").onclick = () => done(true);
        $("#cf-no").onclick = () => done(false);
    });
}
function fmtBytes(n) { n = +n || 0; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return (i ? n.toFixed(1) : n) + " " + u[i]; }
const fmtNum = n => (+n || 0).toLocaleString();
function fmtDate(ts) {
    if (!ts) return '<span class="muted">—</span>';
    const days = Math.floor((new Date().setHours(0, 0, 0, 0) - new Date(ts).setHours(0, 0, 0, 0)) / DAY);
    return `<span class="main">${new Date(ts).toLocaleDateString()}</span><div class="meta">${days <= 0 ? "today" : days === 1 ? "yesterday" : days + "d ago"}</div>`;
}
const fmtTime = ts => new Date(ts).toLocaleString([], { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });

/* date-range filter shared by all tables */
const DATE_OPTS = [["any", "Any date"], ["today", "Today"], ["yesterday", "Yesterday"], ["7", "Last 7 days"], ["30", "Last 30 days"], ["90", "Last 90 days"], ["365", "Last year"], ["custom", "Custom range…"]];
function inDate(ts, p) {
    const v = $(`#${p}-date`).value; if (v === "any") return true; if (!ts) return false;
    const d0 = new Date().setHours(0, 0, 0, 0);
    if (v === "today") return ts >= d0;
    if (v === "yesterday") return ts >= d0 - DAY && ts < d0;
    if (v === "custom") {
        const f = $(`#${p}-from`).value, t = $(`#${p}-to`).value;
        if (f && ts < new Date(f + "T00:00").getTime()) return false;
        if (t && ts >= new Date(t + "T00:00").getTime() + DAY) return false;
        return true;
    }
    return ts >= Date.now() - (+v) * DAY;
}

/* pagination shared by all tables */
const PAGER_RENDER = {};
function paginate(name, rows) {
    const p = PG[name], total = rows.length, size = p.size || total || 1;
    const pages = Math.max(1, Math.ceil(total / size));
    if (p.page > pages) p.page = pages;
    const start = (p.page - 1) * size, slice = p.size ? rows.slice(start, start + size) : rows;
    $(`#${name}-pager`).innerHTML = `<span class="muted">Show</span><select data-pg="${name}">${[10, 25, 50, 100, 0].map(v => `<option value="${v}" ${v === p.size ? "selected" : ""}>${v || "All"}</option>`).join("")}</select>
      <span>${total ? `Showing <b>${start + 1}–${start + slice.length}</b> of <b>${total}</b>` : "Nothing to show"}</span><span class="spacer"></span>
      <button class="btn sm" data-pgp="${name}" ${p.page <= 1 ? "disabled" : ""}>‹ Prev</button><span class="muted">Page ${p.page} of ${pages}</span>
      <button class="btn sm" data-pgn="${name}" ${p.page >= pages ? "disabled" : ""}>Next ›</button>`;
    return slice;
}
function countActive(defaults) {
    let n = 0;
    Object.entries(defaults).forEach(([k, v]) => { const el = $(k); const on = el.value !== v; el.classList.toggle("active-f", on && el.tagName === "SELECT"); if (on) n++; });
    return n;
}

/* ---------------- IP utilities ---------------- */
const PORT_RE = /^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$/;
const V4_RE = /^(\d{1,3})(\.\d{1,3}){3}(\/(\d|[12]\d|3[0-2]))?$/;
const V6_RE = /^[0-9a-fA-F:]+:[0-9a-fA-F:.]*(\/\d{1,3})?$/;
const validPort = p => PORT_RE.test(p) && p.split(/[,-]/).every(n => +n >= 1 && +n <= 65535);
function validIp(ip) {
    if (!ip) return false;
    if (V4_RE.test(ip)) return ip.split("/")[0].split(".").every(n => +n <= 255);
    return V6_RE.test(ip) && (ip.includes("::") || ip.split(":").length >= 8);
}
const isV6 = ip => ip.includes(":");
const isLocal = ip => /^(127\.|::1$|0\.0\.0\.0|::$|fe80:)/i.test(ip);
const ip4n = ip => ip.split(".").reduce((a, b) => a * 256 + (+b), 0);
function inCidr4(ip, cidr) {
    const [net, bits] = cidr.split("/"); const size = Math.pow(2, 32 - (bits === undefined ? 32 : +bits));
    return Math.floor(ip4n(ip.split("/")[0]) / size) === Math.floor(ip4n(net) / size);
}
function inCidr6(ip, cidr) {
    const [net, bits] = cidr.split("/"); const groups = Math.floor((+bits || 128) / 16);
    const ex = a => { const [h, t] = a.split("::"); const hs = h ? h.split(":") : [], ts = t ? t.split(":") : [];
        return hs.concat(Array(Math.max(0, 8 - hs.length - ts.length)).fill("0"), ts).map(x => parseInt(x || "0", 16)); };
    const a = ex(ip.split("/")[0]), n = ex(net);
    for (let i = 0; i < groups; i++) if (a[i] !== n[i]) return false;
    return true;
}
const ipIn = (ip, cidr) => isV6(ip) !== isV6(cidr) ? false : isV6(ip) ? inCidr6(ip, cidr) : inCidr4(ip, cidr);
const isCloudflare = ip => (isV6(ip) ? CF6 : CF4).some(c => ipIn(ip, c));
const isWhitelisted = ip => !!ip && S.whitelist.some(w => w === ip || (!ip.includes("/") && w.includes("/") && ipIn(ip, w)));
const isMyIp = ip => !!ip && S.myips.some(m => m.ip === ip);
function collapse(list) {
    const u = uniq(list);
    return u.filter(a => !u.some(b => b !== a && b.includes("/") && isV6(a) === isV6(b) &&
        (+(b.split("/")[1]) < +((a.split("/")[1]) || (isV6(a) ? 128 : 32))) && ipIn(a, b)));
}
const cleanComment = c => (c || "").replace(/[^\w .,:/@()+-]/g, "").slice(0, 60).trim();

/* ---------------- plain-English explanations ---------------- */
function portDesc(port, proto) {
    if (!port || /^all/i.test(port)) return "<b>every port</b> on this server";
    const parts = String(port).split(",").map(p => {
        const name = PORT_NAMES[+p]; return `<b>${esc(p)}</b>${name ? " (" + name + ")" : /-/.test(p) ? " (port range)" : ""}`;
    });
    const pr = /tcp\+udp|both/i.test(proto) ? " TCP+UDP" : /^(tcp|udp)$/i.test(proto) ? " " + proto.toUpperCase() : "";
    return (parts.length > 1 ? "ports " : "port ") + parts.join(", ") + pr;
}
function whoDesc(src) {
    if (!src) return "<b>anyone on the internet</b>";
    if (/trusted|Cloudflare/.test(src)) return "<b>" + esc(src) + "</b>";
    const tag = isMyIp(src) ? " — your IP" : isWhitelisted(src) ? " — on your whitelist" : validIp(src) && isCloudflare(src) ? " — Cloudflare" : "";
    return `only <b>${esc(src)}</b>${tag}`;
}
function explainRule(r) {
    if (r.guard) return "Safety net: keeps SSH and Cockpit reachable so a mistake can't lock you out. Toggle it in Settings.";
    if (r.proto === "service") return `Lets anyone use the firewalld <b>${esc(r.port)}</b> service (its predefined ports).`;
    let s;
    if (r.action === "allow") s = `Lets ${whoDesc(r.source)} connect to ${portDesc(r.port, r.proto)}.`;
    else if (r.action === "limit") s = `Lets ${whoDesc(r.source)} reach ${portDesc(r.port, r.proto)}, but temporarily blocks any IP that connects too often (brute-force protection).`;
    else s = `Blocks ${whoDesc(r.source)} from reaching ${portDesc(r.port, r.proto)}.`;
    if (r.dir === "out") s = s.replace(/^Lets|^Blocks/, m => m) + " (applies to traffic <b>leaving</b> the server)";
    if (r.v6) s += " IPv6 copy — UFW keeps one rule for IPv4 and one for IPv6.";
    return s;
}
const SET_HINTS = [[/temp/i, "temporary bans"], [/range/i, "blocked IP ranges"], [/perm|ban|black|bl\d|^bl/i, "blocked IPs"], [/white|allow|trust/i, "trusted IPs"], [/seen/i, "recently seen IPs"], [/port/i, "IP + port tracking"], [/meter|limit|rate/i, "rate-limit tracking"]];
const setHint = n => { const h = SET_HINTS.find(([re]) => re.test(n)); return h ? h[1] : "a named list"; };
const CHAIN_HINTS = {
    "ufw-user-input": "your UFW rules", "ufw-before-input": "UFW's built-in safety rules", "ufw-after-input": "UFW's cleanup rules",
    "ufw-not-local": "UFW's check for broadcast/multicast traffic", "ufw-logging-deny": "UFW's logging of blocked traffic",
    "ufw-logging-allow": "UFW's logging of allowed traffic", "ufw-skip-to-policy-input": "UFW's default policy",
    "ufw-user-limit": "UFW's rate-limit action", "ufw-user-limit-accept": "UFW's rate-limit pass-through",
    "ufw-reject-input": "UFW's reject handling", "ufw-track-output": "UFW's connection tracking",
};
function explainNft(r) {
    const b = r.body.replace(/\b(add|update|delete) @[\w-]+ \{[^}]*\}/g, " ");
    const full = r.body;
    const conds = [];
    const st = (b.match(/ct state (\S+)/) || [])[1] || "";
    if (/^iif(name)? "?lo"?/.test(b) || /\biif(name)? "?lo"?\b/.test(b)) conds.push("traffic the server sends to itself");
    if (/established|related/.test(st)) conds.push("replies to connections already in progress");
    else if (/invalid/.test(st)) conds.push("broken or invalid packets");
    else if (/new/.test(st)) conds.push("new connections");
    const src = (b.match(/\bip6? saddr ((?:!= )?(?:\{[^}]*\}|[^\s{}]+))/) || [])[1];
    if (src) conds.push(src.startsWith("@") ? `IPs in the list “${src.slice(1)}” (${setHint(src)})` : `traffic from ${src}`);
    const port = (b.match(/\b(?:tcp|udp|th|sctp) dport ((?:!= )?(?:\{[^}]*\}|[^\s{}]+))/) || [])[1];
    if (port) { const nm = PORT_NAMES[+port]; conds.push(`port ${port}${nm ? " (" + nm + ")" : ""}`); }
    if (/\bicmp(v6)?\b|ipv6-icmp/.test(b)) conds.push(/echo-request/.test(b) ? "ping requests" : "ICMP (ping / network control messages)");
    if (/udp sport 67 udp dport 68/.test(b)) conds.push("DHCP replies (getting an IP address)");
    if (/224\.0\.0\.251|5353/.test(b)) conds.push("mDNS local discovery");
    if (/239\.255\.255\.250|1900/.test(b)) conds.push("UPnP/SSDP local discovery");
    if (/limit rate/.test(b) && !/@/.test(b)) conds.push("traffic above a rate limit");
    const what = conds.length ? conds.join(", ") : "all remaining traffic";
    const upd = full.match(/\b(?:add|update) @([\w-]+)/);
    const v = r.verdict;
    let s;
    if (/^accept/.test(v)) s = `Allows ${what}.`;
    else if (/^drop/.test(v)) s = `Silently blocks ${what}.`;
    else if (/^reject/.test(v)) s = `Rejects ${what} (sender gets an error back).`;
    else if (/^jump|^goto/.test(v)) { const ch = v.split(" ")[1]; s = `Sends ${what} on to <b>${esc(ch)}</b>${CHAIN_HINTS[ch] ? " — " + CHAIN_HINTS[ch] : ""} for more checks.`; }
    else if (v === "return") s = `Stops checking this chain for ${what} and goes back to the previous one.`;
    else if (v === "log") s = `Writes a log line about ${what}; doesn't block or allow on its own.`;
    else if (/masquerade|snat/.test(v)) s = `Rewrites the source address of ${what} (NAT, used for containers/VPN sharing).`;
    else if (/dnat|redirect/.test(v)) s = `Forwards ${what} to another address or port (port forwarding).`;
    else if (upd) s = `Remembers the source of ${what} in the list “${upd[1]}” (${setHint(upd[1])}) — used for tracking, not blocking.`;
    else s = `Counts ${what}; the decision is made by a later rule.`;
    if (upd && !/Remembers/.test(s)) s += ` Also records it in “${upd[1]}”.`;
    if (CHAIN_HINTS[r.c.name] && !/^jump|^goto/.test(v)) s += ` <span class="muted">Part of ${CHAIN_HINTS[r.c.name]}.</span>`;
    return s;
}

/* ---------------- theme ---------------- */
function applyTheme() {
    let s; try { s = localStorage.getItem("shell:style"); } catch (e) {}
    s = s || "auto";
    const dark = s === "dark" || (s === "auto" && matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.classList.toggle("light", !dark);
}
window.addEventListener("storage", e => { if (e.key === "shell:style") applyTheme(); });
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", applyTheme);

/* ---------------- detection (one fast spawn) ---------------- */
async function probe() {
    const out = await sh(`
have(){ command -v "$1" >/dev/null 2>&1 && echo 1 || echo 0; }
echo "ufw_installed=$(have ufw)"
if command -v ufw >/dev/null 2>&1; then echo "ufw=$(ufw status 2>/dev/null | head -1 | awk '{print $2}')"; echo "ufw_boot=$(systemctl is-enabled ufw 2>/dev/null)"; echo "ufw_ipv6=$(. /etc/default/ufw 2>/dev/null; echo $IPV6)"; fi
echo "fwd_installed=$(have firewall-cmd)"
echo "fwd=$(systemctl is-active firewalld 2>/dev/null)"
echo "fwd_boot=$(systemctl is-enabled firewalld 2>/dev/null)"
echo "nft_installed=$(have nft)"
echo "standalone=$(nft list table inet ${TABLE} >/dev/null 2>&1 && echo 1 || echo 0)"
echo "standalone_boot=$(systemctl is-enabled cockpit-firewall 2>/dev/null)"
echo "standalone_loaded=$(nft list table inet ${TABLE} 2>/dev/null | grep 'comment "fw:' | grep -vc -- '-pass"')"
echo "csf=$(have csf)"
echo "crowdsec=$(systemctl is-active crowdsec-firewall-bouncer 2>/dev/null)"
echo "docker=$(systemctl is-active docker 2>/dev/null)"
echo "f2b=$(systemctl is-active fail2ban 2>/dev/null)"
echo "iptlegacy=$(iptables-legacy -S 2>/dev/null | grep -c '^-A')"
`);
    const info = {};
    out.split("\n").forEach(l => { const i = l.indexOf("="); if (i > 0) info[l.slice(0, i)] = l.slice(i + 1).trim(); });
    S.info = info;
    S.engine = info.ufw === "active" ? "ufw" : info.fwd === "active" ? "firewalld" : "nft";
}

async function loadWhitelist() {
    const script = `
OWN="${OWN_WL}"
ext(){ grep -vE '^[[:space:]]*[#;]' "$1" 2>/dev/null | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}(/[0-9]{1,2})?|([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})?'; }
for f in /etc/fail2ban/jail.local /etc/fail2ban/jail.d/*.local /etc/fail2ban/jail.d/*.conf; do
  [ -f "$f" ] || continue
  l=$(awk '/^[[:space:]]*ignoreip[[:space:]]*=/{p=1; sub(/^[^=]*=/,""); print; next} p && /^[ \\t]+[^ \\t#]/{print; next} {p=0}' "$f")
  [ -n "$l" ] || continue
  echo "##FILE fail2ban|$f"; echo "$l" | tr ' ,\\t' '\\n\\n\\n'
done
for f in /etc/csf/csf.allow /etc/csf/csf.ignore; do [ -f "$f" ] && { echo "##FILE csf|$f"; ext "$f"; }; done
[ -f /etc/hosts.allow ] && { echo "##FILE hosts.allow|/etc/hosts.allow"; ext /etc/hosts.allow; }
echo "##FILE module|$OWN"; [ -f "$OWN" ] && ext "$OWN"
find /etc /opt -maxdepth 4 -type f \\( -iname '*whitelist*' -o -iname '*allowlist*' -o -iname '*ignoreip*' \\) -size -2M 2>/dev/null | grep -v -e "^$OWN$" -e '/fail2ban/' | head -40 | while read -r f; do echo "##FILE found|$f"; ext "$f"; done
for f in "$@"; do echo "##FILE custom|$f"; if [ -f "$f" ]; then ext "$f"; else echo "##MISSING"; fi; done
`;
    let out = "";
    try { out = await sh(script, S.settings.customFiles); } catch (e) {}
    const src = []; let cur = null;
    out.split("\n").forEach(l => {
        l = l.trim(); if (!l) return;
        if (l.startsWith("##FILE ")) {
            const [kind, path] = l.slice(7).split("|");
            cur = src.find(s => s.path === path);
            if (!cur) { cur = { kind, path, ips: [], missing: false, custom: kind === "custom" }; src.push(cur); }
            return;
        }
        if (l === "##MISSING") { cur.missing = true; return; }
        if (cur && validIp(l) && !isLocal(l) && !cur.ips.includes(l)) cur.ips.push(l);
    });
    S.wlSources = src;
    S.whitelist = uniq(src.filter(s => !S.settings.disabledFiles.includes(s.path)).flatMap(s => s.ips));
}

async function fetchText(url, ms) {
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), ms || 3000);
    try { const r = await fetch(url, { cache: "no-store", signal: ctl.signal, credentials: "omit" }); return r.ok ? await r.text() : ""; }
    catch (e) { return ""; } finally { clearTimeout(t); }
}
const parseKV = t => { const kv = {}; t.split("\n").forEach(l => { const i = l.indexOf("="); if (i > 0) kv[l.slice(0, i)] = l.slice(i + 1).trim(); }); return kv; };

async function detectConnection() {
    const mine = [];
    const add = (ip, via) => { ip = (ip || "").trim(); if (validIp(ip) && !isLocal(ip) && !mine.some(m => m.ip === ip)) mine.push({ ip, via }); };
    const net = { cfCockpit: false, warp: "", colo: "", tunnel: false, vpnIfaces: [], serverIp: "", proxy: "", webCf: 0, webTotal: 0 };

    // Browser side: real public IP of the person using Cockpit (allowed by this package's CSP).
    const [v4, v6, same, cft] = await Promise.all([
        fetchText("https://api.ipify.org"), fetchText("https://api64.ipify.org"),
        fetchText(window.location.origin + "/cdn-cgi/trace"), fetchText("https://www.cloudflare.com/cdn-cgi/trace"),
    ]);
    const sameKV = parseKV(same), cfKV = parseKV(cft);
    if (sameKV.ip) { net.cfCockpit = true; net.colo = sameKV.colo || ""; }
    net.warp = sameKV.warp || cfKV.warp || "";
    add(v4, "Your browser (public IPv4)");
    add(v6, "Your browser (public IPv6)");
    add(sameKV.ip || cfKV.ip, "Your browser (Cloudflare trace)");

    let out = "";
    try {
        out = await sh(`
echo "##PEERS"; ss -Htn state established '( sport = :9090 )' 2>/dev/null | awk '{print $4}'
echo "##WEB"; ss -Htn state established '( sport = :443 or sport = :80 )' 2>/dev/null | awk '{print $4}' | head -400
echo "##PROXY"; ss -Htlnp '( sport = :443 )' 2>/dev/null | grep -oP 'users:\\(\\("\\K[^"]+' | head -1
echo "##WHO"; who --ips 2>/dev/null | awk '{print $NF}'
echo "##IF"; ip -o addr show 2>/dev/null | awk '{print $2, $4}'
echo "##CFD"; systemctl is-active cloudflared 2>/dev/null; pgrep -x cloudflared >/dev/null 2>&1 && echo running
echo "##DMI"; echo "vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)"; echo "product=$(cat /sys/class/dmi/id/product_name 2>/dev/null)"
echo "host=$(hostname)"; echo "virt=$(systemd-detect-virt 2>/dev/null)"
echo "srcip=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \\K\\S+')"
`);
    } catch (e) {}
    let sec = ""; const dmi = {};
    const strip = a => a.replace(/:\d+$/, "").replace(/^\[|\]$/g, "").replace(/^::ffff:/, "");
    out.split("\n").forEach(l => {
        l = l.trim(); if (!l) return;
        if (l.startsWith("##")) { sec = l.slice(2); return; }
        if (sec === "PEERS") { const p = strip(l); if (validIp(p) && isCloudflare(p)) net.cfCockpit = true; else add(p, "Direct Cockpit connection"); }
        else if (sec === "WEB") { const p = strip(l); if (validIp(p) && !isLocal(p)) { net.webTotal++; if (isCloudflare(p)) net.webCf++; } }
        else if (sec === "PROXY") net.proxy = l;
        else if (sec === "WHO") add(l.replace(/[()]/g, ""), "SSH session");
        else if (sec === "IF") { const [dev, n] = l.split(" "); if (/^(wg|tun|tap|tailscale|zt|nebula|ppp|ipsec)/.test(dev || "")) net.vpnIfaces.push({ dev, net: n }); }
        else if (sec === "CFD") { if (l === "active" || l === "running") net.tunnel = true; }
        else if (sec === "DMI") { const i = l.indexOf("="); dmi[l.slice(0, i)] = l.slice(i + 1); }
    });
    net.serverIp = dmi.srcip || "";
    S.net = net; S.myips = mine;
    const d = { vendor: dmi.vendor || "", product: dmi.product || "", host: dmi.host || "", virt: dmi.virt || "" };
    S.provider = Object.assign({ dmi: d }, PROVIDERS.find(p => p.test(d)) || {});
}

async function refreshCfRanges() {   // weekly, in the background
    try {
        const c = JSON.parse(localStorage.getItem("fwm-cf") || "null");
        if (c && Date.now() - c.ts < 7 * DAY) { CF4 = c.v4; CF6 = c.v6; return; }
    } catch (e) {}
    const [a, b] = await Promise.all([fetchText("https://www.cloudflare.com/ips-v4", 5000), fetchText("https://www.cloudflare.com/ips-v6", 5000)]);
    const v4 = a.split(/\s+/).filter(validIp), v6 = b.split(/\s+/).filter(validIp);
    if (v4.length > 5 && v6.length > 2) { CF4 = v4; CF6 = v6; try { localStorage.setItem("fwm-cf", JSON.stringify({ ts: Date.now(), v4, v6 })); } catch (e) {} }
}

/* ---------------- metadata: dates + external change tracking ---------------- */
const sigOf = r => [S.engine, r.port, r.proto, r.action, r.source || "*", r.v6 ? 6 : 4, r.dir].join("|");
function stampRules() {
    const prefix = S.engine + "|";
    const firstRun = !Object.keys(S.meta).some(k => k.startsWith(prefix));
    const now = Date.now(), seen = new Set();
    S.rules.forEach(r => {
        if (r.synthetic) return;
        r.sig = sigOf(r); seen.add(r.sig);
        let m = S.meta[r.sig];
        if (!m) {
            const mine = S.pending && S.pending.add;
            m = S.meta[r.sig] = { added: r.added || now, by: firstRun ? "existing" : mine ? "module" : "external" };
            S.metaDirty = true;
            if (!firstRun && !mine) logEvent("external", `Rule appeared: ${r.action} ${r.port} ${r.source ? "from " + r.source : "for anyone"}`, "Added outside this module (CLI or another tool)");
        }
        if (m.gone) { delete m.gone; S.metaDirty = true; }
        r.added = r.added || m.added; r.by = m.by;
    });
    Object.keys(S.meta).forEach(k => {
        if (!k.startsWith(prefix) || seen.has(k) || S.meta[k].gone) return;
        S.meta[k].gone = now; S.metaDirty = true;
        if (!(S.pending && S.pending.del)) {
            const [, port, , action, src] = k.split("|");
            logEvent("external", `Rule removed: ${action} ${port} ${src === "*" ? "for anyone" : "from " + src}`, "Removed outside this module");
        }
    });
    S.pending = null;
}
function stampNft() {
    const any = Object.keys(S.meta).some(k => k.startsWith("nft|"));
    const now = Date.now();
    S.nft.rows.forEach(r => {
        const k = "nft|" + r.t.key + "|" + r.c.name + "|" + r.body;
        if (!S.meta[k]) { S.meta[k] = { added: any ? now : 0 }; S.metaDirty = true; }
        r.added = S.meta[k].added || null;
    });
}
function saveMeta() {
    if (!S.metaDirty) return;
    S.metaDirty = false;
    // keep meta small: forget rules gone for more than 30 days
    Object.keys(S.meta).forEach(k => { if (S.meta[k].gone && Date.now() - S.meta[k].gone > 30 * DAY) delete S.meta[k]; });
    writeFile(META, JSON.stringify(S.meta) + "\n").catch(() => {});
}

/* ---------------- engine: UFW ---------------- */
const ufw = {
    async load() {
        const [num, verb] = await Promise.all([run(["ufw", "status", "numbered"]), run(["ufw", "status", "verbose"])]);
        S.policy = ((verb.match(/Default:\s*([^\n]+)/) || [])[1] || "").trim();
        S.ufwLogging = ((verb.match(/Logging:\s*([^\n]+)/) || [])[1] || "").trim();
        const rules = [];
        const re = /^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)\s*(IN|OUT|FWD)?\s+(.+?)(?:\s+#\s*(.*))?$/;
        num.split("\n").forEach(line => {
            const r = line.match(re); if (!r) return;
            let to = r[2].trim(); const v6 = /\(v6\)/.test(to) || /\(v6\)/.test(r[5]);
            to = to.replace(/\s*\(v6\)/, "").trim();
            const src = r[5].replace(/\s*\(v6\)/, "").trim();
            let port = to, proto = "any";
            if (to.includes("/")) [port, proto] = to.split("/");
            if (/^Anywhere$/i.test(port)) port = "All ports";
            rules.push({
                n: +r[1], port: port.replace(/:/g, "-"), proto, v6, ufwVerb: r[3].toLowerCase(),
                action: r[3] === "ALLOW" ? "allow" : r[3] === "LIMIT" ? "limit" : "block",
                source: /^Anywhere$/i.test(src) ? "" : src, dir: (r[4] || "IN").toLowerCase(), comment: r[6] || "",
            });
        });
        S.rules = rules;
    },
    cmds(r, opts) {
        opts = opts || {};
        const cmds = [], ports = r.port && !/^all/i.test(r.port) ? r.port.replace(/-/g, ":") : "";
        const multi = /[,:]/.test(ports);
        const proto = r.proto === "any" || r.proto === "tcp+udp" ? "both" : r.proto;
        const protos = proto === "both" ? (multi ? ["tcp", "udp"] : [null]) : [proto];
        const verb = r.ufwVerb === "reject" ? "reject" : r.action === "allow" ? "allow" : r.action === "limit" ? "limit" : "deny";
        const insert = !opts.del && r.source && !isV6(r.source) && S.rules.some(x => !x.v6) ? ["insert", "1"] : [];
        for (const p of (ports ? protos : [null])) {
            const a = ["ufw", ...(opts.del ? ["delete"] : insert), verb];
            if (r.dir === "out") a.push("out");
            if (p) a.push("proto", p);
            a.push("from", r.source || "any", "to", "any");
            if (ports) a.push("port", ports);
            if (r.comment && !opts.del) a.push("comment", r.comment);
            cmds.push(a);
        }
        return cmds;
    },
    async del(rule) { await run(["ufw", "--force", "delete", String(rule.n)]); },
    async edit(old, r) {
        const same = ["port", "proto", "action", "source"].every(k => normField(old, k) === normField(r, k));
        if (!same) { for (const c of ufw.cmds(old, { del: true })) await run(c).catch(() => {}); }
        for (const c of ufw.cmds(Object.assign({ dir: old.dir }, r))) await run(c);   // same rule + new comment = ufw updates in place
    },
    async reload() { await run(["ufw", "reload"]); },
};
function normField(r, k) {
    const v = r[k] || "";
    if (k === "port") return /^all/i.test(v) ? "" : v;
    if (k === "proto") return v === "any" || v === "tcp+udp" ? "both" : v;
    return v;
}

/* ---------------- engine: firewalld ---------------- */
function richRule(r, port, proto) {
    let s = "rule";
    if (r.source) s += ` family="${isV6(r.source) ? "ipv6" : "ipv4"}" source address="${r.source}"`;
    if (port) s += ` port port="${port}" protocol="${proto}"`;
    return s + (r.action === "allow" ? " accept" : r.action === "limit" ? ' accept limit value="10/m"' : " drop");
}
const firewalld = {
    async load() {
        S.zone = (await run(["firewall-cmd", "--get-default-zone"])).trim() || "public";
        const z = "--zone=" + S.zone;
        const [ports, svcs, rich, target] = await Promise.all([
            run(["firewall-cmd", z, "--list-ports"]), run(["firewall-cmd", z, "--list-services"]),
            run(["firewall-cmd", z, "--list-rich-rules"]), run(["firewall-cmd", "--permanent", z, "--get-target"]).catch(() => "default"),
        ]);
        S.policy = `zone ${S.zone}, target ${target.trim()}`;
        const rules = []; let n = 1;
        svcs.trim().split(/\s+/).filter(Boolean).forEach(s => rules.push({ n: n++, kind: "service", val: s, port: s, proto: "service", action: "allow", source: "", dir: "in", comment: "" }));
        ports.trim().split(/\s+/).filter(Boolean).forEach(p => { const [pp, pr] = p.split("/"); rules.push({ n: n++, kind: "port", val: p, port: pp, proto: pr, action: "allow", source: "", dir: "in", comment: "" }); });
        rich.split("\n").map(l => l.trim()).filter(Boolean).forEach(l => {
            const g = re => (l.match(re) || [])[1] || "";
            rules.push({
                n: n++, kind: "rich", val: l, port: g(/port port="([^"]+)"/) || g(/service name="([^"]+)"/) || "All ports",
                proto: g(/protocol="([^"]+)"/) || "any", action: /\slimit\b/.test(l) ? "limit" : /\saccept\b/.test(l) ? "allow" : "block",
                source: g(/source address="([^"]+)"/), v6: /family="ipv6"/.test(l), dir: "in", comment: "",
            });
        });
        S.rules = rules;
    },
    cmds(r) {
        const z = "--zone=" + S.zone, cmds = [];
        const ports = r.port && !/^all/i.test(r.port) ? r.port.split(",") : [""];
        const protos = r.proto === "both" || r.proto === "any" ? ["tcp", "udp"] : [r.proto];
        if (!r.source && r.action === "allow" && ports[0])
            ports.forEach(p => protos.forEach(pr => cmds.push(["firewall-cmd", "--permanent", z, `--add-port=${p}/${pr}`])));
        else
            ports.forEach(p => (p ? protos : [null]).forEach(pr => cmds.push(["firewall-cmd", "--permanent", z, "--add-rich-rule=" + richRule(r, p, pr)])));
        cmds.push(["firewall-cmd", "--reload"]);
        return cmds;
    },
    async del(rule) {
        const flag = rule.kind === "service" ? "--remove-service=" : rule.kind === "port" ? "--remove-port=" : "--remove-rich-rule=";
        await run(["firewall-cmd", "--permanent", "--zone=" + S.zone, flag + rule.val]);
        await run(["firewall-cmd", "--reload"]);
    },
    async edit(old, r) { await firewalld.del(old); for (const c of firewalld.cmds(r)) await run(c); },
    async reload() { await run(["firewall-cmd", "--reload"]); },
};

/* ---------------- engine: built-in nftables ---------------- */
function nftRuleLine(r) {
    const p = [];
    if (r.source) p.push(`${isV6(r.source) ? "ip6" : "ip"} saddr ${r.source}`);
    if (r.port) {
        const set = r.port.includes(",") ? `{ ${r.port.split(",").join(", ")} }` : r.port;
        p.push(r.proto === "both" ? `meta l4proto { tcp, udp } th dport ${set}` : `${r.proto} dport ${set}`);
    }
    if (r.action === "limit") p.push("ct state new limit rate over 10/minute drop");
    else p.push(r.action === "allow" ? "accept" : "drop");
    const c = cleanComment(r.comment);
    p.push(`comment "fw:${r.id}${c ? " " + c : ""}"`);
    let line = "    " + p.join(" ");
    if (r.action === "limit") line += "\n    " + p.slice(0, r.source ? 2 : 1).join(" ") + ` accept comment "fw:${r.id}-pass"`;
    return line;
}
const orderedRules = rules => rules.slice().sort((a, b) => ((a.source ? 0 : 2) + (a.action === "block" ? 0 : 1)) - ((b.source ? 0 : 2) + (b.action === "block" ? 0 : 1)));
const trustedList = () => collapse(S.whitelist.concat(S.myips.map(m => m.ip)));

function nftScript(cfg) {
    const drop = cfg.policy === "drop";
    const t4 = (cfg.trustAll ? cfg.trusted : []).filter(x => !isV6(x)), t6 = (cfg.trustAll ? cfg.trusted : []).filter(isV6);
    const L = ["# Generated by Cockpit Firewall Manager — manage from Cockpit, not by hand.",
        `add table inet ${TABLE}`, `delete table inet ${TABLE}`, `table inet ${TABLE} {`];
    if (cfg.sshLimit) L.push("  set ssh_meter4 { type ipv4_addr; size 65535; flags dynamic,timeout; timeout 2m; }",
        "  set ssh_meter6 { type ipv6_addr; size 65535; flags dynamic,timeout; timeout 2m; }");
    L.push("  chain input {", `    type filter hook input priority filter; policy ${drop ? "drop" : "accept"};`,
        "    ct state established,related accept", "    ct state invalid drop", '    iif "lo" accept');
    if (cfg.icmp === false) L.push('    icmp type echo-request drop comment "ping blocked"', '    icmpv6 type echo-request drop comment "ping blocked"');
    L.push("    meta l4proto { icmp, ipv6-icmp } accept");
    if (t4.length) L.push(`    ip saddr { ${t4.join(", ")} } accept comment "trusted: my IP + whitelist"`);
    if (t6.length) L.push(`    ip6 saddr { ${t6.join(", ")} } accept comment "trusted: my IP + whitelist"`);
    if (cfg.cloudflare) L.push(`    ip saddr { ${collapse(CF4).join(", ")} } tcp dport { 80, 443 } accept comment "Cloudflare"`,
        `    ip6 saddr { ${collapse(CF6).join(", ")} } tcp dport { 80, 443 } accept comment "Cloudflare"`);
    if (cfg.sshLimit) L.push('    tcp dport 22 ct state new add @ssh_meter4 { ip saddr limit rate over 10/minute } drop comment "SSH rate limit"',
        '    tcp dport 22 ct state new add @ssh_meter6 { ip6 saddr limit rate over 10/minute } drop comment "SSH rate limit"');
    orderedRules(cfg.rules).forEach(r => L.push(nftRuleLine(r)));
    if (drop && cfg.guard !== false) L.push(`    tcp dport { ${GUARD_PORTS.join(", ")} } accept comment "lockout guard (SSH + Cockpit)"`);
    if (drop && cfg.logDrops) L.push('    limit rate 10/minute log prefix "cockpit-fw drop: " level info');
    L.push("  }", "}", "");
    return L.join("\n");
}
const UNIT_TEXT = `[Unit]
Description=Cockpit Firewall Manager (nftables table inet ${TABLE})
Wants=network-pre.target
Before=network-pre.target
After=nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f ${NFT_FILE}
ExecReload=/usr/sbin/nft -f ${NFT_FILE}
ExecStop=-/usr/sbin/nft delete table inet ${TABLE}

[Install]
WantedBy=multi-user.target
`;
const CFG_DEFAULT = { policy: "accept", guard: true, trustAll: false, trusted: [], icmp: true, sshLimit: false, logDrops: false, cloudflare: false, rules: [] };
const nftEngine = {
    async loadCfg() { S.cfg = await readJSON(CFG, CFG_DEFAULT); },
    load() {
        const c = S.cfg;
        S.policy = c.policy === "drop" ? (c.trustAll ? "deny (incoming) · trusted IPs open" : "deny (incoming)") : "allow (incoming)";
        const rows = [];
        const syn = (port, proto, action, source, comment, guard) => rows.push({ n: "—", synthetic: true, guard, port, proto, action, source, dir: "in", comment });
        if (c.trustAll && c.trusted.length) syn("All ports", "any", "allow", c.trusted.length + " trusted IPs", "My IP + whitelist (Settings)");
        if (c.cloudflare) syn("80,443", "tcp", "allow", "Cloudflare ranges", "Cloudflare (Settings)");
        if (c.sshLimit) syn("22", "tcp", "limit", "", "SSH brute-force limit (Settings)");
        orderedRules(c.rules).forEach((r, i) => rows.push({
            n: i + 1, id: r.id, port: r.port || "All ports", proto: r.port ? (r.proto === "both" ? "tcp+udp" : r.proto) : "any",
            action: r.action, source: r.source, v6: r.source ? isV6(r.source) : false, dir: "in", comment: r.comment, added: r.added, isDefault: r.isDefault,
        }));
        if (c.policy === "drop" && c.guard !== false) syn(GUARD_PORTS.join(","), "tcp", "allow", "", "Lockout guard (Settings)", true);
        S.rules = rows;
    },
    async save(activate) {
        if (S.cfg.trustAll) S.cfg.trusted = trustedList();
        await writeFile(CFG, JSON.stringify(S.cfg, null, 2) + "\n");
        await writeFile(NFT_FILE, nftScript(S.cfg));
        await run(["nft", "-c", "-f", NFT_FILE]);
        if (activate || S.info.standalone === "1") await run(["nft", "-f", NFT_FILE]);
    },
    preview: r => "nft: " + nftRuleLine(Object.assign({ id: "new" }, r)).trim(),
    async add(r) { r.id = Date.now().toString(36); r.added = Date.now(); S.cfg.rules.push(r); await this.save(false); },
    async del(rule) { S.cfg.rules = S.cfg.rules.filter(r => r.id !== rule.id); await this.save(false); },
    async edit(old, r) {
        const cur = S.cfg.rules.find(x => x.id === old.id); if (!cur) throw new Error("Rule not found");
        Object.assign(cur, r, { id: cur.id, added: cur.added, isDefault: cur.isDefault });
        await this.save(false);
    },
    async reload() { if (S.info.standalone === "1") await run(["nft", "-f", NFT_FILE]); },
    async enable() {
        await this.save(true);
        await writeFile(UNIT, UNIT_TEXT);
        await run(["systemctl", "daemon-reload"]);
        await run(["systemctl", "enable", "cockpit-firewall.service"]);
        await run(["systemctl", "restart", "cockpit-firewall.service"]);
    },
    async disable() { await sh(`systemctl disable --now cockpit-firewall.service 2>/dev/null; nft delete table inet ${TABLE} 2>/dev/null; true`); },
};
const ENGINES = { ufw, firewalld, nft: nftEngine };

/* ---------------- nftables parsing ---------------- */
function ownerOf(t, c) {
    const tn = t.name, cn = c ? c.name : "";
    if (tn === TABLE) return "This module";
    if (/blacklist/i.test(tn)) return "Blacklist";
    if (/^f2b|fail2ban/i.test(tn) || /^f2b/i.test(cn)) return "fail2ban";
    if (/^ufw/.test(cn)) return "UFW";
    if (tn === "firewalld") return "firewalld";
    if (/crowdsec/i.test(tn + cn)) return "CrowdSec";
    if (/docker/i.test(tn + cn)) return "Docker";
    if (/netavark|cni|podman/i.test(tn + cn)) return "Podman";
    return "Other";
}
function parseNft(text) {
    const rows = [], tables = [], chains = [];
    let tbl = null, ch = null, skip = 0, depth = 0, order = 0;
    text.split("\n").forEach(raw => {
        const line = raw.trim(); if (!line) return;
        const opens = (line.match(/\{/g) || []).length, closes = (line.match(/\}/g) || []).length;
        if (skip) { skip += opens - closes; if (skip < 0) skip = 0; return; }
        let m;
        if ((m = line.match(/^table (\S+) (\S+) \{/))) { tbl = { fam: m[1], name: m[2], key: m[1] + " " + m[2] }; tables.push(tbl); depth = 1; return; }
        if (tbl && (m = line.match(/^chain (\S+) \{/))) { ch = { table: tbl, name: m[1], hook: "", policy: "" }; chains.push(ch); depth = 2; return; }
        if (/^(set|map|flowtable|counter|quota|limit|ct |secmark|synproxy)\b/.test(line) && opens > closes) { skip = opens - closes; return; }
        if (line === "}") { depth--; if (depth <= 1) ch = null; if (depth <= 0) tbl = null; return; }
        if (ch && (m = line.match(/^type (\S+) hook (\S+)(?: device \S+)? priority ([^;]+);(?:\s*policy (\S+);)?/))) { ch.hook = m[2]; ch.policy = m[4] || ""; return; }
        if (ch && (m = line.match(/^(.*?)\s*# handle (\d+)$/))) rows.push(mkNftRow(tbl, ch, m[1], +m[2], order++));
    });
    tables.forEach(t => { t.owner = ownerOf(t, chains.find(c => c.table === t)); });
    return { rows, tables, chains };
}
function mkNftRow(t, c, expr, handle, order) {
    const cnt = expr.match(/counter packets (\d+) bytes (\d+)/);
    const comment = (expr.match(/comment "([^"]*)"/) || [])[1] || "";
    const body = expr.replace(/counter packets \d+ bytes \d+/, "counter").replace(/\s*comment "[^"]*"/, "").trim();
    const vr = [...body.matchAll(/\b(accept|drop|reject(?: with [\w-]+(?: type [\w-]+)?)?|return|jump [\w.-]+|goto [\w.-]+|queue\b[^#]*|masquerade|snat to \S+|dnat to \S+|redirect to \S+)/g)];
    const verdict = vr.length ? vr[vr.length - 1][1].trim() : /\blog\b/.test(body) ? "log" : "continue";
    const cls = /^accept/.test(verdict) ? "allow" : /^(drop|reject)/.test(verdict) ? "block" : /^(jump|goto|return)/.test(verdict) ? "info" : "other";
    // matches, ignoring the contents of "{ ... }" set-update statements
    const m = body.replace(/\b(add|update|delete) @[\w-]+ \{[^}]*\}/g, " ");
    const g = re => (m.match(re) || [])[1];
    const V = "((?:!= )?(?:\\{[^}]*\\}|[^\\s{}.][^\\s{}]*))";
    const chips = [];
    const push = (k, v) => v && chips.push([k, v]);
    push("from", g(new RegExp("\\bip6? saddr " + V)));
    push("to", g(new RegExp("\\bip6? daddr " + V)));
    push("port", g(new RegExp("\\b(?:tcp|udp|th|sctp) dport " + V)));
    push("sport", g(new RegExp("\\b(?:tcp|udp|th|sctp) sport " + V)));
    push("proto", g(/\b(?:meta l4proto|ip protocol|ip6 nexthdr) (\{[^}]*\}|\S+)/) || g(/\b(tcp|udp|sctp)\s+(?:dport|sport|flags)/) || g(/\b(icmpv6|icmp)\s+type/));
    push("in", g(/\biifname? (\S+)/)); push("out", g(/\boifname? (\S+)/));
    push("state", g(/\bct state (\S+)/));
    const sets = uniq([...body.matchAll(/@([\w-]+)/g)].map(x => x[1]));
    sets.forEach(s => push("list", s));
    const row = { t, c, handle, order, expr, body, verdict, cls, comment, chips, packets: cnt ? +cnt[1] : null, bytes: cnt ? +cnt[2] : null, owner: ownerOf(t, c) };
    row.explain = explainNft(row);
    return row;
}
async function loadNft() {
    if (S.info.nft_installed !== "1") { Object.assign(S.nft, { rows: [], tables: [], chains: [], text: "", raw: "nft is not installed." }); return; }
    S.nft.text = await run(["nft", "-a", "list", "ruleset"]).catch(e => "");
    S.nft.raw = S.nft.text.replace(/\s*# handle \d+/g, "");
    Object.assign(S.nft, parseNft(S.nft.text));
}

/* ---------------- activity log ---------------- */
async function loadLog() {
    const t = await readFile(LOG);
    S.log = (t || "").split("\n").filter(Boolean).map(l => { try { return JSON.parse(l); } catch (e) { return null; } }).filter(Boolean);
}
async function loadBlocked() {
    let out = "";
    try { out = await sh(`journalctl -k --since "-30d" -o short-iso --no-pager 2>/dev/null | grep -E 'UFW BLOCK|cockpit-fw drop|FINAL_REJECT|filter_.*DROP' | tail -n 2000`); } catch (e) {}
    S.blocked = out.split("\n").filter(Boolean).map(l => {
        const ts = Date.parse(l.split(" ")[0]);
        const g = k => (l.match(new RegExp("\\b" + k + "=(\\S*)")) || [])[1] || "";
        const who = /UFW/.test(l) ? "UFW" : /cockpit-fw/.test(l) ? "Built-in" : "firewalld";
        return { ts, type: "blocked", user: "—", src: who, msg: `Blocked ${g("PROTO") || "packet"} from ${g("SRC")}${g("DPT") ? " to port " + g("DPT") : ""}`, detail: `IN=${g("IN")} DST=${g("DST")}${g("SPT") ? " SPT=" + g("SPT") : ""}` };
    }).filter(e => e.ts);
    S.blockedLoaded = true;
}

/* ---------------- render: cards + banner ---------------- */
const ENGINE_NAME = { ufw: "UFW", firewalld: "firewalld", nft: "Built-in" };
const engineActive = () => S.engine === "nft" ? S.info.standalone === "1" : !!S.engine;

function renderCards() {
    if (!S.engine) return;
    const active = engineActive();
    $("#c-engine").textContent = ENGINE_NAME[S.engine];
    $("#c-engine-sub").textContent = S.engine === "nft" ? `nftables · table inet ${TABLE}` : S.engine === "firewalld" ? `zone ${S.zone}` : "Uncomplicated Firewall";
    $("#c-status").textContent = active ? "Active" : "Inactive";
    $("#c-status").className = "big " + (active ? "green" : "red");
    $("#ico-status").className = "card-ico " + (active ? "green" : "red");
    $("#c-status-sub").textContent = "Default: " + (S.policy || "—");
    const real = S.rules.filter(r => !r.synthetic), allow = real.filter(r => r.action === "allow");
    $("#c-allow").textContent = allow.length;
    $("#c-allow-sub").textContent = `${allow.filter(r => !r.source).length} public · ${allow.filter(r => r.source).length} IP-restricted`;
    $("#c-block").textContent = real.filter(r => r.action === "block").length;
    $("#c-block-sub").textContent = real.filter(r => r.action === "limit").length + " rate-limited";
    $("#c-tables").textContent = S.nft.tables.length;
    $("#c-tables-sub").textContent = S.nft.tables.map(t => t.name).slice(0, 4).join(" · ") || "none";
    $("#t-rules").textContent = real.length;
    $("#t-nft").textContent = S.nft.rows.length;
}
function showBanner() {
    const b = $("#banner");
    clearTimeout(S.bannerTimer);
    if (S.engine === "nft" && !engineActive()) {
        b.className = "banner";
        b.innerHTML = `No firewall is running — your server is unprotected. Rules below are saved but not enforced yet.<button class="btn green" id="ban-enable">Set up firewall</button>`;
        $("#ban-enable").onclick = openSetup;
        return;
    }
    b.className = "banner info";
    b.textContent = `Managing ${ENGINE_NAME[S.engine]}${S.engine === "nft" ? " firewall" : ""} — rules you add or edit here go straight into ${ENGINE_NAME[S.engine]}.`;
    S.bannerTimer = setTimeout(() => { b.classList.add("fade"); S.bannerTimer = setTimeout(() => b.classList.add("hidden"), 700); }, 5000);
}

/* ---------------- render: rules ---------------- */
function srcLabel(ip) {
    if (!ip) return '<span class="main">Anyone</span><div class="meta">Public</div>';
    let tag = "";
    if (isMyIp(ip)) tag = '<span class="tag blue">my IP</span>';
    else if (isWhitelisted(ip)) tag = '<span class="tag green">whitelist</span>';
    else if (validIp(ip) && isCloudflare(ip)) tag = '<span class="tag amber">Cloudflare</span>';
    return `<span class="main">${esc(ip)}</span> ${tag}`;
}
const FILTER_DEFAULTS = { "#q": "", "#f-action": "any", "#f-src": "any", "#f-proto": "any", "#f-ipv": "any", "#f-dir": "any", "#f-origin": "any", "#f-date": "any", "#f-sort": "n:asc" };
function rulesFiltered() {
    const q = $("#q").value.trim().toLowerCase(), f = k => $(k).value;
    return S.rules.filter(r => {
        if (f("#f-action") !== "any" && r.action !== f("#f-action")) return false;
        const s = f("#f-src");
        if (s === "anyone" && r.source) return false;
        if (s === "specific" && !r.source) return false;
        if (s === "whitelist" && !isWhitelisted(r.source)) return false;
        if (s === "myip" && !isMyIp(r.source)) return false;
        const p = f("#f-proto");
        if (p === "tcp" && !/tcp/.test(r.proto)) return false;
        if (p === "udp" && !/udp/.test(r.proto)) return false;
        if (p === "all" && r.proto !== "any") return false;
        if (f("#f-ipv") === "4" && r.v6) return false;
        if (f("#f-ipv") === "6" && !r.v6) return false;
        if (f("#f-dir") !== "any" && r.dir !== f("#f-dir")) return false;
        if (f("#f-origin") !== "any" && r.by !== f("#f-origin")) return false;
        if (!inDate(r.added, "f")) return false;
        if (q && ![r.port, r.proto, r.source, r.comment, r.action, r.dir, PORT_NAMES[+r.port]].join(" ").toLowerCase().includes(q)) return false;
        return true;
    });
}
function sortRows(rows) {
    const { key, dir } = S.sort, m = dir === "desc" ? -1 : 1;
    const val = r => key === "port" ? (parseInt(r.port) || 1e6) : key === "n" ? (typeof r.n === "number" ? r.n : -1) : key === "added" ? (r.added || 0) : String(r[key] || "").toLowerCase();
    return rows.slice().sort((a, b) => { const x = val(a), y = val(b); return x < y ? -m : x > y ? m : 0; });
}
function renderRules() {
    $("#f-range").classList.toggle("hidden", $("#f-date").value !== "custom");
    const active = countActive(FILTER_DEFAULTS) + ($("#f-date").value === "custom" && ($("#f-from").value || $("#f-to").value) ? 0 : 0);
    $("#f-clear").disabled = !active;
    $("#f-clear").textContent = active ? `Clear (${active})` : "Clear";
    const isDefaultSort = S.sort.key === "n" && S.sort.dir === "asc";
    $$("#tab-rules th[data-sort]").forEach(th => {
        const a = th.querySelector(".arrow"); if (a) a.remove();
        if (!isDefaultSort && th.dataset.sort === S.sort.key) th.insertAdjacentHTML("beforeend", `<span class="arrow">${S.sort.dir === "asc" ? "▲" : "▼"}</span>`);
    });
    const all = sortRows(rulesFiltered());
    const rows = paginate("rules", all);
    const label = { allow: "Allow", block: "Block", limit: "Limit" };
    const origin = { module: ' <span class="tag blue">here</span>', external: ' <span class="tag amber">elsewhere</span>', existing: "" };
    $("#rules-body").innerHTML = rows.length ? rows.map(r => `
      <tr>
        <td class="num">${esc(r.n)}</td>
        <td><span class="main">${esc(r.port)}</span>${r.v6 ? ' <span class="tag">IPv6</span>' : ""}${r.isDefault ? ' <span class="tag green">default</span>' : ""}${r.synthetic ? ' <span class="tag">built-in</span>' : ""}</td>
        <td>${esc(String(r.proto).toUpperCase())}</td>
        <td><span class="badge ${r.action}">${label[r.action] || r.action}</span></td>
        <td>${r.synthetic && r.source ? `<span class="main">${esc(r.source)}</span>` : srcLabel(r.source)}</td>
        <td>${r.dir === "out" ? "Outgoing" : r.dir === "fwd" ? "Forward" : "Incoming"}</td>
        <td>${r.synthetic ? '<span class="muted">—</span>' : fmtDate(r.added) + (origin[r.by] || "")}</td>
        <td>${r.comment ? `<div class="cmt">${esc(r.comment)}</div>` : ""}<div class="explain">${explainRule(r)}</div></td>
        <td class="act">${r.synthetic ? '<button class="link" data-goto="settings">Settings</button>'
            : `<button class="link" data-edit="${S.rules.indexOf(r)}">Edit</button> &nbsp; <button class="link red" data-del="${S.rules.indexOf(r)}">Delete</button>`}</td>
      </tr>`).join("")
        : `<tr><td colspan="9" class="empty">${S.rules.length ? 'No rules match your filters. <button class="link" data-clear="rules">Clear filters</button>' : S.loaded ? "No rules yet. Click <b>+ Add rule</b> to create one." : "Loading…"}</td></tr>`;
}
function clearRuleFilters() {
    Object.entries(FILTER_DEFAULTS).forEach(([k, v]) => { $(k).value = v; });
    $("#f-from").value = $("#f-to").value = "";
    S.sort = { key: "n", dir: "asc" }; PG.rules.page = 1;
    renderRules();
}

/* ---------------- render: nftables ---------------- */
const N_DEFAULTS = { "#n-q": "", "#n-table": "", "#n-chain": "", "#n-action": "any", "#n-owner": "any", "#n-hits": "any", "#n-date": "any", "#n-sort": "order" };
function fillNftSelects() {
    const t = $("#n-table").value, c = $("#n-chain").value, o = $("#n-owner").value;
    $("#n-table").innerHTML = '<option value="">All tables</option>' + S.nft.tables.map(x => `<option value="${esc(x.key)}">${esc(x.fam)} ${esc(x.name)}</option>`).join("");
    $("#n-table").value = S.nft.tables.some(x => x.key === t) ? t : "";
    const chains = S.nft.chains.filter(x => !$("#n-table").value || x.table.key === $("#n-table").value);
    $("#n-chain").innerHTML = '<option value="">All chains</option>' + uniq(chains.map(x => x.name)).map(n => `<option>${esc(n)}</option>`).join("");
    $("#n-chain").value = chains.some(x => x.name === c) ? c : "";
    const owners = uniq(S.nft.rows.map(r => r.owner));
    $("#n-owner").innerHTML = '<option value="any">All owners</option>' + owners.map(n => `<option>${esc(n)}</option>`).join("");
    $("#n-owner").value = owners.includes(o) ? o : "any";
}
function nftFiltered() {
    const v = k => $(k).value, q = v("#n-q").trim().toLowerCase();
    const rows = S.nft.rows.filter(r => {
        if (v("#n-table") && r.t.key !== v("#n-table")) return false;
        if (v("#n-chain") && r.c.name !== v("#n-chain")) return false;
        if (v("#n-action") !== "any" && r.cls !== v("#n-action")) return false;
        if (v("#n-owner") !== "any" && r.owner !== v("#n-owner")) return false;
        if (v("#n-hits") === "hit" && !(r.packets > 0)) return false;
        if (v("#n-hits") === "nohit" && r.packets !== 0) return false;
        if (!inDate(r.added, "n")) return false;
        if (q && ![r.t.name, r.c.name, r.expr, r.comment, r.owner, r.explain].join(" ").toLowerCase().includes(q)) return false;
        return true;
    });
    const s = v("#n-sort");
    const num = (k, d) => (a, b) => d * ((a[k] == null ? -1 : a[k]) - (b[k] == null ? -1 : b[k]));
    if (/^(bytes|packets):/.test(s)) { const [k, d] = s.split(":"); rows.sort(num(k, d === "desc" ? -1 : 1)); }
    else if (s === "newest") rows.sort((a, b) => (b.added || 0) - (a.added || 0) || a.order - b.order);
    else if (s === "oldest") rows.sort((a, b) => (a.added || 0) - (b.added || 0) || a.order - b.order);
    else if (s === "table") rows.sort((a, b) => (a.t.key + a.c.name).localeCompare(b.t.key + b.c.name) || a.order - b.order);
    else if (s === "action") rows.sort((a, b) => a.cls.localeCompare(b.cls) || a.order - b.order);
    return rows;
}
function renderNft() {
    $("#n-range").classList.toggle("hidden", $("#n-date").value !== "custom");
    const active = countActive(N_DEFAULTS);
    $("#n-clear").disabled = !active;
    $("#n-clear").textContent = active ? `Clear (${active})` : "Clear";
    const s = $("#n-sort").value;
    $$("#tab-nft th[data-nsort]").forEach(th => {
        const a = th.querySelector(".arrow"); if (a) a.remove();
        if (s.startsWith(th.dataset.nsort + ":")) th.insertAdjacentHTML("beforeend", `<span class="arrow">${s.endsWith("desc") ? "▼" : "▲"}</span>`);
    });
    $("#n-chips").innerHTML = S.nft.tables.map(t => `<button data-t="${esc(t.key)}" class="${t.key === $("#n-table").value ? "on" : ""}" title="Managed by ${esc(t.owner)}"><span class="fam">${esc(t.fam)}</span>${esc(t.name)} · ${S.nft.rows.filter(r => r.t === t).length}</button>`).join("");

    const all = nftFiltered();
    const rows = paginate("nft", all);
    const label = r => r.cls === "allow" ? "Accept" : r.cls === "block" ? (r.verdict.startsWith("reject") ? "Reject" : "Drop") : r.verdict.split(" ")[0].replace(/^\w/, c => c.toUpperCase());
    const badge = { allow: "allow", block: "block", info: "info", other: "limit" };
    $("#n-body").innerHTML = rows.length ? rows.map(r => `
      <tr>
        <td><span class="fam">${esc(r.t.fam)}</span><span class="main">${esc(r.t.name)}</span></td>
        <td><span class="main">${esc(r.c.name)}</span><div class="meta">${r.c.hook ? esc(r.c.hook) + " hook" + (r.c.policy ? " · policy " + esc(r.c.policy) : "") : "regular chain"}</div></td>
        <td>${r.chips.length ? r.chips.map(([k, val]) => `<span class="m-chip"><b>${k}</b>${esc(val)}</span>`).join("") : '<span class="muted">everything</span>'}
            <div class="m-raw" title="${esc(r.body)}">${esc(r.body)}</div></td>
        <td><span class="badge ${badge[r.cls]}">${esc(label(r))}</span>${r.verdict.includes(" ") && r.cls === "info" ? `<div class="meta">${esc(r.verdict.split(" ")[1])}</div>` : ""}</td>
        <td>${r.packets == null ? '<span class="muted">—</span>' : fmtNum(r.packets)}</td>
        <td>${r.bytes == null ? '<span class="muted">—</span>' : fmtBytes(r.bytes)}</td>
        <td>${r.comment ? `<div class="cmt">${esc(r.comment)}</div>` : ""}<div class="explain">${r.explain}</div></td>
        <td><span class="tag ${r.owner === "This module" ? "blue" : r.owner === "Other" ? "" : "amber"}">${esc(r.owner)}</span></td>
        <td class="act"><button class="link" data-nedit="${S.nft.rows.indexOf(r)}">Edit</button> &nbsp; <button class="link red" data-ndel="${S.nft.rows.indexOf(r)}">Delete</button></td>
      </tr>`).join("")
        : `<tr><td colspan="9" class="empty">${S.nft.rows.length ? 'No rules match your filters. <button class="link" data-clear="nft">Clear filters</button>' : S.loaded ? "The nftables ruleset is empty." : "Loading…"}</td></tr>`;
    const sel = S.nft.tables.find(t => t.key === $("#n-table").value);
    if (sel) $("#nft-pager").insertAdjacentHTML("afterbegin", `<button class="link red" id="n-del-table">Delete table ${esc(sel.name)}</button><span class="muted">·</span>`);
    const dt = $("#n-del-table"); if (dt) dt.onclick = () => deleteTable(sel);

    const hq = $("#n-q").value.trim();
    let html = esc(S.nft.raw || "(empty ruleset)")
        .replace(/^(\s*)(table|chain|set|map)\b/gm, '$1<span class="k">$2</span>')
        .replace(/\b(accept)\b/g, '<span class="a">$1</span>').replace(/\b(drop|reject)\b/g, '<span class="d">$1</span>')
        .replace(/(comment &quot;.*?&quot;)/g, '<span class="c">$1</span>');
    if (hq) html = html.replace(new RegExp("(" + esc(hq).replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")(?![^<]*>)", "gi"), "<mark>$1</mark>");
    $("#n-out").innerHTML = html;
}
function clearNftFilters() {
    Object.entries(N_DEFAULTS).forEach(([k, v]) => { $(k).value = v; });
    $("#n-from").value = $("#n-to").value = ""; PG.nft.page = 1;
    fillNftSelects(); renderNft();
}
const MANAGED_WARN = {
    "UFW": "This chain is generated by UFW. Edits here are lost the next time UFW reloads — change UFW rules from the Rules tab instead.",
    "firewalld": "This table belongs to firewalld and is rebuilt on every reload — use the Rules tab instead.",
    "fail2ban": "This is fail2ban's table. fail2ban adds and removes these entries automatically.",
    "Docker": "Docker manages these rules; changing them can break container networking.",
    "Podman": "Podman manages these rules; changing them can break container networking.",
    "CrowdSec": "CrowdSec manages this table automatically.",
    "This module": "This is the built-in firewall's table and is regenerated from the Rules tab. Prefer editing there.",
    "Blacklist": "This table is managed by your Blacklist module and may be rewritten by it.",
};
async function deleteTable(t) {
    const warn = MANAGED_WARN[t.owner] ? "\n\n" + MANAGED_WARN[t.owner] : "";
    if (!await confirmBox(`Delete table ${t.fam} ${t.name}?`, `This removes the whole table and every chain and rule in it.${warn}`, "Delete table")) return;
    act(() => run(["nft", "delete", "table", t.fam, t.name]), "Table deleted", "rule-delete", `Deleted nftables table ${t.fam} ${t.name}`);
}

/* ---------------- render: status + activity ---------------- */
function healthChecks() {
    const i = S.info, c = [], add = (lvl, t, d) => c.push({ lvl, t, d });
    if (!S.engine) return c;
    const active = engineActive();
    add(active ? "ok" : "bad", active ? `${ENGINE_NAME[S.engine]} firewall is running` : "No firewall is running", active ? "Incoming traffic is being filtered." : "Every port is reachable from the internet. Open Settings to turn one on.");
    const boot = S.engine === "ufw" ? i.ufw_boot : S.engine === "firewalld" ? i.fwd_boot : i.standalone_boot;
    if (active) add(boot === "enabled" ? "ok" : "warn", boot === "enabled" ? "Starts automatically at boot" : "Won't start after a reboot", boot === "enabled" ? "The firewall service is enabled." : `Service is "${boot || "disabled"}" — protection is lost after a reboot.`);
    const n = [i.ufw === "active", i.fwd === "active", i.standalone === "1"].filter(Boolean).length;
    if (n > 1) add("bad", "More than one firewall is active", "UFW / firewalld / built-in are running together; their rules can conflict.");
    const denyDefault = /deny|drop|reject|target default|target DROP|target REJECT/i.test(S.policy);
    if (active) add(denyDefault ? "ok" : "warn", denyDefault ? "Blocks unknown traffic by default" : "Allows unknown traffic by default", denyDefault ? "Only ports you open are reachable." : "Anything not explicitly blocked is open.");
    const real = S.rules.filter(r => !r.synthetic || r.guard);
    const opens = p => !denyDefault || real.some(r => r.action !== "block" && (r.port === p || r.port.split(",").includes(p) || /^all/i.test(r.port) || r.proto === "service" && (p === "22" ? r.port === "ssh" : r.port === "cockpit")));
    if (active) add(opens("22") ? "ok" : "warn", opens("22") ? "SSH (22) is reachable" : "No rule allows SSH (22)", opens("22") ? "You can still log in remotely." : "Make sure you have another way in before logging out.");
    if (active && S.engine === "ufw") add(i.ufw_ipv6 === "yes" ? "ok" : "warn", i.ufw_ipv6 === "yes" ? "IPv6 is protected" : "IPv6 is not filtered by UFW", i.ufw_ipv6 === "yes" ? "Rules apply to IPv4 and IPv6." : "Set IPV6=yes in /etc/default/ufw.");
    if (S.engine === "nft" && active) {
        const want = S.cfg.rules.length, have = +i.standalone_loaded || 0;
        add(want === have ? "ok" : "warn", want === have ? "Loaded rules match saved rules" : "Loaded rules differ from saved rules", want === have ? `${have} rules active.` : `${have} loaded vs ${want} saved — click Refresh to re-apply.`);
    }
    if (i.docker === "active") add("warn", "Docker can bypass this firewall", "Ports published with docker -p are opened by Docker directly, before UFW/built-in rules.");
    if (i.f2b === "active") add("ok", "fail2ban is running", "Repeated failed logins are banned automatically.");
    else add("info", "fail2ban is not running", "Brute-force bans are off.");
    if (S.blockedLoaded) {
        const day = S.blocked.filter(b => b.ts > Date.now() - DAY).length;
        add("info", `${fmtNum(day)} blocked connections in the last 24h`, S.blocked.length ? `${fmtNum(S.blocked.length)} in the last 30 days (from the kernel log).` : "Turn on logging (Settings) to record blocked traffic.");
    }
    return c;
}
function renderHealth() {
    const c = healthChecks(); if (!c.length) return;
    const bad = c.filter(x => x.lvl === "bad").length, warn = c.filter(x => x.lvl === "warn").length;
    const lvl = bad ? "bad" : warn ? "warn" : "ok";
    $("#t-health").textContent = bad ? bad + " problem" + (bad > 1 ? "s" : "") : warn ? warn + " warning" + (warn > 1 ? "s" : "") : "Healthy";
    $("#t-health").className = "pill " + (bad ? "pill-bad" : warn ? "pill-warn" : "pill-ok");
    $("#health").innerHTML = `<div class="hc summary ${lvl}"><span class="dot"></span><div><div class="t">${bad ? "Your firewall needs attention" : warn ? "Firewall is working, with warnings" : "Firewall is healthy"}</div><div class="d">${bad} problems · ${warn} warnings · checked ${new Date().toLocaleTimeString()}</div></div></div>` +
        c.map(x => `<div class="hc ${x.lvl}"><span class="dot"></span><div><div class="t">${esc(x.t)}</div><div class="d">${esc(x.d)}</div></div></div>`).join("");
}
const L_DEFAULTS = { "#l-q": "", "#l-type": "any", "#l-user": "any", "#l-date": "any", "#l-sort": "desc" };
const EV_LABEL = { "rule-add": "Rule added", "rule-edit": "Rule edited", "rule-delete": "Rule deleted", external: "Outside change", setting: "Setting", engine: "Engine", reload: "Reload", blocked: "Blocked" };
function logRows() {
    const v = k => $(k).value, q = v("#l-q").trim().toLowerCase(), t = v("#l-type");
    let rows = S.log.concat(t === "any" || t === "blocked" ? S.blocked : []);
    rows = rows.filter(e => {
        if (t === "changes" && !/^(rule-|external|setting|engine)/.test(e.type)) return false;
        if (!["any", "changes"].includes(t) && e.type !== t) return false;
        if (v("#l-user") !== "any" && e.user !== v("#l-user")) return false;
        if (!inDate(e.ts, "l")) return false;
        if (q && ![e.msg, e.detail, e.user, e.src, e.type].join(" ").toLowerCase().includes(q)) return false;
        return true;
    });
    const d = v("#l-sort") === "asc" ? 1 : -1;
    return rows.sort((a, b) => d * (a.ts - b.ts));
}
function renderLog() {
    $("#l-range").classList.toggle("hidden", $("#l-date").value !== "custom");
    const u = $("#l-user").value;
    const users = uniq(S.log.map(e => e.user)).filter(Boolean);
    $("#l-user").innerHTML = '<option value="any">All users</option>' + users.map(x => `<option>${esc(x)}</option>`).join("");
    $("#l-user").value = users.includes(u) ? u : "any";
    const active = countActive(L_DEFAULTS);
    $("#l-clear").disabled = !active; $("#l-clear").textContent = active ? `Clear (${active})` : "Clear";
    const rows = paginate("log", logRows());
    $("#l-body").innerHTML = rows.length ? rows.map(e => `<tr>
        <td class="time">${esc(fmtTime(e.ts))}</td>
        <td><span class="badge ${e.type === "blocked" || e.type === "rule-delete" ? "block" : e.type === "rule-add" ? "allow" : e.type === "external" ? "limit" : "ev"}">${esc(EV_LABEL[e.type] || e.type)}</span></td>
        <td><span class="main">${esc(e.msg)}</span>${e.detail ? `<div class="meta">${esc(e.detail)}</div>` : ""}</td>
        <td>${esc(e.user)}</td><td><span class="tag">${esc(e.src)}</span></td></tr>`).join("")
        : `<tr><td colspan="5" class="empty">${S.log.length || S.blocked.length ? 'No events match your filters. <button class="link" data-clear="log">Clear filters</button>' : "No activity recorded yet. Changes made from this page are logged here from now on."}</td></tr>`;
}
function exportLogCsv() {
    const q = s => '"' + String(s == null ? "" : s).replace(/"/g, '""') + '"';
    const csv = ["time,event,details,extra,user,source"].concat(logRows().map(e => [new Date(e.ts).toISOString(), EV_LABEL[e.type] || e.type, e.msg, e.detail, e.user, e.src].map(q).join(","))).join("\n");
    download(`firewall-activity-${new Date().toISOString().slice(0, 10)}.csv`, csv, "text/csv");
}
function download(name, text, type) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type }));
    a.download = name; document.body.appendChild(a); a.click(); a.remove();
}

/* ---------------- nft add/edit modal ---------------- */
function openNftModal(row) {
    S.nm = { pos: "insert", edit: row || null };
    $("#nm-title").textContent = row ? `Edit nftables rule (handle ${row.handle})` : "Add nftables rule";
    $("#nm-table").innerHTML = S.nft.tables.map(t => `<option value="${esc(t.key)}">${esc(t.fam)} ${esc(t.name)}</option>`).join("");
    $("#nm-table").disabled = $("#nm-chain").disabled = !!row;
    $("#nm-pos-f").classList.toggle("hidden", !!row);
    if (row) $("#nm-table").value = row.t.key; else if ($("#n-table").value) $("#nm-table").value = $("#n-table").value;
    fillNmChains(row ? row.c.name : $("#n-chain").value);
    $("#nm-expr").value = row ? row.body : "";
    $("#nm-comment").value = row ? row.comment : "";
    $("#nb-src").value = $("#nb-port").value = "";
    setSeg("nm-pos", "insert");
    updateNm();
    $("#nmodal").classList.remove("hidden");
}
function fillNmChains(pref) {
    const chains = S.nft.chains.filter(c => c.table.key === $("#nm-table").value);
    $("#nm-chain").innerHTML = chains.map(c => `<option>${esc(c.name)}</option>`).join("");
    if (chains.some(c => c.name === pref)) $("#nm-chain").value = pref;
}
function buildExpr() {
    const src = $("#nb-src").value.trim(), port = $("#nb-port").value.replace(/\s/g, ""), pr = $("#nb-proto").value;
    const p = [];
    if (src) p.push(`${isV6(src) ? "ip6" : "ip"} saddr ${src}`);
    if (port) { const set = port.includes(",") ? `{ ${port.split(",").join(", ")} }` : port; p.push(pr === "both" ? `meta l4proto { tcp, udp } th dport ${set}` : `${pr} dport ${set}`); }
    p.push("counter", $("#nb-act").value);
    $("#nm-expr").value = p.join(" ");
    updateNm();
}
function nmCommand() {
    const [fam, tbl] = $("#nm-table").value.split(" ");
    const chain = $("#nm-chain").value;
    let expr = $("#nm-expr").value.replace(/\s+/g, " ").trim();
    const c = cleanComment($("#nm-comment").value);
    if (c) expr += ` comment "${c}"`;
    if (!fam || !chain || !expr) return null;
    return S.nm.edit ? `replace rule ${fam} ${tbl} ${chain} handle ${S.nm.edit.handle} ${expr}` : `${S.nm.pos} rule ${fam} ${tbl} ${chain} ${expr}`;
}
function updateNm() {
    const t = S.nft.tables.find(x => x.key === $("#nm-table").value);
    const owner = S.nm.edit ? S.nm.edit.owner : t ? t.owner : "";
    $("#nm-owner-warn").className = MANAGED_WARN[owner] ? "warn" : "warn hidden";
    $("#nm-owner-warn").textContent = MANAGED_WARN[owner] || "";
    const cmd = nmCommand(), bad = /[;`$|&]/.test($("#nm-expr").value);
    $("#nm-warn").className = bad ? "warn err" : "warn hidden";
    $("#nm-warn").textContent = bad ? "The expression can't contain ; ` $ | or & — enter one rule at a time." : "";
    $("#nm-save").disabled = !cmd || bad;
    $("#nm-preview").textContent = cmd ? "nft " + cmd : "—";
    const body = $("#nm-expr").value.trim();
    $("#nm-explain").innerHTML = body ? "<b>In plain English:</b> " + mkNftRow(t || { name: "", fam: "", key: "" }, { name: $("#nm-chain").value || "" }, body, 0, 0).explain : "";
}
async function saveNm() {
    const cmd = nmCommand(); if (!cmd) return;
    $("#nm-save").disabled = true;
    try { await run(["nft", cmd]); $("#nmodal").classList.add("hidden"); }
    catch (e) { toast(errMsg(e), true); $("#nm-save").disabled = false; return; }
    act(null, S.nm.edit ? "nftables rule updated" : "nftables rule added", S.nm.edit ? "rule-edit" : "rule-add", "nft " + cmd);
}
async function deleteNftRow(r) {
    const warn = MANAGED_WARN[r.owner] ? "\n\n" + MANAGED_WARN[r.owner] : "";
    if (!await confirmBox("Delete nftables rule?", `${r.t.fam} ${r.t.name} › ${r.c.name}\n${r.body}${warn}`, "Delete")) return;
    act(() => run(["nft", "delete", "rule", r.t.fam, r.t.name, r.c.name, "handle", String(r.handle)]), "Rule deleted", "rule-delete", `nftables ${r.t.name} › ${r.c.name}: ${r.body}`);
}

/* ---------------- settings ---------------- */
function sw(id, checked, title, desc, disabled, cls) {
    return `<label class="sw ${cls || ""}"><input type="checkbox" id="${id}" ${checked ? "checked" : ""} ${disabled ? "disabled" : ""}><span class="knob"></span><span><b>${title}</b>${desc ? `<span class="muted">${desc}</span>` : ""}</span></label>`;
}
function engineBadge(on, installed) { return installed === false ? '<span class="badge">Not installed</span>' : `<span class="badge ${on ? "allow" : "block"}">${on ? "Active" : "Inactive"}</span>`; }
function renderSettings() {
    if (!S.engine) return;
    const i = S.info, c = S.cfg;
    const nftOn = i.standalone === "1", ufwIn = i.ufw_installed === "1", fwdIn = i.fwd_installed === "1";
    const conflict = i.ufw === "active" || i.fwd === "active";
    const mode = c.policy !== "drop" ? "allow" : c.trustAll ? "lockdown" : "block";
    const H = [];

    /* ---- top: engines ---- */
    H.push('<h2 class="sec">Firewall engines</h2><div class="grid3">');
    H.push(`<div class="box ${conflict ? "dim" : ""}"><h3>Built-in firewall ${engineBadge(nftOn)}</h3>
      <p>Lightweight nftables firewall managed entirely by this page. Rules live in <code>${CFG}</code> and are restored at boot.</p>
      <label class="radio"><input type="radio" name="mode" value="block" ${mode === "block" ? "checked" : ""} ${conflict ? "disabled" : ""}><span><b>Block by default</b> — closed unless a rule allows it (recommended)</span></label>
      <label class="radio"><input type="radio" name="mode" value="lockdown" ${mode === "lockdown" ? "checked" : ""} ${conflict ? "disabled" : ""}><span><b>Block by default + trusted IPs get everything</b> — your IP and whitelist reach every port</span></label>
      <label class="radio"><input type="radio" name="mode" value="allow" ${mode === "allow" ? "checked" : ""} ${conflict ? "disabled" : ""}><span><b>Allow by default</b> — open unless a rule blocks it</span></label>
      ${sw("s-guard", c.guard !== false, "Lockout guard", "Always keep SSH (22) and Cockpit (9090) reachable when blocking by default.", conflict)}
      <div class="actions">
        ${conflict ? `<span class="note">Off while ${i.ufw === "active" ? "UFW" : "firewalld"} runs</span>` : ""}
        <button class="btn" id="s-nft-wizard" ${conflict ? "disabled" : ""}>Setup wizard</button>
        <button class="btn" id="s-nft-reset" ${conflict ? "disabled" : ""}>Reset</button>
        ${nftOn ? `<button class="btn" id="s-nft-reload">Reload</button><button class="btn danger" id="s-nft-off">Turn off</button>` : `<button class="btn green" id="s-nft-on" ${conflict || i.nft_installed !== "1" ? "disabled" : ""}>Turn on</button>`}
      </div></div>`);
    const ufwOn = i.ufw === "active";
    const def = /deny \(incoming\)/.test(S.policy) ? "deny" : /allow \(incoming\)/.test(S.policy) ? "allow" : "";
    H.push(`<div class="box ${ufwIn ? "" : "dim"}"><h3>UFW ${engineBadge(ufwOn, ufwIn)}</h3>
      <p>Uncomplicated Firewall — Ubuntu's standard firewall. ${ufwOn ? "This page is managing it." : ufwIn ? "Enable it to manage UFW rules here." : "Not installed on this server."}</p>
      ${ufwOn ? `<div class="kv"><span>Incoming default</span><span><div class="seg" id="s-ufwdef"><button data-v="deny" class="${def === "deny" ? "on block" : ""}">Deny</button><button data-v="allow" class="${def === "allow" ? "on allow" : ""}">Allow</button></div></span>
          <span>Logging</span><span><select id="s-ufwlog">${["off", "low", "medium", "high"].map(l => `<option ${(l === "off" ? /^off/.test(S.ufwLogging) : S.ufwLogging.includes("(" + l + ")")) ? "selected" : ""}>${l}</option>`).join("")}</select></span>
          <span>IPv6</span><span>${i.ufw_ipv6 === "yes" ? "filtered" : '<span class="err-text">not filtered</span>'}</span>
          <span>Starts at boot</span><span>${esc(i.ufw_boot || "—")}</span></div>` : ""}
      <div class="actions">${!ufwIn ? `<button class="btn" id="s-ufw-install">Install UFW</button>` : ufwOn ? `<button class="btn" id="s-ufw-reset">Reset</button><button class="btn" id="s-ufw-reload">Reload</button><button class="btn danger" id="s-ufw-off">Disable</button>` : `<button class="btn primary" id="s-ufw-on">Enable UFW</button>`}</div></div>`);
    const fwdOn = i.fwd === "active";
    H.push(`<div class="box ${fwdIn ? "" : "dim"}"><h3>firewalld ${engineBadge(fwdOn, fwdIn)}</h3>
      <p>Zone-based firewall used by Red Hat-style systems and Cockpit's built-in Networking page. ${fwdOn ? "Managing default zone <b>" + esc(S.zone) + "</b>." : fwdIn ? "Installed but not running." : "Not installed on this server."}</p>
      ${fwdOn ? `<div class="kv"><span>Zone / target</span><span>${esc(S.policy)}</span><span>Starts at boot</span><span>${esc(i.fwd_boot || "—")}</span></div>` : ""}
      <div class="actions">${!fwdIn ? `<button class="btn" id="s-fwd-install">Install firewalld</button>` : fwdOn ? `<button class="btn" id="s-fwd-reload">Reload</button><button class="btn danger" id="s-fwd-off">Stop</button>` : `<button class="btn primary" id="s-fwd-on">Start firewalld</button>`}</div></div>`);
    H.push("</div>");

    /* ---- middle: detection + protection ---- */
    const n = S.net || {}, others = [];
    if (i.f2b === "active") others.push(["fail2ban", "active — bans IPs after failed logins (your Blacklist module)"]);
    if (i.crowdsec === "active") others.push(["CrowdSec bouncer", "active — blocks IPs from CrowdSec decisions"]);
    if (i.csf === "1") others.push(["CSF", "installed — has its own rules in /etc/csf"]);
    if (i.docker === "active") others.push(["Docker", "active — published ports bypass UFW / built-in rules"]);
    if (+i.iptlegacy > 0) others.push(["iptables-legacy", i.iptlegacy + " legacy rules (not visible in nftables)"]);
    const cfLine = n.cfCockpit ? `Cockpit is reached through Cloudflare${n.colo ? " (edge " + esc(n.colo) + ")" : ""}`
        : n.webCf ? `Your websites are behind Cloudflare (${n.webCf} of ${n.webTotal} web connections come from Cloudflare)`
        : n.tunnel ? "cloudflared tunnel is running on this server" : n.webTotal ? "Not detected on your web traffic" : "Not detected";
    H.push('<h2 class="sec">Detection &amp; protection</h2><div class="grid3">');
    H.push(`<div class="box"><h3>Your connection &amp; environment</h3>
      <p>Detected automatically from your browser, your Cockpit / SSH sessions and live traffic.</p>
      <div class="list">${S.myips.length ? S.myips.map(m => `<div class="li"><span class="grow"><b>${esc(m.ip)}</b> <span class="muted">— ${esc(m.via)}</span></span>
            ${isWhitelisted(m.ip) ? '<span class="tag green">whitelisted</span>' : `<button class="link" data-wladd="${esc(m.ip)}">Add to whitelist</button>`}</div>`).join("")
            : `<div class="li"><span class="grow muted">${S.net ? "Couldn't detect your public IP (a browser extension may block ipify.org). Add it to the whitelist manually." : "Detecting…"}</span></div>`}</div>
      <div class="kv">
        <span>Cloudflare</span><span>${S.net ? cfLine : "…"}</span>
        <span>VPN (WARP)</span><span>${n.warp === "on" || n.warp === "plus" ? '<span class="tag amber">WARP on</span> — your IP may change' : n.warp === "off" ? "No Cloudflare WARP VPN detected" : "unknown"}</span>
        <span>Reverse proxy</span><span>${n.proxy ? esc(n.proxy) + " listens on 443" : "none on 443"}</span>
        <span>Server VPN links</span><span>${n.vpnIfaces && n.vpnIfaces.length ? n.vpnIfaces.map(v => `${esc(v.dev)} ${esc(v.net)}`).join(", ") : "none"}</span>
        <span>Server address</span><span>${esc(n.serverIp || "—")}</span>
      </div>
      ${others.length ? `<h4>Also detected</h4><div class="list">${others.map(([a, b]) => `<div class="li"><span class="grow"><b>${esc(a)}</b> <span class="muted">— ${esc(b)}</span></span></div>`).join("")}</div>` : ""}
      <div class="actions">
        ${S.engine === "nft" ? sw("s-cf", c.cloudflare, "Allow Cloudflare → 80/443", "", conflict, "inline-sw") : `<button class="btn" id="s-cf-rules">Allow Cloudflare on 80/443</button>`}
        ${n.vpnIfaces && n.vpnIfaces.length ? `<button class="btn" id="s-vpn">Trust VPN subnets</button>` : ""}
        <button class="btn" id="s-redetect">Re-detect</button>
      </div></div>`);
    H.push(`<div class="box"><h3>Whitelist sources <span class="pill">${S.whitelist.length} IPs</span></h3>
      <p>Found automatically: fail2ban <code>ignoreip</code> (what your Blacklist module syncs), CSF, hosts.allow and any *whitelist* / *allowlist* file under /etc and /opt. Untick a source to ignore it.</p>
      <div class="list">${S.wlSources.map(s => `<div class="li">
          <input type="checkbox" data-wlsrc="${esc(s.path)}" ${S.settings.disabledFiles.includes(s.path) ? "" : "checked"}>
          <span class="grow"><div class="path" title="${esc(s.path)}">${esc(s.path)}</div><span class="muted small">${esc(s.kind)} · ${s.missing ? '<span class="err-text">file not found</span>' : s.ips.length + " IPs"}${s.ips.length ? " — " + esc(s.ips.slice(0, 3).join(", ")) + (s.ips.length > 3 ? "…" : "") : ""}</span></span>
          ${s.custom ? `<button class="link red" data-wlrm="${esc(s.path)}">Remove</button>` : ""}</div>`).join("") || '<div class="li muted">Scanning…</div>'}</div>
      <div class="inline"><input id="s-wlfile" placeholder="Add a file, e.g. /etc/myapp/allowed_ips.txt"><button class="btn" id="s-wlfile-add">Add file</button></div>
      <div class="inline"><input id="s-wlip" placeholder="Add an IP or range"><button class="btn" id="s-wlip-add">Add IP</button></div>
      <div class="actions"><button class="btn" id="s-rescan">Rescan</button></div></div>`);
    const nftMode = S.engine === "nft";
    H.push(`<div class="box"><h3>Protection extras</h3>
      <p>${nftMode ? "Applied by the built-in firewall." : S.engine === "ufw" ? "Applied through UFW." : "firewalld: use rich rules with limits from the Rules tab."}</p>
      ${nftMode ? sw("s-icmp", c.icmp !== false, "Answer ping", "Turn off to hide from simple ping scans. Other ICMP still works.") : ""}
      ${nftMode || S.engine === "ufw" ? sw("s-ssh", nftMode ? c.sshLimit : S.rules.some(r => r.action === "limit" && r.port === "22"), "SSH brute-force limit", nftMode ? "Drop IPs opening more than 10 SSH connections a minute (whitelist exempt)." : "ufw limit 22/tcp — 6 connections per 30 s per IP.") : ""}
      ${nftMode ? sw("s-log", c.logDrops, "Log blocked connections", "Shows blocked traffic in Status & activity. Only when blocking by default.") : ""}
      ${S.engine === "ufw" ? sw("s-ufwlog-sw", !/^off/.test(S.ufwLogging || "off"), "Log blocked connections", "UFW logging (low). Shows blocked traffic in Status & activity.") : ""}
      <div class="actions"><button class="btn" id="s-export">Download backup</button></div></div>`);
    H.push("</div>");

    /* ---- bottom: hosting provider ---- */
    const p = S.provider || {}, dmi = p.dmi || {};
    H.push('<h2 class="sec">Hosting provider firewall</h2><div class="grid1">');
    H.push(`<div class="box"><h3>${p.id ? esc(p.fw) + ' <span class="badge info">' + esc(p.name) + "</span>" : "Provider firewall"}</h3>
      ${p.id ? `<p>This server is hosted at <b>${esc(p.name)}</b>, which offers <b>${esc(p.fw)}</b>. It runs on ${esc(p.name)}'s network <i>in front of</i> your server, so its rules aren't visible from inside the server. ${esc(p.api || "")}</p>
          <div class="kv"><span>Where to find it</span><span>${esc(p.where)}</span><span>Detected from</span><span>${esc([dmi.vendor, dmi.product, dmi.host].filter(Boolean).join(" · "))}</span></div>
          <p class="small">If it's switched on, a port must be open <b>there and here</b>. If a port you opened here still isn't reachable, check the provider firewall first.</p>`
        : `<p>${S.provider ? `Couldn't identify the hosting provider (${esc([dmi.vendor, dmi.product, dmi.virt].filter(Boolean).join(" · ") || "no hardware info")}).` : "Detecting…"} If your host has a network firewall, ports must be open there too.</p>`}
      <div class="actions">${p.url ? `<a class="btn primary" href="${esc(p.url)}" target="_blank" rel="noopener">Log in to ${esc(p.name)} ↗</a>` : ""}</div></div></div>`);

    $("#settings-body").innerHTML = H.join("");
    wireSettings();
}

function wireSettings() {
    const on = (id, fn) => { const el = $(id); if (el) el.onclick = fn; };
    const chg = (id, fn) => { const el = $(id); if (el) el.onchange = () => fn(el.type === "checkbox" ? el.checked : el.value); };
    const i = S.info;
    $$('input[name="mode"]').forEach(el => el.onchange = async () => {
        const v = el.value;
        if (v !== "allow" && S.cfg.guard === false && i.standalone === "1" &&
            !await confirmBox("Block by default without the lockout guard?", "Make sure you have an allow rule for SSH/Cockpit from your IP, or you may lose access.", "Apply")) return renderSettings();
        S.cfg.policy = v === "allow" ? "accept" : "drop"; S.cfg.trustAll = v === "lockdown";
        act(() => nftEngine.save(false), "Default behaviour saved", "setting", "Built-in default: " + el.parentElement.querySelector("b").textContent);
    });
    const cfgSw = (id, key, label) => chg(id, v => { S.cfg[key] = v; act(() => nftEngine.save(false), `${label} ${v ? "on" : "off"}`, "setting", `${label} turned ${v ? "on" : "off"}`); });
    cfgSw("#s-guard", "guard", "Lockout guard"); cfgSw("#s-cf", "cloudflare", "Cloudflare allow rule");
    cfgSw("#s-icmp", "icmp", "Ping replies"); cfgSw("#s-log", "logDrops", "Blocked-traffic logging");
    chg("#s-ssh", v => {
        if (S.engine === "nft") { S.cfg.sshLimit = v; act(() => nftEngine.save(false), "SSH limit " + (v ? "on" : "off"), "setting", "SSH brute-force limit " + (v ? "on" : "off")); }
        else act(() => v ? run(["ufw", "limit", "22/tcp"]) : run(["ufw", "delete", "limit", "22/tcp"]), "SSH limit " + (v ? "on" : "off"), "setting", "UFW SSH limit " + (v ? "on" : "off"));
    });
    chg("#s-ufwlog-sw", v => act(() => run(["ufw", "logging", v ? "low" : "off"]), "UFW logging " + (v ? "on" : "off"), "setting", "UFW logging " + (v ? "low" : "off")));

    on("#s-nft-wizard", openSetup);
    on("#s-nft-on", enableStandalone);
    on("#s-nft-reload", () => act(() => nftEngine.reload(), "Built-in firewall reloaded", "reload", "Re-applied " + NFT_FILE));
    on("#s-nft-off", async () => { if (await confirmBox("Turn off built-in firewall?", "All built-in rules stop being enforced (they stay saved).", "Turn off")) act(() => nftEngine.disable(), "Built-in firewall turned off", "engine", "Built-in firewall turned off"); });
    on("#s-nft-reset", async () => {
        if (!await confirmBox("Reset built-in firewall?", "Deletes every built-in rule and setting and turns the built-in firewall off. Your whitelist files are not touched.", "Reset")) return;
        act(async () => { await nftEngine.disable(); S.cfg = Object.assign({}, CFG_DEFAULT, { rules: [] }); await writeFile(CFG, JSON.stringify(S.cfg, null, 2) + "\n"); S.settings.setupDone = false; await saveSettings(); }, "Built-in firewall reset", "engine", "Built-in firewall reset to defaults");
    });

    on("#s-ufw-on", async () => {
        if (!await confirmBox("Enable UFW?", "SSH (22) and Cockpit (9090) are allowed first so you don't get locked out." + (i.standalone === "1" ? " The built-in firewall will be turned off." : ""), "Enable", true)) return;
        act(async () => { await nftEngine.disable(); await run(["ufw", "allow", "22/tcp"]); await run(["ufw", "allow", "9090/tcp"]); await run(["ufw", "--force", "enable"]); }, "UFW enabled", "engine", "UFW enabled");
    });
    on("#s-ufw-off", async () => { if (await confirmBox("Disable UFW?", "UFW rules stop being enforced. You can use the built-in firewall instead.", "Disable")) act(() => run(["ufw", "disable"]), "UFW disabled", "engine", "UFW disabled"); });
    on("#s-ufw-reload", () => act(() => ufw.reload(), "UFW reloaded", "reload", "ufw reload"));
    on("#s-ufw-reset", async () => {
        if (!await confirmBox("Reset UFW?", "Deletes ALL UFW rules (UFW keeps a backup in /etc/ufw) and re-enables it with only SSH (22) and Cockpit (9090) allowed.", "Reset UFW")) return;
        act(async () => { await run(["ufw", "--force", "reset"]); await run(["ufw", "default", "deny", "incoming"]); await run(["ufw", "allow", "22/tcp"]); await run(["ufw", "allow", "9090/tcp"]); await run(["ufw", "--force", "enable"]); }, "UFW reset", "engine", "UFW reset — only 22 and 9090 allowed");
    });
    const install = (pkg) => async () => {
        if (!await confirmBox(`Install ${pkg}?`, `Runs apt-get install ${pkg}. It will be installed but not enabled.`, "Install", true)) return;
        act(() => sh(`DEBIAN_FRONTEND=noninteractive apt-get install -y "$1" && { [ "$1" = firewalld ] && systemctl disable --now firewalld || true; }`, [pkg]), pkg + " installed", "engine", pkg + " installed");
    };
    on("#s-ufw-install", install("ufw")); on("#s-fwd-install", install("firewalld"));
    $$("#s-ufwdef button").forEach(b => b.onclick = async () => {
        if (b.dataset.v === "deny" && !S.rules.some(r => r.action === "allow" && /\b22\b/.test(r.port)) &&
            !await confirmBox("Deny incoming by default?", "There is no allow rule for SSH (22). You could lose SSH access.", "Apply anyway")) return;
        act(() => run(["ufw", "default", b.dataset.v, "incoming"]), "Default incoming: " + b.dataset.v, "setting", "UFW default incoming → " + b.dataset.v);
    });
    chg("#s-ufwlog", v => act(() => run(["ufw", "logging", v]), "UFW logging: " + v, "setting", "UFW logging → " + v));
    on("#s-fwd-on", async () => {
        if (!await confirmBox("Start firewalld?", (i.ufw === "active" ? "UFW is also active — running two firewalls is not recommended. " : "") + "SSH and Cockpit will be allowed.", "Start", true)) return;
        act(async () => { await nftEngine.disable(); await run(["systemctl", "enable", "--now", "firewalld"]); await run(["firewall-cmd", "--permanent", "--add-service=ssh"]); await run(["firewall-cmd", "--permanent", "--add-service=cockpit"]).catch(() => {}); await run(["firewall-cmd", "--reload"]); }, "firewalld started", "engine", "firewalld started");
    });
    on("#s-fwd-off", async () => { if (await confirmBox("Stop firewalld?", "firewalld rules stop being enforced.", "Stop")) act(() => run(["systemctl", "disable", "--now", "firewalld"]), "firewalld stopped", "engine", "firewalld stopped"); });
    on("#s-fwd-reload", () => act(() => firewalld.reload(), "firewalld reloaded", "reload", "firewall-cmd --reload"));

    on("#s-cf-rules", async () => {
        const n = (CF4.length + CF6.length);
        if (!await confirmBox("Allow Cloudflare on 80/443?", `Adds about ${n * (S.engine === "ufw" ? 1 : 2)} ${ENGINE_NAME[S.engine]} rules (one per Cloudflare range).`, "Add rules", true)) return;
        act(async () => {
            S.pending = { add: true };
            for (const ip of CF4.concat(CF6)) for (const cmd of ENGINES[S.engine].cmds({ action: "allow", port: "80,443", proto: "tcp", source: ip, comment: "Cloudflare" })) await run(cmd).catch(() => {});
        }, "Cloudflare ranges allowed", "rule-add", "Allowed Cloudflare ranges on 80/443");
    });
    on("#s-vpn", async () => {
        const nets = S.net.vpnIfaces.map(v => v.net).filter(validIp);
        if (!await confirmBox("Trust VPN subnets?", `Adds these to the module whitelist: ${nets.join(", ")}`, "Add", true)) return;
        act(() => addOwnWhitelist(nets), "VPN subnets whitelisted", "setting", "Whitelisted " + nets.join(", "));
    });
    $$("[data-wladd]").forEach(b => b.onclick = () => act(() => addOwnWhitelist([b.dataset.wladd]), "Added to whitelist", "setting", "Whitelisted " + b.dataset.wladd));
    $$("[data-wlsrc]").forEach(cb => cb.onchange = () => {
        const p = cb.dataset.wlsrc, d = S.settings.disabledFiles;
        S.settings.disabledFiles = cb.checked ? d.filter(x => x !== p) : uniq(d.concat(p));
        act(saveSettings, null, "setting", `Whitelist source ${cb.checked ? "enabled" : "disabled"}: ${p}`);
    });
    $$("[data-wlrm]").forEach(b => b.onclick = () => { S.settings.customFiles = S.settings.customFiles.filter(x => x !== b.dataset.wlrm); act(saveSettings, "Source removed", "setting", "Removed whitelist file " + b.dataset.wlrm); });
    on("#s-wlfile-add", () => {
        const p = $("#s-wlfile").value.trim();
        if (!/^\/[\w./@+-]+$/.test(p)) return toast("Enter an absolute file path, e.g. /etc/myapp/allow.txt", true);
        S.settings.customFiles = uniq(S.settings.customFiles.concat(p));
        act(saveSettings, "Whitelist file added", "setting", "Added whitelist file " + p);
    });
    on("#s-wlip-add", () => {
        const ip = $("#s-wlip").value.trim();
        if (!validIp(ip)) return toast("That isn't a valid IP or CIDR range.", true);
        act(() => addOwnWhitelist([ip]), ip + " added to whitelist", "setting", "Whitelisted " + ip);
    });
    on("#s-rescan", () => slowPhase().then(() => toast("Rescanned")));
    on("#s-redetect", () => slowPhase().then(() => toast("Re-detected")));
    on("#s-export", exportBackup);
}

async function addOwnWhitelist(ips) {
    const cur = (await readFile(OWN_WL)) || "# Cockpit Firewall Manager whitelist — one IP or CIDR per line\n";
    const have = new Set(cur.split("\n").map(l => l.trim()));
    await writeFile(OWN_WL, cur.replace(/\n*$/, "\n") + ips.filter(ip => !have.has(ip)).map(ip => ip + "\n").join(""));
    S.settings.disabledFiles = S.settings.disabledFiles.filter(p => p !== OWN_WL);
    await saveSettings();
    await loadWhitelist();
    if (S.engine === "nft" && S.cfg.trustAll) await nftEngine.save(false);
}
function exportBackup() {
    const data = {
        exported: new Date().toISOString(), engine: S.engine, policy: S.policy,
        rules: S.rules.filter(r => !r.synthetic).map(({ n, port, proto, action, source, dir, comment, v6, added }) => ({ n, port, proto, action, source, dir, comment, v6, added })),
        builtin: S.cfg, whitelist: S.whitelist, nftables: S.nft.raw,
    };
    download(`firewall-backup-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(data, null, 2), "application/json");
}
async function enableStandalone() {
    if (!S.cfg.rules.length && S.cfg.policy !== "drop") return openSetup();
    if (!await confirmBox("Turn on built-in firewall?", `Your ${S.cfg.rules.length} rule(s) will be enforced and restored at every boot. Default: ${S.cfg.policy === "drop" ? "block" : "allow"} incoming.`, "Turn on", true)) return;
    act(() => nftEngine.enable(), "Built-in firewall is on", "engine", "Built-in firewall turned on");
}

/* ---------------- first-run wizard ---------------- */
function openSetup() {
    S.setupShown = true;
    $("#su-ports").innerHTML = DEFAULT_OPEN.map(([n, p]) => `<label><input type="checkbox" value="${p}" checked> ${n} ${p}</label>`).join("");
    const t = trustedList();
    $("#su-trust-info").textContent = t.length ? `(${t.length} IPs: ${t.slice(0, 3).join(", ")}${t.length > 3 ? "…" : ""})` : "(none detected yet)";
    $("#su-extra").value = "";
    $("#setup").classList.remove("hidden");
}
async function runSetup() {
    const ports = $$("#su-ports input:checked").map(x => x.value);
    const extra = $("#su-extra").value.replace(/\s/g, "");
    if (extra && !validPort(extra)) return toast("Extra ports must look like 8080 or 8080,25565", true);
    if (extra) extra.split(",").forEach(p => ports.push(p));
    $("#setup").classList.add("hidden");
    const have = new Set(S.cfg.rules.map(r => `${r.port}|${r.source}|${r.action}`));
    ports.forEach((p, i) => {
        if (have.has(`${p}||allow`)) return;
        const name = (DEFAULT_OPEN.find(d => d[1] === p) || [])[0];
        S.cfg.rules.push({ id: Date.now().toString(36) + i, action: "allow", port: p, proto: p === "443" ? "both" : "tcp", source: "", comment: name ? name + " (default)" : "default", isDefault: true, added: Date.now() });
    });
    Object.assign(S.cfg, { policy: "drop", guard: true, trustAll: $("#su-trust").checked, sshLimit: $("#su-ssh").checked });
    S.settings.setupDone = true;
    S.pending = { add: true };
    act(async () => { await saveSettings(); await nftEngine.enable(); }, "Firewall is on — everything else is blocked", "engine", `Setup wizard: block by default, open ${ports.join(", ")}`);
}

/* ---------------- add / edit rule modal ---------------- */
function setSeg(id, v) { $$(`#${id} button`).forEach(b => b.classList.toggle("on", b.dataset.v === v)); }
function openModal(rule) {
    const edit = rule || null;
    S.m = { action: "allow", proto: "tcp", src: "anyone", edit };
    $("#m-limit").classList.toggle("hidden", S.engine === "firewalld");
    $("#m-me").innerHTML = S.myips.length ? S.myips.map(m => `<option value="${esc(m.ip)}">${esc(m.ip)} — ${esc(m.via)}</option>`).join("") : '<option value="">Not detected — use Whitelist IP or Custom</option>';
    const srcOf = ip => (S.wlSources.find(s => s.ips.includes(ip)) || {}).path || "";
    $("#m-wl").innerHTML = S.whitelist.length ? S.whitelist.map(ip => `<option value="${esc(ip)}">${esc(ip)}${isMyIp(ip) ? "  (you)" : ""} — ${esc(srcOf(ip).split("/").pop())}</option>`).join("") : '<option value="">Whitelist is empty — add one in Settings</option>';
    $("#m-presets").innerHTML = PRESETS.map(([n, p, pr]) => `<button data-p="${p}" data-pr="${pr}">${n} ${p}</button>`).join("");
    $("#m-port").value = $("#m-custom").value = $("#m-comment").value = "";
    if (edit) {
        S.m.action = edit.action;
        S.m.proto = normField(edit, "proto");
        $("#m-port").value = normField(edit, "port");
        $("#m-comment").value = edit.comment || "";
        if (edit.source) {
            if (isMyIp(edit.source)) { S.m.src = "me"; $("#m-me").value = edit.source; }
            else if (S.whitelist.includes(edit.source)) { S.m.src = "wl"; $("#m-wl").value = edit.source; }
            else { S.m.src = "custom"; $("#m-custom").value = edit.source; }
        }
    }
    $("#m-title").textContent = edit ? "Edit firewall rule" : "Add firewall rule";
    const note = edit ? (S.engine === "ufw" ? (edit.v6 || S.rules.some(x => x !== edit && x.sig && x.port === edit.port && x.source === edit.source && x.v6 !== edit.v6) ? "UFW stores IPv4 and IPv6 copies of this rule — both are updated together." : "") : S.engine === "firewalld" && edit.kind === "service" ? "This is a firewalld service; saving replaces it with an equivalent port rule." : "") : "";
    $("#m-editnote").className = note ? "warn" : "warn hidden"; $("#m-editnote").textContent = note;
    [["m-action", S.m.action], ["m-proto", S.m.proto], ["m-src", S.m.src]].forEach(([id, v]) => setSeg(id, v));
    updateModal();
    $("#modal").classList.remove("hidden");
    $("#m-port").focus();
}
function readModal() {
    const r = { action: S.m.action, proto: S.m.proto, port: $("#m-port").value.replace(/\s/g, ""), comment: cleanComment($("#m-comment").value), source: "" };
    if (S.m.src === "me") r.source = $("#m-me").value;
    if (S.m.src === "wl") r.source = $("#m-wl").value;
    if (S.m.src === "custom") r.source = $("#m-custom").value.trim();
    return r;
}
function checkRule(r) {
    if (r.port && !validPort(r.port)) return "Port must be 1–65535, e.g. 22, 80,443 or 8000-8100.";
    if (S.m.src !== "anyone" && !r.source) return "Choose or enter an IP address.";
    if (r.source && !validIp(r.source)) return "That doesn't look like a valid IP address or CIDR range.";
    if (!r.port && !r.source) return "Enter a port, or pick an IP to apply the rule to all ports.";
    if (r.action === "limit" && !r.port) return "Limit rules need a port.";
    return "";
}
function updateModal() {
    ["me", "wl", "custom"].forEach(k => $("#m-src-" + k).classList.toggle("show", S.m.src === k));
    const r = readModal(), err = checkRule(r), w = $("#m-warn");
    const touches = p => r.port && r.port.split(",").some(x => { const [a, b] = x.split("-").map(Number); return b ? +p >= a && +p <= b : +p === a; });
    let warn = "";
    if (r.action === "block" && !r.source && (!r.port || GUARD_PORTS.some(touches))) warn = "⚠ This blocks SSH or Cockpit for everyone — you could lock yourself out. Add an allow rule for your own IP first.";
    if (r.action === "block" && r.source && (isMyIp(r.source) || isWhitelisted(r.source))) warn = "⚠ This IP is yours or on your whitelist.";
    if (r.action === "allow" && !r.source && r.port && ["3306", "5432", "6379", "27017"].some(touches)) warn = "Heads up: exposing a database port to the whole internet is risky. Consider My IP or a whitelist IP instead.";
    w.className = err ? "warn err" : warn ? "warn" : "warn hidden";
    w.textContent = err || warn;
    $("#m-save").disabled = !!err;
    $("#m-save").textContent = S.m.edit ? "Save changes" : r.action === "allow" ? "Allow" : r.action === "limit" ? "Add limit" : "Block";
    $("#m-save").className = "btn " + (r.action === "block" ? "danger" : "primary");
    $("#m-explain").innerHTML = err ? "" : "<b>In plain English:</b> " + explainRule(Object.assign({ dir: "in" }, r, { proto: r.port ? r.proto : "any" }));
    let pv = "";
    if (!err) {
        if (S.engine === "nft") pv = nftEngine.preview(r);
        else {
            const cm = [];
            if (S.m.edit && S.engine === "ufw") { const old = S.m.edit; if (!["port", "proto", "action", "source"].every(k => normField(old, k) === normField(r, k))) cm.push(...ufw.cmds(old, { del: true })); }
            if (S.m.edit && S.engine === "firewalld") cm.push(["firewall-cmd", "--permanent", "--zone=" + S.zone, "(remove old rule)"]);
            cm.push(...ENGINES[S.engine].cmds(Object.assign({ dir: S.m.edit ? S.m.edit.dir : "in" }, r)));
            pv = cm.map(a => a.map(x => /\s/.test(x) ? `'${x}'` : x).join(" ")).join("\n");
        }
    }
    $("#m-preview").textContent = pv || "—";
}
async function saveModal() {
    const r = readModal(); if (checkRule(r)) return;
    const edit = S.m.edit;
    $("#m-save").disabled = true;
    const desc = `${r.action} ${r.port || "all ports"}/${r.proto} ${r.source ? "from " + r.source : "for anyone"}${r.comment ? " — " + r.comment : ""}`;
    try {
        if (edit) {
            S.pending = { add: true, del: true };
            const metaSig = edit.sig && S.meta[edit.sig];
            await ENGINES[S.engine].edit(edit, r);
            if (metaSig) S.pending.keepDate = metaSig.added;
        } else {
            S.pending = { add: true };
            if (S.engine === "nft") await nftEngine.add(r);
            else for (const c of ENGINES[S.engine].cmds(r)) await run(c);
        }
        $("#modal").classList.add("hidden");
    } catch (e) { toast(errMsg(e), true); $("#m-save").disabled = false; S.pending = null; return; }
    if (S.engine === "nft" && S.info.standalone !== "1") toast("Saved. Turn on the firewall to enforce it.");
    act(null, edit ? "Rule updated" : (r.action === "allow" ? "Allowed " : r.action === "limit" ? "Limited " : "Blocked ") + (r.port || "all ports"),
        edit ? "rule-edit" : "rule-add", edit ? `${edit.action} ${edit.port} ${edit.source || "anyone"} → ${desc}` : desc);
}

/* ---------------- refresh pipeline (fast first paint) ---------------- */
async function act(fn, ok, logType, logMsg) {
    try { if (fn) await fn(); if (ok) toast(ok); if (logType) logEvent(logType, logMsg || ok || "", ""); }
    catch (e) { toast(errMsg(e), true); S.pending = null; }
    await refresh();
}
function renderAll() {
    renderCards(); renderRules(); fillNftSelects(); renderNft(); renderSettings(); renderHealth();
    if (!$("#tab-log").classList.contains("hidden")) renderLog();
}
function saveCache() {
    try {
        localStorage.setItem(CACHE_KEY, JSON.stringify({
            engine: S.engine, info: S.info, rules: S.rules, policy: S.policy, zone: S.zone, ufwLogging: S.ufwLogging,
            cfg: S.cfg, settings: S.settings, nftText: S.nft.text, whitelist: S.whitelist, wlSources: S.wlSources,
            myips: S.myips, net: S.net, provider: S.provider ? Object.assign({}, S.provider, { test: undefined }) : null, meta: S.meta,
        }));
    } catch (e) { /* quota — ignore */ }
}
function loadCache() {
    try {
        const c = JSON.parse(localStorage.getItem(CACHE_KEY) || "null"); if (!c) return false;
        Object.assign(S, { engine: c.engine, info: c.info, rules: c.rules, policy: c.policy, zone: c.zone, ufwLogging: c.ufwLogging, cfg: c.cfg, settings: c.settings, whitelist: c.whitelist, wlSources: c.wlSources, myips: c.myips, net: c.net, provider: c.provider, meta: c.meta || {} });
        S.nft.text = c.nftText || ""; S.nft.raw = S.nft.text.replace(/\s*# handle \d+/g, "");
        Object.assign(S.nft, parseNft(S.nft.text));
        stampNft();
        return true;
    } catch (e) { return false; }
}
async function fastPhase() {
    const [, settings, meta] = await Promise.all([probe(), readJSON(SETTINGS, { setupDone: false, customFiles: [], disabledFiles: [] }), readJSON(META, {}), nftEngine.loadCfg()]);
    S.settings = settings; S.meta = meta;
    if (S.engine === "nft") nftEngine.load(); else await ENGINES[S.engine].load();
    if (S.pending && S.pending.keepDate) { const kd = S.pending.keepDate; S.rules.forEach(r => { if (!r.synthetic && !S.meta[sigOf(r)]) r.added = kd; }); }
    stampRules();
    await loadNft(); stampNft();
    S.loaded = true;
    renderAll();
}
async function slowPhase() {
    await Promise.all([loadWhitelist(), detectConnection(), loadLog()]);
    if (S.engine === "nft" && S.cfg.trustAll && S.info.standalone === "1" && trustedList().join() !== (S.cfg.trusted || []).join()) {
        await nftEngine.save(false).catch(() => {}); nftEngine.load(); stampRules();
    }
    saveMeta(); renderAll(); saveCache();
}
async function refresh() {
    if (S.busy) return S.busy;
    S.busy = (async () => {
        try { await fastPhase(); saveMeta(); saveCache(); slowPhase().catch(() => {}); }
        catch (e) { toast("Failed to load: " + errMsg(e), true); }
    })();
    try { await S.busy; } finally { S.busy = null; }
}
async function reloadAll() {
    const b = $("#btn-refresh");
    if (b.classList.contains("busy")) return;
    b.classList.add("busy"); b.disabled = true; b.querySelector("span").textContent = "Refreshing…";
    try {
        if (engineActive()) await ENGINES[S.engine].reload();
        await refresh();
        await slowPhase();
        if (S.blockedLoaded) { await loadBlocked(); renderHealth(); renderLog(); }
        logEvent("reload", `${ENGINE_NAME[S.engine]} reloaded and all rules re-read`, "");
        toast(`${ENGINE_NAME[S.engine]} reloaded · ${S.rules.filter(r => !r.synthetic).length} rules, ${S.nft.rows.length} nftables rules`);
    } catch (e) { toast(errMsg(e), true); }
    b.classList.remove("busy"); b.disabled = false; b.querySelector("span").textContent = "Refresh";
}

/* ---------------- init ---------------- */
function init() {
    applyTheme();
    $$(".date-sel").forEach(s => { s.innerHTML = DATE_OPTS.map(([v, l]) => `<option value="${v}">${l}</option>`).join(""); });
    cockpit.user().then(u => { S.user = u.name || u.full_name || ""; }).catch(() => {});

    $$(".tab").forEach(t => t.onclick = () => {
        $$(".tab").forEach(x => x.classList.toggle("active", x === t));
        $$(".tab-body").forEach(b => b.classList.toggle("hidden", b.id !== "tab-" + t.dataset.tab));
        $("#btn-add").textContent = t.dataset.tab === "nft" ? "+ Add nftables rule" : "+ Add rule";
        if (t.dataset.tab === "log") {
            renderLog();
            if (!S.blockedLoaded) loadBlocked().then(() => { renderHealth(); renderLog(); });
        }
    });
    const gotoTab = name => $(`.tab[data-tab="${name}"]`).click();
    $("#btn-add").onclick = () => $("#tab-nft").classList.contains("hidden") ? openModal() : openNftModal();
    $("#btn-refresh").onclick = reloadAll;

    // pagers + "clear" links (delegated)
    const RERENDER = { rules: renderRules, nft: renderNft, log: renderLog };
    document.addEventListener("change", e => { const n = e.target.dataset && e.target.dataset.pg; if (n) { PG[n].size = +e.target.value; PG[n].page = 1; RERENDER[n](); } });
    document.addEventListener("click", e => {
        const d = e.target.dataset || {};
        if (d.pgp) { PG[d.pgp].page--; RERENDER[d.pgp](); }
        if (d.pgn) { PG[d.pgn].page++; RERENDER[d.pgn](); }
        if (d.clear) ({ rules: clearRuleFilters, nft: clearNftFilters, log: clearLogFilters })[d.clear]();
    });

    // rules filters
    const onF = (keys, extra, fn) => keys.concat(extra).forEach(k => $(k).addEventListener(/-q$|^#q$/.test(k) ? "input" : "change", () => fn(k)));
    onF(Object.keys(FILTER_DEFAULTS), ["#f-from", "#f-to"], k => {
        if (k === "#f-sort") { const [key, dir] = $(k).value.split(":"); S.sort = { key, dir }; }
        PG.rules.page = 1; renderRules();
    });
    $("#f-clear").onclick = clearRuleFilters;
    $$("#tab-rules th[data-sort]").forEach(th => th.onclick = () => {
        const key = th.dataset.sort;
        S.sort = { key, dir: S.sort.key === key && S.sort.dir === "asc" ? "desc" : "asc" };
        const opt = `${key}:${S.sort.dir}`;
        $("#f-sort").value = [...$("#f-sort").options].some(o => o.value === opt) ? opt : "n:asc";
        if ($("#f-sort").value === "n:asc" && !(key === "n" && S.sort.dir === "asc")) $("#f-sort").value = "n:asc";
        renderRules();
    });
    $("#rules-body").onclick = async e => {
        const d = e.target.dataset;
        if (d.goto) return gotoTab(d.goto);
        if (d.edit != null) return openModal(S.rules[+d.edit]);
        if (d.del == null) return;
        const r = S.rules[+d.del];
        if (!await confirmBox("Delete rule?", `${r.action.toUpperCase()} ${r.port} (${r.proto}) from ${r.source || "anyone"}`, "Delete")) return;
        S.pending = { del: true };
        act(() => ENGINES[S.engine].del(r), "Rule deleted", "rule-delete", `${r.action} ${r.port}/${r.proto} ${r.source ? "from " + r.source : "for anyone"}${r.v6 ? " (IPv6)" : ""}`);
    };

    // nft filters
    onF(Object.keys(N_DEFAULTS), ["#n-from", "#n-to"], k => { if (k === "#n-table") fillNftSelects(); PG.nft.page = 1; renderNft(); });
    $("#n-clear").onclick = clearNftFilters;
    $$("#tab-nft th[data-nsort]").forEach(th => th.onclick = () => {
        const k = th.dataset.nsort, cur = $("#n-sort").value;
        $("#n-sort").value = cur === k + ":desc" ? k + ":asc" : cur === k + ":asc" ? "order" : k + ":desc";
        renderNft();
    });
    $("#n-chips").onclick = e => { const b = e.target.closest("button"); if (!b) return; $("#n-table").value = b.dataset.t === $("#n-table").value ? "" : b.dataset.t; fillNftSelects(); PG.nft.page = 1; renderNft(); };
    $("#n-raw").onclick = () => {
        S.nft.rawMode = !S.nft.rawMode;
        $("#n-raw-view").classList.toggle("hidden", !S.nft.rawMode);
        $("#n-table-view").classList.toggle("hidden", S.nft.rawMode);
        $("#n-raw").textContent = S.nft.rawMode ? "Table view" : "Raw view";
    };
    $("#n-copy").onclick = () => navigator.clipboard.writeText(S.nft.raw).then(() => toast("Copied"));
    $("#n-add").onclick = () => openNftModal();
    $("#n-body").onclick = e => {
        if (e.target.dataset.nedit != null) openNftModal(S.nft.rows[+e.target.dataset.nedit]);
        if (e.target.dataset.ndel != null) deleteNftRow(S.nft.rows[+e.target.dataset.ndel]);
    };

    // log filters
    onF(Object.keys(L_DEFAULTS), ["#l-from", "#l-to"], () => { PG.log.page = 1; renderLog(); });
    $("#l-clear").onclick = clearLogFilters;
    $("#l-export").onclick = exportLogCsv;

    // nft modal
    $("#nm-table").onchange = () => { fillNmChains(); updateNm(); };
    $("#nm-chain").onchange = updateNm;
    ["#nm-expr", "#nm-comment"].forEach(k => $(k).addEventListener("input", updateNm));
    ["#nb-src", "#nb-port", "#nb-proto", "#nb-act"].forEach(k => $(k).addEventListener("input", buildExpr));
    $("#nm-pos").onclick = e => { const v = e.target.dataset.v; if (!v) return; S.nm.pos = v; setSeg("nm-pos", v); updateNm(); };
    $("#nm-save").onclick = saveNm;

    // rule modal
    $$("[data-close]").forEach(b => b.onclick = () => $("#" + b.dataset.close).classList.add("hidden"));
    [["m-action", "action"], ["m-proto", "proto"], ["m-src", "src"]].forEach(([id, k]) =>
        $("#" + id).onclick = e => { const v = e.target.dataset.v; if (!v) return; S.m[k] = v; setSeg(id, v); updateModal(); });
    $("#m-presets").onclick = e => { const b = e.target.closest("button"); if (!b) return; $("#m-port").value = b.dataset.p; S.m.proto = b.dataset.pr; setSeg("m-proto", b.dataset.pr); updateModal(); };
    ["#m-port", "#m-custom", "#m-comment", "#m-me", "#m-wl"].forEach(s => $(s).addEventListener("input", updateModal));
    $("#m-save").onclick = saveModal;

    // wizard
    $("#su-go").onclick = runSetup;
    $("#su-later").onclick = () => $("#setup").classList.add("hidden");
    $("#su-never").onclick = () => { $("#setup").classList.add("hidden"); S.settings.setupDone = true; saveSettings().catch(e => toast(errMsg(e), true)); };
    document.addEventListener("keydown", e => { if (e.key === "Escape") ["#modal", "#nmodal"].forEach(m => $(m).classList.add("hidden")); });

    // instant paint from cache, then live data
    refreshCfRanges();
    const cached = loadCache();
    if (cached) { renderAll(); showBanner(); }
    refresh().then(() => {
        if (!cached || (S.engine === "nft" && !engineActive())) showBanner();
        if (S.engine === "nft" && !engineActive() && !S.settings.setupDone && !S.setupShown) openSetup();
    });
}
function clearLogFilters() {
    Object.entries(L_DEFAULTS).forEach(([k, v]) => { $(k).value = v; });
    $("#l-from").value = $("#l-to").value = ""; PG.log.page = 1; renderLog();
}
document.addEventListener("DOMContentLoaded", init);

# Cockpit Firewall Manager

A clean, lightweight firewall module for [Cockpit](https://cockpit-project.org/) — view, add, edit and remove every firewall rule on your server from one page. Designed dark-mode first and follows Cockpit's light/dark setting.

**Version 1.0.0**

## Features

- **Works with what you have** — manages **UFW** or **firewalld** if one is running; if neither is, it provides its own lightweight **built-in nftables firewall** with a safe setup wizard (blocks everything except SSH, HTTP, HTTPS and Cockpit).
- **Easy rules** — allow, block or rate-limit a port for anyone, *your IP*, a *whitelist IP* or a custom IP/range. Edit or comment any existing rule.
- **Plain-English explanations** for every rule ("Lets anyone on the internet connect to port 443 (HTTPS)").
- **nftables viewer** — every nftables rule as a searchable, sortable, paginated table with owner (UFW, fail2ban, Docker…), traffic counters, edit/delete, and a raw view for advanced users.
- **Smart detection** — your public IP, Cloudflare (proxy, tunnel, WARP), VPN interfaces, reverse proxy, fail2ban/CSF/CrowdSec/Docker, and your hosting provider's network firewall.
- **Whitelist sources** — auto-reads fail2ban `ignoreip`, CSF, hosts.allow and any whitelist/allowlist file, plus custom files.
- **Status & activity** — health checks, a full change history (who/when/what, including changes made outside the module) and blocked-connection log, with filters, date ranges and CSV export.
- **Lockout protection** — warnings before risky rules, a lockout guard for SSH/Cockpit, confirmation on every destructive action.

## Requirements

- Cockpit 137 or newer
- Ubuntu / Debian (tested on Ubuntu 24.04) with `nftables` (installed by default)
- Administrative access turned on in Cockpit

## Install

**For all users (recommended):**

```bash
sudo git clone --branch v1.0.0 --depth 1 https://github.com/tinescast/cockpit-firewall.git /usr/local/share/cockpit/firewall-manager
```

**Just for your user (no root needed):**

```bash
mkdir -p ~/.local/share/cockpit
git clone --branch v1.0.0 --depth 1 https://github.com/tinescast/cockpit-firewall.git ~/.local/share/cockpit/firewall-manager
```

No `git`? Use the release zip instead:

```bash
cd /tmp && curl -fsSL -o fw.zip https://github.com/tinescast/cockpit-firewall/archive/refs/tags/v1.0.0.zip
unzip -q fw.zip && sudo mkdir -p /usr/local/share/cockpit
sudo mv cockpit-firewall-1.0.0 /usr/local/share/cockpit/firewall-manager
```

Reload Cockpit (Ctrl+Shift+R) — **Firewall** appears under *Tools*.

You can also upload the five module files with the Cockpit Navigator into either folder.

## Update

```bash
cd /usr/local/share/cockpit/firewall-manager   # or ~/.local/share/cockpit/firewall-manager
sudo git fetch --tags && sudo git checkout <new-version-tag>
```

## Files it creates

| Path | Purpose |
|---|---|
| `/etc/cockpit-firewall/rules.json` | Built-in firewall rules and settings |
| `/etc/cockpit-firewall/ruleset.nft` | Generated nftables script |
| `/etc/cockpit-firewall/activity.log` | Change history |
| `/etc/cockpit-firewall/whitelist.txt` | Module's own whitelist |
| `/etc/systemd/system/cockpit-firewall.service` | Restores the built-in firewall at boot |

## Emergency undo

If the built-in firewall ever locks you out, from the provider's console run:

```bash
sudo systemctl disable --now cockpit-firewall
```

## Uninstall

```bash
rm -rf ~/.local/share/cockpit/firewall-manager      # or /usr/local/share/cockpit/firewall-manager
sudo systemctl disable --now cockpit-firewall 2>/dev/null
sudo rm -rf /etc/cockpit-firewall /etc/systemd/system/cockpit-firewall.service
```

## License

MIT

"""Render server2 deployment files for the single Biomni web service; installs nothing.

The output is reviewed and installed by an administrator (see the generated guide). The
service runs from the shared checkout and the existing ``biomni`` environment.
"""

import argparse
import ipaddress
import json
import re
from pathlib import Path

from biomni.localenv import RuntimeProfile

UNIT = """[Unit]
Description=Biomni web service (login, UI, jobs and model gateway)
After=network-online.target
Wants=network-online.target

[Service]
User=root
WorkingDirectory={repository}
Environment=PYTHONPATH={repository}
Environment=PYTHONNOUSERSITE=1
ExecStart={python} -s -m biomni.server.app serve --config /etc/biomni/web.json
UMask=0077
# Only the web process is stopped; each user's dispatcher sees its connection close,
# cancels that user's local and remote work, records it as interrupted and exits.
KillMode=process
TimeoutStopSec=30
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

PAM = """#%PAM-1.0
# Biomni sign-in: same password and account checks as other remote logins.
auth       include      password-auth
account    include      password-auth
"""

GUIDE = """# Biomni on server2: install and operate

Generated {date}. Review every file before installing. Run as root on server2.

## Install

```sh
install -d -m 0755 /etc/biomni
install -m 0644 {date}-web.json /etc/biomni/web.json
install -m 0644 {date}-runtime.json /etc/biomni/runtime.json   # readable by users' dispatchers
install -m 0644 {catalog} /etc/biomni/catalog.json
install -m 0644 {date}-pam-biomni /etc/pam.d/biomni
install -m 0644 {date}-biomni-web.service /etc/systemd/system/biomni-web.service
{python} -m biomni.server.app init-key /etc/biomni/master.key  # back this key up separately
ss -ltn | grep -q ':{port} ' && echo "port {port} is busy" || echo "port {port} is free"
systemctl daemon-reload
systemctl enable --now biomni-web
```

If firewalld is active, allow the port from the private ranges only, for example:
`firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=10.0.0.0/8 port port={port} protocol=tcp accept'`
(repeat for 172.16.0.0/12 and 192.168.0.0/16), then `firewall-cmd --reload`.

## First use

1. Open http://{host}:{port}/ and sign in with a `wheel` account (administrators need no approval).
2. Administration → approve users, add a shared provider (base URL ending in `/v1` and key), refresh models, grant models.
3. Users can instead save a personal URL/key for their session.
4. Each user needs their own passwordless SSH key to run tasks on servers other than server2.

## Operate

- Status/logs: `systemctl status biomni-web`, `journalctl -u biomni-web -f`.
- User dispatcher log: `~/.local/share/biomni/dispatcher.log`; tasks: `~/.local/share/biomni/runs/`.
- Restart: `systemctl restart biomni-web`. Sessions and personal keys are lost; running tasks are cancelled
  and shown as interrupted when the user signs in again. Nothing is resubmitted automatically.
- Reservations whose worker state is uncertain stay listed under Administration → Reserved resources;
  release them only after confirming the worker has stopped.
- Upgrade: `git -C {repository} pull`, rerun tests, then restart.
- Back up `/var/lib/biomni/policy.sqlite3` and `/etc/biomni/master.key` (separately) before upgrades.

## Rollback

`systemctl disable --now biomni-web`, remove `/etc/systemd/system/biomni-web.service` and `/etc/pam.d/biomni`,
`systemctl daemon-reload`, then check out the previous commit if the code changed. User task files are untouched.
"""


def render(output, profile_path, host, date, *, port=8765, catalog=None, local_server="server2"):
    if not re.fullmatch(r"[0-9]{8}", date):
        raise ValueError("Use a YYYYMMDD creation date")
    ipaddress.IPv4Address(host)
    profile = RuntimeProfile.from_file(profile_path)
    if local_server not in profile.servers:
        raise ValueError("The local server must be listed in the runtime profile")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("Choose an empty deployment output directory")
    python = profile.python()
    repository = profile.repository or str(Path(__file__).resolve().parents[2])
    runtime = {**profile.to_dict(), "catalog_file": "/etc/biomni/catalog.json"}
    web = {
        "bind": host,
        "port": port,
        "gateway_url": f"http://{host}:{port}/gateway/v1",
        "profile": "/etc/biomni/runtime.json",
        "local_server": local_server,
        "state_dir": "/var/lib/biomni",
        "key_file": "/etc/biomni/master.key",
        "pam_service": "biomni",
        "session_hours": 24,
        "min_uid": 1000,
    }
    contents = {
        "web.json": json.dumps(web, indent=2) + "\n",
        "runtime.json": json.dumps(runtime, indent=2) + "\n",
        "biomni-web.service": UNIT.format(python=python, repository=repository),
        "pam-biomni": PAM,
        "install-guide.md": GUIDE.format(
            date=date,
            host=host,
            port=port,
            python=python,
            repository=repository,
            catalog=catalog or profile.catalog_file or "<catalog.json>",
        ),
    }
    for name, content in contents.items():
        (output / (date + "-" + name)).write_text(content)
    print(json.dumps({"files": sorted(contents), "output": str(output), "installed": False}))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--host", required=True, help="server2 IPv4 address users and workers can reach")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--date", required=True)
    parser.add_argument("--local-server", default="server2")
    args = parser.parse_args(argv)
    render(args.output, args.profile, args.host, args.date, port=args.port, local_server=args.local_server)


if __name__ == "__main__":
    main()

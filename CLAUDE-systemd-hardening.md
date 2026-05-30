# CLAUDE-systemd-hardening.md — systemd Unit with Full Hardening

Companion to `CLAUDE.md`. Follow all conventions there. Ships a
production-grade systemd unit file with the full hardening directive
set, plus SysV and OpenRC equivalents for non-systemd Linux. Validated
in CI against `systemd-analyze security`.

---

## What this is

PyPKI's existing deployment story is Docker Compose. That's fine for
"let me try it" but most production Linux deployments want a native
systemd unit. This spec defines that unit, the rationale for every
hardening directive, and the CI test that prevents regression.

Goals:

- `systemd-analyze security pypki.service` score ≤ 1.0 (lower = more
  secure; the kernel docs treat <1.0 as "exposure: minimal").
- All hardening directives justified inline so future edits don't
  silently remove protections.
- Documented escape hatches: which directives might break which
  features, and how to relax them safely.

---

## The unit

```ini
# /etc/systemd/system/pypki.service
[Unit]
Description=PyPKI Certificate Authority
Documentation=https://github.com/lucianpopovici/pypki
After=network-online.target postgresql.service
Wants=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
Type=notify
ExecStart=/usr/bin/pypki-server --config /etc/pypki/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStartSec=60
TimeoutStopSec=30
WatchdogSec=120s

# --- Identity ---
User=pypki
Group=pypki
# DynamicUser=no is intentional: PyPKI owns persistent state on disk
# (DB, CA keys, audit log). DynamicUser would break that.

# --- Filesystem isolation ---
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectHostname=true
ProtectClock=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectProc=invisible
ProcSubset=pid

# Writable paths must be explicit. Add to this list when adding
# features that need new write locations.
ReadWritePaths=/var/lib/pypki
ReadWritePaths=/var/log/pypki
ConfigurationDirectory=pypki
StateDirectory=pypki
LogsDirectory=pypki
RuntimeDirectory=pypki
CacheDirectory=pypki

# --- Process isolation ---
NoNewPrivileges=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RemoveIPC=true
KeyringMode=private
UMask=0077

# --- Network ---
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
IPAddressDeny=any
IPAddressAllow=localhost
# Operators add their RFC1918 / VPC ranges here. nginx in front
# of PyPKI means PyPKI only ever talks to localhost.
# Override examples in docs/SYSTEMD.md.

# --- Privileges ---
CapabilityBoundingSet=
AmbientCapabilities=
# PyPKI never binds <1024 directly when deployed correctly
# (nginx fronts it). If you must bind 443/80 directly, set:
#   CapabilityBoundingSet=CAP_NET_BIND_SERVICE
#   AmbientCapabilities=CAP_NET_BIND_SERVICE

# --- System call filtering ---
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount @reboot @swap @raw-io @cpu-emulation @debug
SystemCallArchitectures=native
SystemCallErrorNumber=EPERM

# --- Resource limits ---
LimitNOFILE=65536
LimitNPROC=4096
LimitCORE=0
TasksMax=4096

# --- Environment ---
Environment=PYTHONHASHSEED=random
Environment=PYTHONDONTWRITEBYTECODE=1
EnvironmentFile=-/etc/pypki/env

[Install]
WantedBy=multi-user.target
```

---

## Directive rationale

Every directive is here because removing it lowers security. Document
the threat each one defends against so future maintainers don't
"clean up" a directive they don't recognize.

| Directive                | Defends against                                          |
| ------------------------ | -------------------------------------------------------- |
| `NoNewPrivileges`        | setuid/setgid escalation if PyPKI's process is compromised |
| `ProtectSystem=strict`   | Mounts `/usr`, `/boot`, `/efi` read-only — compromised PyPKI cannot modify binaries |
| `ProtectHome`            | Hides `/home`, `/root` — limits credential theft surface |
| `PrivateTmp`             | Isolated `/tmp` — prevents tmp-file race attacks         |
| `PrivateDevices`         | Only essential `/dev` nodes — no raw disk, no HW backdoor |
| `ProtectHostname`        | Cannot change hostname (subtle persistence trick)        |
| `ProtectClock`           | Cannot rewind clock to make expired certs look valid     |
| `ProtectKernelTunables`  | Read-only `/proc/sys`, `/sys`                            |
| `ProtectKernelModules`   | No `init_module()`, `delete_module()`                    |
| `ProtectKernelLogs`      | Cannot read `kmsg` — hides side-channel info             |
| `ProtectControlGroups`   | Read-only cgroup hierarchy — prevents resource manipulation |
| `ProtectProc=invisible`  | Cannot see other users' processes — limits recon         |
| `RestrictSUIDSGID`       | Cannot create suid binaries                              |
| `RestrictNamespaces`     | No namespace creation — blocks container-escape primitives |
| `LockPersonality`        | Cannot disable ASLR via `personality(2)`                 |
| `MemoryDenyWriteExecute` | No W^X pages — defeats most exploit techniques           |
| `RestrictRealtime`       | No RT scheduler — prevents DoS by priority abuse         |
| `RemoveIPC`              | No SysV IPC / POSIX message queues — reduces lateral movement |
| `KeyringMode=private`    | Isolated kernel keyring                                  |
| `UMask=0077`             | New files default to owner-only — prevents accidental world-readable secrets |
| `RestrictAddressFamilies` | No `AF_PACKET`, `AF_BLUETOOTH`, etc. — narrows attack surface |
| `IPAddressDeny=any` + allowlist | Egress firewall at the kernel level             |
| `CapabilityBoundingSet=` (empty) | No file capabilities — defense in depth         |
| `SystemCallFilter=@system-service ~@privileged` | Coarse seccomp — blocks `keyctl`, `ptrace`, etc. |
| `SystemCallArchitectures=native` | Blocks 32-bit syscalls on 64-bit kernels (compat layer often has bugs) |
| `MemoryDenyWriteExecute` | Repeated for emphasis — single biggest exploit-mitigation win |
| `LimitCORE=0`            | No core dumps — prevents key material in coredumps       |

`Type=notify` requires PyPKI to call `sd_notify(READY=1)` once it's
done startup. Add this to `pki_server.py:main()` if not already
present. Without it, systemd assumes "ready" immediately and dependent
services may start too early.

`WatchdogSec=120s` requires PyPKI to call `sd_notify(WATCHDOG=1)`
every <60s. Add a heartbeat thread that posts the watchdog every 30s.
If PyPKI hangs (deadlocked DB connection, slow HSM, etc.), systemd
restarts it after 2 minutes.

---

## What might break and how to relax

| Feature                   | Conflicting directive             | Safe relaxation                             |
| ------------------------- | --------------------------------- | ------------------------------------------- |
| Bind directly to 80/443   | `CapabilityBoundingSet=`          | Add `CAP_NET_BIND_SERVICE` (both `CapabilityBoundingSet` and `AmbientCapabilities`) |
| HSM via USB device        | `PrivateDevices=true`             | Add `DeviceAllow=/dev/usb/hiddevN rw`       |
| TPM access for attestation | `PrivateDevices=true`            | Add `DeviceAllow=/dev/tpm0 rw`              |
| Cloud KMS auth via IMDSv2 | `IPAddressDeny=any`               | Add `IPAddressAllow=169.254.169.254`        |
| Backup to remote target   | `IPAddressDeny=any`               | Add `IPAddressAllow=<provider CIDR>`        |
| Postgres on different host | `IPAddressDeny=any`              | Add `IPAddressAllow=<db-host>/32`           |
| Calling out via DNS       | `IPAddressDeny=any`               | Add `IPAddressAllow=<resolver-ip>/32`       |

Each relaxation is a tradeoff. Document each in `docs/SYSTEMD.md` with
the threat it reopens. The init wizard (`CLAUDE-bootstrap-cli.md`)
applies the right relaxations automatically based on selected backends.

---

## SysV init script

For Linux distributions without systemd (Devuan, certain Alpine
configurations, legacy CentOS 6). Minimal LSB-conformant script in
`packaging/sysv/pypki`:

```sh
#!/bin/sh
### BEGIN INIT INFO
# Provides:          pypki
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: PyPKI Certificate Authority
### END INIT INFO

. /lib/lsb/init-functions

DAEMON=/usr/bin/pypki-server
DAEMON_ARGS="--config /etc/pypki/config.yaml"
PIDFILE=/var/run/pypki.pid
USER=pypki

case "$1" in
  start)
    log_daemon_msg "Starting PyPKI" "pypki"
    start-stop-daemon --start --quiet --background \
      --pidfile $PIDFILE --make-pidfile \
      --chuid $USER --exec $DAEMON -- $DAEMON_ARGS
    log_end_msg $?
    ;;
  stop)
    log_daemon_msg "Stopping PyPKI" "pypki"
    start-stop-daemon --stop --quiet --retain=TERM/30/KILL/5 \
      --pidfile $PIDFILE
    log_end_msg $?
    rm -f $PIDFILE
    ;;
  restart) $0 stop && sleep 2 && $0 start ;;
  status) status_of_proc -p $PIDFILE $DAEMON pypki ;;
  *) echo "Usage: $0 {start|stop|restart|status}"; exit 1 ;;
esac
```

The SysV script can't replicate systemd's hardening. Document this:
SysV deployments rely on AppArmor / SELinux (see
`CLAUDE-os-hardening-firewall.md`) for equivalent protection.

---

## OpenRC script

For Alpine / Gentoo. Minimal OpenRC-conformant in `packaging/openrc/pypki`:

```sh
#!/sbin/openrc-run

name="PyPKI Certificate Authority"
command="/usr/bin/pypki-server"
command_args="--config /etc/pypki/config.yaml"
command_user="pypki:pypki"
pidfile="/run/pypki.pid"
command_background="yes"

depend() {
    need net
    after postgresql
}
```

Alpine's `chrt` and `setpriv` provide some of what systemd hardening
gives; document the Alpine recipe in `docs/SYSTEMD.md`.

---

## CI validation

Every PR runs `systemd-analyze security` against the unit on an Ubuntu
runner. Required score ≤ 1.0.

```yaml
# .github/workflows/systemd-security.yml
name: systemd security
on: [pull_request]
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install unit file
        run: sudo cp packaging/systemd/pypki.service /etc/systemd/system/
      - name: Reload
        run: sudo systemctl daemon-reload
      - name: Analyze
        run: |
          set -e
          score=$(systemd-analyze security pypki.service --no-pager | tail -1 | awk '{print $NF}')
          echo "Score: $score"
          python3 -c "exit(0 if float('$score') <= 1.0 else 1)"
```

Score regression blocks merge. If a feature genuinely needs a relaxation,
document it in the PR and update the threshold deliberately.

---

## Implementation

### Files touched

| File                                  | Change                              |
| ------------------------------------- | ----------------------------------- |
| `packaging/systemd/pypki.service`     | New: the unit above                 |
| `packaging/systemd/pypki@.service`    | Templated variant for HA deployments |
| `packaging/sysv/pypki`                | New SysV script                     |
| `packaging/openrc/pypki`              | New OpenRC script                   |
| `packaging/systemd/pypki.socket`      | Optional socket activation          |
| `pki_server.py`                       | `sd_notify` integration             |
| `notify.py`                           | New module: stdlib `sd_notify` shim |
| `test_pypki_init.py`                  | `TestSystemdNotify`                 |
| `.github/workflows/systemd-security.yml` | CI check                         |
| `README.md`                           | Update install section              |
| `CHANGELOG.md`                        | `### Added`                         |
| `docs/SYSTEMD.md`                     | Operator guide                      |

### `sd_notify` shim

systemd's notification is just a `sendmsg(2)` to the socket at
`$NOTIFY_SOCKET`. ~40 LoC, no `python-systemd` dep needed.

```python
# notify.py
import os, socket
def sd_notify(state: str) -> bool:
    sock_path = os.environ.get("NOTIFY_SOCKET")
    if not sock_path: return False
    if sock_path.startswith("@"):
        sock_path = "\0" + sock_path[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
        s.sendto(state.encode(), sock_path)
    return True

def ready():        return sd_notify("READY=1")
def reloading():    return sd_notify("RELOADING=1")
def stopping():     return sd_notify("STOPPING=1")
def watchdog():     return sd_notify("WATCHDOG=1")
def status(msg):    return sd_notify(f"STATUS={msg}")
```

Heartbeat thread starts after `ready()` and posts `watchdog()` every
30s as long as the main HTTP server is responsive (use the same liveness
check as the preflight CLI — see `CLAUDE-preflight-check.md`).

---

## Tests

```
class TestSystemdNotify(unittest.TestCase):
    def test_sd_notify_no_op_without_notify_socket(self): ...
    def test_sd_notify_sends_ready(self): ...
    def test_sd_notify_handles_abstract_socket(self): ...
    def test_watchdog_heartbeat_stops_on_unhealthy(self): ...

class TestSystemdUnit(unittest.TestCase):
    # Static analysis of the unit file
    def test_unit_parses_via_systemd_analyze(self): ...
    def test_security_score_below_threshold(self): ...
    def test_no_dynamic_user(self): ...
    def test_read_write_paths_only_in_state_dir(self): ...
    def test_capability_bounding_set_empty(self): ...
    def test_system_call_filter_includes_privileged_negation(self): ...
```

---

## Per-change checklist

- [ ] `packaging/systemd/pypki.service`, `.socket`, `@.service` —
      systemd files
- [ ] `packaging/sysv/pypki`, `packaging/openrc/pypki` — alternatives
- [ ] `notify.py` — `sd_notify` shim
- [ ] `pki_server.py` — call `ready()`, start watchdog thread
- [ ] `.github/workflows/systemd-security.yml` — CI check
- [ ] `test_pypki_init.py` — two new test classes
- [ ] `README.md` — install section
- [ ] `CHANGELOG.md` — `### Added`, `### Security`
- [ ] `docs/SYSTEMD.md` — operator guide, relaxation matrix
- [ ] `pypki-flows.html` — unit-file lifecycle diagram

Run `./run_tests.sh` and the systemd-security workflow.

---

## Open questions

1. **Socket activation**: `pypki.socket` lets systemd hold the listen
   sockets and hand them to PyPKI at start. Faster restarts, no
   dropped connections during reload. Worth supporting but increases
   complexity. Ship the unit, document the socket as advanced.

2. **Hardening on Debian/Ubuntu vs RHEL/Rocky**: SELinux defaults
   differ; `ProtectHome=tmpfs` works differently with home-on-NFS.
   Test the unit on the four most common server distros (Ubuntu LTS,
   Debian stable, RHEL/Rocky, Alma) and document any per-distro
   tweaks needed.

3. **Container interaction**: in Podman/Docker, systemd inside the
   container is rare. Document the container deployment path
   separately (`CLAUDE-deployment-topologies.md`) and keep the
   systemd unit focused on native deployments.

4. **Watchdog tuning**: `WatchdogSec=120s` is conservative.
   High-throughput CAs doing 1k issuance/s may want tighter
   (30s/15s heartbeat). Surface as a tunable in `init-answers.yaml`.

5. **Signal handling**: `kill -HUP` for reload assumes PyPKI can
   safely reload config + policy + JWKS without dropping in-flight
   requests. Verify each reload path is signal-safe and idempotent.
   `SIGTERM` graceful-shutdown is also worth testing — bind socket
   release, in-flight cert issuance completion, audit-chain seal
   before exit.

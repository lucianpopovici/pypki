# CLAUDE-os-hardening-firewall.md — OS Hardening & Firewall Templates

Companion to `CLAUDE.md`. Follow all conventions there. Ships the
non-systemd half of host hardening: firewall templates for every
common stack, sysctl tuning, ulimits, AppArmor and SELinux profiles,
plus a single authoritative port matrix that every other artifact
references.

---

## What this is

`CLAUDE-systemd-hardening.md` covers what systemd can enforce inside
the unit. This spec covers everything outside that boundary: kernel
parameters, file descriptor limits, mandatory access control (MAC),
and the firewall — the layers that protect the host from external
traffic and protect the rest of the host from PyPKI.

Ship templates rather than ask operators to invent these themselves.
Wrong firewall rules and missing MAC are the most common deployment
defects in CA software.

---

## The port matrix

The authoritative table. Every firewall template, every deployment
topology, every doc references this:

| Port  | Protocol | Direction | Service          | Visibility       | Notes                                 |
| ----- | -------- | --------- | ---------------- | ---------------- | ------------------------------------- |
| 80    | TCP      | inbound   | ACME http-01     | public           | Required for ACME http-01 challenges  |
| 443   | TCP      | inbound   | Admin / REST / ACME / OCSP / CRL | public | Main HTTPS endpoint           |
| 8443  | TCP      | inbound   | Admin (separated) | internal        | If admin separated from public        |
| 80/443 | TCP     | inbound   | Web UI           | public/internal  | Served by main listener               |
| 9090  | TCP      | inbound   | Prometheus metrics | internal       | Loopback or internal monitoring net   |
| 8080  | TCP      | inbound   | PyPKI plaintext  | loopback only    | Pattern B (nginx fronts)              |
| 2525  | TCP      | inbound   | CMP (if TCP transport) | internal   | Per RFC 4210; uncommon                |
| 11112 | TCP      | inbound   | EST              | internal         | If EST enabled                        |
| 5432  | TCP      | outbound  | Postgres         | private          | If remote DB                          |
| 6432  | TCP      | outbound  | PgBouncer        | loopback         | If local PgBouncer                    |
| 443   | TCP      | outbound  | Cloud KMS        | public/private   | Provider-specific                     |
| 443   | TCP      | outbound  | OIDC IdP         | public/private   | If OIDC auth enabled                  |
| 53    | UDP+TCP  | outbound  | DNS              | private          | For ACME DNS-01, CRL DP fetches       |
| 123   | UDP      | outbound  | NTP              | public/private   | Time sync (critical for cert validity)|
| 514   | UDP+TCP  | outbound  | syslog           | private          | If syslog logging                     |
| 169.254.169.254 | TCP | outbound | IMDS            | link-local       | Cloud metadata for IAM auth           |

Egress is at least as important as ingress. Default-deny outbound,
allowlist these targets. A compromised PyPKI that can't dial out to
arbitrary hosts is a much smaller blast radius.

---

## Firewall templates

One template per major firewall syntax. All implement the same
policy: deny by default, allow exactly what's in the port matrix.

### nftables (modern Linux default)

`packaging/firewall/nftables/pypki.nft`:

```
#!/usr/sbin/nft -f

table inet pypki {
    set admin_networks {
        type ipv4_addr; flags interval;
        elements = { 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12 }
    }
    set monitoring_networks {
        type ipv4_addr; flags interval;
        elements = { 10.10.0.0/16 }
    }
    set db_hosts {
        type ipv4_addr; flags interval;
        elements = { 10.20.0.5/32, 10.20.0.6/32 }
    }

    chain inbound {
        type filter hook input priority 0; policy drop;

        # Conntrack
        ct state established,related accept
        ct state invalid drop

        # Loopback
        iifname "lo" accept

        # ICMP
        ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } accept
        ip6 nexthdr ipv6-icmp icmpv6 type {
            echo-request, destination-unreachable, packet-too-big,
            time-exceeded, parameter-problem, nd-neighbor-solicit,
            nd-neighbor-advert, nd-router-advert
        } accept

        # SSH from admin networks only (NOT from public)
        tcp dport 22 ip saddr @admin_networks accept

        # ACME http-01
        tcp dport 80 accept

        # HTTPS (admin + ACME + OCSP + CRL)
        tcp dport 443 accept

        # Prometheus from monitoring net only
        tcp dport 9090 ip saddr @monitoring_networks accept

        # EST (if enabled) — internal only
        # tcp dport 11112 ip saddr @admin_networks accept

        # Default drop with logging at low rate
        limit rate 5/minute log prefix "pypki-fw-drop: "
    }

    chain outbound {
        type filter hook output priority 0; policy drop;

        ct state established,related accept

        # Loopback
        oifname "lo" accept

        # DNS
        udp dport 53 accept
        tcp dport 53 accept

        # NTP
        udp dport 123 accept

        # HTTPS to cloud KMS, OIDC IdP, ACME upstreams
        tcp dport 443 accept

        # HTTP for OCSP, CRL fetches (some peers only serve over HTTP)
        tcp dport 80 accept

        # Postgres (if remote)
        tcp dport 5432 ip daddr @db_hosts accept

        # syslog (if remote)
        # udp dport 514 ip daddr 10.30.0.5 accept

        limit rate 5/minute log prefix "pypki-egress-drop: "
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }
}
```

Tune sets per deployment. The template ships with sensible
defaults that the init wizard customizes.

### ufw (Ubuntu)

`packaging/firewall/ufw/setup-ufw.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
ufw --force reset
ufw default deny incoming
ufw default deny outgoing

ufw allow in on lo
ufw allow out on lo

ufw allow from 10.0.0.0/8 to any port 22 proto tcp comment 'SSH from RFC1918'
ufw allow 80/tcp comment 'ACME http-01'
ufw allow 443/tcp comment 'HTTPS / Admin / OCSP / CRL'
ufw allow from 10.10.0.0/16 to any port 9090 proto tcp comment 'Prometheus'

ufw allow out 53 comment 'DNS'
ufw allow out 123/udp comment 'NTP'
ufw allow out 443/tcp comment 'HTTPS egress'
ufw allow out 80/tcp comment 'HTTP egress for OCSP/CRL upstream'
ufw allow out from any to 10.20.0.0/24 port 5432 proto tcp comment 'Postgres'

ufw logging medium
ufw --force enable
ufw status verbose
```

### firewalld (RHEL family)

`packaging/firewall/firewalld/pypki.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>pypki</short>
  <description>PyPKI Certificate Authority</description>
  <port protocol="tcp" port="80"/>
  <port protocol="tcp" port="443"/>
</service>
```

Plus a setup script that defines zones (`public`, `internal`,
`monitoring`) and binds NICs to zones — concrete commands in
`docs/FIREWALL.md`.

### iptables (legacy)

`packaging/firewall/iptables/rules.v4` + `rules.v6`. Same policy
expressed in iptables syntax for systems without nftables. Documented
as legacy-only — recommend nftables migration in `docs/FIREWALL.md`.

### Cloud security groups

Same policy, different syntax:

- `packaging/firewall/aws/security-group.json` — Terraform-friendly
- `packaging/firewall/gcp/firewall-rules.json` — gcloud-friendly
- `packaging/firewall/azure/nsg-rules.json` — az-cli-friendly

Each is the *minimum* set; operators add their environment-specific
allowlists for monitoring, bastion access, etc.

---

## sysctl tuning

`packaging/sysctl/pypki.conf`:

```
# Network — handle high concurrent TLS handshakes
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# Conntrack — needed for high issuance rates
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 1800

# Memory — predictable signing latency
vm.swappiness = 1
vm.overcommit_memory = 0

# Source address validation
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable IP forwarding (we're a CA, not a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Disable redirects (we don't need them)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Log martians
net.ipv4.conf.all.log_martians = 1

# ASLR maximum entropy
kernel.randomize_va_space = 2

# Restrict ptrace
kernel.yama.ptrace_scope = 1

# Restrict dmesg
kernel.dmesg_restrict = 1

# Hide kernel pointers
kernel.kptr_restrict = 2

# Disable kexec
kernel.kexec_load_disabled = 1

# Restrict performance event tracing
kernel.perf_event_paranoid = 3

# Restrict BPF
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# File descriptor limit
fs.file-max = 2097152
```

Applied via `sysctl --system` and persisted in `/etc/sysctl.d/`.

---

## ulimits

`packaging/limits/pypki.conf`:

```
# /etc/security/limits.d/pypki.conf
pypki soft nofile 65536
pypki hard nofile 131072
pypki soft nproc 8192
pypki hard nproc 16384
pypki soft memlock unlimited
pypki hard memlock unlimited
pypki soft core 0
pypki hard core 0
```

`memlock unlimited` lets PyPKI lock CA-key memory pages so they don't
swap. `core 0` matches `LimitCORE=0` in the systemd unit — no core
dumps that might contain key material.

---

## AppArmor profile

`packaging/apparmor/usr.bin.pypki-server`:

```
#include <tunables/global>

profile pypki-server /usr/bin/pypki-server flags=(complain) {
    #include <abstractions/base>
    #include <abstractions/openssl>
    #include <abstractions/python>
    #include <abstractions/nameservice>
    #include <abstractions/ssl_certs>

    capability net_bind_service,

    /usr/bin/pypki-server mr,
    /usr/bin/python3* ix,
    /usr/lib/python3.*/** mr,
    /usr/local/lib/python3.*/** mr,

    /etc/pypki/** r,
    /etc/pypki/secrets/** r,
    /var/lib/pypki/** rw,
    /var/log/pypki/** rw,
    /run/pypki/** rw,

    # CA keys explicitly never executable
    deny /var/lib/pypki/ca/** mx,
    deny /etc/pypki/secrets/** mx,

    # No reading other users' homes or system secrets
    deny /home/** r,
    deny /root/** r,
    deny /etc/shadow r,
    deny /etc/gshadow r,

    # No raw network operations
    network inet stream,
    network inet6 stream,
    network unix stream,
    deny network raw,
    deny network packet,

    # No ptrace
    deny ptrace,

    # Allow notify socket
    /run/systemd/notify w,

    # PKCS#11 module access (if HSM)
    /usr/lib/x86_64-linux-gnu/libsofthsm2.so mr,
    /usr/lib/x86_64-linux-gnu/pkcs11/** mr,
    /var/lib/softhsm/** rwk,

    signal (receive) peer=unconfined,
}
```

Ship in `complain` mode initially so deployment isn't blocked by
unknown access patterns; flip to `enforce` after a week of clean
logs. Document the workflow in `docs/HARDENING.md`.

---

## SELinux policy

For RHEL/Rocky/Alma. `packaging/selinux/pypki.te`:

```selinux
policy_module(pypki, 1.0.0)

require {
    type unconfined_t;
    class file { read write open execute };
    class tcp_socket { connect listen };
}

# Type definitions
type pypki_t;
type pypki_exec_t;
type pypki_etc_t;
type pypki_var_lib_t;
type pypki_var_log_t;
type pypki_port_t;

# Domain transition
init_daemon_domain(pypki_t, pypki_exec_t)

# File access patterns mirror AppArmor profile above
files_read_etc_files(pypki_t)
allow pypki_t pypki_etc_t:file { read open };
allow pypki_t pypki_var_lib_t:dir { read write add_name search };
allow pypki_t pypki_var_lib_t:file { read write open create unlink };
allow pypki_t pypki_var_log_t:file { read write open append };

# Network: listen on pypki_port_t, connect to KMS/Postgres
allow pypki_t pypki_port_t:tcp_socket { listen };
corenet_tcp_connect_postgresql_port(pypki_t)
corenet_tcp_connect_http_port(pypki_t)   # for cloud KMS

# Deny everything else by default (SELinux enforcing)
```

Plus an `.fc` file mapping paths to types and a setup script:

```bash
semodule -i pypki.pp
semanage fcontext -a -t pypki_exec_t '/usr/bin/pypki-server'
semanage fcontext -a -t pypki_etc_t '/etc/pypki(/.*)?'
semanage fcontext -a -t pypki_var_lib_t '/var/lib/pypki(/.*)?'
semanage fcontext -a -t pypki_var_log_t '/var/log/pypki(/.*)?'
semanage port -a -t pypki_port_t -p tcp 443
restorecon -R /etc/pypki /var/lib/pypki /var/log/pypki
```

Same `permissive`-first deployment pattern as AppArmor.

---

## Entropy and time sync

Two often-forgotten basics that bite CAs hard.

**Entropy**: in 2026 the kernel's crypto-quality RNG is well-stocked
on any reasonable hardware, but VMs without RDRAND/VirtIO-RNG and
some containers can still stall. Document the check:

```
cat /proc/sys/kernel/random/entropy_avail   # should be >256 always
```

Install `rng-tools` and enable `rngd` on VMs without hardware RNG.
Detect at preflight (`CLAUDE-preflight-check.md`).

**Time sync**: certificate validity depends on agreement between
PyPKI's clock and verifiers' clocks. >5s drift produces "not yet valid"
or "expired" errors that look like bugs.

Required:

```
systemctl enable --now chronyd       # or systemd-timesyncd
chronyc tracking                     # check System time within ±1s
```

Document this in `docs/HARDENING.md`. The preflight CLI fails if
drift exceeds 1 second.

---

## Implementation

### Files touched

| File / Path                          | Change                              |
| ------------------------------------ | ----------------------------------- |
| `packaging/firewall/`                | All firewall templates above        |
| `packaging/sysctl/pypki.conf`        | sysctl tuning                       |
| `packaging/limits/pypki.conf`        | ulimits                             |
| `packaging/apparmor/usr.bin.pypki-server` | AppArmor profile               |
| `packaging/selinux/`                 | SELinux module + scripts            |
| `bootstrap/firewall_setup.py`        | Detect firewall stack, apply template |
| `bootstrap/mac_setup.py`             | Detect AA/SELinux, install profile  |
| `pypki_admin.py`                     | `hardening-status`, `hardening-apply`, `hardening-validate` |
| `test_pypki_init.py`                 | `TestFirewallTemplates`, `TestMACProfiles`, `TestSysctlApplied` |
| `README.md`                          | Hardening section                   |
| `CHANGELOG.md`                       | `### Added`, `### Security`         |
| `docs/HARDENING.md`                  | Full operator guide                 |
| `docs/FIREWALL.md`                   | Firewall stack matrix, customization |

### Detection logic

```python
def detect_firewall_stack() -> str:
    if shutil.which("nft") and _service_active("nftables"):
        return "nftables"
    if shutil.which("ufw") and _service_active("ufw"):
        return "ufw"
    if shutil.which("firewall-cmd") and _service_active("firewalld"):
        return "firewalld"
    if shutil.which("iptables"):
        return "iptables"
    return "none"

def detect_mac() -> str:
    if Path("/sys/kernel/security/apparmor").exists():
        return "apparmor"
    if Path("/sys/fs/selinux").exists():
        return "selinux"
    return "none"
```

`hardening-apply` runs the right template based on detection. Refuses
silently to install templates that conflict with existing rules
unless `--force-replace` is passed.

---

## CLI flags

```
--hardening-level standard|strict|paranoid
--firewall-stack auto|nftables|ufw|firewalld|iptables|none
--mac auto|apparmor|selinux|none
--apparmor-mode complain|enforce
--selinux-mode permissive|enforcing
--apply-sysctl true
--apply-ulimits true
```

`pypki_admin.py`:

- `hardening-status` — print what's currently in place
- `hardening-apply` — install everything for the configured level
- `hardening-validate` — assert what's in place matches expectations
  (fails CI / cron if drift)

---

## Tests

```
class TestFirewallTemplates(unittest.TestCase):
    def test_nftables_template_parses(self): ...        # nft -c
    def test_ufw_script_idempotent(self): ...
    def test_firewalld_xml_valid(self): ...
    def test_iptables_rules_apply_in_test_netns(self): ...
    def test_all_templates_share_same_port_matrix(self): ...

class TestMACProfiles(unittest.TestCase):
    def test_apparmor_profile_parses(self): ...         # apparmor_parser -Q
    def test_selinux_module_compiles(self): ...         # checkmodule
    def test_apparmor_blocks_unexpected_file_access(self): ...
    def test_selinux_blocks_unexpected_network_access(self): ...

class TestSysctlApplied(unittest.TestCase):
    def test_sysctl_file_parses(self): ...              # sysctl -p --dry-run
    def test_apply_then_read_matches(self): ...
    def test_no_conflict_with_existing_sysctl_d(self): ...
```

Each runs on a CI runner with the relevant tool installed. Firewall
tests use a network namespace so they don't touch the host's actual
firewall.

---

## Per-change checklist

- [ ] `packaging/firewall/` — six template stacks
- [ ] `packaging/sysctl/pypki.conf`, `packaging/limits/pypki.conf`
- [ ] `packaging/apparmor/`, `packaging/selinux/`
- [ ] `bootstrap/firewall_setup.py`, `bootstrap/mac_setup.py`
- [ ] `pypki_admin.py` — `hardening-*` subcommands
- [ ] `test_pypki_init.py` — three test classes
- [ ] `README.md` — Hardening section
- [ ] `CHANGELOG.md` — `### Added`, `### Security`
- [ ] `docs/HARDENING.md`, `docs/FIREWALL.md` — operator guides
- [ ] `pypki-flows.html` — host-hardening summary

Run `./run_tests.sh`. The firewall-template parse tests catch the
most common breakage (syntax drift between firewall tool versions).

---

## Open questions

1. **Confidential computing**: AMD SEV-SNP, Intel TDX, AWS Nitro
   Enclaves. PyPKI could leverage attested compute for CA key
   handling. Significant architectural work; out of scope here but
   sketch in `docs/HARDENING.md` for the truly paranoid.

2. **SELinux MLS**: multi-level security mode for government
   deployments. Skip; the targeted policy is sufficient for >99% of
   users. Document the gap.

3. **eBPF-based observability vs eBPF-as-attack-surface**: bpf is
   restricted in the sysctl above. Operators wanting eBPF
   observability (Cilium, Pixie, etc.) must relax
   `kernel.unprivileged_bpf_disabled` — document the tradeoff.

4. **Cloud-managed MAC equivalents**: AWS Nitro security groups,
   GCP Shielded VMs, Azure Confidential VMs each have their own
   confidentiality story. Document the integration points but don't
   try to replace MAC with cloud features — they solve different
   problems.

5. **Firewall management vs PyPKI-managed firewall**: should PyPKI
   ever modify the host firewall at runtime (e.g. adding an IP to
   an allowlist when a new monitoring host registers)? No. The
   firewall is the host's responsibility. PyPKI ships templates
   and validates them; it doesn't manage them.

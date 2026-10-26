# Proxmox VE → Wazuh: alert rules & dashboard

Custom Wazuh content that adds **Proxmox VE** hypervisor threat detection — VM/CT lifecycle,
snapshot deletion / rollback and backup failures (anti-recovery), rogue-admin / API-token creation,
web-UI/API brute force, `/etc/pve` cluster-config tampering and a file-only **SCA hardening
policy** for the PVE management plane — with MITRE ATT&CK tags and a ready-made
**"Proxmox VE Security & Threats"** dashboard.

> **Agent, not syslog.** Proxmox VE is Debian-based and runs the Wazuh **agent**, so it inherits the
> entire stock Linux ruleset (SSH, sudo, PAM, dpkg, kernel, auditd) plus Wazuh's **stock Proxmox VE
> ruleset**. This pack only fills the gaps the stock content leaves.

## Requirements

- **Wazuh manager 4.x** — relies on the stock Proxmox VE ruleset (`0440-proxmox-ve_decoders.xml`,
  `0495-proxmox-ve_rules.xml`, base rule `87200`) and the stock web-accesslog decoder, plus PCRE2
  rule syntax. Validated on Wazuh 4.14.5.
- **Wazuh dashboard / OpenSearch Dashboards 2.16.x** with a `wazuh-alerts-*` index pattern
  (for importing the dashboard).
- A **Proxmox VE host** (Debian-based) running the **Wazuh agent**, with `/var/log/pveproxy/access.log`
  present (default) and read access to `/etc/pve` for FIM.

## Why Proxmox needs **no** custom decoders

Agentless devices that emit **foreign wire formats** with zero stock coverage need full decoder
suites. Proxmox is different: every field these rules need is already produced by **stock** decoders,
and a custom decoder could not even win (stock `ruleset/decoders` load before `etc/decoders`). So this
is a **rules-only** pack that chains off stock decoders/rules:

| PVE log source | Stock decoder / rule that already parses it | This pack adds |
|---|---|---|
| `pvedaemon` (incl. task UPID lines) | `0440-proxmox-ve_decoders.xml`, base rule **87200** | VM/CT lifecycle, pveum admin, snapshot delete/rollback, backup task failure (100390–100394, 100428–100431) |
| `pvescheduler` (scheduled backup jobs) | **none** — no stock decoder; without help these lines fall to stock `1002` or nothing | program-name parent **100435** (L0) + children 100436/100437 |
| `vzdump` ERROR lines | none; stock **1002** ("bad words", L2) claims them | 100433 (child of 1002, scoped by program name) |
| kernel OOM | stock **5108** (L12 for host-wide *and* cgroup OOM) | cgroup-vs-host split (100426/100427) |
| `pveproxy/access.log` | `0375-web-accesslog` → `srcip`/`url`/`id`; rules **31100/31108/31101** | PVE-labelled login + brute force (100416–100418). NB: 100416 declares `if_sid=31100,31108` because stock **31108** (L0 "Ignored URLs") claims every 2xx line as a 31100 child — without the dual parent, 100416 is never evaluated (verified with `wazuh-logtest`). |
| `/etc/pve` FIM | stock syscheck parents **550/553/554** | per-file escalation (100419–100425, 100434) |
| SCA scan results | stock SCA rules (failed check **19007**) | hardening-policy failures escalated (101511) + the policy itself (`sca/pve_hardening.yml`) |

**Already covered by Wazuh's stock `0495-proxmox-ve_rules.xml` (do _not_ duplicate):** `87201` (L6) PVE
auth failure, `87202` (L10) PVE brute force, `87203` (L3) PVE auth success. This pack keeps them as the
safety net and adds only what they leave silent (everything else routes to `87200` at L0).

## Contents

```
proxmox_rules.xml      # 28 rules (100390–100437 except 100432, + 100023, 101511): VM/CT lifecycle, pveum,
                       #   web-UI auth, /etc/pve FIM, snapshot/backup integrity (section D), Wazuh-layer
                       #   mawk de-rate (section E), kernel cgroup-OOM split (section F), SCA
                       #   hardening-failure escalation (section G)
sca/
  pve_hardening.yml    # file-only SCA policy "Proxmox VE Management-Plane Hardening" (checks 90001–90006)
audit-rules/
  99-wazuh-mitre.rules # auditd kernel rules for /etc/audit/rules.d/ on the Proxmox host:
                       #   execve never-rules (daemon firehose suppression) + full MITRE watch-list
                       #   + clock-tampering watch
dashboards/
  gen_proxmox_dashboard.py        # generator for the "Proxmox VE Security & Threats" dashboard (stdlib only)
  wazuh_proxmox_dashboard.ndjson  # pre-generated saved-objects export (import this)
```
> No decoders directory — by design (see above). The dashboard's **overview & auth** panels span all
> PVE security activity (`rule.groups: (proxmox or "proxmox-ve")` — Wazuh's stock pvedaemon auth rules
> `87201/87202/87203` **plus** this pack's custom rules `100390–100437`), so the board reflects ongoing
> PVE logins/auth on a healthy box rather than sitting blank. The **detection** panels (VM/CT
> destruction, attack roll-up, lifecycle, pveum/admin, `/etc/pve` FIM) stay scoped to the specific
> custom rule IDs — these legitimately read zero until the corresponding event first occurs.

## Alert rules

| Rule | Level | Event | MITRE |
|------|------|-------|-------|
| 100390 | 6 | VM/CT created or restored (`qmcreate`/`vzcreate`/`pct_create`/`qmrestore`/`vzrestore`) | T1578.002 |
| 100391 | **10** | **VM/CT DESTROYED** (`qmdestroy`/`vzdestroy`/`pct_destroy`) | T1578.001 / T1485 |
| 100392 | 6 | `vzdump` backup job started | T1005 |
| 100393 | 7 | VM/CT migration (`qmmigrate`/`vzmigrate`) | T1578 |
| 100394 | 8 | pveum user/role/ACL/token admin op (best-effort) | T1136.001 / T1098 |
| 100416 | 4 | PVE web-UI/API login **success** (with `srcip`) | T1078 |
| 100417 | 8 | PVE web-UI/API login **failure** | T1110 |
| 100418 | **10** | PVE web-UI/API **brute force** (6 fails/120s, same source) | T1110.001 |
| 100419 | **10** | `/etc/pve/user.cfg` changed (**rogue admin / token**) | T1098 / T1136.001 |
| 100420 | **10** | `/etc/pve/priv/` key or secret changed | T1552 |
| 100421 | **10** | `/etc/pve/corosync.conf` changed (cluster membership) | T1489 |
| 100422 | 8 | PVE firewall config changed | T1562.007 |
| 100423 | 7 | PVE storage / datacenter config changed | T1098 |
| 100424 | 1 | `/etc/pve/priv/authkey.key` changed — pvedaemon's **daily** ticket-key rotation, de-rated (child of 100420) | T1552 |
| 100425 | **12** | `authkey.key` changed **≥3× in 3h** — off-cadence, possible ticket-key tampering | T1552 |

### Snapshot & backup integrity (section D)

Ransomware on a hypervisor typically deletes snapshots, rolls guests back or breaks/disables backups
before encrypting or destroying guests. Single events are normal admin work (below the gate); bursts
and failures stand out.

| Rule | Level | Event | MITRE |
|------|------|-------|-------|
| 100428 | 8 | VM/CT **snapshot deleted** (`qmdelsnapshot`/`vzdelsnapshot`) | T1490 |
| 100429 | 8 | VM/CT **rolled back** to a snapshot (`qmrollback`/`vzrollback`) — current state discarded | T1485 |
| 100430 | **12** | **≥3 snapshot deletions in 10 min** — possible recovery inhibition | T1490 |
| 100431 | 8 | `vzdump` task (pvedaemon) **ended with a non-OK status** | T1490 |
| 100433 | 8 | `vzdump` **ERROR** line (`Backup of VM N failed`, `Backup job finished with errors`); child of stock 1002 | T1490 |
| 100434 | 8 | `/etc/pve/jobs.cfg` or legacy `/etc/pve/vzdump.cron` changed — **backup schedule** altered/removed (FIM) | T1490 |
| 100435 | 0 | `pvescheduler` parent (no stock decoder covers it) | — |
| 100436 | 3 | **scheduled** `vzdump` job started (pvescheduler) | — |
| 100437 | 8 | **scheduled** `vzdump` job ended with errors (pvescheduler) | T1490 |

> Why 100435 exists: scheduled backups run under `pvescheduler`, not `pvedaemon`, so stock `87200` and
> rule 100392 never see them. 100435 is a root rule on `program_name`; it claims `pvescheduler` lines
> ahead of stock `1002`, which is why the failed scheduled-job line has its own child (100437).
> ID **100432** is intentionally unused.

### Kernel OOM: container limit vs host (section F)

Stock rule `5108` fires **L12** for both a host-wide OOM and a container/VM hitting its own memory-cgroup
limit. On a hypervisor, an unprivileged LXC (cache, database, …) hitting its limit is routine and is not
a host-availability event.

| Rule | Level | Event | MITRE |
|------|------|-------|-------|
| 100426 | **12** | cgroup OOM killed a **critical service** (`sshd`, `sudo`, `auditd`, `wazuh-*`, `pmxcfs`, `corosync`, `pveproxy`, `pvedaemon`, `pve-cluster`, `systemd`, `dockerd`, `containerd`) | T1499 |
| 100427 | 7 | any other cgroup OOM (a container/VM hit its memory limit) | — |

Host-wide `Out of memory:` lines (no `Memory cgroup`) still fire stock `5108` at L12.
**Scope:** `5108` is generic, so these two rules apply to **every Linux agent**, not only Proxmox hosts.
They are deliberately kept out of the `proxmox` group (they do not appear on the Proxmox dashboard).
Edit the process list in 100426 to match the services that matter in your environment.

### SCA: management-plane hardening (section G)

`sca/pve_hardening.yml` is a small **file-only** Wazuh SCA policy (`Proxmox VE Management-Plane
Hardening`, checks **90001–90006**) for PVE-specific controls that a broad OS CIS benchmark does not
cover. SSH/OS hardening is intentionally left to the OS CIS policy, which uses `c:sshd -T` for
accurate effective-config checks.

| Check | Control | Evidence |
|-------|---------|----------|
| 90001 | Datacenter firewall enabled | `enable: 1` in `/etc/pve/firewall/cluster.fw` |
| 90002 | Datacenter default input policy is DROP | `policy_in: DROP` in `cluster.fw` |
| 90003 | Two-factor authentication configured for `root@pam` | `root@pam` entry in `/etc/pve/priv/tfa.cfg` |
| 90004 | Postfix listens on loopback only | `inet_interfaces = loopback-only` / `localhost` in `/etc/postfix/main.cf` |
| 90005 | auditd installed | `/sbin/auditd` or `/usr/sbin/auditd` exists |
| 90006 | pveproxy web UI bound to a management IP | `LISTEN_IP=` in `/etc/default/pveproxy` |

| Rule | Level | Event | MITRE |
|------|-------|-------|-------|
| 101511 | **10** | a check of **this** policy failed (child of stock `19007`, matched on the policy name) | — |

Stock `19007` reports every failed SCA check at L7 — fine for an OS benchmark with dozens of
findings, but it buries the handful of hypervisor management-plane gaps. `101511` escalates only
this policy's failures; other policies stay at L7 and passed checks are untouched. Rule 101511
matches the policy **name**, so keep `name:` unchanged if you edit the YAML.

**Design: no remote commands.** Every check is an `f:`/`d:` file check, so the agent runs no
commands for this policy and `sca.remote_commands` can (and should) stay at its default **0** in the
agent's `local_internal_options.conf`. A compromised manager therefore cannot use SCA to execute
commands on the hypervisor.

**Honest limits:** the policy only applies to hosts with `/usr/bin/pveversion` or `/etc/pve`
(elsewhere it is skipped as not applicable). A missing evidence file — no `tfa.cfg` at all, no
`/etc/default/pveproxy` — is reported by SCA as *not applicable*, not *failed*. 90004 uses
`regex_type: pcre2` because the default SCA regex engine has no grouped alternation. Check IDs
90001–90006 do not collide with Wazuh's stock SCA policies (verified on 4.14.5).

## Auditd noise-suppression rules (section E)

These rules de-rate benign Proxmox-host daemon execve noise in the **Wazuh layer** (as a second line
of defence behind the kernel-level never-rules in `audit-rules/`).

| Rule | Level | Event |
|------|-------|-------|
| 100023 | 1 | `80789` child: `/usr/bin/mawk` executed by daemon process (auid=4294967295, cwd=/) — Proxmox `pvestatd`/firewall-pipeline polling (~1.7k events/24h). De-rated to L1 (logged, not triaged). |

**Safety:** 100023 matches ONLY `/usr/bin/mawk` AND `auid=4294967295` (no interactive login) AND
`cwd=/`. A human running `awk` in a login session (auid set) still fires stock `80789` at L3.
**Prohibited from ever being added to this de-rate list:** `nmap`, `nc`, `netcat`, `masscan`,
`rustscan`, `hping3`, `socat`, `wget`, `curl`, `ssh` (these feed rule 200166 T1046 recon detection).

## Auditd kernel rules (`audit-rules/99-wazuh-mitre.rules`)

> **This is an endpoint configuration artifact, not a Wazuh XML rule.** Deploy it on each Proxmox
> host to `/etc/audit/rules.d/99-wazuh-mitre.rules` and run `augenrules --load`.

The file contains two logical blocks:

1. **NEVER-rules (daemon execve firehose suppression):**  
   Suppress the high-volume Proxmox daemon execve events at the kernel before they reach Wazuh.
   Covers: `perl` (~59k/24h pvestatd), `lxc-info` (~57k/24h), `proxmox-firewall` (~42k/24h),
   `nft` (~21k/24h), `lvm` (~10k/24h), `timeout` (~5k/24h), `mawk` (~1.7k/24h), and the
   pve-firewall legacy toolchain `xtables-legacy-multi` (~43k/24h), `ebtables-legacy` /
   `ebtables-legacy-restore` (~5.4k/24h each), `ipset` (~5.3k/24h).  
   All scoped to `auid=4294967295` (daemon, no interactive login session) — human-initiated execve
   is unaffected. Each suppressed binary is paired b64+b32.

2. **ALWAYS-rules (MITRE ATT&CK watch-list):**  
   Must come AFTER the never-rules (auditd is first-match-wins). Covers execve (T1059), privilege
   escalation (setuid/setgid family, T1548), credential files (T1003), cron/sudoers persistence
   (T1053/T1548), shell-profile persistence (T1546.004), kernel module load/unload (T1547.006),
   network-config tampering (T1565), and system-clock changes by anything other than the time
   daemon (`-k time-change`; T1070.006-adjacent).

> **PROHIBITED from the never-rules list** (must never be added — would blind detection rules):
> `nmap`, `nc`, `netcat`, `masscan`, `rustscan`, `hping3`, `socat`, `wget`, `curl`, `ssh`.
> These feed rule 200166 (T1046 network-scan, L12) and other IOC detections.

**Deploy on a Proxmox host:**
```bash
# SSH to the Proxmox host (NOT the Wazuh manager container)
sudo cp audit-rules/99-wazuh-mitre.rules /etc/audit/rules.d/99-wazuh-mitre.rules
sudo augenrules --load
sudo auditctl -l | grep never   # verify the never-rules are loaded first
```
> The never-rules must appear BEFORE the always-rules in the file. Do not sort or re-order the file.
> Verify the effective rule order with `auditctl -l`; auditd processes rules top-to-bottom and the
> first matching rule wins.

Levels follow a triage gate of **L10** (≥10 reaches analyst triage). Single events stay below it; only
near-zero-FP events (VM destruction, rogue-admin / key / cluster change) and the brute-force composite
reach the gate.

**Forward-looking rules:** on a quiet box several rules have no positive sample yet (destruction,
pveum, web brute force). The chains are validated with `wazuh-logtest` against synthetic lines and fire
when the event first occurs.

## Canonical fields & MISP

Rules 100416–100418 inherit the stock `web-accesslog` decoder's canonical **`srcip`**, so MISP IP-IOC
rules **100210/100211** auto-flag known-bad sources hitting the management plane and `same_source_ip`
frequency rules work. The stock `pvedaemon` failure decoder also sets `srcip` for `@pam`/`@pve` realms
(stock rules 87201/87202). The pveproxy access.log is the **only** source of source IP on a *successful*
login (the stock pvedaemon success decoder emits none).

## Install / deploy

### 1. Install the rules (Docker)
Run from the unpacked pack root (paths are relative to it):
```bash
docker cp custom_rules/proxmox_rules.xml wazuh.manager:/var/ossec/etc/rules/
docker exec wazuh.manager chown wazuh:wazuh /var/ossec/etc/rules/proxmox_rules.xml
docker exec wazuh.manager /var/ossec/bin/wazuh-analysisd -t   # expect no errors
docker exec wazuh.manager /var/ossec/bin/wazuh-control restart
```
> First confirm the `100390–100394, 100416–100431, 100433–100437`, `100023` and `101511` IDs are free on your manager:
> `docker exec wazuh.manager grep -rhoE 'rule id="(10039[0-4]|1004(1[6-9]|2[0-9]|3[013-7])|100023|101511)"' /var/ossec/etc/rules/ /var/ossec/ruleset/rules/` (expect empty).

### 2. Feed the agent: collect the access.log + watch `/etc/pve`
Rules 100416–100418 need the pveproxy access.log, and 100419–100425 / 100434 need `/etc/pve` FIM
(100434 needs the backup-schedule files `jobs.cfg` / `vzdump.cron`). Add this to
the Proxmox host's agent — either to its local `ossec.conf` or, preferred, to a dedicated **`proxmox`
agent group** `agent.conf` on the manager (`/var/ossec/etc/shared/proxmox/agent.conf`):

```xml
<agent_config>
  <!-- Source of client IP for SUCCESSFUL PVE web logins. log_format=syslog (not apache):
       the stock web-accesslog decoder claims the line on content and extracts srcip/url/id. -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/pveproxy/access.log</location>
  </localfile>

  <!-- /etc/pve is FUSE/pmxcfs: inotify does NOT work, so realtime="yes" is silently ignored here.
       Scheduled scan only. Confirm: `inotifywait /etc/pve` ("No such device" = FUSE, as expected).
       Scoped to high-value files so VM/CT config churn does not flood FIM. -->
  <syscheck>
    <directories check_all="yes">/etc/pve/user.cfg</directories>
    <directories check_all="yes">/etc/pve/corosync.conf</directories>
    <directories check_all="yes">/etc/pve/storage.cfg</directories>
    <directories check_all="yes">/etc/pve/datacenter.cfg</directories>
    <!-- Backup schedule (rule 100434): jobs.cfg is the PVE 7+ scheduler, vzdump.cron is legacy.
         A missing file is simply not reported. -->
    <directories check_all="yes">/etc/pve/jobs.cfg</directories>
    <directories check_all="yes">/etc/pve/vzdump.cron</directories>
    <directories check_all="yes">/etc/pve/firewall</directories>
    <directories check_all="yes">/etc/pve/priv</directories>
    <nodiff type="sregex">\.key$|\.pem$|authkey|shadow\.cfg$|token\.cfg$|tfa\.cfg$</nodiff>
    <ignore>/etc/pve/.version</ignore>
    <ignore>/etc/pve/.rrd</ignore>
    <ignore>/etc/pve/.clusterlog</ignore>
    <ignore>/etc/pve/.vmlist</ignore>
    <ignore>/etc/pve/.members</ignore>
    <ignore type="sregex">^/etc/pve/nodes/[^/]+/lrm_status$</ignore>
  </syscheck>
</agent_config>
```
Create + assign the group (manager-side):
```bash
docker exec wazuh.manager /var/ossec/bin/agent_groups -a -g proxmox -q
docker exec wazuh.manager /var/ossec/bin/agent_groups -a -i <AGENT ID> -g proxmox -q
docker exec wazuh.manager /var/ossec/bin/verify-agent-conf    # no output = clean
```

### 3. Deploy the SCA hardening policy (section G)
Copy the policy into the `proxmox` group's shared directory on the manager — group files are
pushed to member agents and land in the agent's `/var/ossec/etc/shared/`:
```bash
docker cp sca/pve_hardening.yml wazuh.manager:/var/ossec/etc/shared/proxmox/pve_hardening.yml
docker exec wazuh.manager chown wazuh:wazuh /var/ossec/etc/shared/proxmox/pve_hardening.yml
```
and enable it in the same group `agent.conf` (`/var/ossec/etc/shared/proxmox/agent.conf`), inside
`<agent_config>`:
```xml
  <sca>
    <policies>
      <policy>etc/shared/pve_hardening.yml</policy>
    </policies>
  </sca>
```
Leave `sca.remote_commands` at **0** on the Proxmox agent — the policy needs no commands. Run
`verify-agent-conf` again; the agent picks the policy up on its next SCA scan (or restart it).
Failed checks then raise **101511** (L10); confirm in the agent's SCA tab in the Wazuh dashboard.

### 4. Import the dashboard
```bash
docker cp dashboards/wazuh_proxmox_dashboard.ndjson wazuh.dashboard:/tmp/
docker exec wazuh.dashboard curl -sk -u <ADMIN>:<INDEXER_PASSWORD> \
  -X POST "https://localhost:5601/api/saved_objects/_import?overwrite=true" \
  -H "osd-xsrf: true" --form file=@/tmp/wazuh_proxmox_dashboard.ndjson
```
Regenerate after editing panels (writes `wazuh_proxmox_dashboard.ndjson` to the current dir):
`cd dashboards && python3 gen_proxmox_dashboard.py` (stdlib only).
SCA hardening failures (101511) carry the `proxmox` group, so they appear in the overview,
event-type and high-severity panels; there is no dedicated SCA panel (use the agent's SCA
tab for per-check detail).

## Notes & tuning

- **Validate the UPID tokens.** The task-type strings (`qmdestroy`, `vzdump`, …) and whether `pveum`
  logs via `pvedaemon` at all vary by PVE version. Confirm against a real line:
  `journalctl -u pvedaemon -S '7 days ago' | grep 'task UPID' | grep -oE 'UPID:[^ ]+' | sort -u`, then
  `wazuh-logtest`. If `pveum` produces no `pvedaemon` line, rule 100394 never fires (harmless) and the
  `user.cfg` FIM rule (100419) remains the reliable rogue-admin/token detector.
- **FUSE / pmxcfs.** `/etc/pve` is FUSE-backed, so FIM is scheduled-scan only (detection lag up to the
  syscheck interval). For a near-realtime signal you can add `realtime="yes"` on
  `/var/lib/pve-cluster/config.db` (real ext4) — but it fires generically on every pmxcfs write (noisy,
  no file granularity), so it is left **off** by default.
- **Brute-force thresholds** (`100418` 6/120s web) are conservative; tune to your environment. Stock
  `87202` (8/120s pvedaemon) keeps running in parallel.
- **`::ffff:` source IPs.** pveproxy may log IPv4-mapped addresses; `same_source_ip` works either way,
  but MISP CDB correlation may need the prefix normalised.
- **Backup failure wording.** 100431/100437 key on the task `end` status (anything but `OK`) and
  100433 on `vzdump` ERROR text. Confirm on your version with
  `journalctl -u pvescheduler -u pvedaemon -S '30 days ago' | grep -E 'vzdump|Backup'`.
- **Snapshot burst threshold** (`100430`, 3 deletions/10 min) — raise it if you run automated snapshot
  pruning (e.g. a retention script that deletes several snapshots at once).
- **Cluster.** Single-node hosts never emit `corosync.conf`/cluster events — those rules are inert
  there, active on clusters.

## Disclaimer

Provided as-is, with no warranty. Review and tune alert levels and suppression to your own environment
before relying on them.

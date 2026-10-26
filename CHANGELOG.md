# Changelog

All notable changes to this pack are documented here. Versions follow
[Semantic Versioning](https://semver.org/).

## [1.2.0] — 2026-10-26

### Added
- **Snapshot & backup integrity** (section D, anti-recovery / T1490):
  - **100428** (L8) snapshot deleted, **100429** (L8) VM/CT rolled back to a snapshot,
    **100430** (L12) ≥3 snapshot deletions in 10 minutes.
  - **100431** (L8) `vzdump` task ended with a non-OK status (pvedaemon);
    **100433** (L8) `vzdump` ERROR lines (child of stock 1002).
  - **100435** (L0) `pvescheduler` parent — scheduled backups have no stock decoder, so
    100392 never saw them; children **100436** (L3) scheduled backup started and
    **100437** (L8) scheduled backup ended with errors.
  - **100434** (L8) FIM: backup schedule `/etc/pve/jobs.cfg` / `vzdump.cron` changed.
    README agent.conf snippet now watches both files.
- **Kernel OOM split** (section F, children of stock 5108): **100426** (L12) cgroup OOM that
  killed a critical service; **100427** (L7) any other container/VM cgroup OOM (was L12 via
  5108). Host-wide OOM still fires 5108. Applies to every Linux agent; kept out of the
  `proxmox` group.

### Changed
- Auditd mawk de-rate (100023) is now section E (content unchanged).
- Dashboard: attack panel adds 100430 and stock brute force 87202; lifecycle panel adds the
  snapshot/backup rules; FIM panel adds 100424 and 100434.
- README rule tables, ID ranges (`100390–100394, 100416–100431, 100433–100437`, `100023`) and
  collision-check command updated. ID 100432 is intentionally unused.

## [1.1.0] — 2026-10-26

### Added
- Rule **100424** (L1): de-rates the expected daily rotation of
  `/etc/pve/priv/authkey.key` (pvedaemon ticket-signing key). Every other `/etc/pve/priv`
  secret still fires 100420 at L10.
- Rule **100425** (L12): `authkey.key` changed ≥3 times in 3 hours — off-cadence rotation,
  possible ticket-key tampering (T1552).
- auditd never-rules for the pve-firewall legacy toolchain (`xtables-legacy-multi`,
  `ebtables-legacy`, `ebtables-legacy-restore`, `ipset`) — roughly 54k daemon-only SYSCALL
  alerts per day removed at the kernel. Interactive use (auid set) is still audited.
- auditd `time-change` watch: system-clock syscalls by anything other than the time
  daemon, plus writes to `/etc/localtime`.

### Changed
- Dashboard attack and FIM panels include 100425.
- README rule tables, ID range (`100390–100394, 100416–100425`) and collision-check
  command updated.

## [1.0.0] — 2026-06-27

- Initial public release: VM/CT lifecycle, pveum, web-UI/API auth, `/etc/pve` FIM
  escalation, auditd MITRE watch-list and the "Proxmox VE Security & Threats" dashboard.

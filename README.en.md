# linux-pagecache-lpe-2026

**Copy Fail · Dirty Frag family** — a **temporary mitigation script** and response guide for 8 Linux kernel page-cache local privilege escalation (LPE) vulnerabilities disclosed in 2026 (5 of which the script automates).

[🇰🇷 한국어 버전](README.ko.md)

---

## Why a mitigation script at all

The real fix is a kernel patch, but production fleets often can't patch immediately — no reboot window, a vendor-pinned kernel, no patch published yet, or a change-management process that takes weeks. This script is a **compensating control** for that gap.

---

## TL;DR

- **8 CVEs in scope, but the script only automates 6.** All share the same failure class — "treating file-backed page-cache memory as a normal write target and writing to it in place." Trigger paths differ, so **each CVE needs its own patch**. [mitigate-cve-2026.sh](mitigate-cve-2026.sh) automates 31431/43284/43500/46300/43503/46331; 43494 (PinTheft) and 31694 (FUSE) only have manual steps documented in the guide.

- **Real-world risk splits into 3 tiers.**
  - 🔴 **P1**: Copy Fail (31431) — the family is commonly called "Dirty Frag," but Copy Fail is the **only one of the eight listed in the CISA KEV catalog** (2026-05-01) with **confirmed active exploitation**, and its trigger bar is the lowest — an `AF_ALG` socket can be opened by any local account without an unprivileged namespace. If you can only apply a partial mitigation, **block `algif_aead` first**.
  - 🟠 **P2**: Dirty Frag (43284/43500), Fragnesia (46300), DirtyClone (43503), pedit COW (46331) — all share the same prerequisite (an unprivileged user/net namespace to acquire CAP_NET_ADMIN), and all have public PoCs and a vendor RHSB.
  - ⚪ **Other**: PinTheft (43494), FUSE cache overflow (31694) — "Other" doesn't mean "low risk"; the reason differs per CVE, see the Target CVEs table and guide section 5.6.

- **How it works**: blocks autoload of the kernel modules that reach the vulnerable code (`esp4`/`esp6`/`rxrpc`/`algif_aead`). This is **the exact mitigation procedure Red Hat documents in RHSB-2026-003**, so it can be cited when requesting change-management approval. No reboot required; `--rollback` reverts instantly.

- **Only a patch is a complete fix**: DirtyClone's (43503) root cause lives in a core kernel function (`__pskb_copy_fclone()`), so blocking modules only closes the known trigger, not the flaw itself. Full protection requires a kernel with the entire DirtyFrag+Fragnesia chain (upstream v7.1-rc5 or later).

```bash
sudo bash mitigate-cve-2026.sh --dry-run    # 1) inspect only, no changes
sudo bash mitigate-cve-2026.sh              # 2) interactive apply
sudo bash mitigate-cve-2026.sh --rollback   # 3) revert if needed
```

> ⚠️ **Must run as root.** As non-root, usage-signal detection (`ip xfrm`, etc.) fails silently, which can misclassify an IPsec-using server as "unused" — so the script refuses to run at all.

## Needs re-verification before you apply

- **CISA KEV listing and active-exploitation status change over time.** Re-check all 8 CVEs against the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) at the time you apply this.
- **Oracle Linux 9 (UEK) has no published advisory for CVE-2026-43503 as of 2026-07.** Even the latest UEK kernel may still be unpatched for this CVE — reconfirm current status before relying on it.
- **"RHEL family, so not affected" doesn't hold without checking the specific distro.** PinTheft (43494) is not affected on RHEL proper, but **Oracle Linux (UEK) is affected** — RDS is Oracle's own RAC database-interconnect protocol, and `CONFIG_RDS=m` was directly confirmed there (2026-07-23, guide section 2.7). Re-rate FUSE (31694) upward too if your fleet tracks kernel 6.16+ directly.
- All CVE data in this repo is a snapshot **re-verified against OSV/NVD/RHSB primary sources on 2026-07-22**. Vendor advisories and package versions keep changing, so reconfirm against your distro's current information before applying anything.

---

## Target CVEs

| CVE | Alias | Priority | CVSS | Subsystem / module | Script support |
|---|---|---|---|---|---|
| CVE-2026-31431 | Copy Fail | 🔴 P1 | 7.8 | Kernel crypto API / `algif_aead` | ✅ |
| CVE-2026-43284 | Dirty Frag (ESP) | 🟠 P2 | 8.8 (Red Hat rating 7.8) | IPsec ESP input processing / `esp4`, `esp6` | ✅ |
| CVE-2026-43500 | Dirty Frag (RxRPC) | 🟠 P2 | 7.8 | RxRPC protocol / `rxrpc`. **Not affected for Red Hat products** | ✅ |
| CVE-2026-46300 | Fragnesia | 🟠 P2 | 7.8 | Pre-existing flaw in `skb_try_coalesce()`. Became exploitable only after the 43284 patch (not a regression) | ✅ |
| CVE-2026-43503 | DirtyClone | 🟠 P2 | 8.8 (Red Hat rating 7.0) | skb clone path (kernel core). Confirmed trigger sink is `esp4`/`esp6` | ✅ |
| CVE-2026-46331 | pedit COW | 🟠 P2 | 7.8 (kernel.org) / 6.7 (Red Hat) | COW-range miscalculation in tc `act_pedit`. Same prerequisite as the rest of P2 (via namespace) | ✅ |
| CVE-2026-43494 | PinTheft | ⚪ Other | 7.8 (kernel.org) / 7.0 (Red Hat) | RDS zerocopy + io_uring. Not affected on RHEL proper, but **Oracle Linux (UEK) is affected** (CONFIG_RDS=m) | ❌ manual (guide §5.6) |
| CVE-2026-31694 | (FUSE cache overflow) | ⚪ Other | 7.8 (kernel.org) | FUSE directory-entry caching. Needs kernel 6.16-rc1+; not affected across RHEL 6–10 | ❌ manual (guide §5.6) |

For root-cause details, patch commits, version ranges, RHEL specifics, and manual mitigation for PinTheft/FUSE, see [pagecache-lpe-guide.en.md](pagecache-lpe-guide.en.md).

---

## Files

| File | Description |
|---|---|
| [mitigate-cve-2026.sh](mitigate-cve-2026.sh) | The mitigation script |
| [pagecache-lpe-guide.en.md](pagecache-lpe-guide.en.md) | Technical guide: root cause per CVE, patch chain structure, RHEL/CentOS version details |

---

## Features

- **Automatic distro patch detection** — scans changelogs for CVE IDs and excludes already-patched modules from action; exits with no changes if all 5 script-supported CVEs are resolved.
- **Vendor advisory lookup (`--online`)** — for kernels whose changelog carries no CVE IDs (e.g. Oracle UEK), confirms "fix shipped but not installed" as vulnerable.
- **Fail-safe default** — if patch status can't be proven, the module stays in scope for action. Only one exemption is backed by a primary source (RxRPC on Red Hat).
- **Built-in (`=y`) detection** — flags cases where module blocking won't work and suggests alternatives.
- **Distinguishes "unused" from "unknown"** — detection failures are never collapsed into "no signal," which would risk misreading an IPsec-using server as unused and cutting its VPN.
- **Usage-signal detection (heuristic)** — checks `ip xfrm`, IKE ports, strongswan/libreswan, AFS mounts, container runtimes.
- **Conclusion-first output, offline by default** — the default output is a ~20-line diagnosis-and-action summary; rationale is behind `--verbose`, network access behind `--online`.
- **Idempotent + reversible + automatable** — reruns are stable, `--rollback` restores prior state (including original sysctl values), and meaningful exit codes wire into [Ansible/CI](#ansible-integration).

---

## Details

### Options

| Option | Description |
|---|---|
| `-n`, `--dry-run` | Inspect only, no changes (no prompt) |
| `-y`, `--yes` | Auto-confirm prompts (for Ansible/CI). The high-impact namespace restriction is never auto-applied by this flag |
| `--rollback` | Revert configuration created by this script |
| `-v`, `--verbose` | Print full rationale and intermediate steps (default is summary only) |
| `--online` | Allow network access (default: offline). Red Hat family uses `dnf updateinfo`; Debian family falls back to `apt changelog` |
| `-h`, `--help` / `-V`, `--version` | Help / version |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No action needed (or rollback complete) |
| `1` | Error (not root, bash < 4, etc.) |
| `2` | Invalid argument |
| `10` | Action needed (`--dry-run` result, or user declined) |
| `20` | Changes were actually applied |

In Ansible, pair `--yes` with `failed_when: rc not in [0, 20]`.

### Ansible integration

The script's exit codes are designed to map directly onto Ansible's `changed_when`/`failed_when`.

**1. Bulk apply**
```yaml
- name: Apply Dirty Frag family mitigation
  ansible.builtin.command: bash /opt/mitigate-cve-2026.sh --yes
  register: mitigate
  changed_when: mitigate.rc == 20
  failed_when: mitigate.rc not in [0, 20]
```
`rc==20` (changes applied) maps to `changed`; `rc==0` (already safe / no action needed) is a no-op success; anything else fails the task.

**2. Pre-scan (identify targets without changing anything)**
```yaml
- name: Check whether action is needed (no changes)
  ansible.builtin.command: bash /opt/mitigate-cve-2026.sh --dry-run --yes
  register: precheck
  changed_when: false
  failed_when: precheck.rc not in [0, 10]
```
Collect only hosts with `rc==10` to build your rollout target list.

**3. Rollback**
```yaml
- name: Revert the mitigation
  ansible.builtin.command: bash /opt/mitigate-cve-2026.sh --rollback --yes
  register: rollback
```

**Caveats**
- **The namespace restriction (built-in mitigation) is never auto-applied, even with `--yes`** — it's deliberately excluded from unattended automation because of its impact. Those hosts need individual interactive approval.
- Idempotent, so reruns are safe — but **rerunning after a kernel patch automatically lifts the block for that CVE's module**. Account for this if the playbook reruns on a schedule.
- Requires root. In non-interactive contexts, pass `--yes` or `--dry-run` to avoid hitting an interactive prompt.
- **Don't apply to the whole inventory at once — validate on 1-2 canary hosts first.** Roll out in small batches with `serial` and confirm there's no service impact (IPsec/VPN drops, AF_ALG disruption, etc.) before expanding to the rest of the fleet (same recommendation as guide section 5.4, "Phased rollout").
  ```yaml
  - hosts: patch_targets
    serial: "10%"
    tasks:
      - name: Apply Dirty Frag family mitigation
        ansible.builtin.command: bash /opt/mitigate-cve-2026.sh --yes
        register: mitigate
        changed_when: mitigate.rc == 20
        failed_when: mitigate.rc not in [0, 20]
  ```

For full procedures, see sections 5.3–5.4 of [pagecache-lpe-guide.en.md](pagecache-lpe-guide.en.md).

### Distro "not affected" determination

The script skips action for exactly one case, backed by the Red Hat Security Data API (primary source).

| CVE / target | Basis |
|---|---|
| CVE-2026-43500 (RxRPC) / all Red Hat family | `package_state` is `Not affected` across all products, no `affected_release` entries. Reason: **Red Hat does not ship or support a binary RPM providing the rxrpc module** |

Any other "not affected" claims mix in inaccurate secondary-source statements and are not used to skip action. See guide section 4.4.

### Execution flow

1. **Pre-check** — shows module load status, built-in status, distro patch status, and VPN/container usage signals, with no changes.
2. **Confirmation prompt** — if `algif_aead` (Copy Fail, the top-priority KEV-listed item) needs action, it's asked about **independently and first**; the remaining modules are then asked about as a group (`y/N` each). Approving only one still applies whatever was approved, so hesitating over another module never sinks the most urgent, lowest-risk Copy Fail action along with it. `N`/Enter on both exits with no changes.
3. **Create blocklist and unload** — on confirmation, creates `/etc/modprobe.d/mitigate-cve-2026.conf` to block autoload and unloads currently loaded modules.
4. **Post-verification** — re-checks load status and confirms the blocklist took effect.
5. **(Optional) built-in handling** — if built-in code was detected, additionally asks whether to restrict unprivileged user/net namespace creation (may affect containers/sandboxes).

For prerequisites, operational recommendations, and rollback, see section 5 of [pagecache-lpe-guide.en.md](pagecache-lpe-guide.en.md).

### Requirements

- **Bash 4+** (uses associative arrays — aborts with a clear message below this)
- **Root privileges** (non-root execution is refused)
- An interactive terminal — not needed with `--dry-run` or `--yes`
- Red Hat family: `rpm` / Debian/Ubuntu family: `dpkg`, optionally `apt`, `timeout`
- `kmod` (modprobe/lsmod) and `procps` (sysctl) are **not required** — the script falls back to reading `/etc/modprobe.d`, `/proc/modules`, `/proc/sys` directly. Without `modprobe`, however, an already-loaded module **cannot be unloaded**, and the script warns about this.

### Mitigation scope and limits

| Action | Addresses CVE |
|---|---|
| Block `esp4`/`esp6` | 43284, 46300, 43503 |
| Block `rxrpc` | 43500 |
| Block `algif_aead` | 31431 |
| Block `act_pedit` | 46331 |
| Restrict unprivileged namespaces (optional) | 43284/46300/43503/46331 — core-kernel and COW flaws |

DirtyClone's (43503) root cause is in a core kernel function (`__pskb_copy_fclone()`), so blocking modules alone may not fully close it. The only complete fix is a kernel patched with the full DirtyFrag+Fragnesia chain (upstream v7.1-rc5 or later). See sections 4 and 5.5 of [pagecache-lpe-guide.en.md](pagecache-lpe-guide.en.md).

> **Scope of the rxrpc block**: the script decides whether rxrpc needs action based on 43500 alone. JFrog's advisory includes rxrpc as a precautionary measure for the whole family, not because it's DirtyClone's (43503) trigger path — so skipping it where 43500 doesn't apply (e.g. RHEL) does not leave the 43503 path open. You can block it manually to harden the whole family preemptively, but this breaks RxRPC-dependent workloads such as AFS.

> **Blocking `act_pedit`**: pedit COW (46331) is supported using the same mechanism as `esp4`/`esp6`/`rxrpc`/`algif_aead` (autoload block + unload), plus its own tc-pedit usage-signal detection (heuristic). It shares the same trigger prerequisite as the rest of P2, so restricting unprivileged namespaces closes it too.

> **2 CVEs the script doesn't cover yet, for different reasons each**: PinTheft (43494) isn't excluded for being rare — it's excluded because **automated blocking carries an asymmetric risk**: RDS is Oracle's own RAC database-cluster interconnect protocol, so reliable usage-signal detection needs to be designed first. The FUSE cache overflow (31694) is excluded because **`fuse`'s real-world usage footprint is too broad for a safe default block** (sshfs, rclone, Snap packages, etc. depend on it). Manual mitigation commands and full reasoning are in section 5.6 of [pagecache-lpe-guide.en.md](pagecache-lpe-guide.en.md).

---

## License

[MIT License](LICENSE).

This script is provided **"AS IS," with no warranty of any kind**. It unloads kernel modules and changes system configuration — before applying it in production, review sections 5.2 (prerequisites) and 5.5 (limits) of [pagecache-lpe-guide.en.md](pagecache-lpe-guide.en.md) and verify on a canary server first.
